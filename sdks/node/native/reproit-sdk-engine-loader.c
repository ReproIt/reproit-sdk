#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <node_api.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_CALL_BYTES ((size_t)1048576)
#define RESPONSE_CAPACITY ((size_t)16384)

#if defined(_WIN32)
#include <windows.h>
#define MAX_ENGINE_PATH_CHARS ((size_t)4096)
#define ENGINE_LIBRARY_NAME L"reproit_sdk_engine.dll"
#else
#include <dlfcn.h>
#include <string.h>
#include <sys/stat.h>
#define MAX_ENGINE_PATH_BYTES ((size_t)4096)
#if defined(__APPLE__)
#define ENGINE_LIBRARY_NAME "libreproit_sdk_engine.dylib"
#else
#define ENGINE_LIBRARY_NAME "libreproit_sdk_engine.so"
#endif
#endif

typedef uint32_t (*engine_abi_version_fn)(void);
typedef uint32_t (*engine_capture_probe_fn)(void);
typedef intptr_t (*engine_call_fn)(
    const void *input,
    size_t input_len,
    void *output,
    size_t output_capacity);

static engine_abi_version_fn engine_abi_version = NULL;
static engine_call_fn engine_call = NULL;
static engine_capture_probe_fn engine_capture_probe = NULL;

static napi_value initialize(napi_env env, napi_value exports);

static napi_value throw_engine_error(napi_env env) {
  napi_throw_error(
      env,
      NULL,
      "The packaged shared SDK engine is unavailable.");
  return NULL;
}

#if defined(_WIN32)
static bool load_engine(void) {
  HMODULE module = NULL;
  if (!GetModuleHandleExW(
          GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
          (LPCWSTR)(uintptr_t)&initialize,
          &module)) {
    return false;
  }

  wchar_t engine_path[MAX_ENGINE_PATH_CHARS];
  DWORD length = GetModuleFileNameW(
      module,
      engine_path,
      (DWORD)MAX_ENGINE_PATH_CHARS);
  if (length == 0 || length >= MAX_ENGINE_PATH_CHARS) return false;
  size_t separator = (size_t)length;
  while (separator > 0 &&
         engine_path[separator - 1] != L'\\' &&
         engine_path[separator - 1] != L'/') {
    separator -= 1;
  }
  const size_t name_chars = sizeof(ENGINE_LIBRARY_NAME) / sizeof(wchar_t);
  if (separator == 0 || separator + name_chars > MAX_ENGINE_PATH_CHARS) {
    return false;
  }
  for (size_t index = 0; index < name_chars; index += 1) {
    engine_path[separator + index] = ENGINE_LIBRARY_NAME[index];
  }

  DWORD attributes = GetFileAttributesW(engine_path);
  if (attributes == INVALID_FILE_ATTRIBUTES ||
      (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
      (attributes & FILE_ATTRIBUTE_DEVICE) != 0 ||
      (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
    return false;
  }
  HMODULE engine = LoadLibraryExW(
      engine_path,
      NULL,
      LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (engine == NULL) return false;
  engine_abi_version = (engine_abi_version_fn)(void *)GetProcAddress(
      engine,
      "reproit_sdk_engine_abi_version");
  engine_call = (engine_call_fn)(void *)GetProcAddress(
      engine,
      "reproit_sdk_engine_call");
  engine_capture_probe = (engine_capture_probe_fn)(void *)GetProcAddress(
      engine,
      "reproit_sdk_engine_capture_probe");
  return engine_abi_version != NULL && engine_call != NULL &&
      engine_capture_probe != NULL;
}
#else
static bool load_engine(void) {
  Dl_info module;
  if (dladdr((const void *)(uintptr_t)&initialize, &module) == 0 ||
      module.dli_fname == NULL) {
    return false;
  }
  const size_t module_bytes = strlen(module.dli_fname);
  if (module_bytes == 0 || module_bytes >= MAX_ENGINE_PATH_BYTES) return false;
  const char *separator = strrchr(module.dli_fname, '/');
  if (separator == NULL) return false;
  const size_t directory_bytes = (size_t)(separator - module.dli_fname) + 1;
  const size_t name_bytes = sizeof(ENGINE_LIBRARY_NAME);
  if (directory_bytes + name_bytes > MAX_ENGINE_PATH_BYTES) return false;

  char engine_path[MAX_ENGINE_PATH_BYTES];
  memcpy(engine_path, module.dli_fname, directory_bytes);
  memcpy(engine_path + directory_bytes, ENGINE_LIBRARY_NAME, name_bytes);
  struct stat metadata;
  if (lstat(engine_path, &metadata) != 0 ||
      S_ISLNK(metadata.st_mode) ||
      !S_ISREG(metadata.st_mode)) {
    return false;
  }
  void *engine = dlopen(engine_path, RTLD_NOW | RTLD_LOCAL);
  if (engine == NULL) return false;
  void *abi_symbol = dlsym(engine, "reproit_sdk_engine_abi_version");
  void *call_symbol = dlsym(engine, "reproit_sdk_engine_call");
  void *capture_probe_symbol = dlsym(engine, "reproit_sdk_engine_capture_probe");
  if (abi_symbol == NULL || call_symbol == NULL || capture_probe_symbol == NULL) {
    return false;
  }
  _Static_assert(sizeof(engine_abi_version) == sizeof(abi_symbol), "ABI pointer size");
  _Static_assert(sizeof(engine_call) == sizeof(call_symbol), "call pointer size");
  _Static_assert(
      sizeof(engine_capture_probe) == sizeof(capture_probe_symbol),
      "capture probe pointer size");
  memcpy(&engine_abi_version, &abi_symbol, sizeof(engine_abi_version));
  memcpy(&engine_call, &call_symbol, sizeof(engine_call));
  memcpy(
      &engine_capture_probe,
      &capture_probe_symbol,
      sizeof(engine_capture_probe));
  return true;
}
#endif

static napi_value abi_version(napi_env env, napi_callback_info info) {
  (void)info;
  if (engine_abi_version == NULL) return throw_engine_error(env);
  napi_value result;
  if (napi_create_uint32(env, engine_abi_version(), &result) != napi_ok) {
    return throw_engine_error(env);
  }
  return result;
}

static napi_value call_engine(napi_env env, napi_callback_info info) {
  size_t argument_count = 2;
  napi_value arguments[2];
  if (engine_call == NULL ||
      napi_get_cb_info(
          env,
          info,
          &argument_count,
          arguments,
          NULL,
          NULL) != napi_ok ||
      argument_count != 2) {
    return throw_engine_error(env);
  }

  bool input_is_buffer = false;
  void *input = NULL;
  size_t input_len = 0;
  uint32_t output_capacity = 0;
  if (napi_is_buffer(env, arguments[0], &input_is_buffer) != napi_ok ||
      !input_is_buffer ||
      napi_get_buffer_info(env, arguments[0], &input, &input_len) != napi_ok ||
      napi_get_value_uint32(env, arguments[1], &output_capacity) != napi_ok ||
      input_len == 0 ||
      input_len > MAX_CALL_BYTES ||
      output_capacity != RESPONSE_CAPACITY) {
    return throw_engine_error(env);
  }

  void *output = malloc(RESPONSE_CAPACITY);
  if (output == NULL) return throw_engine_error(env);
  intptr_t written = engine_call(
      input,
      input_len,
      output,
      RESPONSE_CAPACITY);
  if (written < 0 || (size_t)written > RESPONSE_CAPACITY) {
    free(output);
    return throw_engine_error(env);
  }

  napi_value result;
  napi_status status = napi_create_buffer_copy(
      env,
      (size_t)written,
      output,
      NULL,
      &result);
  free(output);
  if (status != napi_ok) return throw_engine_error(env);
  return result;
}

static napi_value initialize(napi_env env, napi_value exports) {
  if (!load_engine()) return throw_engine_error(env);
  napi_property_descriptor properties[] = {
      {"abiVersion", NULL, abi_version, NULL, NULL, NULL, napi_default, NULL},
      {"call", NULL, call_engine, NULL, NULL, NULL, napi_default, NULL},
  };
  if (napi_define_properties(
          env,
          exports,
          sizeof(properties) / sizeof(properties[0]),
          properties) != napi_ok) {
    return throw_engine_error(env);
  }
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, initialize)
