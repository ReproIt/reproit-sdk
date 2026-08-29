//go:build cgo && (linux || darwin)

package reproit

/*
#cgo linux LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>

typedef uint32_t (*reproit_sdk_engine_abi_version_fn)(void);
typedef uint32_t (*reproit_sdk_engine_capture_probe_fn)(void);
typedef intptr_t (*reproit_sdk_engine_call_fn)(
    const void *, size_t, void *, size_t);

typedef struct {
    void *library;
    reproit_sdk_engine_abi_version_fn abi_version;
    reproit_sdk_engine_call_fn call;
    reproit_sdk_engine_capture_probe_fn capture_probe;
} reproit_sdk_engine_handle;

static reproit_sdk_engine_handle *reproit_open_sdk_engine(const char *name) {
    void *library = dlopen(name, RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) {
        return NULL;
    }
    reproit_sdk_engine_handle *handle = calloc(1, sizeof(*handle));
    if (handle == NULL) {
        dlclose(library);
        return NULL;
    }
    handle->library = library;
    handle->abi_version = (reproit_sdk_engine_abi_version_fn)
        dlsym(library, "reproit_sdk_engine_abi_version");
    handle->call = (reproit_sdk_engine_call_fn)
        dlsym(library, "reproit_sdk_engine_call");
    handle->capture_probe = (reproit_sdk_engine_capture_probe_fn)
        dlsym(library, "reproit_sdk_engine_capture_probe");
    if (handle->abi_version == NULL || handle->call == NULL ||
        handle->capture_probe == NULL) {
        dlclose(library);
        free(handle);
        return NULL;
    }
    return handle;
}

static uint32_t reproit_sdk_engine_version(reproit_sdk_engine_handle *handle) {
    return handle->abi_version();
}

static intptr_t reproit_sdk_engine_call_proxy(
    reproit_sdk_engine_handle *handle,
    const void *input,
    size_t input_len,
    void *output,
    size_t output_capacity) {
    return handle->call(input, input_len, output, output_capacity);
}

static void reproit_close_sdk_engine(reproit_sdk_engine_handle *handle) {
    if (handle == NULL) {
        return;
    }
    dlclose(handle->library);
    free(handle);
}
*/
import "C"

import (
	"sync"
	"unsafe"
)

type cgoSDKEngine struct {
	handle *C.reproit_sdk_engine_handle
	mu     sync.Mutex
}

func openNativeSDKEngine(libraryPath string) (nativeSDKEngine, error) {
	name := C.CString(libraryPath)
	defer C.free(unsafe.Pointer(name))
	handle := C.reproit_open_sdk_engine(name)
	if handle == nil {
		return nil, errSDKEngineUnavailable
	}
	return &cgoSDKEngine{handle: handle}, nil
}

func (engine *cgoSDKEngine) abiVersion() uint32 {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.handle == nil {
		return 0
	}
	return uint32(C.reproit_sdk_engine_version(engine.handle))
}

func (engine *cgoSDKEngine) call(input []byte, output []byte) int64 {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.handle == nil || len(input) == 0 || len(output) == 0 {
		return -1
	}
	return int64(C.reproit_sdk_engine_call_proxy(
		engine.handle,
		unsafe.Pointer(&input[0]),
		C.size_t(len(input)),
		unsafe.Pointer(&output[0]),
		C.size_t(len(output)),
	))
}

func (engine *cgoSDKEngine) close() {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.handle != nil {
		C.reproit_close_sdk_engine(engine.handle)
		engine.handle = nil
	}
}
