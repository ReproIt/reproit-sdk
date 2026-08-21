import { runOperation } from "./index.js";

export function wrapHttpHandler(sdk, prepare, failure, handler) {
  return function reproItHttpHandler(request, response) {
    let capture;
    try {
      capture = prepare(request);
    } catch {
      return handler(request, response);
    }
    return runOperation(
      sdk,
      capture.start,
      capture.begin,
      capture.inputs,
      () => handler(request, response),
      failure,
    );
  };
}
