import { runOperation } from "../src/index.js";

export function wrapHttpHandler(sdk, prepare, failure, handler) {
  return function validationHttpHandler(request, response) {
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
