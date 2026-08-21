import type { CandidateStart, Json, Sdk } from "./index.js";

export interface HttpCapture {
  start: CandidateStart;
  begin: { [key: string]: Json };
  inputs: { [key: string]: Json }[];
}

export declare function wrapHttpHandler<Request, Response, Result>(
  sdk: Sdk,
  prepare: (request: Request) => HttpCapture,
  failure: (error: unknown) => { [key: string]: Json },
  handler: (request: Request, response: Response) => Result,
): (request: Request, response: Response) => Result;
