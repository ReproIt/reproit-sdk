export type Json =
  | null
  | boolean
  | number
  | string
  | Json[]
  | { [key: string]: Json };

export type TriggerCompletion =
  | "acknowledgment"
  | "return"
  | "stream-end"
  | "task-end";

export interface OperationPreparation {
  begin: { [key: string]: Json };
  inputs: { [key: string]: Json }[];
  completion: TriggerCompletion;
  fuzzContext?: FuzzCampaignContext;
}

export interface FuzzCampaignContext {
  readonly campaignId: string;
  readonly caseId: string;
  readonly contextDigest: string;
  readonly encoded: string;
  readonly parentOperationId: string | null;
  readonly projectId: string;
  readonly serviceId: string;
}

export interface FuzzContextValidatorOptions {
  projectId: string;
  serviceId: string;
  verificationKey: string;
}

export declare class FuzzContextError extends Error {}

export declare class FuzzContextValidator {
  constructor(options: FuzzContextValidatorOptions);
  validate(encoded: string, now: string): FuzzCampaignContext;
}

export declare const FUZZ_CONTEXT_HTTP_HEADER: "ReproIt-Fuzz-Context";
export declare const FUZZ_PARENT_HTTP_HEADER: "ReproIt-Parent-Operation";
export declare const FUZZ_CONTEXT_QUEUE_METADATA: "reproit.fuzz.context";
export declare const FUZZ_PARENT_QUEUE_METADATA: "reproit.parent.operation";

export declare function extractHttpFuzzContext(
  headers: Record<string, string | undefined>,
  validator: FuzzContextValidator,
  now: string,
): FuzzCampaignContext | null;

export declare function extractQueueFuzzContext(
  metadata: Record<string, string>,
  validator: FuzzContextValidator,
  now: string,
): FuzzCampaignContext | null;

export declare function propagateQueueFuzzContext(
  metadata: Record<string, string>,
): void;

export interface OperationContext {
  readonly operationId: string | null;
  recordInput(value: { [key: string]: Json }): void;
}

export interface ManagedEngineProjectOptions {
  projectToml: string;
  buildRepositoryId: string;
  sourceRevision: string;
  projectTokenProvider: () => string;
  entryScript?: string;
}

export declare class ManagedEngineProject {
  private constructor();
  static open(options: ManagedEngineProjectOptions): ManagedEngineProject;
  close(): void;
}

export declare function runOperation<Result>(
  project: ManagedEngineProject,
  preparation: OperationPreparation,
  operation: (context: OperationContext) => Result,
  failure: (error: unknown) => { [key: string]: Json } | null,
): Result;
