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
}

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
