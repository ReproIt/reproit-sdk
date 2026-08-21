export type Json =
  | null
  | boolean
  | number
  | string
  | Json[]
  | { [key: string]: Json };

export interface CandidateStart {
  captureId: string;
  deployment: { [key: string]: Json };
  operationId: string;
  worldId: string;
}

export interface CandidateSink {
  readonly processingModes: ReadonlySet<"managed">;
  readonly queuedBytes: number;
  trySend(captureId: string, candidate: Uint8Array): boolean;
}

export interface OperationPreparation {
  start: CandidateStart;
  begin: { [key: string]: Json };
  inputs: { [key: string]: Json }[];
  dependencies: { [key: string]: Json }[];
}

export interface RecallCounters {
  readonly candidate_delivery_expired: number;
  readonly candidate_durably_accepted: number;
  readonly candidate_incomplete: number;
  readonly candidate_queue_full: number;
  readonly candidate_rejected: number;
  readonly eligible_failure_observed: number;
  readonly suppressed_exact_storm: number;
  readonly suppressed_high_cardinality_storm: number;
}

export declare class CaptureError extends Error {}
export declare class ManagedWorldCapture {
  constructor(
    worldId: string,
    complete: (
      operationId: string,
    ) => ManagedCaptureClosure | Promise<ManagedCaptureClosure>,
  );
  readonly worldId: string;
}
export declare class OperationCapture {
  readonly operationId: string | null;
  recordDependency(dependency: { [key: string]: Json }): void;
}
export declare function operationFromRequest(
  request: object,
): OperationCapture | null;
export declare class ReproIt {
  constructor(
    project: { [key: string]: Json },
    buildRepositoryId: string,
    sourceRevision: string,
    worldCapture: () => ManagedWorldCapture,
  );
  run<Result>(
    operationName: string,
    contentType: string,
    input: Uint8Array | string,
    operation: (capture: OperationCapture) => Result,
    classifyFailure: (error: unknown) => { [key: string]: Json } | null,
  ): Result;
  runStream<Result>(
    operationName: string,
    contentType: string,
    input: Uint8Array | string,
    operation: (capture: OperationCapture) => Result,
    classifyFailure: (error: unknown) => { [key: string]: Json } | null,
  ): Result;
  runDeliveredWork<Result>(
    operationName: string,
    contentType: string,
    input: Uint8Array | string,
    operation: (capture: OperationCapture) => Result,
    classifyFailure: (error: unknown) => { [key: string]: Json } | null,
  ): Result;
  http<Request extends object, Response, Result>(
    operationName: string,
    captureInput: (request: Request) => {
      contentType: string;
      input: Uint8Array | string;
    },
    classifyFailure: (error: unknown) => { [key: string]: Json } | null,
    handler: (request: Request, response: Response) => Result,
  ): (request: Request, response: Response) => Result;
}
export declare class Sdk {
  constructor(sink: CandidateSink);
  readonly activeOperations: number;
  readonly recallCounters: RecallCounters;
  begin(start: CandidateStart, value: { [key: string]: Json }): void;
  recordInput(operationId: string, value: { [key: string]: Json }): void;
  recordDependency(operationId: string, value: { [key: string]: Json }): void;
  succeed(operationId: string): void;
  cancel(operationId: string): void;
  abandonIncomplete(operationId: string): void;
  fail(operationId: string, value: { [key: string]: Json }): void;
}

// Managed-mode capture client.

export declare class ManagedError extends Error {
  readonly code: string;
  readonly retryable: boolean;
  constructor(code: string, message: string, retryable?: boolean);
}

export declare function loadOrCreateManagedWorkloadKey(
  keyPath: string,
): Uint8Array;

export declare class ManagedWorkloadIdentityState {
  constructor(stateRoot: string, bindingDigest: string);
  static fromEnvironment(bindingDigest: string): ManagedWorkloadIdentityState;
  readonly directory: string;
  loadOrCreateKey(): Uint8Array;
  loadOrCreateDeploymentSignedAt(
    bindingDigest: string,
    proposedSignedAt: string,
  ): string;
  loadRegistrationReceipt(expected: {
    deployment_digest: string;
    service_id: string;
    workload_key_id: string;
  }): { [key: string]: Json } | null;
  persistRegistrationReceipt(receipt: {
    deployment_digest: string;
    service_id: string;
    workload_key_id: string;
  }): void;
}

export declare class ManagedProjectToken {
  constructor(value: string);
  authorization(): string;
}

export declare class EncryptionResponse {
  readonly candidateKey: Uint8Array;
  readonly captureGrant: { [key: string]: Json };
  constructor(candidateKey: Uint8Array, captureGrant: { [key: string]: Json });
}

export declare class ManagedTlsEndpoint {
  constructor(
    host: string,
    port: number,
    serverName: string,
    authority: string,
    caCertificatePath: string,
  );
  static official(origin: string): ManagedTlsEndpoint;
  readonly origin: string;
  request(
    method: string,
    target: string,
    authorization: string | null,
    contentType: string | null,
    body: Uint8Array,
    timeoutMilliseconds: number,
  ): Promise<{ body: Uint8Array; status: number }>;
  uploadTarget(uploadUrl: string): string;
}

export declare class ManagedTlsClient {
  constructor(keyService: ManagedTlsEndpoint, ingress: ManagedTlsEndpoint);
  registerWorkloadKey(
    projectToken: ManagedProjectToken,
    request: { [key: string]: Json },
    timeoutMilliseconds: number,
  ): Promise<{
    deployment_digest: string;
    key_id: string;
    service_id: string;
  }>;
  requestEncryptionGrant(
    request: { [key: string]: Json },
    timeoutMilliseconds: number,
  ): Promise<EncryptionResponse>;
  start(
    request: { [key: string]: Json },
    timeoutMilliseconds: number,
  ): Promise<{ [key: string]: Json }>;
  missing(
    uploadId: string,
    uploadToken: string,
    cursor: string | null,
    timeoutMilliseconds: number,
  ): Promise<{ [key: string]: Json }>;
  uploadObject(
    uploadUrl: string,
    digest: string,
    value: Uint8Array,
    timeoutMilliseconds: number,
  ): Promise<void>;
  commit(
    uploadId: string,
    uploadToken: string,
    timeoutMilliseconds: number,
  ): Promise<{ [key: string]: Json }>;
  cancel(
    uploadId: string,
    uploadToken: string,
    timeoutMilliseconds: number,
  ): Promise<{ [key: string]: Json }>;
}

export interface ManagedCandidateArtifact {
  mediaType: string;
  objectId: string;
  path: string;
  role: "dependency-transcript" | "world-state";
  uri: string;
}

export interface ManagedCaptureClosure {
  artifacts: ManagedCandidateArtifact[];
  completion: string;
  world: { [key: string]: Json };
}

export declare class FrozenManagedCaptureClosure {
  readonly closure: ManagedCaptureClosure;
  constructor(closure: ManagedCaptureClosure);
  worldId(): string;
  dispose(): void;
}

export declare class NodeSubjectPackage {
  readonly manifest: { [key: string]: Json };
  readonly objects: { digest: string; path: string; size: number }[];
  dispose(): void;
}

export declare function packageRunningNodeSubject(
  entryScript?: string,
): NodeSubjectPackage;

export declare function subjectBinding(manifest: { [key: string]: Json }): {
  [key: string]: Json;
};

export interface ManagedCandidateGrantDelivery {
  requestEncryptionGrant(
    request: { [key: string]: Json },
    timeoutMilliseconds: number,
  ): Promise<EncryptionResponse>;
}

export interface ManagedCandidateIngressDelivery {
  start(
    request: { [key: string]: Json },
    timeoutMilliseconds: number,
  ): Promise<{ [key: string]: Json }>;
  missing(
    uploadId: string,
    uploadToken: string,
    cursor: string | null,
    timeoutMilliseconds: number,
  ): Promise<{ [key: string]: Json }>;
  uploadObject(
    uploadUrl: string,
    digest: string,
    value: Uint8Array,
    timeoutMilliseconds: number,
  ): Promise<void>;
  commit(
    uploadId: string,
    uploadToken: string,
    timeoutMilliseconds: number,
  ): Promise<{ [key: string]: Json }>;
  cancel(
    uploadId: string,
    uploadToken: string,
    timeoutMilliseconds: number,
  ): Promise<{ [key: string]: Json }>;
}

export declare class PreparedManagedCandidate {
  static prepareComplete(
    candidate: { [key: string]: Json },
    subject: NodeSubjectPackage,
    closure: ManagedCaptureClosure | FrozenManagedCaptureClosure,
  ): PreparedManagedCandidate;
  readonly identity: { [key: string]: Json };
  requestEncryptionGrant(
    delivery: ManagedCandidateGrantDelivery,
    signerKeyId: string,
    signingKey: Uint8Array,
  ): Promise<EncryptionResponse>;
  seal(
    response: EncryptionResponse,
    now: string,
    captureSignerId: string,
    captureSignerPublicKey: Uint8Array,
  ): SealedManagedCandidate;
}

export declare class SealedManagedCandidate {
  readonly request: { [key: string]: Json };
  ciphertextDigests(): string[];
  ciphertextPath(digest: string): string | undefined;
  requestCaptureGrantRenewal(
    delivery: ManagedCandidateGrantDelivery,
    signerKeyId: string,
    signingKey: Uint8Array,
  ): Promise<EncryptionResponse>;
  applyRenewedCaptureGrant(
    response: EncryptionResponse,
    now: string,
    captureSignerId: string,
    captureSignerPublicKey: Uint8Array,
  ): void;
  upload(
    delivery: ManagedCandidateIngressDelivery,
  ): Promise<{ [key: string]: Json }>;
  dispose(): void;
}

export interface ManagedSinkConfiguration {
  captureSignerId: string;
  captureSignerPublicKey: Uint8Array;
  projectToken?: ManagedProjectToken | null;
  projectTokenProvider?: () => ManagedProjectToken | Promise<ManagedProjectToken>;
  serviceId: string;
}

export declare function captureProcessorCapabilities(): string[];

export declare class ManagedCandidateSink implements CandidateSink {
  static create(
    client: ManagedCandidateGrantDelivery &
      ManagedCandidateIngressDelivery & {
        registerWorkloadKey(
          projectToken: ManagedProjectToken,
          request: { [key: string]: Json },
          timeoutMilliseconds: number,
        ): Promise<{
          deployment_digest: string;
          key_id: string;
          service_id: string;
        }>;
      },
    closure: ManagedCaptureClosure | FrozenManagedCaptureClosure,
    configuration: ManagedSinkConfiguration,
    options: {
      deployment: { [key: string]: Json };
      operationId?: string;
      subject?: NodeSubjectPackage;
      workloadStateRoot?: string;
    },
  ): Promise<ManagedCandidateSink>;
  readonly processingModes: ReadonlySet<"managed">;
  readonly queuedBytes: number;
  readonly recallCounters: RecallCounters;
  readonly subjectManifest: { [key: string]: Json };
  readonly workloadKeyId: string;
  readonly workloadPublicKey: Uint8Array;
  readonly worldId: string;
  bindDeployment(deployment: { [key: string]: Json }): void;
  waitUntilIdle(timeoutMilliseconds: number): Promise<boolean>;
  trySend(captureId: string, candidate: Uint8Array): boolean;
}

export declare function createOfficialManagedCandidateSink(
  closure: ManagedCaptureClosure | FrozenManagedCaptureClosure,
  configuration: {
    projectTokenProvider: () =>
      | ManagedProjectToken
      | Promise<ManagedProjectToken>;
    serviceId: string;
  },
  options: {
    deployment: { [key: string]: Json };
    operationId?: string;
    subject?: NodeSubjectPackage;
    workloadStateRoot?: string;
  },
): Promise<ManagedCandidateSink>;

export declare class OfficialManagedProject {
  constructor(
    project: { [key: string]: Json },
    buildRepositoryId: string,
    sourceRevision: string,
  );
  startOperation(worldId: string): OfficialManagedOperation;
}

export declare class OfficialManagedOperation {
  readonly captureId: string;
  readonly operationId: string;
  readonly worldId: string;
  readonly deployment: { [key: string]: Json };
  candidateSink(
    closure: ManagedCaptureClosure | FrozenManagedCaptureClosure,
    configuration: {
      projectTokenProvider: () =>
        | ManagedProjectToken
        | Promise<ManagedProjectToken>;
      serviceId: string;
    },
    options?: {
      subject?: NodeSubjectPackage;
      workloadStateRoot?: string;
    },
  ): Promise<ManagedCandidateSink>;
}

export declare function canonicalBytes(value: Json): Uint8Array;
export declare function runOperation<T>(
  sdk: Sdk,
  start: CandidateStart,
  begin: { [key: string]: Json },
  inputs: { [key: string]: Json }[],
  operation: () => T,
  failure: (error: unknown) => { [key: string]: Json },
): T;
export declare function runPreparedOperation<T>(
  sdk: Sdk,
  preparation: OperationPreparation,
  operation: () => T,
  failure: (error: unknown) => { [key: string]: Json },
): T;
export declare function runStreamOperation<T>(
  sdk: Sdk,
  preparation: OperationPreparation,
  operation: () => T,
  failure: (error: unknown) => { [key: string]: Json },
): T;
export declare function runDeliveredWork<T>(
  sdk: Sdk,
  preparation: OperationPreparation,
  operation: () => T,
  failure: (error: unknown) => { [key: string]: Json },
): T;
