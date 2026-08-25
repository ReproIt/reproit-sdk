const MAX_LOGICAL_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_ACTIVE_OPERATIONS = 512;
const MAX_FAILURE_STORM_IDENTITIES = 256;
const MAX_GLOBAL_BYTES = 1_048_576;
const MAX_QUEUED_CANDIDATES = 16;
const FAILURE_SUPPRESSION_MS = 60_000;
const FAILURE_TOKEN_CAPACITY = 4;
const FAILURE_TOKENS_PER_MS = 0.002;

const state = {
  activeBytes: 0,
  activeOperations: new Set(),
  logicalBytes: 0,
  queuedBytes: 0,
  queuedCandidates: 0,
  stormAdmitted: new Map(),
  stormLastRefill: performance.now(),
  stormTokenRejections: 0n,
  stormTokens: FAILURE_TOKEN_CAPACITY,
};
let privateSdkForTests = false;

export function allowsPrivateSdkForTests() {
  return privateSdkForTests;
}

export function enablePrivateSdkForTests() {
  privateSdkForTests = true;
}

export function reserveOperation(operationId, bytes) {
  if (state.activeOperations.has(operationId)) return "duplicate";
  if (
    state.activeOperations.size >= MAX_ACTIVE_OPERATIONS ||
    state.activeBytes + state.queuedBytes + bytes > MAX_GLOBAL_BYTES
  ) {
    return "limit";
  }
  state.activeOperations.add(operationId);
  state.activeBytes += bytes;
  return "reserved";
}

export function growOperation(operationId, bytes) {
  if (
    !state.activeOperations.has(operationId) ||
    state.activeBytes + state.queuedBytes + bytes > MAX_GLOBAL_BYTES
  ) {
    return false;
  }
  state.activeBytes += bytes;
  return true;
}

export function releaseOperation(operationId, bytes) {
  if (!state.activeOperations.delete(operationId)) return;
  state.activeBytes = Math.max(0, state.activeBytes - bytes);
}

export function reserveCandidate(bytes) {
  if (
    state.queuedCandidates >= MAX_QUEUED_CANDIDATES ||
    state.activeBytes + state.queuedBytes + bytes > MAX_GLOBAL_BYTES
  ) {
    return false;
  }
  state.queuedCandidates += 1;
  state.queuedBytes += bytes;
  return true;
}

export function releaseCandidate(bytes) {
  state.queuedCandidates = Math.max(0, state.queuedCandidates - 1);
  state.queuedBytes = Math.max(0, state.queuedBytes - bytes);
}

export function queuedBytes() {
  return state.queuedBytes;
}

export function reserveLogical(bytes) {
  if (bytes < 0 || state.logicalBytes > MAX_LOGICAL_BYTES - bytes) return false;
  state.logicalBytes += bytes;
  return true;
}

export function releaseLogical(bytes) {
  state.logicalBytes = Math.max(0, state.logicalBytes - bytes);
}

export function admitFailure(key) {
  const now = performance.now();
  const elapsed = Math.max(0, now - state.stormLastRefill);
  state.stormTokens = Math.min(
    FAILURE_TOKEN_CAPACITY,
    state.stormTokens + elapsed * FAILURE_TOKENS_PER_MS,
  );
  state.stormLastRefill = now;
  for (const [known, entry] of state.stormAdmitted) {
    if (now - entry.admitted >= FAILURE_SUPPRESSION_MS) {
      state.stormAdmitted.delete(known);
    }
  }
  const existing = state.stormAdmitted.get(key);
  if (existing) {
    existing.observed = now;
    existing.suppressed =
      existing.suppressed === 2n ** 64n - 1n
        ? existing.suppressed
        : existing.suppressed + 1n;
    return "suppressed-exact";
  }
  if (state.stormTokens < 1) {
    state.stormTokenRejections =
      state.stormTokenRejections === 2n ** 64n - 1n
        ? state.stormTokenRejections
        : state.stormTokenRejections + 1n;
    return "suppressed-high-cardinality";
  }
  if (state.stormAdmitted.size >= MAX_FAILURE_STORM_IDENTITIES) {
    const oldest = [...state.stormAdmitted].sort(
      ([leftKey, left], [rightKey, right]) =>
        left.observed - right.observed || leftKey.localeCompare(rightKey),
    )[0];
    if (oldest) state.stormAdmitted.delete(oldest[0]);
  }
  state.stormTokens -= 1;
  state.stormAdmitted.set(key, {
    admitted: now,
    observed: now,
    suppressed: 0n,
  });
  return "admitted";
}

export function resetProcessResourcesForTests() {
  state.activeBytes = 0;
  state.activeOperations.clear();
  state.logicalBytes = 0;
  state.queuedBytes = 0;
  state.queuedCandidates = 0;
  state.stormAdmitted.clear();
  state.stormLastRefill = performance.now();
  state.stormTokenRejections = 0n;
  state.stormTokens = FAILURE_TOKEN_CAPACITY;
}
