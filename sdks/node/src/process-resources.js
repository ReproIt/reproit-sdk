const MAX_LOGICAL_BYTES = 4 * 1024 * 1024 * 1024;

let logicalBytes = 0;

export function reserveLogical(bytes) {
  if (bytes < 0 || logicalBytes > MAX_LOGICAL_BYTES - bytes) return false;
  logicalBytes += bytes;
  return true;
}

export function releaseLogical(bytes) {
  logicalBytes = Math.max(0, logicalBytes - bytes);
}
