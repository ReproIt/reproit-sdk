const INSTALLED = new Map();
const MAX_INSTALLED = 7;
const REGISTRATION_KEYS = [
  "adapter_id",
  "adapter_version",
  "class",
  "implementation_digest",
];

// Install one real package-owned adapter before an engine opens.
export function installObservationAdapter(registration) {
  if (
    registration === null ||
    typeof registration !== "object" ||
    Array.isArray(registration) ||
    Object.keys(registration).sort().join("\0") !==
      [...REGISTRATION_KEYS].sort().join("\0")
  ) {
    throw new TypeError("The observation adapter registration is invalid.");
  }
  if (INSTALLED.has(registration.class)) {
    throw new Error("The observation adapter is already installed.");
  }
  if (INSTALLED.size >= MAX_INSTALLED) {
    throw new Error("The observation adapter limit was reached.");
  }
  INSTALLED.set(registration.class, Object.freeze({ ...registration }));
}

// Return a stable copy of the package-owned installed adapters.
export function installedObservationAdapters() {
  return [...INSTALLED]
    .sort(([left], [right]) => {
      if (left < right) return -1;
      if (left > right) return 1;
      return 0;
    })
    .map(([, registration]) => ({ ...registration }));
}
