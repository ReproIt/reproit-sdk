import { acquireRuntimeObservationAdapters } from "./runtime-observation-adapters.js";

// Keep one adapter lease for the lifetime of this module and process.
const releaseProcessLease = acquireRuntimeObservationAdapters();
void releaseProcessLease;
