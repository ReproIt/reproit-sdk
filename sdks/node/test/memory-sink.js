export class MemorySink {
  candidates = [];

  get processingModes() {
    return new Set(["managed", "private"]);
  }

  get queuedBytes() {
    return 0;
  }

  trySend(captureId, candidate) {
    void captureId;
    this.candidates.push(Buffer.from(candidate));
    return true;
  }
}
