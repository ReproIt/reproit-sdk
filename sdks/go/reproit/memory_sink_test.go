package reproit

import (
	"bytes"
	"os/exec"
	"sync"
	"testing"
)

// MemorySink stores candidate bytes for package tests only.
type MemorySink struct {
	Candidates [][]byte
	mu         sync.Mutex
}

func (sink *MemorySink) AllowsProcessingMode(mode string) bool {
	return mode == "managed" || mode == "private"
}

func (sink *MemorySink) QueuedBytes() int { return 0 }

func (sink *MemorySink) TrySend(_ string, candidate []byte) bool {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.Candidates = append(sink.Candidates, bytes.Clone(candidate))
	return true
}

func TestProductionPackageExcludesMemorySink(t *testing.T) {
	command := exec.Command("go", "doc", "reproit.dev/sdk-go/reproit.MemorySink")
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("the production package exposes MemorySink: %s", output)
	}
}
