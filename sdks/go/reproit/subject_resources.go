package reproit

import "sync"

const maxProcessSubjectBytes = int64(4 * 1024 * 1024 * 1024)

type subjectResourceBudget struct {
	bytes int64
	mu    sync.Mutex
}

var subjectResources subjectResourceBudget

func (resources *subjectResourceBudget) reserve(size int64) bool {
	resources.mu.Lock()
	defer resources.mu.Unlock()
	if size < 0 || resources.bytes > maxProcessSubjectBytes-size {
		return false
	}
	resources.bytes += size
	return true
}

func (resources *subjectResourceBudget) release(size int64) {
	resources.mu.Lock()
	defer resources.mu.Unlock()
	resources.bytes = max(0, resources.bytes-size)
}
