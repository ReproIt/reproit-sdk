package reproit

import "runtime"

const (
	automaticGoroutineHeaderBytes = 64
)

func currentAutomaticGoroutineID() (uint64, bool) {
	// Standard hooks such as time.Now do not receive a context. The build
	// instrumentor pins this runtime header shape. A changed shape returns no
	// owner and makes every active operation incomplete.
	var header [automaticGoroutineHeaderBytes]byte
	count := runtime.Stack(header[:], false)
	return parseAutomaticGoroutineID(header[:count])
}

func parseAutomaticGoroutineID(header []byte) (uint64, bool) {
	const prefix = "goroutine "
	if len(header) <= len(prefix) || string(header[:len(prefix)]) != prefix {
		return 0, false
	}
	identifier := uint64(0)
	digits := 0
	for _, value := range header[len(prefix):] {
		if value == ' ' {
			return identifier, digits > 0 && identifier > 0
		}
		if value < '0' || value > '9' || digits >= 20 {
			return 0, false
		}
		next := identifier*10 + uint64(value-'0')
		if next < identifier {
			return 0, false
		}
		identifier = next
		digits++
	}
	return 0, false
}
