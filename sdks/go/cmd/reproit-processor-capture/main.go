// Print this host's captured processor capabilities, one per line. The
// sdk-portability gate diffs this output against the other four SDKs to
// prove the cross-SDK capture rule yields one identical list per host.
package main

import (
	"fmt"

	"reproit.dev/sdk-go/reproit"
)

func main() {
	for _, capability := range reproit.CaptureProcessorCapabilities() {
		fmt.Println(capability)
	}
}
