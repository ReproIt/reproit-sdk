//go:build !cgo || (!linux && !darwin)

package reproit

func openNativeSDKEngine(string) (nativeSDKEngine, error) {
	return nil, errSDKEngineUnavailable
}
