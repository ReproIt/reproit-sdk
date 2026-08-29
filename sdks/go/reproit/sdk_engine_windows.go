//go:build windows

package reproit

import (
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

type windowsSDKEngine struct {
	abiVersionProcedure *syscall.Proc
	callProcedure       *syscall.Proc
	library             *syscall.DLL
	mu                  sync.Mutex
}

func openNativeSDKEngine(libraryPath string) (nativeSDKEngine, error) {
	library, err := syscall.LoadDLL(libraryPath)
	if err != nil {
		return nil, errSDKEngineUnavailable
	}
	abiVersion, abiError := library.FindProc(sdkEngineABIVersionSymbol)
	call, callError := library.FindProc(sdkEngineCallSymbol)
	_, probeError := library.FindProc(sdkEngineCaptureProbeSymbol)
	if abiError != nil || callError != nil || probeError != nil {
		_ = library.Release()
		return nil, errSDKEngineUnavailable
	}
	return &windowsSDKEngine{
		abiVersionProcedure: abiVersion,
		callProcedure:       call,
		library:             library,
	}, nil
}

func (engine *windowsSDKEngine) abiVersion() uint32 {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.library == nil {
		return 0
	}
	version, _, _ := engine.abiVersionProcedure.Call()
	return uint32(version)
}

func (engine *windowsSDKEngine) call(input []byte, output []byte) int64 {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.library == nil || len(input) == 0 || len(output) == 0 {
		return -1
	}
	written, _, _ := engine.callProcedure.Call(
		uintptr(unsafe.Pointer(&input[0])),
		uintptr(len(input)),
		uintptr(unsafe.Pointer(&output[0])),
		uintptr(len(output)),
	)
	runtime.KeepAlive(input)
	runtime.KeepAlive(output)
	return int64(written)
}

func (engine *windowsSDKEngine) close() {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.library != nil {
		_ = engine.library.Release()
		engine.library = nil
	}
}
