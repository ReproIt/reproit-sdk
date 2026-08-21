package reproit

import "net/http"

type HTTPPreparation struct {
	Begin        map[string]any
	Dependencies []map[string]any
	Inputs       []map[string]any
	Start        CandidateStart
}

func HTTPMiddleware(
	sdk *SDK,
	prepare func(*http.Request) HTTPPreparation,
	failure func(any) map[string]any,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		capture, prepared := prepareHTTP(request, prepare)
		captureActive := prepared && startPreparedCapture(sdk, OperationPreparation{
			Begin: capture.Begin, Dependencies: capture.Dependencies,
			Inputs: capture.Inputs, Start: capture.Start,
		})
		defer func() {
			if recovered := recover(); recovered != nil {
				if captureActive {
					recordApplicationPanic(sdk, capture.Start.OperationID, recovered, failure)
				}
				panic(recovered)
			}
			if captureActive {
				completeCapture(sdk, capture.Start.OperationID)
			}
		}()
		next.ServeHTTP(writer, request)
	})
}

func prepareHTTP(
	request *http.Request,
	prepare func(*http.Request) HTTPPreparation,
) (preparation HTTPPreparation, prepared bool) {
	defer func() {
		if recover() != nil {
			preparation = HTTPPreparation{}
			prepared = false
		}
	}()
	return prepare(request), true
}
