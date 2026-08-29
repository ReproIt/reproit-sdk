package reproit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
)

type fuzzContextVector struct {
	EncodedContext    string `json:"encoded_context"`
	Now               string `json:"now"`
	ParentOperationID string `json:"parent_operation_id"`
	VerificationKey   string `json:"verification_key"`
	Expected          struct {
		CampaignID    string `json:"campaign_id"`
		CaseID        string `json:"case_id"`
		ContextDigest string `json:"context_digest"`
		ProjectID     string `json:"project_id"`
		ServiceID     string `json:"service_id"`
	} `json:"expected"`
}

func TestDistributedFuzzContextVector(t *testing.T) {
	vector := readFuzzContextVector(t)
	verificationKey, err := base64.RawURLEncoding.DecodeString(vector.VerificationKey)
	if err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse("2006-01-02T15:04:05.000Z", vector.Now)
	if err != nil {
		t.Fatal(err)
	}
	validator := FuzzContextValidator{
		Clock: func() time.Time { return now }, ProjectID: vector.Expected.ProjectID,
		VerificationKey: verificationKey,
	}
	headers := make(http.Header)
	headers.Set(FuzzContextHTTPHeader, vector.EncodedContext)
	headers.Set(FuzzParentHTTPHeader, vector.ParentOperationID)
	ctx, err := ExtractHTTPFuzzContext(context.Background(), headers, validator)
	if err != nil {
		t.Fatal(err)
	}
	fuzzContext, ok := fuzzContextFromContext(ctx)
	if !ok || fuzzContext.context.CampaignID != vector.Expected.CampaignID ||
		fuzzContext.context.CaseID != vector.Expected.CaseID ||
		fuzzContext.contextDigest != vector.Expected.ContextDigest {
		t.Fatal("The HTTP context did not match the shared vector.")
	}
	metadata := map[string]string{}
	PropagateQueueFuzzContext(ctx, metadata)
	if metadata[FuzzContextQueueField] != vector.EncodedContext ||
		metadata[FuzzParentQueueField] != vector.ParentOperationID {
		t.Fatal("The queue metadata did not preserve the fuzz context.")
	}
	queueContext, err := ExtractQueueFuzzContext(context.Background(), metadata, validator)
	if err != nil {
		t.Fatal(err)
	}
	queueFuzzContext, ok := fuzzContextFromContext(queueContext)
	if !ok || queueFuzzContext.context.CampaignID != vector.Expected.CampaignID ||
		queueFuzzContext.context.CaseID != vector.Expected.CaseID ||
		queueFuzzContext.parentOperation != vector.ParentOperationID {
		t.Fatal("The queue context did not match the shared HTTP context.")
	}

	tampered := vector.EncodedContext[:len(vector.EncodedContext)-1] + "A"
	if _, err := validator.Validate(tampered); err == nil {
		t.Fatal("A tampered fuzz context was accepted.")
	}
	wrongProject := validator
	wrongProject.ProjectID = "prj_01890f3e-7b21-7cc0-8a1b-123456789abc"
	if _, err := wrongProject.Validate(vector.EncodedContext); err == nil {
		t.Fatal("A cross-project fuzz context was accepted.")
	}
}

func readFuzzContextVector(t *testing.T) fuzzContextVector {
	t.Helper()
	bytes, err := os.ReadFile("../../../conformance/distributed-fuzz-context-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector fuzzContextVector
	if err := json.Unmarshal(bytes, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}
