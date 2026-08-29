package reproit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"
)

const (
	FuzzContextHTTPHeader   = "ReproIt-Fuzz-Context"
	FuzzParentHTTPHeader    = "ReproIt-Parent-Operation"
	FuzzContextQueueField   = "reproit.fuzz.context"
	FuzzParentQueueField    = "reproit.parent.operation"
	maximumFuzzContextBytes = 4_096
)

var (
	fuzzCampaignIDPattern = regexp.MustCompile(
		`^fc_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
	fuzzCaseIDPattern = regexp.MustCompile(
		`^case_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
	fuzzProjectIDPattern = regexp.MustCompile(
		`^prj_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
	fuzzServiceIDPattern = regexp.MustCompile(
		`^svc_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
	fuzzOperationIDPattern = regexp.MustCompile(
		`^op_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
)

var ErrFuzzContext = errors.New("Repro It rejected the fuzz context.")

type signedFuzzContext struct {
	CampaignID string `json:"campaign_id"`
	CaseID     string `json:"case_id"`
	ExpiresAt  string `json:"expires_at"`
	Format     string `json:"format"`
	ProjectID  string `json:"project_id"`
	ServiceID  string `json:"service_id"`
	Signature  string `json:"signature"`
}

type FuzzContextValidator struct {
	Clock           func() time.Time
	ProjectID       string
	VerificationKey []byte
}

type FuzzCampaignContext struct {
	context         signedFuzzContext
	contextDigest   string
	encoded         string
	now             string
	parentOperation string
	verificationKey string
}

type fuzzContextKey struct{}

func (validator FuzzContextValidator) Validate(encoded string) (*FuzzCampaignContext, error) {
	if len(encoded) == 0 || len(encoded) > 5_462 || len(validator.VerificationKey) != 32 ||
		validator.Clock == nil {
		return nil, ErrFuzzContext
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) > maximumFuzzContextBytes {
		return nil, ErrFuzzContext
	}
	var value signedFuzzContext
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, ErrFuzzContext
	}
	signed, err := CanonicalBytes(fuzzContextValue(value))
	if err != nil || string(signed) != string(decoded) || !validFuzzContext(value) ||
		value.ProjectID != validator.ProjectID {
		return nil, ErrFuzzContext
	}
	expiresAt, err := time.Parse("2006-01-02T15:04:05.000Z", value.ExpiresAt)
	if err != nil {
		return nil, ErrFuzzContext
	}
	now := validator.Clock().UTC()
	if !now.Before(expiresAt) {
		return nil, ErrFuzzContext
	}
	signature, err := base64.RawURLEncoding.DecodeString(value.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, ErrFuzzContext
	}
	unsigned := value
	unsigned.Signature = ""
	message, err := CanonicalBytes(fuzzContextValue(unsigned))
	if err != nil || !ed25519.Verify(validator.VerificationKey, message, signature) {
		return nil, ErrFuzzContext
	}
	digest := sha256.Sum256(signed)
	return &FuzzCampaignContext{
		context:         value,
		contextDigest:   "sha256:" + hex.EncodeToString(digest[:]),
		encoded:         encoded,
		now:             now.Format("2006-01-02T15:04:05.000Z"),
		verificationKey: base64.RawURLEncoding.EncodeToString(validator.VerificationKey),
	}, nil
}

func ExtractHTTPFuzzContext(
	parent context.Context,
	headers http.Header,
	validator FuzzContextValidator,
) (context.Context, error) {
	if parent == nil || headers == nil {
		return nil, ErrFuzzContext
	}
	encoded := headers.Get(FuzzContextHTTPHeader)
	parentID := headers.Get(FuzzParentHTTPHeader)
	if encoded == "" {
		if parentID != "" {
			return nil, ErrFuzzContext
		}
		return parent, nil
	}
	fuzzContext, err := validator.Validate(encoded)
	if err != nil || (parentID != "" && !fuzzOperationIDPattern.MatchString(parentID)) {
		return nil, ErrFuzzContext
	}
	fuzzContext.parentOperation = parentID
	return context.WithValue(parent, fuzzContextKey{}, fuzzContext), nil
}

func ExtractQueueFuzzContext(
	parent context.Context,
	metadata map[string]string,
	validator FuzzContextValidator,
) (context.Context, error) {
	headers := make(http.Header, 2)
	if encoded := metadata[FuzzContextQueueField]; encoded != "" {
		headers.Set(FuzzContextHTTPHeader, encoded)
	}
	if parentID := metadata[FuzzParentQueueField]; parentID != "" {
		headers.Set(FuzzParentHTTPHeader, parentID)
	}
	return ExtractHTTPFuzzContext(parent, headers, validator)
}

func PropagateQueueFuzzContext(ctx context.Context, metadata map[string]string) {
	fuzzContext, ok := fuzzContextFromContext(ctx)
	if !ok || metadata == nil {
		return
	}
	metadata[FuzzContextQueueField] = fuzzContext.encoded
	if fuzzContext.parentOperation != "" {
		metadata[FuzzParentQueueField] = fuzzContext.parentOperation
	}
}

func fuzzContextFromContext(ctx context.Context) (*FuzzCampaignContext, bool) {
	if ctx == nil || ctx.Err() != nil {
		return nil, false
	}
	value, ok := ctx.Value(fuzzContextKey{}).(*FuzzCampaignContext)
	return value, ok && value != nil
}

func (value *FuzzCampaignContext) beginIdentity() map[string]any {
	return map[string]any{
		"campaign_id":    value.context.CampaignID,
		"case_id":        value.context.CaseID,
		"context_digest": value.contextDigest,
	}
}

func (value *FuzzCampaignContext) nativeInput() *sdkEngineFuzzContextInput {
	return &sdkEngineFuzzContextInput{
		Encoded:         value.encoded,
		Now:             value.now,
		ProjectID:       value.context.ProjectID,
		ServiceID:       value.context.ServiceID,
		VerificationKey: value.verificationKey,
	}
}

func (value *FuzzCampaignContext) withParent(operationID string) *FuzzCampaignContext {
	child := *value
	child.parentOperation = operationID
	return &child
}

func validFuzzContext(value signedFuzzContext) bool {
	return value.Format == "reproit.fuzz-context.v1" &&
		fuzzCampaignIDPattern.MatchString(value.CampaignID) &&
		fuzzCaseIDPattern.MatchString(value.CaseID) &&
		fuzzProjectIDPattern.MatchString(value.ProjectID) &&
		fuzzServiceIDPattern.MatchString(value.ServiceID) && len(value.Signature) == 86
}

func fuzzContextValue(value signedFuzzContext) map[string]any {
	return map[string]any{
		"campaign_id": value.CampaignID,
		"case_id":     value.CaseID,
		"expires_at":  value.ExpiresAt,
		"format":      value.Format,
		"project_id":  value.ProjectID,
		"service_id":  value.ServiceID,
		"signature":   value.Signature,
	}
}
