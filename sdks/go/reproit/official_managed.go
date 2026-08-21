package reproit

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	officialManagedHTTPSOrigin          = "__REPROIT_OFFICIAL_MANAGED_HTTPS_ORIGIN_SENTINEL__"
	officialCaptureGrantSignerID        = "__REPROIT_OFFICIAL_CAPTURE_GRANT_SIGNER_ID_SENTINEL__"
	officialCaptureGrantSignerPublicKey = "__REPROIT_OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY_SENTINEL__"
	officialMaxDNSAddresses             = 8
)

var fixtureCaptureSignerPublicKeys = map[string]bool{
	"1238bj1eePRsVOlCHJedzcDZ0DmBthqGWrICsYCNzpA": true,
	"Pm6nrLpZVoxfNqy0GBb7FqsrJ6sTq9OLCSTKJpGtZZk": true,
	"IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI": true,
	"Ivwpd5Lwtv_Av8_bftsMCqFOAlo2XsDjQuhuOCnLdLY": true,
	"p_bfr484uJuozmSbWU-R5NAf3Ff5yUk99DteUKmYc2c": true,
}

type officialManagedConfiguration struct {
	captureSignerID        string
	captureSignerPublicKey []byte
	client                 *ManagedTlsClient
	workloadStateRoot      string
}

// OfficialManagedProject binds one reviewed project to an installed SDK package.
type OfficialManagedProject struct {
	project        map[string]any
	sourceRevision string
}

// NewOfficialManagedProject validates the release and reviewed build binding.
func NewOfficialManagedProject(
	project map[string]any, buildRepositoryID, sourceRevision string,
) (*OfficialManagedProject, error) {
	if _, err := loadOfficialManagedConfiguration(nil); err != nil {
		return nil, err
	}
	if err := validateOfficialProject(project, buildRepositoryID, sourceRevision); err != nil {
		return nil, err
	}
	copied, err := cloneMap(project)
	if err != nil {
		return nil, errProjectBindingInvalid()
	}
	return &OfficialManagedProject{project: copied, sourceRevision: sourceRevision}, nil
}

// OfficialManagedOperation owns one managed operation identity and deployment.
type OfficialManagedOperation struct {
	CaptureID   string
	OperationID string
	WorldID     string
	deployment  map[string]any
}

// StartOperation creates one package-owned operation without network work.
func (project *OfficialManagedProject) StartOperation(
	worldID string,
) (*OfficialManagedOperation, error) {
	if !validDigest(worldID) {
		return nil, errProjectBindingInvalid()
	}
	captureID, err := newOfficialIdentifier("cap_")
	if err != nil {
		return nil, err
	}
	operationID, err := newOfficialIdentifier("op_")
	if err != nil {
		return nil, err
	}
	return &OfficialManagedOperation{
		CaptureID: captureID, OperationID: operationID, WorldID: worldID,
		deployment: officialDeployment(project.project, project.sourceRevision),
	}, nil
}

// Deployment returns the deployment bound by the official sink.
func (operation *OfficialManagedOperation) Deployment() map[string]any {
	return operation.deployment
}

// CandidateSink binds one complete closure to the installed official package.
func (operation *OfficialManagedOperation) CandidateSink(
	projectToken *ManagedProjectToken,
	closure ManagedCaptureClosure,
	subject *GoSubjectPackage,
) (*ManagedCandidateSink, error) {
	sink, deployment, err := newOfficialManagedCandidateSink(
		projectToken, closure, operation.deployment, subject, operation.OperationID,
	)
	if err != nil {
		return nil, err
	}
	operation.deployment = deployment
	return sink, nil
}

// NewOfficialManagedCandidateSink creates the released managed capture sink.
// The released SDK owns its Cloud origin and capture-grant verification key.
func NewOfficialManagedCandidateSink(
	projectToken *ManagedProjectToken,
	serviceID string,
	closure ManagedCaptureClosure,
	deployment map[string]any,
	subject *GoSubjectPackage,
) (*ManagedCandidateSink, error) {
	sink, _, err := newOfficialManagedCandidateSink(
		projectToken, closure, deployment, subject, "",
	)
	return sink, err
}

func newOfficialManagedCandidateSink(
	projectToken *ManagedProjectToken,
	closure ManagedCaptureClosure,
	deployment map[string]any,
	subject *GoSubjectPackage,
	operationID string,
) (*ManagedCandidateSink, map[string]any, error) {
	if deployment == nil {
		return nil, nil, errSchemaInvalid()
	}
	configuration, err := loadOfficialManagedConfiguration(projectToken)
	if err != nil {
		return nil, nil, err
	}
	boundDeployment, err := cloneMap(deployment)
	if err != nil {
		return nil, nil, err
	}
	boundDeployment["runtime_endpoint"] = officialManagedHTTPSOrigin
	serviceID, err := requireTypedID(boundDeployment["service_id"], "service_id")
	if err != nil {
		return nil, nil, err
	}
	sink, err := NewManagedCandidateSink(
		configuration.client,
		closure,
		ManagedSinkConfiguration{
			CaptureSignerID:        configuration.captureSignerID,
			CaptureSignerPublicKey: configuration.captureSignerPublicKey,
			ServiceID:              serviceID,
			WorkloadStateRoot:      configuration.workloadStateRoot,
		},
		subject,
	)
	if err != nil {
		return nil, nil, err
	}
	_ = operationID
	if err := sink.BindDeployment(boundDeployment); err != nil {
		return nil, nil, err
	}
	return sink, boundDeployment, nil
}

func loadOfficialManagedConfiguration(
	projectToken *ManagedProjectToken,
) (*officialManagedConfiguration, error) {
	if isOfficialReleaseSentinel(officialManagedHTTPSOrigin) ||
		isOfficialReleaseSentinel(officialCaptureGrantSignerID) ||
		isOfficialReleaseSentinel(officialCaptureGrantSignerPublicKey) {
		return nil, newManagedError(
			"CONFIG_CONFLICT", "This Repro It SDK has no official managed release binding.",
		)
	}
	publicKey, err := validateOfficialReleaseBinding(
		officialManagedHTTPSOrigin,
		officialCaptureGrantSignerID,
		officialCaptureGrantSignerPublicKey,
	)
	if err != nil {
		return nil, err
	}
	endpoint, err := newOfficialManagedTLSEndpoint(officialManagedHTTPSOrigin)
	if err != nil {
		return nil, errOfficialReleaseBinding()
	}
	stateRoot, err := officialProtectedStateRoot()
	if err != nil {
		return nil, err
	}
	return &officialManagedConfiguration{
		captureSignerID:        officialCaptureGrantSignerID,
		captureSignerPublicKey: publicKey,
		client:                 NewManagedTlsClient(endpoint, endpoint, projectToken),
		workloadStateRoot:      stateRoot,
	}, nil
}

func validateOfficialReleaseBinding(
	origin string, signerID string, signerPublicKey string,
) ([]byte, error) {
	if _, err := officialManagedAuthority(origin); err != nil || !validOfficialSignerID(signerID) {
		return nil, errOfficialReleaseBinding()
	}
	publicKey, err := decodeBase64URL(signerPublicKey, 32)
	if err != nil || bytes.Equal(publicKey, make([]byte, 32)) ||
		fixtureCaptureSignerPublicKeys[signerPublicKey] {
		return nil, errOfficialReleaseBinding()
	}
	return publicKey, nil
}

func newOfficialManagedTLSEndpoint(origin string) (*ManagedTlsEndpoint, error) {
	authority, err := officialManagedAuthority(origin)
	if err != nil {
		return nil, err
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return nil, errManagedServiceUnavailable()
	}
	tlsConfiguration := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: authority,
	}
	return &ManagedTlsEndpoint{
		authority: authority,
		origin:    origin,
		dial: func(timeout time.Duration) (net.Conn, error) {
			return dialOfficialManagedTLS(authority, tlsConfiguration, timeout)
		},
	}, nil
}

func officialManagedAuthority(origin string) (string, error) {
	authority, found := strings.CutPrefix(origin, "https://")
	if !found || len(authority) == 0 || len(authority) > 253 ||
		!strings.Contains(authority, ".") {
		return "", errEndpointInvalid()
	}
	for _, character := range authority {
		if !(character >= 'a' && character <= 'z') &&
			!(character >= '0' && character <= '9') && character != '-' && character != '.' {
			return "", errEndpointInvalid()
		}
	}
	for _, label := range strings.Split(authority, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") ||
			strings.HasSuffix(label, "-") {
			return "", errEndpointInvalid()
		}
	}
	return authority, nil
}

func dialOfficialManagedTLS(
	authority string, configuration *tls.Config, timeout time.Duration,
) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", authority)
	if err != nil || len(addresses) == 0 || len(addresses) > officialMaxDNSAddresses {
		return nil, errManagedServiceUnavailable()
	}
	deadline := time.Now().Add(timeout)
	for _, address := range addresses {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		tcpConnection, dialErr := net.DialTimeout(
			"tcp", net.JoinHostPort(address.String(), "443"), remaining,
		)
		if dialErr != nil {
			continue
		}
		connection := tls.Client(tcpConnection, configuration.Clone())
		_ = connection.SetDeadline(deadline)
		if handshakeErr := connection.Handshake(); handshakeErr == nil {
			return connection, nil
		}
		_ = connection.Close()
	}
	return nil, errManagedServiceUnavailable()
}

func isOfficialReleaseSentinel(value string) bool {
	return strings.HasPrefix(value, "__REPROIT_OFFICIAL_") &&
		strings.HasSuffix(value, "_SENTINEL__")
}

func validOfficialSignerID(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') &&
			!(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') &&
			character != '-' && character != '_' && character != '.' && character != ':' {
			return false
		}
	}
	return true
}

func errOfficialReleaseBinding() *ManagedError {
	return newManagedError("CONFIG_CONFLICT", "The official managed release binding is invalid.")
}

func validateOfficialProject(
	project map[string]any, buildRepositoryID, sourceRevision string,
) error {
	servicePath, servicePathOK := project["service_path"].(string)
	if project == nil || project["format"] != 1 || project["profile"] != "backend" ||
		project["profile_format"] != 1 || project["processing_mode"] != "managed" ||
		project["sdk"] != "go" || project["repository_id"] != buildRepositoryID ||
		!validOfficialRevision(sourceRevision) || !servicePathOK || servicePath == "" ||
		strings.HasPrefix(servicePath, "/") || containsPathParent(servicePath) ||
		!validTypedID(project["organization_id"], "organization_id") ||
		!validTypedID(project["project_id"], "project_id") ||
		!validTypedID(project["service_id"], "service_id") {
		return errProjectBindingInvalid()
	}
	return nil
}

func officialDeployment(project map[string]any, sourceRevision string) map[string]any {
	return map[string]any{
		"format": "reproit.deployment.v1", "organization_id": project["organization_id"],
		"processing_mode": "managed", "project_id": project["project_id"],
		"repository_id":        project["repository_id"],
		"runtime_capabilities": []any{"runtime.go-native"},
		"runtime_endpoint":     "pending-official-managed-origin",
		"service_id":           project["service_id"], "service_path": project["service_path"],
		"signature":       strings.Repeat("A", 86),
		"signed_at":       "1970-01-01T00:00:00.000Z",
		"signer_key_id":   "pending-managed-registration",
		"source_revision": sourceRevision, "subject": map[string]any{},
	}
}

func validOfficialRevision(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9') &&
			!(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func containsPathParent(value string) bool {
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func newOfficialIdentifier(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errSchemaInvalid()
	}
	milliseconds := uint64(time.Now().UnixMilli())
	for index := 0; index < 6; index++ {
		value[5-index] = byte(milliseconds >> (index * 8))
	}
	value[6] = value[6]&0x0f | 0x70
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value)
	return prefix + encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] +
		"-" + encoded[16:20] + "-" + encoded[20:], nil
}

func officialProtectedStateRoot() (string, error) {
	if runtime.GOOS != "linux" {
		return "", newManagedError(
			"UNSUPPORTED", "The managed Go capture path requires a supported Linux application host.",
		)
	}
	stateRoot := os.Getenv("XDG_STATE_HOME")
	if stateRoot == "" {
		home := os.Getenv("HOME")
		if home == "" {
			return "", errProjectBindingInvalid()
		}
		stateRoot = filepath.Join(home, ".local", "state")
	}
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot {
		return "", errProjectBindingInvalid()
	}
	return stateRoot, nil
}

func errProjectBindingInvalid() *ManagedError {
	return newManagedError("CONFIG_CONFLICT", "The managed project build binding is invalid.")
}
