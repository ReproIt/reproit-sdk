// Managed key-service and ingress HTTP client with strict bounds.
//
// Mirrors crates/reproit-sdk-rust/src/managed_transport.rs: TLS 1.3 only,
// HTTP/1.1 with Connection: close, bounded request and response sizes, the
// exact routes and JSON bodies the Rust client sends, and typed rejection of
// every invalid response.
package reproit

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	managedMaxCABytes           = 1_048_576
	managedMaxHeaderBytes       = 8_192
	managedMaxJSONResponseBytes = 8_388_608
	managedMaxProjectTokenBytes = 1_024
	managedMaxRegistrationBytes = 3_372_783
)

var managedUploadStates = map[string]bool{
	"CANCELLED": true, "COMMITTED": true, "COMMITTING": true,
	"EXPIRED": true, "OPEN": true, "UPLOADING": true,
}

var managedDurabilityStates = map[string]bool{"CLOUD_PROTECTED": true, "LOCAL_ONLY": true}

var managedLimitKeys = []string{
	"max_candidate_bytes", "max_object_bytes", "max_objects",
	"max_total_ciphertext_bytes", "missing_page_size", "object_attempts",
	"upload_lifetime_ms",
}

// ManagedProjectToken authorizes one managed workload registration.
type ManagedProjectToken struct {
	value string
}

func NewManagedProjectToken(value string) (*ManagedProjectToken, error) {
	if value == "" || len(value) > managedMaxProjectTokenBytes {
		return nil, newManagedError("SCHEMA_INVALID", "The managed project token is invalid.")
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 33 || value[index] > 126 {
			return nil, newManagedError("SCHEMA_INVALID", "The managed project token is invalid.")
		}
	}
	return &ManagedProjectToken{value: value}, nil
}

func (token *ManagedProjectToken) authorization() string {
	return "Bearer " + token.value
}

type managedHTTPResponse struct {
	body   []byte
	status int
}

// EncryptionResponse carries the managed candidate key and its signed
// capture grant.
type EncryptionResponse struct {
	CandidateKey []byte
	CaptureGrant map[string]any
}

// ManagedTlsEndpoint is one TLS 1.3 origin for the managed key service or
// the managed ingress.
type ManagedTlsEndpoint struct {
	authority string
	origin    string
	dial      func(timeout time.Duration) (net.Conn, error)
}

func NewManagedTlsEndpoint(
	host string,
	port int,
	serverName string,
	authority string,
	caCertificatePath string,
) (*ManagedTlsEndpoint, error) {
	if host == "" || len(host) > 253 || port < 1 || port > 65_535 ||
		serverName == "" || len(serverName) > 253 {
		return nil, errEndpointInvalid()
	}
	if err := validateAuthority(authority); err != nil {
		return nil, err
	}
	roots, err := managedRootPool(caCertificatePath)
	if err != nil {
		return nil, err
	}
	configuration := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: serverName,
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	return &ManagedTlsEndpoint{
		authority: authority,
		origin:    "https://" + authority,
		dial: func(timeout time.Duration) (net.Conn, error) {
			return tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", address, configuration)
		},
	}, nil
}

func managedRootPool(caCertificatePath string) (*x509.CertPool, error) {
	metadata, err := os.Lstat(caCertificatePath)
	if err != nil || !metadata.Mode().IsRegular() || metadata.Mode()&os.ModeSymlink != 0 ||
		metadata.Size() <= 0 || metadata.Size() > managedMaxCABytes {
		return nil, errEndpointInvalid()
	}
	certificate, err := os.ReadFile(caCertificatePath)
	if err != nil || int64(len(certificate)) != metadata.Size() {
		return nil, errEndpointInvalid()
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return nil, errEndpointInvalid()
	}
	return roots, nil
}

// request sends one bounded HTTP/1.1 request on a fresh connection. Empty
// authorization or contentType values omit that header.
func (endpoint *ManagedTlsEndpoint) request(
	method string,
	target string,
	authorization string,
	contentType string,
	body []byte,
	timeout time.Duration,
) (managedHTTPResponse, error) {
	if err := validateRequestComponent(method); err != nil {
		return managedHTTPResponse{}, err
	}
	if err := validateTarget(target); err != nil {
		return managedHTTPResponse{}, err
	}
	if authorization != "" {
		if err := validateHeaderValue(authorization); err != nil {
			return managedHTTPResponse{}, err
		}
	}
	if contentType != "" {
		if err := validateHeaderValue(contentType); err != nil {
			return managedHTTPResponse{}, err
		}
	}
	connection, err := endpoint.dial(timeout)
	if err != nil {
		return managedHTTPResponse{}, classifyDialError(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	header := fmt.Sprintf(
		"%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", method, target, endpoint.authority,
	)
	if authorization != "" {
		header += "Authorization: " + authorization + "\r\n"
	}
	if contentType != "" {
		header += "Content-Type: " + contentType + "\r\n"
	}
	header += fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
	if _, err := io.WriteString(connection, header); err != nil {
		return managedHTTPResponse{}, errManagedServiceUnavailable()
	}
	if _, err := connection.Write(body); err != nil {
		return managedHTTPResponse{}, errManagedServiceUnavailable()
	}
	return readManagedResponse(connection)
}

func (endpoint *ManagedTlsEndpoint) uploadTarget(uploadURL string) (string, error) {
	if !strings.HasPrefix(uploadURL, endpoint.origin) {
		return "", errEndpointInvalid()
	}
	target := uploadURL[len(endpoint.origin):]
	if err := validateTarget(target); err != nil {
		return "", err
	}
	return target, nil
}

func classifyDialError(err error) *ManagedError {
	var certificateError *tls.CertificateVerificationError
	var recordError tls.RecordHeaderError
	if errors.As(err, &certificateError) || errors.As(err, &recordError) {
		return errEndpointInvalid()
	}
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	if errors.As(err, &unknownAuthority) || errors.As(err, &hostnameError) {
		return errEndpointInvalid()
	}
	return errManagedServiceUnavailable()
}

func readManagedResponse(connection io.Reader) (managedHTTPResponse, error) {
	reader := bufio.NewReader(connection)
	header := make([]byte, 0, 512)
	for len(header) < managedMaxHeaderBytes {
		value, err := reader.ReadByte()
		if err != nil {
			return managedHTTPResponse{}, errManagedResponseInvalid()
		}
		header = append(header, value)
		if len(header) >= 4 && string(header[len(header)-4:]) == "\r\n\r\n" {
			break
		}
	}
	if len(header) < 4 || string(header[len(header)-4:]) != "\r\n\r\n" {
		return managedHTTPResponse{}, errManagedResponseInvalid()
	}
	lines := strings.Split(string(header), "\r\n")
	statusParts := strings.Fields(lines[0])
	if len(statusParts) < 2 {
		return managedHTTPResponse{}, errManagedResponseInvalid()
	}
	status, err := strconv.Atoi(statusParts[1])
	if err != nil || status < 100 || status > 999 {
		return managedHTTPResponse{}, errManagedResponseInvalid()
	}
	contentLength := -1
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			return managedHTTPResponse{}, errManagedResponseInvalid()
		}
		if strings.EqualFold(name, "transfer-encoding") {
			return managedHTTPResponse{}, errManagedResponseInvalid()
		}
		if strings.EqualFold(name, "content-length") {
			if contentLength >= 0 {
				return managedHTTPResponse{}, errManagedResponseInvalid()
			}
			contentLength, err = strconv.Atoi(strings.TrimSpace(value))
			if err != nil || contentLength < 0 {
				return managedHTTPResponse{}, errManagedResponseInvalid()
			}
		}
	}
	if contentLength < 0 {
		contentLength = 0
	}
	if contentLength > managedMaxJSONResponseBytes {
		return managedHTTPResponse{}, errManagedResponseInvalid()
	}
	body := make([]byte, contentLength)
	if _, err := io.ReadFull(reader, body); err != nil {
		return managedHTTPResponse{}, errManagedServiceUnavailable()
	}
	return managedHTTPResponse{body: body, status: status}, nil
}

// ManagedTlsClient is the SDK-side client for the managed key service and
// the managed ingress.
type ManagedTlsClient struct {
	ingress        *ManagedTlsEndpoint
	keyService     *ManagedTlsEndpoint
	projectToken   *ManagedProjectToken
	registrationMu sync.Mutex
}

func NewManagedTlsClient(
	keyService *ManagedTlsEndpoint,
	ingress *ManagedTlsEndpoint,
	projectToken *ManagedProjectToken,
) *ManagedTlsClient {
	return &ManagedTlsClient{ingress: ingress, keyService: keyService, projectToken: projectToken}
}

func (client *ManagedTlsClient) RegisterWorkloadKey(
	request map[string]any, timeout time.Duration,
) (map[string]any, error) {
	client.registrationMu.Lock()
	defer client.registrationMu.Unlock()
	if err := validateWorkloadKeyRegistration(request); err != nil {
		return nil, err
	}
	body, err := CanonicalBytes(request)
	if err != nil || len(body) > managedMaxRegistrationBytes {
		return nil, errSchemaInvalid()
	}
	if client.projectToken == nil {
		return nil, newManagedError(
			"AUTHENTICATION_REQUIRED", "The managed workload registration token is unavailable.",
		)
	}
	response, err := client.keyService.request(
		"POST", "/v1/workload-keys", client.projectToken.authorization(),
		"application/json", body, timeout,
	)
	if err != nil {
		return nil, err
	}
	value, err := decodeManagedJSON(response, 200)
	if err != nil {
		return nil, err
	}
	registration, ok := value.(map[string]any)
	if !ok || !hasExactKeys(registration, "deployment_digest", "key_id", "service_id") ||
		registration["service_id"] != request["service_id"] {
		return nil, errManagedResponseInvalid()
	}
	publicKeyText, _ := request["public_key"].(string)
	publicKey, err := decodeBase64URL(publicKeyText, 32)
	if err != nil {
		return nil, errManagedResponseInvalid()
	}
	expectedKeyID := managedWorkloadKeyID(publicKey)
	deployment, _ := request["deployment"].(map[string]any)
	expectedDeploymentDigest, err := canonicalDigest(deployment)
	if err != nil || registration["key_id"] != expectedKeyID ||
		registration["deployment_digest"] != expectedDeploymentDigest {
		return nil, errManagedResponseInvalid()
	}
	client.projectToken.value = ""
	client.projectToken = nil
	return registration, nil
}

func (client *ManagedTlsClient) RequestEncryptionGrant(
	request map[string]any, timeout time.Duration,
) (EncryptionResponse, error) {
	if err := validateGrantRequest(request); err != nil {
		return EncryptionResponse{}, err
	}
	body, err := CanonicalBytes(request)
	if err != nil {
		return EncryptionResponse{}, errSchemaInvalid()
	}
	response, err := client.keyService.request(
		"POST", "/v1/managed-candidate-encryption-grants",
		"", "application/json", body, timeout,
	)
	if err != nil {
		return EncryptionResponse{}, err
	}
	parsed, err := decodeManagedJSON(response, 200)
	if err != nil {
		return EncryptionResponse{}, err
	}
	value, ok := parsed.(map[string]any)
	if !ok || !hasExactKeys(value, "candidate_key", "capture_grant") {
		return EncryptionResponse{}, errManagedResponseInvalid()
	}
	keyText, keyTextOK := value["candidate_key"].(string)
	if !keyTextOK {
		return EncryptionResponse{}, errManagedResponseInvalid()
	}
	candidateKey, err := decodeBase64URL(keyText, 32)
	if err != nil {
		return EncryptionResponse{}, err
	}
	if err := validateCaptureGrant(value["capture_grant"]); err != nil {
		return EncryptionResponse{}, err
	}
	return EncryptionResponse{
		CandidateKey: candidateKey,
		CaptureGrant: value["capture_grant"].(map[string]any),
	}, nil
}

func (client *ManagedTlsClient) Start(
	request map[string]any, timeout time.Duration,
) (map[string]any, error) {
	if err := validateUploadRequest(request); err != nil {
		return nil, err
	}
	body, err := CanonicalBytes(request)
	if err != nil {
		return nil, errSchemaInvalid()
	}
	response, err := client.ingress.request(
		"POST", "/v1/managed-candidates", "", "application/json", body, timeout,
	)
	if err != nil {
		return nil, err
	}
	value, err := decodeManagedJSON(response, 200)
	if err != nil {
		return nil, err
	}
	return validateStartResponse(value)
}

// Missing fetches one bounded page of missing objects. An empty cursor
// requests the first page.
func (client *ManagedTlsClient) Missing(
	uploadID string, uploadToken string, cursor string, timeout time.Duration,
) (map[string]any, error) {
	if _, err := requireTypedID(uploadID, "upload_id"); err != nil {
		return nil, err
	}
	if err := validateUploadToken(uploadToken); err != nil {
		return nil, err
	}
	target := "/v1/managed-candidates/" + uploadID + "/missing?limit=100"
	if cursor != "" {
		if err := validateUploadToken(cursor); err != nil {
			return nil, err
		}
		target += "&cursor=" + cursor
	}
	response, err := client.ingress.request(
		"GET", target, "Bearer "+uploadToken, "", nil, timeout,
	)
	if err != nil {
		return nil, err
	}
	value, err := decodeManagedJSON(response, 200)
	if err != nil {
		return nil, err
	}
	return validateMissingPage(value)
}

func (client *ManagedTlsClient) UploadObject(
	uploadURL string, digest string, value []byte, timeout time.Duration,
) error {
	if digestBytes(value) != digest {
		return errObjectDigestMismatch()
	}
	target, err := client.ingress.uploadTarget(uploadURL)
	if err != nil {
		return err
	}
	response, err := client.ingress.request(
		"PUT", target, "", "application/octet-stream", value, timeout,
	)
	if err != nil {
		return err
	}
	return expectEmptyManagedResponse(response, 204)
}

func (client *ManagedTlsClient) Commit(
	uploadID string, uploadToken string, timeout time.Duration,
) (map[string]any, error) {
	if _, err := requireTypedID(uploadID, "upload_id"); err != nil {
		return nil, err
	}
	if err := validateUploadToken(uploadToken); err != nil {
		return nil, err
	}
	response, err := client.ingress.request(
		"POST", "/v1/managed-candidates/"+uploadID+"/commit",
		"Bearer "+uploadToken, "", nil, timeout,
	)
	if err != nil {
		return nil, err
	}
	value, err := decodeManagedJSON(response, 200)
	if err != nil {
		return nil, err
	}
	return validateCommitResponse(value)
}

func (client *ManagedTlsClient) Cancel(
	uploadID string, uploadToken string, timeout time.Duration,
) (map[string]any, error) {
	if _, err := requireTypedID(uploadID, "upload_id"); err != nil {
		return nil, err
	}
	if err := validateUploadToken(uploadToken); err != nil {
		return nil, err
	}
	response, err := client.ingress.request(
		"DELETE", "/v1/managed-candidates/"+uploadID,
		"Bearer "+uploadToken, "", nil, timeout,
	)
	if err != nil {
		return nil, err
	}
	value, err := decodeManagedJSON(response, 200)
	if err != nil {
		return nil, err
	}
	return validateStatusResponse(value)
}

func validateGrantRequest(value map[string]any) error {
	if !hasExactKeys(value,
		"candidate_identity_digest", "capture_id", "cipher_suite", "deployment_digest",
		"organization_id", "processing_mode", "project_id", "service_id", "signature",
		"signer_key_id",
	) || value["processing_mode"] != "managed" ||
		value["cipher_suite"] != managedCipherSuite ||
		!validDigest(value["candidate_identity_digest"]) ||
		!validDigest(value["deployment_digest"]) ||
		!validTypedID(value["capture_id"], "capture_id") ||
		!validTypedID(value["organization_id"], "organization_id") ||
		!validTypedID(value["project_id"], "project_id") ||
		!validTypedID(value["service_id"], "service_id") ||
		!validManagedWorkloadKeyID(value["signer_key_id"]) {
		return errSchemaInvalid()
	}
	signature, signatureOK := value["signature"].(string)
	if !signatureOK {
		return errSchemaInvalid()
	}
	_, err := decodeBase64URL(signature, 64)
	return err
}

func validateWorkloadKeyRegistration(value map[string]any) error {
	if !hasExactKeys(value, "algorithm", "deployment", "public_key", "service_id") ||
		value["algorithm"] != "Ed25519" ||
		!validTypedID(value["service_id"], "service_id") {
		return errSchemaInvalid()
	}
	publicKeyText, publicKeyOK := value["public_key"].(string)
	if !publicKeyOK {
		return errSchemaInvalid()
	}
	publicKey, err := decodeBase64URL(publicKeyText, 32)
	if err != nil {
		return errSchemaInvalid()
	}
	deployment, deploymentOK := value["deployment"].(map[string]any)
	if !deploymentOK || deployment["service_id"] != value["service_id"] ||
		deployment["processing_mode"] != "managed" ||
		deployment["signer_key_id"] != managedWorkloadKeyID(publicKey) {
		return errSchemaInvalid()
	}
	if err := validateManagedDeployment(deployment); err != nil {
		return err
	}
	return verifySignedValue(deployment, publicKey)
}

func validManagedWorkloadKeyID(value any) bool {
	text, ok := value.(string)
	if !ok || len(text) != len("managed-workload-sha256:")+64 ||
		!strings.HasPrefix(text, "managed-workload-sha256:") {
		return false
	}
	for _, character := range text[len("managed-workload-sha256:"):] {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func validateMissingObject(value any) error {
	missing, ok := value.(map[string]any)
	if !ok || !hasExactKeys(missing, "cipher_digest", "expires_at", "upload_url") {
		return errManagedResponseInvalid()
	}
	uploadURL, uploadURLOK := missing["upload_url"].(string)
	if !validDigest(missing["cipher_digest"]) || !validTimestamp(missing["expires_at"]) ||
		!uploadURLOK || uploadURL == "" || len(uploadURL) > 4_096 {
		return errManagedResponseInvalid()
	}
	return nil
}

func validateManagedLimits(value any) error {
	limits, ok := value.(map[string]any)
	if !ok || !hasExactKeys(limits, managedLimitKeys...) {
		return errManagedResponseInvalid()
	}
	for _, key := range managedLimitKeys {
		limit, limitOK := integerValue(limits[key])
		if !limitOK || limit < 0 {
			return errManagedResponseInvalid()
		}
	}
	return nil
}

func validateStartResponse(value any) (map[string]any, error) {
	start, ok := value.(map[string]any)
	if !ok || !hasExactKeys(start,
		"expires_at", "limits", "missing_objects", "next_missing_cursor", "state",
		"upload_id", "upload_token",
	) {
		return nil, errManagedResponseInvalid()
	}
	state, stateOK := start["state"].(string)
	missingObjects, missingOK := anyList(start["missing_objects"])
	if !validTimestamp(start["expires_at"]) || !stateOK || !managedUploadStates[state] ||
		!validTypedID(start["upload_id"], "upload_id") || !missingOK {
		return nil, errManagedResponseInvalid()
	}
	if err := validateManagedLimits(start["limits"]); err != nil {
		return nil, err
	}
	token, tokenOK := start["upload_token"].(string)
	if !tokenOK {
		return nil, errManagedResponseInvalid()
	}
	if err := validateUploadToken(token); err != nil {
		return nil, err
	}
	if err := validateOptionalCursor(start["next_missing_cursor"]); err != nil {
		return nil, err
	}
	for _, missing := range missingObjects {
		if err := validateMissingObject(missing); err != nil {
			return nil, err
		}
	}
	return start, nil
}

func validateMissingPage(value any) (map[string]any, error) {
	page, ok := value.(map[string]any)
	if !ok || !hasExactKeys(page, "missing_objects", "next_missing_cursor") {
		return nil, errManagedResponseInvalid()
	}
	missingObjects, missingOK := anyList(page["missing_objects"])
	if !missingOK {
		return nil, errManagedResponseInvalid()
	}
	if err := validateOptionalCursor(page["next_missing_cursor"]); err != nil {
		return nil, err
	}
	for _, missing := range missingObjects {
		if err := validateMissingObject(missing); err != nil {
			return nil, err
		}
	}
	return page, nil
}

func validateCommitResponse(value any) (map[string]any, error) {
	commit, ok := value.(map[string]any)
	if !ok || !hasExactKeys(commit,
		"candidate_identity_digest", "candidate_key_reference", "capture_id",
		"encrypted_candidate_digest", "state", "upload_id",
	) {
		return nil, errManagedResponseInvalid()
	}
	state, stateOK := commit["state"].(string)
	if !validDigest(commit["candidate_identity_digest"]) ||
		!validOpaqueReference(commit["candidate_key_reference"]) ||
		!validTypedID(commit["capture_id"], "capture_id") ||
		!validDigest(commit["encrypted_candidate_digest"]) ||
		!stateOK || !managedDurabilityStates[state] ||
		!validTypedID(commit["upload_id"], "upload_id") {
		return nil, errManagedResponseInvalid()
	}
	return commit, nil
}

func validateStatusResponse(value any) (map[string]any, error) {
	status, ok := value.(map[string]any)
	if !ok || !hasExactKeys(status,
		"candidate_identity_digest", "candidate_key_reference", "capture_id",
		"encrypted_candidate_digest", "expires_at", "missing_digests", "state", "upload_id",
	) {
		return nil, errManagedResponseInvalid()
	}
	state, stateOK := status["state"].(string)
	missingDigests, missingOK := anyList(status["missing_digests"])
	if !validDigest(status["candidate_identity_digest"]) ||
		!validOpaqueReference(status["candidate_key_reference"]) ||
		!validTypedID(status["capture_id"], "capture_id") ||
		!validDigest(status["encrypted_candidate_digest"]) ||
		status["expires_at"] != nil && !validTimestamp(status["expires_at"]) ||
		!missingOK || !stateOK || !managedUploadStates[state] ||
		!validTypedID(status["upload_id"], "upload_id") {
		return nil, errManagedResponseInvalid()
	}
	for _, digest := range missingDigests {
		if !validDigest(digest) {
			return nil, errManagedResponseInvalid()
		}
	}
	return status, nil
}

func decodeManagedJSON(response managedHTTPResponse, expectedStatus int) (any, error) {
	if response.status != expectedStatus {
		return nil, decodeManagedServerError(response.status, response.body)
	}
	if len(response.body) == 0 {
		return nil, errManagedResponseInvalid()
	}
	value, err := parseStrictJSON(response.body, managedMaxJSONResponseBytes)
	if err != nil {
		return nil, errManagedResponseInvalid()
	}
	return value, nil
}

func expectEmptyManagedResponse(response managedHTTPResponse, expectedStatus int) error {
	if response.status != expectedStatus {
		return decodeManagedServerError(response.status, response.body)
	}
	if len(response.body) != 0 {
		return errManagedResponseInvalid()
	}
	return nil
}

func decodeManagedServerError(status int, body []byte) *ManagedError {
	if len(body) != 0 {
		parsed, err := parseStrictJSON(body, managedMaxJSONResponseBytes)
		if err == nil {
			if value, ok := parsed.(map[string]any); ok &&
				hasExactKeys(value, "code", "message", "retryable") {
				code, codeOK := value["code"].(string)
				message, messageOK := value["message"].(string)
				retryable, retryableOK := value["retryable"].(bool)
				if codeOK && managedErrorCodes[code] && messageOK && retryableOK {
					return &ManagedError{Code: code, Message: message, Retryable: retryable}
				}
			}
		}
	}
	if status == 429 || status == 502 || status == 503 || status == 504 {
		return errManagedServiceUnavailable()
	}
	return errManagedResponseInvalid()
}

func validateAuthority(value string) error {
	if value == "" || len(value) > 512 {
		return errEndpointInvalid()
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character < 33 || character > 126 || strings.ContainsRune("/?#@", rune(character)) {
			return errEndpointInvalid()
		}
	}
	return nil
}

func validateRequestComponent(value string) error {
	if value == "" || len(value) > 16 {
		return errEndpointInvalid()
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 'A' || value[index] > 'Z' {
			return errEndpointInvalid()
		}
	}
	return nil
}

func validateTarget(value string) error {
	if !strings.HasPrefix(value, "/") || len(value) > 4_096 || strings.Contains(value, "#") {
		return errEndpointInvalid()
	}
	for index := 0; index < len(value); index++ {
		if value[index] <= 32 || value[index] == 127 {
			return errEndpointInvalid()
		}
	}
	return nil
}

func validateHeaderValue(value string) error {
	if value == "" || len(value) > 4_096 {
		return errEndpointInvalid()
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 32 || value[index] > 126 {
			return errEndpointInvalid()
		}
	}
	return nil
}

func validateUploadToken(value string) error {
	if value == "" || len(value) > 256 {
		return errManagedResponseInvalid()
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' {
			return errManagedResponseInvalid()
		}
	}
	return nil
}

func validateOptionalCursor(value any) error {
	if value == nil {
		return nil
	}
	cursor, ok := value.(string)
	if !ok {
		return errManagedResponseInvalid()
	}
	return validateUploadToken(cursor)
}

func errEndpointInvalid() *ManagedError {
	return newManagedError(
		"SCHEMA_INVALID", "The managed TLS endpoint configuration is invalid.",
	)
}

func errManagedResponseInvalid() *ManagedError {
	return newManagedError("SCHEMA_INVALID", "The managed service response is invalid.")
}

func errManagedServiceUnavailable() *ManagedError {
	return newManagedError(
		"SERVICE_UNAVAILABLE", "The managed capture service is unavailable.",
	)
}
