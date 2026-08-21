package reproit

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxWorldTokenBytes = 65_536

var (
	worldRequestMutex         sync.Mutex
	worldSeed, worldSeedError = processWorldSeed()
)

type worldToken struct {
	ExpiresInMilliseconds uint64 `json:"expires_in_ms"`
	Format                string `json:"format"`
	WorldID               string `json:"world_id"`
}

// worldTokenCache refreshes a Runtime World token outside the operation path.
type worldTokenCache struct {
	done       chan struct{}
	serviceID  string
	stateMutex sync.Mutex
	stop       sync.Once
	token      worldTokenState
	transport  *runtimeSink
	workerDone chan struct{}
}

type worldTokenState struct {
	expires time.Time
	id      string
}

func newworldTokenCache(transport interface{ runtimeTransport() *runtimeSink }, serviceID string) (*worldTokenCache, error) {
	if worldSeedError != nil || serviceID == "" {
		return nil, errors.New("The World-token refresh seed is unavailable.")
	}
	cache := &worldTokenCache{
		done:       make(chan struct{}),
		serviceID:  serviceID,
		transport:  transport.runtimeTransport(),
		workerDone: make(chan struct{}),
	}
	go cache.refresh()
	return cache, nil
}

func (cache *worldTokenCache) CandidateStart(
	captureID string,
	deployment map[string]any,
	operationID string,
) (CandidateStart, error) {
	if deployment["service_id"] != cache.serviceID {
		return CandidateStart{}, errors.New("The World token does not match the deployment service.")
	}
	cache.stateMutex.Lock()
	token := cache.token
	cache.stateMutex.Unlock()
	if token.id == "" || !time.Now().Before(token.expires) {
		return CandidateStart{}, errors.New("The operation started without a current Runtime World token.")
	}
	return CandidateStart{
		CaptureID: captureID, Deployment: deployment, OperationID: operationID, WorldID: token.id,
	}, nil
}

func (cache *worldTokenCache) Close() error {
	cache.stop.Do(func() { close(cache.done) })
	select {
	case <-cache.workerDone:
		return nil
	case <-time.After(1_100 * time.Millisecond):
		return errors.New("The World-token refresh worker did not stop.")
	}
}

func (cache *worldTokenCache) refresh() {
	defer close(cache.workerDone)
	backoff := [...]time.Duration{100, 200, 400, 800, 1_600, 3_200}
	refreshPercent := worldRefreshPercent(cache.serviceID)
	attempt := 0
	for {
		worldRequestMutex.Lock()
		token, ok := cache.transport.fetchWorldToken(cache.serviceID, time.Second)
		worldRequestMutex.Unlock()
		if ok {
			received := time.Now()
			cache.stateMutex.Lock()
			cache.token = worldTokenState{id: token.WorldID, expires: received.Add(5 * time.Second)}
			cache.stateMutex.Unlock()
			attempt = 0
			if cache.wait(time.Duration(refreshPercent) * 50 * time.Millisecond) {
				return
			}
			continue
		}
		delay := backoff[min(attempt, len(backoff)-1)] * time.Millisecond
		attempt++
		cache.stateMutex.Lock()
		if cache.token.id != "" {
			delay = min(delay, max(0, time.Until(cache.token.expires)))
		}
		cache.stateMutex.Unlock()
		if cache.wait(delay) {
			return
		}
	}
}

func (cache *worldTokenCache) wait(delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-cache.done:
		return true
	case <-timer.C:
		return false
	}
}

func (sink *runtimeSink) fetchWorldToken(serviceID string, timeout time.Duration) (worldToken, bool) {
	authorization := sink.authorization()
	if authorization == "" || len(authorization) > 4_096 || strings.ContainsAny(authorization, "\r\n") {
		return worldToken{}, false
	}
	connection, err := sink.dial(timeout)
	if err != nil {
		return worldToken{}, false
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	request := fmt.Sprintf(
		"GET /v1/services/%s/world HTTP/1.1\r\nHost: %s\r\nReproit-Protocol: 1\r\nAuthorization: %s\r\nConnection: close\r\n\r\n",
		serviceID, sink.host, authorization,
	)
	if _, err = io.WriteString(connection, request); err != nil {
		return worldToken{}, false
	}
	return readWorldToken(connection)
}

func readWorldToken(source io.Reader) (worldToken, bool) {
	reader := bufio.NewReaderSize(source, maxWorldTokenBytes+maxResponseHeaderBytes)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, " 200 ") {
		return worldToken{}, false
	}
	contentLength := -1
	for headerBytes := len(status); ; {
		line, readError := reader.ReadString('\n')
		headerBytes += len(line)
		if readError != nil || headerBytes > maxResponseHeaderBytes {
			return worldToken{}, false
		}
		if line == "\r\n" {
			break
		}
		name, value, found := strings.Cut(line, ":")
		if found && strings.EqualFold(name, "content-length") {
			contentLength, err = strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return worldToken{}, false
			}
		}
	}
	if contentLength <= 0 || contentLength > maxWorldTokenBytes {
		return worldToken{}, false
	}
	body := make([]byte, contentLength)
	if _, err = io.ReadFull(reader, body); err != nil {
		return worldToken{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var token worldToken
	if decoder.Decode(&token) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		token.ExpiresInMilliseconds != 5_000 || token.Format != "reproit.world-token.v1" ||
		!validWorldDigest(token.WorldID) {
		return worldToken{}, false
	}
	return token, true
}

func validWorldDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[7:] {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func processWorldSeed() ([32]byte, error) {
	var seed [32]byte
	_, err := rand.Read(seed[:])
	return seed, err
}

func worldRefreshPercent(serviceID string) byte {
	input := append(worldSeed[:], serviceID...)
	digest := sha256.Sum256(input)
	return 50 + digest[0]%21
}

func (sink *unixRuntimeSink) runtimeTransport() *runtimeSink { return sink.runtimeSink }

func (sink *tlsRuntimeSink) runtimeTransport() *runtimeSink { return sink.runtimeSink }
