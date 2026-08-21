package reproit

import (
	"bytes"
	"testing"
)

func TestOfficialManagedConfigurationIsBoundOrFailsClosed(t *testing.T) {
	configuration, err := loadOfficialManagedConfiguration(nil)
	if isOfficialReleaseSentinel(officialManagedHTTPSOrigin) {
		if managedErrorCode(t, err) != "CONFIG_CONFLICT" || configuration != nil {
			t.Fatalf("unbound official configuration: %#v, %v", configuration, err)
		}
		return
	}
	if err != nil {
		t.Fatalf("load bound official configuration: %v", err)
	}
}

func TestOfficialManagedAuthorityAcceptsOnlyCanonicalHTTPSOrigin(t *testing.T) {
	authority, err := officialManagedAuthority("https://cloud.reproit.com")
	if err != nil || authority != "cloud.reproit.com" {
		t.Fatalf("canonical authority: %s, %v", authority, err)
	}
	for _, origin := range []string{
		"http://cloud.reproit.com",
		"https://cloud.reproit.com/",
		"https://user@example.com",
		"https://cloud.reproit.com/path",
		"https://cloud.reproit.com?query=yes",
		"https://cloud.reproit.com#fragment",
		"https://LOCAL.reproit.com",
		"https://localhost",
	} {
		if _, err := officialManagedAuthority(origin); err == nil {
			t.Fatalf("invalid official origin %q was accepted", origin)
		}
	}
}

func TestOfficialSignerIDRejectsInvalidValues(t *testing.T) {
	for _, signerID := range []string{
		"", "contains space", "contains/slash", string(make([]byte, 257)),
	} {
		if validOfficialSignerID(signerID) {
			t.Fatalf("invalid signer ID %q was accepted", signerID)
		}
	}
}

func TestOfficialReleaseBindingRejectsFixturePlaceholderAndMalformedValues(t *testing.T) {
	publicKey, err := verificationKey(fixtureWorkloadSeed)
	if err != nil {
		t.Fatalf("workload verification key: %v", err)
	}
	if _, err := validateOfficialReleaseBinding(
		"https://cloud.reproit.com", "managed-candidate-capture-release", encodeBase64URL(publicKey),
	); err != nil {
		t.Fatalf("valid release binding: %v", err)
	}
	for _, candidate := range []struct {
		origin    string
		signerID  string
		publicKey string
	}{
		{"http://cloud.reproit.com", "managed-candidate-capture-release", encodeBase64URL(publicKey)},
		{"https://cloud.reproit.com", "contains space", encodeBase64URL(publicKey)},
		{"https://cloud.reproit.com", "managed-candidate-capture-release", "not-a-key"},
		{
			"https://cloud.reproit.com",
			"managed-candidate-capture-release",
			encodeBase64URL(bytes.Repeat([]byte{0}, 32)),
		},
		{
			"https://cloud.reproit.com",
			"managed-candidate-capture-release",
			"1238bj1eePRsVOlCHJedzcDZ0DmBthqGWrICsYCNzpA",
		},
	} {
		if _, err := validateOfficialReleaseBinding(
			candidate.origin, candidate.signerID, candidate.publicKey,
		); err == nil {
			t.Fatalf("invalid release binding was accepted: %#v", candidate)
		}
	}
}

func TestOfficialManagedEntryFailsBeforeCandidateNetworkUseWhenUnbound(t *testing.T) {
	token, err := NewManagedProjectToken("test-project-token")
	if err != nil {
		t.Fatalf("project token: %v", err)
	}
	deployment := unboundLoopbackDeployment("2026-01-01T00:00:00.000Z")
	deployment["runtime_endpoint"] = "unchanged"
	_, err = NewOfficialManagedCandidateSink(
		token,
		fixtureServiceID,
		ManagedCaptureClosure{Completion: "return", World: emptyWorld()},
		deployment,
		fixtureSubjectPackage(t),
	)
	if managedErrorCode(t, err) != "CONFIG_CONFLICT" {
		t.Fatalf("unbound official entry: %v", err)
	}
	if deployment["runtime_endpoint"] != "unchanged" {
		t.Fatal("official entry changed the caller deployment")
	}
}

func TestOfficialManagedProjectFailsBeforeProjectOrCaptureUseWhenUnbound(t *testing.T) {
	project, err := NewOfficialManagedProject(nil, "invalid", "invalid")
	if managedErrorCode(t, err) != "CONFIG_CONFLICT" || project != nil {
		t.Fatalf("unbound official project: %#v, %v", project, err)
	}
}

func TestPublicIntegrationFailsBeforeWorldCaptureWhenUnbound(t *testing.T) {
	worldAccessed := false
	capture, err := Start(nil, "invalid", "invalid", func() (ManagedWorldCapture, error) {
		worldAccessed = true
		return ManagedWorldCapture{}, nil
	})
	if managedErrorCode(t, err) != "CONFIG_CONFLICT" || capture != nil || worldAccessed {
		t.Fatalf("unbound public integration: %#v, %v, %t", capture, err, worldAccessed)
	}
}
