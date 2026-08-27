package oraclecloud

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5" // #nosec G501 -- the test reproduces OCI's documented fingerprint algorithm.
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const (
	testUserOCID = "ocid1.user.oc1..aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff"
	encryptedKey = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIE6TAbBgkqhkiG9w0BBQMwDgQIAAAAAAAAAAECAggABIIEyAAAAAAAAAAA
-----END ENCRYPTED PRIVATE KEY-----`
)

func TestOracleCloud_FromData(t *testing.T) {
	matchingKey, matchingFingerprint := generateRSAKey(t, 2048)
	otherKey, otherFingerprint := generateRSAKey(t, 2048)
	ecdsaKey := generateECDSAKey(t)

	tests := []struct {
		name               string
		input              string
		verify             bool
		wantResults        int
		wantValidation     string
		wantFingerprint    string
		wantPrivateKeyPart string
	}{
		{
			name:               "matching OCI credential",
			input:              credentialText(testUserOCID, matchingFingerprint, matchingKey),
			wantResults:        1,
			wantValidation:     "matched",
			wantFingerprint:    matchingFingerprint,
			wantPrivateKeyPart: matchingKey,
		},
		{
			name:               "private key before config",
			input:              matchingKey + "\n" + credentialText(testUserOCID, matchingFingerprint, ""),
			verify:             true,
			wantResults:        1,
			wantValidation:     "matched",
			wantFingerprint:    matchingFingerprint,
			wantPrivateKeyPart: matchingKey,
		},
		{
			name:               "uppercase fingerprint",
			input:              credentialText(testUserOCID, strings.ToUpper(matchingFingerprint), matchingKey),
			wantResults:        1,
			wantValidation:     "matched",
			wantFingerprint:    strings.ToUpper(matchingFingerprint),
			wantPrivateKeyPart: matchingKey,
		},
		{
			name:        "fingerprint belongs to another key",
			input:       credentialText(testUserOCID, otherFingerprint, matchingKey),
			wantResults: 0,
		},
		{
			name:        "missing fingerprint",
			input:       "user=" + testUserOCID + "\n" + matchingKey,
			wantResults: 0,
		},
		{
			name:        "missing private key",
			input:       credentialText(testUserOCID, matchingFingerprint, ""),
			wantResults: 0,
		},
		{
			name:        "missing user OCID",
			input:       "fingerprint=" + matchingFingerprint + "\n" + matchingKey,
			wantResults: 0,
		},
		{
			name:        "tenancy OCID is not a user",
			input:       credentialText(strings.Replace(testUserOCID, ".user.", ".tenancy.", 1), matchingFingerprint, matchingKey),
			wantResults: 0,
		},
		{
			name:        "non RSA key",
			input:       credentialText(testUserOCID, matchingFingerprint, ecdsaKey),
			wantResults: 0,
		},
		{
			name:        "RSA key below OCI minimum",
			input:       credentialText(testUserOCID, matchingFingerprint, mustGenerateRSAKey(t, 1024)),
			wantResults: 0,
		},
		{
			name:               "matching key selected from multiple PEM blocks",
			input:              credentialText(testUserOCID, matchingFingerprint, otherKey+"\n"+matchingKey),
			wantResults:        1,
			wantValidation:     "matched",
			wantFingerprint:    matchingFingerprint,
			wantPrivateKeyPart: matchingKey,
		},
		{
			name:               "duplicate credential is deduplicated",
			input:              credentialText(testUserOCID, matchingFingerprint, matchingKey) + "\n" + credentialText(testUserOCID, matchingFingerprint, matchingKey),
			wantResults:        1,
			wantValidation:     "matched",
			wantFingerprint:    matchingFingerprint,
			wantPrivateKeyPart: matchingKey,
		},
		{
			name:            "encrypted private key with one fingerprint",
			input:           credentialText(testUserOCID, matchingFingerprint, encryptedKey),
			wantResults:     1,
			wantValidation:  "unavailable_encrypted_key",
			wantFingerprint: matchingFingerprint,
		},
		{
			name:        "encrypted key with ambiguous fingerprints",
			input:       credentialText(testUserOCID, matchingFingerprint, encryptedKey) + "\nfingerprint=" + otherFingerprint,
			wantResults: 0,
		},
		{
			name:        "malformed encrypted PEM",
			input:       credentialText(testUserOCID, matchingFingerprint, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nnot-base64!\n-----END ENCRYPTED PRIVATE KEY-----"),
			wantResults: 0,
		},
	}

	scanner := Scanner{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results, err := scanner.FromData(context.Background(), test.verify, []byte(test.input))
			if err != nil {
				t.Fatalf("FromData() error = %v", err)
			}
			if len(results) != test.wantResults {
				t.Fatalf("got %d results, want %d", len(results), test.wantResults)
			}
			if test.wantResults == 0 {
				return
			}

			result := results[0]
			if result.DetectorType != detector_typepb.DetectorType_OracleCloud {
				t.Errorf("DetectorType = %v, want OracleCloud", result.DetectorType)
			}
			if result.Verified {
				t.Error("offline fingerprint matching must not mark an OCI credential active")
			}
			if got := result.ExtraData["fingerprint_validation"]; got != test.wantValidation {
				t.Errorf("fingerprint_validation = %q, want %q", got, test.wantValidation)
			}
			if got := result.SecretParts["user_ocid"]; got != testUserOCID {
				t.Errorf("user_ocid = %q, want %q", got, testUserOCID)
			}
			if got := result.SecretParts["fingerprint"]; got != test.wantFingerprint {
				t.Errorf("fingerprint = %q, want %q", got, test.wantFingerprint)
			}
			if test.wantPrivateKeyPart != "" && result.SecretParts["private_key"] != test.wantPrivateKeyPart {
				t.Error("private_key SecretPart does not contain the matched key")
			}
			if result.GetPrimarySecretValue() == "" {
				t.Error("primary secret was not set to the private key")
			}
		})
	}
}

func TestOracleCloud_AhoCorasickCredentialWindow(t *testing.T) {
	privateKey, fingerprint := generateRSAKey(t, 2048)
	input := "user=" + testUserOCID + "\n" + strings.Repeat("x", 20*1024) + "\nfingerprint=" + fingerprint + "\n" + privateKey

	scanner := Scanner{}
	core := ahocorasick.NewAhoCorasickCore([]detectors.Detector{scanner})
	matches := core.FindDetectorMatches([]byte(input))
	if len(matches) != 1 {
		t.Fatalf("got %d detector matches, want 1", len(matches))
	}

	found := false
	for _, detectorMatch := range matches {
		for _, match := range detectorMatch.Matches() {
			results, err := scanner.FromData(context.Background(), false, match)
			if err != nil {
				t.Fatalf("FromData() error = %v", err)
			}
			found = found || len(results) == 1
		}
	}
	if !found {
		t.Fatal("multipart scan window did not include the complete OCI credential")
	}
}

func TestOracleCloud_Metadata(t *testing.T) {
	scanner := Scanner{}
	if scanner.Type() != detector_typepb.DetectorType_OracleCloud {
		t.Fatalf("Type() = %v", scanner.Type())
	}
	if got := scanner.Type().String(); got != "OracleCloud" {
		t.Fatalf("Type().String() = %q, want OracleCloud", got)
	}
	if isFalsePositive, reason := scanner.IsFalsePositive(detectors.Result{Raw: []byte(testUserOCID)}); isFalsePositive {
		t.Fatalf("OCI credential was marked false positive: %s", reason)
	}
	if scanner.MaxCredentialSpan() != 64*1024 {
		t.Fatalf("MaxCredentialSpan() = %d", scanner.MaxCredentialSpan())
	}
	if !strings.Contains(scanner.Description(), "Oracle Cloud Infrastructure") {
		t.Fatalf("unexpected description: %q", scanner.Description())
	}
}

func credentialText(userOCID, fingerprint, privateKey string) string {
	return fmt.Sprintf("user=%s\nfingerprint=%s\nprivate_key=\n%s", userOCID, fingerprint, privateKey)
}

func generateRSAKey(t *testing.T, bits int) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal RSA key: %v", err)
	}
	privateKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}))

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal RSA public key: %v", err)
	}
	digest := md5.Sum(publicKeyDER) // #nosec G401 -- required by OCI's fingerprint format.
	parts := make([]string, len(digest))
	for i, value := range digest {
		parts[i] = fmt.Sprintf("%02x", value)
	}
	return privateKeyPEM, strings.Join(parts, ":")
}

func mustGenerateRSAKey(t *testing.T, bits int) string {
	t.Helper()
	privateKey, _ := generateRSAKey(t, bits)
	return privateKey
}

func generateECDSAKey(t *testing.T) string {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal ECDSA key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}))
}
