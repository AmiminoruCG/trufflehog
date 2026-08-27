package oraclecloud

import (
	"context"
	"crypto/md5" // #nosec G501 -- OCI defines API key fingerprints using MD5.
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"

	regexp "github.com/wasilibs/go-re2"
	"golang.org/x/crypto/ssh"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/privatekey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const maxCredentialSpan = 64 * 1024

type Scanner struct{}

var (
	_ detectors.Detector                    = (*Scanner)(nil)
	_ detectors.CustomFalsePositiveChecker  = (*Scanner)(nil)
	_ detectors.MultiPartCredentialProvider = (*Scanner)(nil)

	userOCIDPat    = regexp.MustCompile(`(?i)\b(ocid1\.user\.oc[0-9]+\.\.[a-z0-9_-]{16,})\b`)
	fingerprintPat = regexp.MustCompile(`(?i)\b((?:[a-f0-9]{2}:){15}[a-f0-9]{2})\b`)
	privateKeyPat  = regexp.MustCompile(`(?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[\s\S]*?----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----`)
)

type fingerprintCandidate struct {
	value      string
	normalized string
}

type privateKeyCandidate struct {
	value       string
	primary     string
	fingerprint string
	encrypted   bool
}

func (s Scanner) Keywords() []string {
	return []string{"ocid1.user"}
}

// MaxCredentialSpan allows the engine to keep the OCID, fingerprint, and PEM
// key together when the keyword is near a chunk boundary.
func (s Scanner) MaxCredentialSpan() int64 {
	return maxCredentialSpan
}

// FromData finds OCI API signing credentials and correlates the user OCID,
// fingerprint, and RSA private key into one result.
func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	users := findUserOCIDs(dataStr)
	fingerprints := findFingerprints(dataStr)
	if len(users) == 0 || len(fingerprints) == 0 {
		return nil, nil
	}

	privateKeys := findPrivateKeys(dataStr)
	if len(privateKeys) == 0 {
		return nil, nil
	}

	results := make([]detectors.Result, 0)
	for _, key := range privateKeys {
		if key.encrypted {
			// An encrypted key cannot be fingerprinted without its passphrase. Only
			// correlate it when the scan window contains one unambiguous fingerprint.
			if len(fingerprints) != 1 {
				continue
			}
			for _, user := range users {
				results = append(results, newResult(user, fingerprints[0].value, key, "unavailable_encrypted_key"))
			}
			continue
		}

		for _, fingerprint := range fingerprints {
			if key.fingerprint != fingerprint.normalized {
				continue
			}
			for _, user := range users {
				results = append(results, newResult(user, fingerprint.value, key, "matched"))
			}
		}
	}

	return results, nil
}

func findUserOCIDs(data string) []string {
	seen := make(map[string]struct{})
	users := make([]string, 0)
	for _, match := range userOCIDPat.FindAllStringSubmatch(data, -1) {
		user := match[1]
		if _, ok := seen[user]; ok {
			continue
		}
		seen[user] = struct{}{}
		users = append(users, user)
	}
	return users
}

func findFingerprints(data string) []fingerprintCandidate {
	seen := make(map[string]struct{})
	fingerprints := make([]fingerprintCandidate, 0)
	for _, match := range fingerprintPat.FindAllStringSubmatch(data, -1) {
		normalized := strings.ToLower(match[1])
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		fingerprints = append(fingerprints, fingerprintCandidate{
			value:      match[1],
			normalized: normalized,
		})
	}
	return fingerprints
}

func findPrivateKeys(data string) []privateKeyCandidate {
	seen := make(map[string]struct{})
	privateKeys := make([]privateKeyCandidate, 0)
	for _, match := range privateKeyPat.FindAllString(data, -1) {
		normalized := privatekey.Normalize(match)
		if _, ok := seen[normalized]; ok {
			continue
		}

		fingerprint, encrypted, ok := inspectPrivateKey(normalized)
		if !ok {
			continue
		}
		seen[normalized] = struct{}{}
		privateKeys = append(privateKeys, privateKeyCandidate{
			value:       normalized,
			primary:     match,
			fingerprint: fingerprint,
			encrypted:   encrypted,
		})
	}
	return privateKeys
}

func inspectPrivateKey(privateKeyPEM string) (fingerprint string, encrypted bool, ok bool) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") {
		return "", false, false
	}

	parsedKey, err := ssh.ParseRawPrivateKey([]byte(privateKeyPEM))
	if err != nil {
		if isEncryptedPrivateKey(privateKeyPEM, err) {
			return "", true, true
		}
		return "", false, false
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok || rsaKey.N.BitLen() < 2048 {
		return "", false, false
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return "", false, false
	}

	// OCI specifies MD5 over the DER-encoded public key for this fingerprint.
	digest := md5.Sum(publicKeyDER) // #nosec G401 -- required by OCI's fingerprint format.
	return colonSeparatedHex(digest[:]), false, true
}

func isEncryptedPrivateKey(privateKeyPEM string, parseErr error) bool {
	upperKey := strings.ToUpper(privateKeyPEM)
	lowerErr := strings.ToLower(parseErr.Error())
	return strings.Contains(upperKey, "BEGIN ENCRYPTED PRIVATE KEY") ||
		strings.Contains(upperKey, "PROC-TYPE: 4,ENCRYPTED") ||
		strings.Contains(lowerErr, "passphrase") ||
		strings.Contains(lowerErr, "encrypted")
}

func colonSeparatedHex(value []byte) string {
	encoded := hex.EncodeToString(value)
	var result strings.Builder
	result.Grow(len(encoded) + len(value) - 1)
	for i := 0; i < len(encoded); i += 2 {
		if i > 0 {
			result.WriteByte(':')
		}
		result.WriteString(encoded[i : i+2])
	}
	return result.String()
}

func newResult(userOCID, fingerprint string, key privateKeyCandidate, fingerprintValidation string) detectors.Result {
	result := detectors.Result{
		DetectorType: detector_typepb.DetectorType_OracleCloud,
		Raw:          []byte(userOCID),
		RawV2:        []byte(userOCID + "\n" + fingerprint + "\n" + key.value),
		Redacted:     userOCID,
		ExtraData: map[string]string{
			"fingerprint_validation": fingerprintValidation,
		},
		SecretParts: map[string]string{
			"user_ocid":   userOCID,
			"fingerprint": fingerprint,
			"private_key": key.value,
		},
	}
	result.SetPrimarySecretValue(key.primary)
	return result
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_OracleCloud
}

// IsFalsePositive bypasses the generic wordlist check. OCI user OCIDs commonly
// contain the generic "aaaaaa" placeholder term, while this detector already
// requires a matching fingerprint and RSA private key.
func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

func (s Scanner) Description() string {
	return "Oracle Cloud Infrastructure API signing credentials consist of a user OCID, public key fingerprint, and RSA private key."
}
