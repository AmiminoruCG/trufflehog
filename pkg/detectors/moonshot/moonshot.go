package moonshot

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(`\b(sk-[A-Za-z0-9]{48})\b`)
	contextPat    = regexp.MustCompile(`(?i)(moonshot|kimi|api\.moonshot\.ai|api\.kimi\.ai|MOONSHOT_API_KEY|KIMI_API_KEY)`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"sk-", "moonshot", "kimi"}
}

// FromData will find and optionally verify Moonshot secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	hasMoonshotContext := contextPat.MatchString(dataStr)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		token := strings.TrimSpace(match[1])
		if strings.Contains(token, "T3BlbkFJ") {
			continue
		}
		uniqueMatches[token] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Moonshot,
			Raw:          []byte(token),
			SecretParts:  map[string]string{"key": token},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			verified, verificationErr := verifyToken(ctx, client, token)
			s1.Verified = verified
			s1.SetVerificationError(verificationErr, token)
			if !verified && !hasMoonshotContext {
				continue
			}
		} else if !hasMoonshotContext {
			continue
		}

		results = append(results, s1)
	}

	return
}

func verifyToken(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.moonshot.ai/v1/models", nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Moonshot
}

func (s Scanner) Description() string {
	return "Moonshot AI provides OpenAI-compatible APIs for Kimi and Moonshot models."
}
