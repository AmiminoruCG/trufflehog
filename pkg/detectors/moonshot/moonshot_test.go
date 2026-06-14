package moonshot

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestMoonshot_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	canonicalKey := fakeKey("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKl")
	secondKey := fakeKey(strings.Repeat("b", 48))

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "canonical API key with variable context",
			input: "MOONSHOT_API_KEY = '" + canonicalKey + "'",
			want:  []string{canonicalKey},
		},
		{
			name:  "API key with endpoint context",
			input: "base_url=https://api.moonshot.ai/v1\napi_key=" + canonicalKey,
			want:  []string{canonicalKey},
		},
		{
			name: "finds all unique matches",
			input: `kimi_key = "` + canonicalKey + `"
MOONSHOT_API_KEY = "` + secondKey + `"`,
			want: []string{
				canonicalKey,
				secondKey,
			},
		},
		{
			name:  "requires context when not verifying",
			input: "api_key = " + canonicalKey,
			want:  nil,
		},
		{
			name:  "too short",
			input: "MOONSHOT_API_KEY = " + fakeKey("short"),
			want:  nil,
		},
		{
			name:  "sk-kimi belongs to Kimi Code, not Moonshot Open Platform",
			input: "MOONSHOT_API_KEY = sk-kimi-" + strings.Repeat("a", 48),
			want:  nil,
		},
		{
			name:  "legacy OpenAI marker is ignored",
			input: "moonshot_key = " + fakeKey("abcT3BlbkFJ"+strings.Repeat("a", 37)),
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

func TestMoonshot_Verify(t *testing.T) {
	verifyKey := fakeKey(strings.Repeat("c", 48))
	tests := []struct {
		name                string
		input               string
		client              *http.Client
		wantResults         int
		wantVerified        bool
		wantVerificationErr bool
	}{
		{
			name:         "verified without context",
			input:        "api_key=" + verifyKey,
			client:       common.ConstantResponseHttpClient(200, `{"object":"list","data":[]}`),
			wantResults:  1,
			wantVerified: true,
		},
		{
			name:        "unauthorized without context is suppressed",
			input:       "api_key=" + verifyKey,
			client:      common.ConstantResponseHttpClient(401, `{"error":{"message":"invalid key"}}`),
			wantResults: 0,
		},
		{
			name:         "unauthorized with context remains unverified",
			input:        "MOONSHOT_API_KEY=" + verifyKey,
			client:       common.ConstantResponseHttpClient(401, `{"error":{"message":"invalid key"}}`),
			wantResults:  1,
			wantVerified: false,
		},
		{
			name:                "unexpected status is indeterminate",
			input:               "MOONSHOT_API_KEY=" + verifyKey,
			client:              common.ConstantResponseHttpClient(500, `{"error":"server error"}`),
			wantResults:         1,
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:        "unexpected status without context is suppressed",
			input:       "api_key=" + verifyKey,
			client:      common.ConstantResponseHttpClient(500, `{"error":"server error"}`),
			wantResults: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d := Scanner{client: test.client}
			results, err := d.FromData(context.Background(), true, []byte(test.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(results) != test.wantResults {
				t.Fatalf("expected %d results, got %d", test.wantResults, len(results))
			}
			if test.wantResults == 0 {
				return
			}
			if results[0].Verified != test.wantVerified {
				t.Fatalf("Verified = %v, want %v", results[0].Verified, test.wantVerified)
			}
			if (results[0].VerificationError() != nil) != test.wantVerificationErr {
				t.Fatalf("wantVerificationError = %v, verification error = %v", test.wantVerificationErr, results[0].VerificationError())
			}
		})
	}
}

func fakeKey(suffix string) string {
	return "sk-" + suffix
}
