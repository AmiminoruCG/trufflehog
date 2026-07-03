package glm

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

func TestGLM_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	canonicalKey := fakeKey("0123456789abcdef0123456789abcdef", "SyntheticKey0001")
	secondKey := fakeKey(strings.Repeat("b", 32), "AbCdEfGhIjKlMnOp")

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "canonical API key with variable context",
			input: "ZHIPU_API_KEY = '" + canonicalKey + "'",
			want:  []string{canonicalKey},
		},
		{
			name:  "API key with endpoint context",
			input: "base_url=https://open.bigmodel.cn/api/paas/v4\napi_key=" + canonicalKey,
			want:  []string{canonicalKey},
		},
		{
			name: "finds all unique matches",
			input: `glm_key = "` + canonicalKey + `"
BIGMODEL_API_KEY = "` + secondKey + `"`,
			want: []string{
				canonicalKey,
				secondKey,
			},
		},
		{
			name:  "requires GLM context when not verifying",
			input: "api_key = " + canonicalKey,
			want:  nil,
		},
		{
			name:  "too short prefix",
			input: "ZHIPU_API_KEY = " + fakeKey("short", "SyntheticKey0001"),
			want:  nil,
		},
		{
			name:  "too short suffix",
			input: "ZHIPU_API_KEY = " + fakeKey(strings.Repeat("a", 32), "short"),
			want:  nil,
		},
		{
			name:  "wrong separator",
			input: "ZHIPU_API_KEY = " + strings.Repeat("a", 32) + "-" + strings.Repeat("b", 16),
			want:  nil,
		},
		{
			name:  "non hex prefix",
			input: "ZHIPU_API_KEY = " + fakeKey("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "SyntheticKey0001"),
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

func TestGLM_Verify(t *testing.T) {
	verifyKey := fakeKey(strings.Repeat("c", 32), strings.Repeat("d", 16))
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
			input:        "GLM_API_KEY=" + verifyKey,
			client:       common.ConstantResponseHttpClient(401, `{"error":{"message":"invalid key"}}`),
			wantResults:  1,
			wantVerified: false,
		},
		{
			name:                "unexpected status is indeterminate",
			input:               "ZHIPU_API_KEY=" + verifyKey,
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

func fakeKey(prefix, suffix string) string {
	return prefix + "." + suffix
}
