package rule

import (
	"github.com/dlclark/regexp2"
	"github.com/insidersec/insider/engine"
)

var CsharpRules []engine.Rule = []engine.Rule{
	Rule{
		PatternInside: regexp2.MustCompile(`(?s)\.AddJwtBearer\s*\([^)]*\)\s*\{.*?TokenValidationParameters\s*=\s*new\s+TokenValidationParameters\s*\{.*?\}`, 0),
		ExactMatch:    regexp2.MustCompile(`(?s)((?:ValidateLifetime|RequireExpirationTime)\s*=\s*false)`, 0),
		CWE:           "CWE-613",
		AverageCVSS:   5.0,
		Title:         "JWT Token Validation Parameters with No Expiry Validation",
		Severity:      "WARNING",
		Description:   "TokenValidationParameters.ValidateLifetime or RequireExpirationTime set to false, allowing use of expired JWT tokens, which has security implications.",
		Recomendation: "Set ValidateLifetime and RequireExpirationTime to true to ensure JWT token lifetime validation.",
		NotAnd: []*regexp2.Regexp{
			regexp2.MustCompile(`(?s)(ValidateLifetime|RequireExpirationTime)\s*=\s*true`, 0),
		},
	},
}
