package rule

import (
	"github.com/dlclark/regexp2"
	"github.com/insidersec/insider/engine"
)

var CsharpRules []engine.Rule = []engine.Rule{

	// net-webconfig-debug
	Rule{
		PatternInside: regexp2.MustCompile(`(?s)<system\.web>.*?</system\.web>`, 0),
		ExactMatch:    regexp2.MustCompile(`(?s)(<compilation\s+[^>]*debug\s*=\s*"(?:true|True|TRUE)"[^>]*?(?:\/>|>.*?</compilation>))`, 0),
		CWE:           "CWE-11",
		AverageCVSS:   3.0,
		Title:         "ASP.NET Debug Mode Enabled",
		Severity:      "WARNING",
		Description:   "ASP.NET web.config with debug='true' in compilation tag may leak debug information, impacting security and performance.",
		Recomendation: "Set debug='false' or remove the debug attribute in the compilation tag for production environments.",
	},

	// net-webconfig-trace
	Rule{
		PatternInside: regexp2.MustCompile(`(?s)<system\.web>.*?</system\.web>`, 0),
		ExactMatch:    regexp2.MustCompile(`(?s)(<trace\s+[^>]*enabled\s*=\s*"(?:true|True|TRUE)"[^>]*?(?:\/>|>.*?</trace>))`, 0),
		CWE:           "CWE-1323",
		AverageCVSS:   4.0,
		Title:         "ASP.NET Trace Enabled",
		Severity:      "WARNING",
		Description:   "ASP.NET web.config with trace enabled='true' may leak sensitive application information, such as session IDs or stack traces, to attackers.",
		Recomendation: "Set enabled='false' or remove the trace element in production environments to prevent accidental leakage of sensitive data.",
		NotAnd: []*regexp2.Regexp{
			regexp2.MustCompile(`(?s)enabled\s*=\s*"(?:false|False|FALSE)"`, 0),
		},
	},

	// razor-template-injection
	Rule{
		PatternInside: regexp2.MustCompile(`(?s)\[(?:HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch)\][\s\n]*public\s+ActionResult\s+\w+\s*\([^)]*string\s+(\w+)[^)]*\)\s*\{.*?\}`, 0),
		ExactMatch:    regexp2.MustCompile(`(?s)(Razor\.Parse\s*\(\s*\w+\s*,?\s*[^)]*\))`, 0),
		CWE:           "CWE-94",
		AverageCVSS:   5.5,
		Title:         "Razor Template Injection in HTTP Endpoint",
		Severity:      "WARNING",
		Description:   "User-controllable string passed to Razor.Parse in an HTTP endpoint can lead to Server-Side Template Injection (SSTI), enabling code execution.",
		Recomendation: "Avoid passing user-controlled strings to Razor.Parse. Use safe templating or sanitize inputs with a trusted function like Html.Encode.",
		NotAnd: []*regexp2.Regexp{
			regexp2.MustCompile(`(?s)(?:Html\.Encode|HttpUtility\.HtmlEncode)\s*\(\s*\w+\s*\)`, 0), // Specific sanitizers
		},
	},

	// deprecated-cipher-algorithm
	Rule{
		PatternInside: regexp2.MustCompile(`(?s)using\s+System\.Security\.Cryptography;.*?\{`, 0),
		ExactMatch:    regexp2.MustCompile(`(?s)(\w+\s*=\s*DES\.Create\s*\(\s*(?:"[^"]*")?\s*\))`, 0),
		CWE:           "CWE-327",
		AverageCVSS:   5.3,
		Title:         "Use of Deprecated Cipher Algorithm (DES)",
		Severity:      "WARNING",
		Description:   "Use of DES.Create() employs a deprecated cryptographic algorithm vulnerable to attacks.",
		Recomendation: "Use secure algorithms like Aes.Create() with a strong key size (e.g., 256-bit) instead of DES.",
	},

	// use-ecb-mode
	Rule{
		Or: []*regexp2.Regexp{regexp2.MustCompile(`(EncryptEcb|DecryptEcb| = CipherMode.Ecb)`, 0),
			regexp2.MustCompile(`(?s)(\w+\s*\.\s*Mode\s*=\s*CipherMode\.ECB)`, 0),
		},
		CWE:           "CWE-327",
		AverageCVSS:   5.3,
		Title:         "Use of Insecure ECB Cipher Mode in EncryptEcb",
		Severity:      "WARNING",
		Description:   "Using EncryptEcb with SymmetricAlgorithm, Aes, Rijndael, DES, TripleDES, or RC2 is insecure due to ECB's predictable encryption pattern.",
		Recomendation: "Use secure cipher modes like CBC or GCM with a random IV instead of ECB.",
	},

	// use_weak_rsa_encryption_padding
	Rule{
		PatternInside: regexp2.MustCompile(`(?s)using\s+System\.Security\.Cryptography;.*?\{`, 0),
		ExactMatch:    regexp2.MustCompile(`(?s)(new\s+(?:RSAPKCS1KeyExchangeFormatter|RSAPKCS1KeyExchangeDeformatter)\s*\([^)]*\))`, 0),
		CWE:           "CWE-327",
		AverageCVSS:   5.3,
		Title:         "Use of Deprecated RSAPKCS1 Key Exchange",
		Severity:      "WARNING",
		Description:   "Using RSAPKCS1KeyExchangeFormatter or RSAPKCS1KeyExchangeDeformatter is insecure due to vulnerabilities in PKCS#1 v1.5 padding.",
		Recomendation: "Use modern key exchange mechanisms like ECDH or RSA-OAEP instead of RSAPKCS1.",
		NotAnd: []*regexp2.Regexp{
			regexp2.MustCompile(`(?s)new\s+(?:RSAOAEPKeyExchangeFormatter|RSAOAEPKeyExchangeDeformatter)\s*\([^)]*\)`, 0),
		},
	},

	// web-config-insecure-cookie-settings
	Rule{
		PatternInside: regexp2.MustCompile(`(?s)(?:<httpCookies[^>]*>|<forms[^>]*>|<roleManager[^>]*>).*?</(?:httpCookies|forms|roleManager)>`, 0),
		ExactMatch:    regexp2.MustCompile(`(?s)((?:requireSSL|cookieRequireSSL)\s*=\s*"(?:false|False|FALSE)")`, 0),
		CWE:           "CWE-614",
		AverageCVSS:   3.0,
		Title:         "Insecure Cookie Settings in web.config",
		Severity:      "WARNING",
		Description:   "Cookie Secure flag is disabled (requireSSL='false' or cookieRequireSSL='false'), risking sensitive cookie exposure over plaintext HTTP.",
		Recomendation: "Set requireSSL='true' and cookieRequireSSL='true' to enforce secure cookie transmission over HTTPS.",
		NotAnd: []*regexp2.Regexp{
			regexp2.MustCompile(`(?s)(?:requireSSL|cookieRequireSSL)\s*=\s*"(?:true|True|TRUE)"`, 0),
		},
	},

	// // jwt-tokenvalidationparameters-no-expiry-validation
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
