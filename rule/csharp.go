package rule

import (
	"github.com/dlclark/regexp2"
	"github.com/insidersec/insider/engine"
)

var CsharpRules []engine.Rule = []engine.Rule{

	// // net-webconfig-debug
	// Rule{
	// 	PatternInside: regexp2.MustCompile(`(?s)<system\.web>.*?</system\.web>`, 0),
	// 	ExactMatch:    regexp2.MustCompile(`(?s)(<compilation\s+[^>]*debug\s*=\s*"(?:true|True|TRUE)"[^>]*?(?:\/>|>.*?</compilation>))`, 0),
	// 	CWE:           "CWE-11",
	// 	AverageCVSS:   3.0,
	// 	Title:         "ASP.NET Debug Mode Enabled",
	// 	Severity:      "WARNING",
	// 	Description:   "ASP.NET web.config with debug='true' in compilation tag may leak debug information, impacting security and performance.",
	// 	Recomendation: "Set debug='false' or remove the debug attribute in the compilation tag for production environments.",
	// },

	// // net-webconfig-trace
	// Rule{
	// 	PatternInside: regexp2.MustCompile(`(?s)<system\.web>.*?</system\.web>`, 0),
	// 	ExactMatch:    regexp2.MustCompile(`(?s)(<trace\s+[^>]*enabled\s*=\s*"(?:true|True|TRUE)"[^>]*?(?:\/>|>.*?</trace>))`, 0),
	// 	CWE:           "CWE-1323",
	// 	AverageCVSS:   4.0,
	// 	Title:         "ASP.NET Trace Enabled",
	// 	Severity:      "WARNING",
	// 	Description:   "ASP.NET web.config with trace enabled='true' may leak sensitive application information, such as session IDs or stack traces, to attackers.",
	// 	Recomendation: "Set enabled='false' or remove the trace element in production environments to prevent accidental leakage of sensitive data.",
	// 	NotAnd: []*regexp2.Regexp{
	// 		regexp2.MustCompile(`(?s)enabled\s*=\s*"(?:false|False|FALSE)"`, 0),
	// 	},
	// },

	// // razor-template-injection
	// Rule{
	// 	PatternInside: regexp2.MustCompile(`(?s)\[(?:HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch)\][\s\n]*public\s+ActionResult\s+\w+\s*\([^)]*string\s+(\w+)[^)]*\)\s*\{.*?\}`, 0),
	// 	ExactMatch:    regexp2.MustCompile(`(?s)(Razor\.Parse\s*\(\s*\w+\s*,?\s*[^)]*\))`, 0),
	// 	CWE:           "CWE-94",
	// 	AverageCVSS:   5.5,
	// 	Title:         "Razor Template Injection in HTTP Endpoint",
	// 	Severity:      "WARNING",
	// 	Description:   "User-controllable string passed to Razor.Parse in an HTTP endpoint can lead to Server-Side Template Injection (SSTI), enabling code execution.",
	// 	Recomendation: "Avoid passing user-controlled strings to Razor.Parse. Use safe templating or sanitize inputs with a trusted function like Html.Encode.",
	// 	NotAnd: []*regexp2.Regexp{
	// 		regexp2.MustCompile(`(?s)(?:Html\.Encode|HttpUtility\.HtmlEncode)\s*\(\s*\w+\s*\)`, 0), // Specific sanitizers
	// 	},
	// },

	// // deprecated-cipher-algorithm
	// Rule{
	// 	PatternInside: regexp2.MustCompile(`(?s)using\s+System\.Security\.Cryptography;.*?\{`, 0),
	// 	ExactMatch:    regexp2.MustCompile(`(?s)(\w+\s*=\s*DES\.Create\s*\(\s*(?:"[^"]*")?\s*\))`, 0),
	// 	CWE:           "CWE-327",
	// 	AverageCVSS:   5.3,
	// 	Title:         "Use of Deprecated Cipher Algorithm (DES)",
	// 	Severity:      "WARNING",
	// 	Description:   "Use of DES.Create() employs a deprecated cryptographic algorithm vulnerable to attacks.",
	// 	Recomendation: "Use secure algorithms like Aes.Create() with a strong key size (e.g., 256-bit) instead of DES.",
	// },

	// // use-ecb-mode
	// Rule{
	// 	Or: []*regexp2.Regexp{regexp2.MustCompile(`(EncryptEcb|DecryptEcb| = CipherMode.Ecb)`, 0),
	// 		regexp2.MustCompile(`(?s)(\w+\s*\.\s*Mode\s*=\s*CipherMode\.ECB)`, 0),
	// 	},
	// 	CWE:           "CWE-327",
	// 	AverageCVSS:   5.3,
	// 	Title:         "Use of Insecure ECB Cipher Mode in EncryptEcb",
	// 	Severity:      "WARNING",
	// 	Description:   "Using EncryptEcb with SymmetricAlgorithm, Aes, Rijndael, DES, TripleDES, or RC2 is insecure due to ECB's predictable encryption pattern.",
	// 	Recomendation: "Use secure cipher modes like CBC or GCM with a random IV instead of ECB.",
	// },

	// // use_weak_rsa_encryption_padding
	// Rule{
	// 	PatternInside: regexp2.MustCompile(`(?s)using\s+System\.Security\.Cryptography;.*?\{`, 0),
	// 	ExactMatch:    regexp2.MustCompile(`(?s)(new\s+(?:RSAPKCS1KeyExchangeFormatter|RSAPKCS1KeyExchangeDeformatter)\s*\([^)]*\))`, 0),
	// 	CWE:           "CWE-327",
	// 	AverageCVSS:   5.3,
	// 	Title:         "Use of Deprecated RSAPKCS1 Key Exchange",
	// 	Severity:      "WARNING",
	// 	Description:   "Using RSAPKCS1KeyExchangeFormatter or RSAPKCS1KeyExchangeDeformatter is insecure due to vulnerabilities in PKCS#1 v1.5 padding.",
	// 	Recomendation: "Use modern key exchange mechanisms like ECDH or RSA-OAEP instead of RSAPKCS1.",
	// 	NotAnd: []*regexp2.Regexp{
	// 		regexp2.MustCompile(`(?s)new\s+(?:RSAOAEPKeyExchangeFormatter|RSAOAEPKeyExchangeDeformatter)\s*\([^)]*\)`, 0),
	// 	},
	// },

	// // web-config-insecure-cookie-settings
	// Rule{
	// 	PatternInside: regexp2.MustCompile(`(?s)(?:<httpCookies[^>]*>|<forms[^>]*>|<roleManager[^>]*>).*?</(?:httpCookies|forms|roleManager)>`, 0),
	// 	ExactMatch:    regexp2.MustCompile(`(?s)((?:requireSSL|cookieRequireSSL)\s*=\s*"(?:false|False|FALSE)")`, 0),
	// 	CWE:           "CWE-614",
	// 	AverageCVSS:   3.0,
	// 	Title:         "Insecure Cookie Settings in web.config",
	// 	Severity:      "WARNING",
	// 	Description:   "Cookie Secure flag is disabled (requireSSL='false' or cookieRequireSSL='false'), risking sensitive cookie exposure over plaintext HTTP.",
	// 	Recomendation: "Set requireSSL='true' and cookieRequireSSL='true' to enforce secure cookie transmission over HTTPS.",
	// 	NotAnd: []*regexp2.Regexp{
	// 		regexp2.MustCompile(`(?s)(?:requireSSL|cookieRequireSSL)\s*=\s*"(?:true|True|TRUE)"`, 0),
	// 	},
	// },

	// // structured-logging
	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`(?s)\w+\.(?:Debug|Error|Fatal|Information|Verbose|Warning|LogCritical|LogDebug|LogError|LogInformation|LogTrace|LogWarning|Info|Trace|Warn)\s*\(\s*\$"[^"]*(?:\{[^}]+\})[^"]*"\s*\)`, 0),
	// 	CWE:           "CWE-117",
	// 	AverageCVSS:   2.0,
	// 	Title:         "Unstructured Logging with Variable Interpolation",
	// 	Severity:      "INFO",
	// 	Description:   "Interpolated log messages with variables (e.g., $\"log {var}\") obscure parameters and reduce log searchability. Use structured logging.",
	// 	Recomendation: "Replace interpolated strings ($\"...\") with structured logging templates (e.g., \"Processed {@Position} in {Elapsed} ms.\", position, elapsed).",
	// },

	// correctness-double-epsilon-equality (doing)

	// // correctness-regioninfo-interop
	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`(?s)RegionInfo\s+\w+\s*=\s*new\s+RegionInfo\s*\(\s*"\w{2}"\s*\)\s*;`, 0),
	// 	CWE:           "CWE-687",
	// 	AverageCVSS:   3.0,
	// 	Title:         "Potential Incorrect RegionInfo Serialization in Inter-Process Communication",
	// 	Severity:      "WARNING",
	// 	Description:   "Using a two-character ISO region code to instantiate RegionInfo and writing it via a PipeStream may lead to incorrect serialization or inter-process communication issues.",
	// 	Recomendation: "Instantiate RegionInfo with a full culture name (e.g., 'en-US') instead of a two-letter ISO region code (e.g., 'US') for inter-process communication.",
	// },

	// // correctness-sslcertificatetrust-handshake-no-trust
	// Rule{
	// 	PatternInside: nil,
	// 	ExactMatch:    regexp2.MustCompile(`(?s)SslCertificateTrust\.CreateForX509(Collection|Store)\s*\(\s*[^\)]*?,\s*(?:sendTrustInHandshake\s*=\s*true|true)\s*\)\s*;`, 0),
	// 	CWE:           "CWE-295",
	// 	AverageCVSS:   5.0,
	// 	Title:         "Insecure SSL Certificate Trust Configuration",
	// 	Severity:      "WARNING",
	// 	Description:   "Using SslCertificateTrust.CreateForX509Collection with sendTrustInHandshake=true or second parameter true may expose sensitive trust information, leading to potential man-in-the-middle attacks.",
	// 	Recomendation: "Set sendTrustInHandshake=false or use false as the second parameter to avoid sending trust information in the handshake.",
	// },

	// // unsigned-security-token
	// Rule{
	// 	PatternInside: regexp2.MustCompile(`(?s)new\s+TokenValidationParameters\s*\{.*?\}`, 0),
	// 	ExactMatch:    regexp2.MustCompile(`RequireSignedTokens\s*=\s*false`, 0),
	// 	CWE:           "CWE-347",
	// 	AverageCVSS:   6.5,
	// 	Title:         "JWT Token Validation with Disabled Signature Verification",
	// 	Severity:      "ERROR",
	// 	Description:   "Setting RequireSignedTokens = false in TokenValidationParameters allows unsigned JWT tokens, which may permit token tampering or spoofing.",
	// 	Recomendation: "Set RequireSignedTokens = true to enforce signature validation for JWT tokens.",
	// 	NotAnd: []*regexp2.Regexp{
	// 		regexp2.MustCompile(`RequireSignedTokens\s*=\s*true`, 0),
	// 	},
	// },

	// // X509Certificate2-privkey (enhancing, required taint track)

	// Rule{
	// 	Auxiliary:     []*regexp2.Regexp{regexp2.MustCompile(`(?s)using\s+System\.Security\.Cryptography;`, 0)},
	// 	PatternInside: regexp2.MustCompile(`(?s)X509Certificate2Collection\s+(\w+)\s*=\s*.*?;`, 0),
	// 	ExactMatch:    regexp2.MustCompile(`(?s)\w+\.PrivateKey\s*;`, 0),
	// 	CWE:           "CWE-321",
	// 	AverageCVSS:   5.0,
	// 	Title:         "Access to PrivateKey in X509Certificate2 from X509Certificate2Collection",
	// 	Severity:      "WARNING",
	// 	Description:   "Accessing the PrivateKey property on an X509Certificate2 object from an X509Certificate2Collection may indicate improper handling of sensitive cryptographic material.",
	// 	Recomendation: "Ensure secure key management when accessing PrivateKey on X509Certificate2 objects within a collection, and avoid exposing or hard-coding key material.",
	// },

	// // http-listener-wildcard-bindings (it works, but somehow always show 1 result only)

	// Rule{
	// 	Auxiliary:     []*regexp2.Regexp{regexp2.MustCompile(`(?s)using\s+System\.Net\s*;`, 0)},
	// 	ExactMatch:    regexp2.MustCompile(`(?s)\w+\.Prefixes\.Add\s*\(\s*"(http|https):\/\/(\*|\+|\*\.[a-zA-Z]{2,})(:[0-9]+)"\s*\)\s*;`, 0),
	// 	AverageCVSS:   4.0,
	// 	Title:         "Use of Wildcard in HttpListener Prefixes",
	// 	Severity:      "WARNING",
	// 	Description:   "The top level wildcard bindings (* or +) in HttpListener.Prefixes leave your application open to security vulnerabilities and give attackers more control over where traffic is routed.",
	// 	Recomendation: "If wildcards are necessary, consider using subdomain wildcard binding (e.g., '*.asdf.gov' if you own 'asdf.gov'). Preferably, specify explicit hostnames to restrict access to trusted domains.",
	// },

	// // insecure-binaryformatter-deserialization

	// Rule{
	// 	Auxiliary:     []*regexp2.Regexp{regexp2.MustCompile(`(?s)using\s+System\.Runtime\.Serialization\.Formatters\.Binary;`, 0)},
	// 	ExactMatch:    regexp2.MustCompile(`(?s)new\s+BinaryFormatter\s*\(\s*\)\s*;`, 0),
	// 	CWE:           "CWE-502",
	// 	AverageCVSS:   7.0,
	// 	Title:         "Insecure BinaryFormatter Deserialization",
	// 	Severity:      "WARNING",
	// 	Description:   "The BinaryFormatter type is dangerous and is not recommended for data processing. Applications should stop using BinaryFormatter as soon as possible, even if they believe the data they're processing to be trustworthy. BinaryFormatter is insecure and can't be made secure, posing risks of deserialization vulnerabilities (CWE-502, OWASP A08:2017/A08:2021). Reference: https://docs.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide",
	// 	Recomendation: "Replace BinaryFormatter with safer serialization alternatives, such as System.Text.Json or XmlSerializer, which are less susceptible to deserialization attacks. Ensure input data is validated and sanitized before processing.",
	// },

	// // data-contract-resolver

	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`(?s)class\s+\w+\s*:\s*DataContractResolver\s*\{.*?\}`, 0),
	// 	CWE:           "CWE-502",
	// 	AverageCVSS:   6.0,
	// 	Title:         "Insecure DataContractResolver Implementation",
	// 	Severity:      "WARNING",
	// 	Description:   "Implementing a custom DataContractResolver can be dangerous if used with untrusted data, as malicious types may cause unexpected behavior during deserialization (CWE-502, OWASP A08:2017/A08:2021). Only use DataContractResolver if you are completely sure of what information is being serialized. Reference: https://docs.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide",
	// 	Recomendation: "Avoid using custom DataContractResolver implementations unless the serialized data is fully trusted and validated. Consider safer serialization alternatives like System.Text.Json or XmlSerializer to mitigate deserialization risks.",
	// },

	// // insecure-fastjson-deserialization

	// Rule{
	// 	Auxiliary:     []*regexp2.Regexp{regexp2.MustCompile(`(?s)using\s+fastJSON\s*;`, 0)},
	// 	ExactMatch:    regexp2.MustCompile(`(?s)new\s+JSONParameters\s*\{\s*BadListTypeChecking\s*=\s*false\s*\}`, 0),
	// 	CWE:           "CWE-502",
	// 	AverageCVSS:   6.0,
	// 	Title:         "Insecure fastJSON Deserialization Configuration",
	// 	Severity:      "WARNING",
	// 	Description:   "Configuring fastJSON with BadListTypeChecking = false has the potential to be unsafe, as it disables type checking during deserialization, increasing the risk of processing malicious types from untrusted JSON sources (CWE-502, OWASP A08:2017/A08:2021). Reference: https://github.com/mgholam/fastJSON#security-warning-update",
	// 	Recomendation: "Avoid setting BadListTypeChecking = false in JSONParameters. Use fastJSON with trusted JSON sources only, and ensure type checking is enabled to mitigate deserialization risks. Consider safer serialization libraries like System.Text.Json or XmlSerializer.",
	// },

	// // insecure-fspickler-deserialization

	// Rule{
	// 	Auxiliary:     []*regexp2.Regexp{regexp2.MustCompile(`(?s)using\s+MBrace\.FsPickler\.Json\s*;`, 0)},
	// 	ExactMatch:    regexp2.MustCompile(`(?s)FsPickler\.CreateJsonSerializer\s*\(\s*\)\s*;`, 0),
	// 	CWE:           "CWE-502",
	// 	AverageCVSS:   6.0,
	// 	Title:         "Insecure FsPickler JSON Deserialization",
	// 	Severity:      "WARNING",
	// 	Description:   "The FsPickler JSON serializer, created via FsPickler.CreateJsonSerializer(), is dangerous due to its default configuration, which may enable insecure deserialization of untrusted data, potentially leading to arbitrary code execution (CWE-502, OWASP A08:2017/A08:2021). Reference: https://mbraceproject.github.io/FsPickler/tutorial.html#Disabling-Subtype-Resolution",
	// 	Recomendation: "Avoid using FsPickler.CreateJsonSerializer() with its default configuration. If FsPickler is necessary, explicitly configure it to disable subtype resolution and validate input data. Consider safer serialization libraries like System.Text.Json or XmlSerializer to mitigate deserialization risks.",
	// 	NotAnd:        []*regexp2.Regexp{},
	// },

	// // insecure-typefilterlevel-full

	// Rule{
	// 	Or: []*regexp2.Regexp{
	// 		regexp2.MustCompile(`(?s)(new\s+BinaryServerFormatterSinkProvider\s*\{\s*TypeFilterLevel\s*=\s*TypeFilterLevel\.(Full|Low)\s*\}\s*;|\w+\s*=\s*new\s+BinaryServerFormatterSinkProvider\s*\(.*?\)\s*;.*?\w+\.TypeFilterLevel\s*=\s*TypeFilterLevel\.(Full|Low)\s*;)`, 0),
	// 		regexp2.MustCompile(`(?s)\w+\["typeFilterLevel"\]\s*=\s*"(Full|Low)"\s*;`, 0),
	// 	},
	// 	CWE:           "CWE-502",
	// 	AverageCVSS:   6.0,
	// 	Title:         "Insecure TypeFilterLevel in BinaryServerFormatterSinkProvider",
	// 	Severity:      "WARNING",
	// 	Description:   "Setting TypeFilterLevel to Full or Low in BinaryServerFormatterSinkProvider enables insecure deserialization, which can lead to remote code execution (RCE) in .NET remoting services (CWE-502, OWASP A08:2017/A08:2021). References: https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.typefilterlevel?view=net-6.0, https://www.synacktiv.com/en/publications/izi-izi-pwn2own-ics-miami.html",
	// 	Recomendation: "Avoid using .NET remoting with TypeFilterLevel set to Full or Low. Migrate to Windows Communication Foundation (WCF) for safer communication. See https://docs.microsoft.com/en-us/dotnet/framework/wcf/migrating-from-net-remoting-to-wcf. If remoting is necessary, validate and sanitize input data and avoid untrusted sources.",
	// },

	// // insecure-javascriptserializer-deserialization

	// Rule{
	// 	Auxiliary:     []*regexp2.Regexp{regexp2.MustCompile(`(?s)using\s+System\.Web\.Script\.Serialization\s*;`, 0)},
	// 	ExactMatch:    regexp2.MustCompile(`(?s)new\s+SimpleTypeResolver\s*\(\s*\)`, 0),
	// 	CWE:           "CWE-502",
	// 	AverageCVSS:   5.0,
	// 	Title:         "Insecure JavaScriptSerializer with SimpleTypeResolver",
	// 	Severity:      "ERROR",
	// 	Description:   "Using SimpleTypeResolver with JavaScriptSerializer is insecure and should not be used, as it allows deserialization of untrusted JSON data, potentially enabling remote code execution (RCE) by malicious clients (CWE-502, OWASP A08:2017/A08:2021). Reference: https://docs.microsoft.com/en-us/dotnet/api/system.web.script.serialization.simpletyperesolver?view=netframework-4.8#remarks",
	// 	Recomendation: "Avoid using SimpleTypeResolver with JavaScriptSerializer. Use safer serialization libraries like System.Text.Json or XmlSerializer, and validate input data. If JavaScriptSerializer is necessary, avoid SimpleTypeResolver and ensure strict type constraints with trusted sources.",
	// },

	// // insecure-losformatter-deserialization

	// Rule{
	// 	Auxiliary:     []*regexp2.Regexp{regexp2.MustCompile(`(?s)using\s+System\.Web\.UI\s*;`, 0)},
	// 	ExactMatch:    regexp2.MustCompile(`(?s)new\s+LosFormatter\s*\(\s*\)`, 0),
	// 	CWE:           "CWE-502",
	// 	AverageCVSS:   6.0,
	// 	Title:         "Insecure LosFormatter Deserialization",
	// 	Severity:      "WARNING",
	// 	Description:   "The LosFormatter type is dangerous and is not recommended for data processing. It is inherently insecure and cannot be made secure, posing risks of deserialization vulnerabilities (CWE-502, OWASP A08:2017/A08:2021). Applications should stop using LosFormatter, even with trusted data. Reference: https://docs.microsoft.com/en-us/dotnet/api/system.web.ui.losformatter?view=netframework-4.8",
	// 	Recomendation: "Replace LosFormatter with safer serialization alternatives, such as System.Text.Json or XmlSerializer, which are less susceptible to deserialization attacks. Ensure input data is validated and sanitized before processing.",
	// },

	// // insecure-netdatacontract-deserialization

	// Rule{
	// 	Auxiliary:     []*regexp2.Regexp{regexp2.MustCompile(`(?s)using\s+System\.Runtime\.Serialization\s*;`, 0)},
	// 	ExactMatch:    regexp2.MustCompile(`(?s)new\s+NetDataContractSerializer\s*\(\s*\)`, 0),
	// 	CWE:           "CWE-502",
	// 	AverageCVSS:   6.0,
	// 	Title:         "Insecure NetDataContractSerializer Deserialization",
	// 	Severity:      "WARNING",
	// 	Description:   "The NetDataContractSerializer type is dangerous and is not recommended for data processing. It is inherently insecure and cannot be made secure, posing risks of deserialization vulnerabilities (CWE-502, OWASP A08:2017/A08:2021). Applications should stop using NetDataContractSerializer, even with trusted data. Reference: https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.netdatacontractserializer?view=netframework-4.8#security",
	// 	Recomendation: "Replace NetDataContractSerializer with safer serialization alternatives, such as System.Text.Json or XmlSerializer, which are less susceptible to deserialization attacks. Ensure input data is validated and sanitized before processing.",
	// },

	// // insecure-soapformatter-deserialization

	// Rule{
	// 	Auxiliary:     []*regexp2.Regexp{regexp2.MustCompile(`(?s)using\s+System\.Runtime\.Serialization\.Formatters\.Soap\s*;`, 0)},
	// 	ExactMatch:    regexp2.MustCompile(`(?s)new\s+SoapFormatter\s*\(\s*\)\s*;`, 0),
	// 	CWE:           "CWE-502",
	// 	AverageCVSS:   6.0,
	// 	Title:         "Insecure SoapFormatter Deserialization",
	// 	Severity:      "WARNING",
	// 	Description:   "The SoapFormatter type is dangerous and is not recommended for data processing. It is inherently insecure and cannot be made secure, posing risks of deserialization vulnerabilities (CWE-502, OWASP A08:2017/A08:2021). Applications should stop using SoapFormatter, even with trusted data. Reference: https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.soap.soapformatter?view=netframework-4.8#remarks",
	// 	Recomendation: "Replace SoapFormatter with safer serialization alternatives, such as System.Text.Json or XmlSerializer, which are less susceptible to deserialization attacks. Ensure input data is validated and sanitized before processing.",
	// },

	// jwt-tokenvalidationparameters-no-expiry-validation

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
