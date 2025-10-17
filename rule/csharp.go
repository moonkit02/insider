package rule

import (
	"github.com/dlclark/regexp2"
	"github.com/insidersec/insider/engine"
)

var CsharpRules []engine.Rule = []engine.Rule{

	// // mvc-missing-antiforgery
	// Rule{
	// 	Auxiliary: []*regexp2.Regexp{regexp2.MustCompile(`(?m)^\s*using\s+Microsoft\.AspNetCore\.Mvc\s*;`, 0)},
	// 	And:       []*regexp2.Regexp{regexp2.MustCompile(`(?:\[\s*[A-Za-z][A-Za-z0-9]*\s*(?:\([^)]*\))?\s*\]\s*)*\[\s*Http(?:Post|Put|Delete|Patch)\s*\][\s\S]*?public\s+IActionResult\s+\w+\s*\([^)]*\)\s*\{[\s\S]*?\}`, 0)},
	// 	NotOr: []*regexp2.Regexp{
	// 		// [ValidateAntiForgeryToken] public IActionResult Method(...)
	// 		regexp2.MustCompile(
	// 			`\[\s*ValidateAntiForgeryToken\s*\](?:\s*\[[^\]]+\])*\s*public\s+IActionResult\s+\w+\s*\([^)]*\)\s*\{[\s\S]*?\}`,
	// 			0),

	// 		// [Consumes(...)] public IActionResult Method(...)
	// 		regexp2.MustCompile(
	// 			`\[\s*Consumes\s*\([^)]*\)\s*\](?:\s*\[[^\]]+\])*\s*public\s+IActionResult\s+\w+\s*\([^)]*\)\s*\{[\s\S]*?\}`,
	// 			0),
	// 	},
	// 	CWE:           "CWE-352",
	// 	AverageCVSS:   6.5,
	// 	Description:   "$METHOD is a state-changing MVC method that does not validate the antiforgery token or do strict content-type checking.",
	// 	Recomendation: "State-changing controller methods should either enforce antiforgery tokens or do strict content-type checking to prevent simple HTTP request types from bypassing CORS preflight controls.",
	// },

	// // net-webconfig-debug
	// Rule{
	// 	PatternInside: regexp2.MustCompile(`(?s)<system\.web>.*?</system\.web>`, 0),
	// 	ExactMatch:    regexp2.MustCompile(`(?s)(<compilation\s+[^>]*debug\s*=\s*"(?:true|True|TRUE)"[^>]*?(?:\/>|>.*?</compilation>))`, 0),
	// 	CWE:           "CWE-11",
	// 	AverageCVSS:   3.0,
	// 	Description:   "ASP.NET applications built with `debug` set to true in production may leak debug information to attackers. Debug mode also affects performance and reliability. Set `debug` to `false` or remove it from `<compilation... />`",
	// 	Recomendation: "Set debug='false' or remove the debug attribute in the compilation tag for production environments.",
	// },

	// // net-webconfig-trace
	// Rule{
	// 	PatternInside: regexp2.MustCompile(`(?s)<system\.web>.*?</system\.web>`, 0),
	// 	ExactMatch:    regexp2.MustCompile(`(?s)(<trace\s+[^>]*enabled\s*=\s*"(?:true|True|TRUE)"[^>]*?(?:\/>|>.*?</trace>))`, 0),
	// 	CWE:           "CWE-1323",
	// 	AverageCVSS:   4.0,
	// 	Description:   "OWASP guidance recommends disabling tracing for production applications to prevent accidental leakage of sensitive application information.",
	// 	Recomendation: "Set enabled='false' or remove the trace element in production environments to prevent accidental leakage of sensitive data.",
	// 	NotAnd: []*regexp2.Regexp{
	// 		regexp2.MustCompile(`(?s)enabled\s*=\s*"(?:false|False|FALSE)"`, 0),
	// 	},
	// },

	// // razor-template-injection - need taint
	// Rule{
	// 	// PatternInside: regexp2.MustCompile(`(?s)\[(?:HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch)\][\s\n]*public\s+ActionResult\s+\w+\s*\([^)]*string\s+(\w+)[^)]*\)\s*\{.*?\}`, 0),
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
	// 	Auxiliary:     []*regexp2.Regexp{regexp2.MustCompile(`(?s)using\s+System\.Security\.Cryptography;.*?\{`, 0)},
	// 	ExactMatch:    regexp2.MustCompile(`(?s)(\w+\s*=\s*(DES|RC2)\.Create\s*\(\s*(?:"[^"]*")?\s*\))`, 0),
	// 	CWE:           "CWE-327",
	// 	AverageCVSS:   5.3,
	// 	Title:         "Use of Deprecated Cipher Algorithm (DES & RC2)",
	// 	Severity:      "WARNING",
	// 	Description:   "Usage of deprecated cipher algorithm detected. Use Aes or ChaCha20Poly1305 instead.",
	// 	Recomendation: "Use secure algorithms like Aes.Create() with a strong key size (e.g., 256-bit) instead of DES.",
	// },

	// // use-ecb-mode
	// Rule{
	// 	Or: []*regexp2.Regexp{
	// 		regexp2.MustCompile(`(EncryptEcb|DecryptEcb)\s*\([^)]*\)\s*;`, 0),
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
	// 	Auxiliary:     []*regexp2.Regexp{regexp2.MustCompile(`(?s)using\s+System\.Security\.Cryptography\s*;`, 0)},
	// 	ExactMatch:    regexp2.MustCompile(`(?s)(new\s+(RSAPKCS1KeyExchangeFormatter|RSAPKCS1KeyExchangeDeformatter)\([^)]*\))`, 0),
	// 	CWE:           "CWE-780",
	// 	AverageCVSS:   5.3,
	// 	Title:         "Use of Deprecated RSAPKCS1 Key Exchange",
	// 	Severity:      "WARNING",
	// 	Description:   "Using RSAPKCS1KeyExchangeFormatter or RSAPKCS1KeyExchangeDeformatter is insecure due to vulnerabilities in PKCS#1 v1.5 padding.",
	// 	Recomendation: "Use modern key exchange mechanisms like ECDH or RSA-OAEP instead of RSAPKCS1.",
	// },

	// // web-config-insecure-cookie-settings
	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`(?i)<\s*(?:httpCookies|forms|roleManager)\b[^>]*(?:requireSSL|cookieRequireSSL)\s*=\s*"(FALSE|False|false)"[^>]*>`, 0),
	// 	CWE:           "CWE-614",
	// 	AverageCVSS:   3.0,
	// 	Title:         "Insecure Cookie Settings in web.config",
	// 	Severity:      "WARNING",
	// 	Description:   "Cookie Secure flag is disabled (requireSSL='false' or cookieRequireSSL='false'), risking sensitive cookie exposure over plaintext HTTP.",
	// 	Recomendation: "Set requireSSL='true' and cookieRequireSSL='true' to enforce secure cookie transmission over HTTPS.",
	// },

	// structured-logging
	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`(?s)\w+\.(?:Debug|Error|Fatal|Information|Verbose|Warning|LogCritical|LogDebug|LogError|LogInformation|LogTrace|LogWarning|Info|Trace|Warn)\s*\(\s*\$"[^"]*(?:\{[^}]+\})[^"]*"\s*\)`, 0),
	// 	CWE:           "CWE-117",
	// 	AverageCVSS:   2.0,
	// 	Title:         "Unstructured Logging with Variable Interpolation",
	// 	Severity:      "INFO",
	// 	Description:   "Interpolated log messages with variables (e.g., $\"log {var}\") obscure obscures the distinction between variables and the log message.",
	// 	Recomendation: "Replace interpolated strings ($\"...\") with structured logging templates (e.g., \"Processed {@Position} in {Elapsed} ms.\", position, elapsed) instead, where the variables are passed as additional arguments and the interpolation is performed by the logging library. This reduces the possibility of log injection and makes it easier to search through logs.",
	// },

	// // correctness-double-epsilon-equality

	// // correctness-regioninfo-interop
	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`(?s)RegionInfo\s+\w+\s*=\s*new\s+RegionInfo\s*\(\s*"\w{2}"\s*\)\s*;`, 0),
	// 	CWE:           "CWE-687",
	// 	AverageCVSS:   3.0,
	// 	Title:         "Potential Incorrect RegionInfo Serialization in Inter-Process Communication",
	// 	Severity:      "WARNING",
	// 	Description:   "Potential inter-process write of RegionInfo $RI via $PIPESTREAM $P that was instantiated with a two-character culture code $REGION.",
	// 	Recomendation: "Per .NET documentation, if you want to persist a RegionInfo object or communicate it between processes, you should instantiate RegionInfo with a full culture name (e.g., 'en-US') instead of a two-letter ISO region code (e.g., 'US').",
	// },

	// correctness-sslcertificatetrust-handshake-no-trust
	// Rule{
	// 	PatternInside: nil,
	// 	ExactMatch:    regexp2.MustCompile(`(?s)SslCertificateTrust\.CreateForX509(Collection|Store)\s*\(\s*[^\)]*?,\s*(?:sendTrustInHandshake\s*=\s*true|true)\s*\)\s*;`, 0),
	// 	CWE:           "CWE-200",
	// 	AverageCVSS:   5.0,
	// 	Title:         "Insecure SSL Certificate Trust Configuration",
	// 	Severity:      "WARNING",
	// 	Description:   "Sending the trusted CA list increases the size of the handshake request and can leak system configuration information.",
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

	// // memory-marshal-create-span

	// Rule{
	// 	Or: []*regexp2.Regexp{
	// 		regexp2.MustCompile(`(?s)MemoryMarshal\.CreateSpan\s*\([^()]*\)\s*;`, 0),
	// 		regexp2.MustCompile(`(?s)MemoryMarshal\.CreateReadOnlySpan\s*\([^()]*\)\s*;`, 0),
	// 	},
	// 	CWE:           "CWE-125",
	// 	AverageCVSS:   5.0,
	// 	Title:         "Insecure MemoryMarshal CreateSpan Usage",
	// 	Severity:      "WARNING",
	// 	Description:   "MemoryMarshal.CreateSpan and MemoryMarshal.CreateReadOnlySpan should be used with caution, as the length argument is not checked, potentially leading to out-of-bounds read vulnerabilities (CWE-125, OWASP A04:2021). References: https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.memorymarshal.createspan?view=net-6.0, https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.memorymarshal.createreadonlyspan?view=net-6.0",
	// 	Recomendation: "Ensure the length argument in MemoryMarshal.CreateSpan and MemoryMarshal.CreateReadOnlySpan is validated to prevent out-of-bounds reads. Consider safer memory management alternatives or add explicit bounds checking before calling these methods.",
	// },

	// // jwt-tokenvalidationparameters-no-expiry-validation 1
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

	// // jwt-tokenvalidationparameters-no-expiry-validation 2
	Rule{
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

	// // misconfigured-lockout-option
	// Rule{
	// 	PatternInside: regexp2.MustCompile(`(?s)public\s+async\s+\w+<IActionResult>\s+\w+\s*\([^)]*\)\s*\{.*?\}`, 0),
	// 	ExactMatch:    regexp2.MustCompile(`\b(?:PasswordSignInAsync|CheckPasswordSignInAsync)\s*\([^)]*lockoutOnFailure:\s*false[^)]*\)`, 0),
	// 	CWE:           "CWE-307",
	// 	AverageCVSS:   7.7,
	// 	Description:   "A misconfigured account lockout mechanism was detected. If lockoutOnFailure is set to false, attackers can brute-force credentials without being locked out.",
	// 	Recomendation: "Set lockoutOnFailure to true when calling PasswordSignInAsync or CheckPasswordSignInAsync to mitigate brute-force attacks. Account lockout must be correctly configured and enabled to prevent these attacks.",
	// },

	// missing-or-broken-authorization
	// Rule{
	// 	Auxiliary:     []*regexp2.Regexp{regexp2.MustCompile(`^\s*using\s+Microsoft\.AspNetCore\.Mvc\s*;`, 0)},
	// 	And:           []*regexp2.Regexp{regexp2.MustCompile(`(?:\[\s*\w+(?:\s*\([^)]*\))?\s*\]\s*)*public\s+class\s+([A-Za-z_]\w*)\s*:\s*Controller\b\s*\{(?:[^{}]|\{[^{}]*\})*\}`, 0)},
	// 	NotAnd:        []*regexp2.Regexp{regexp2.MustCompile(`\[(?:AllowAnonymous|Authorize(?:\s*\([^)]*\))?)\]\s*public\s+class\s+([A-Za-z_]\w*)\s*:\s*Controller\b\s*\{(?:[^{}]|\{[^{}]*\})*\}`, 0)},
	// 	CWE:           "CWE-862",
	// 	AverageCVSS:   8,
	// 	Description:   "Controller class detected without explicit authorization attributes. This allows anonymous access by default and may violate least privilege principles.",
	// 	Recomendation: "Add [Authorize], [Authorize(Roles=..)], [Authorize(Policy=..)], or [AllowAnonymous] explicitly to controller classes to define access control.",
	// },

	// // open-directory-listing
	// Rule{
	// 	PatternInside: regexp2.MustCompile(`public\s+void\s+Configure\s*\([^)]*\bIApplicationBuilder\b[^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*\}`, 0),
	// 	ExactMatch:    regexp2.MustCompile(`[A-Za-z_]\w*\.UseDirectoryBrowser\s*\([^)]*\)|[A-Za-z_]\w*\.Services\.AddDirectoryBrowser\s*\([^)]*\);`, 0),
	// 	CWE:           "CWE-548",
	// 	AverageCVSS:   4.6,
	// 	Description:   "Open directory browsing is enabled, potentially exposing sensitive files to attackers. Directory listings should not be publicly accessible in production environments.",
	// 	Recomendation: "Remove AddDirectoryBrowser() and UseDirectoryBrowser() calls from production code. Use static file middleware with strict access rules, or explicitly serve only necessary files.",
	// },

	// razor-use-of-htmlstring
	// Rule{
	// 	// ExactMatch:    regexp2.MustCompile(`new\s+(?:[\w\.]+\.)?HtmlString\s*\((?![^)]*(?:HtmlEncode|Encode)\s*\()[^)]*\)|@\(new\s+(?:[\w\.]+\.)?HtmlString\s*\((?![^)]*(?:HtmlEncode|Encode)\s*\()[^)]*\)\)`, 0),
	// 	Or: []*regexp2.Regexp{
	// 		regexp2.MustCompile(`new\s+(?:[A-Za-z_][\w\.]*\.)?HtmlString\s*\([^)]*\)\s*\)`, 0),
	// 		regexp2.MustCompile(`@\s*\(\s*new\s+(?:[A-Za-z_][\w\.]*\.)?HtmlString\s*\([^)]*\)\s*\)*`, 0),
	// 	},
	// 	NotOr: []*regexp2.Regexp{
	// 		regexp2.MustCompile(`new\s+(?:[A-Za-z_][\w\.]*\.)?HtmlString\s*\(\s*(?:\w*\.)?(?:HtmlEncode|Encode)\s*\([^)]*\)\s*\)`, 0),
	// 		regexp2.MustCompile(`@\s*\(\s*new\s+(?:[A-Za-z_][\w\.]*\.)?HtmlString\s*\(\s*(?:\w*\.)?(?:HtmlEncode|Encode)\s*\([^)]*\)\s*\)\s*\)`, 0),
	// 	},
	// 	CWE:           "CWE-116",
	// 	AverageCVSS:   7,
	// 	Description:   "ASP.NET Core MVC provides an HtmlString class which isn't automatically encoded upon output. This should never be used in combination with untrusted input as this will expose an XSS vulnerability.",
	// 	Recomendation: "Avoid using HtmlString with untrusted input. Always sanitize or encode input with HtmlEncode/Encode before constructing an HtmlString.",
	// },

	// // missing-hsts-header pt 1
	// Rule{
	// 	PatternInside: regexp2.MustCompile(`(?s)(?:public\s+void\s+Configure\s*\([^)]*IApplicationBuilder[^)]*\)\s*\{[^}]*\}|public\s+void\s+ConfigureServices\s*\([^)]*IServiceCollection[^)]*\)\s*\{[^}]*\})`, 0),
	// 	ExactMatch:    regexp2.MustCompile(`\b(?:app\.Use|services\.Add)\w+\s*\(\s*\)`, 0),
	// 	CWE:           "CWE-346",
	// 	AverageCVSS:   3.0,
	// 	Title:         "Missing HSTS Header Configuration",
	// 	Severity:      "WARNING",
	// 	Description:   "The HSTS HTTP response security header is missing, allowing interaction	 and communication to be sent over the insecure HTTP protocol.",
	// 	Recomendation: "Add app.UseHsts() in the Configure method or services.AddHsts() in ConfigureServices to enforce HTTPS Strict Transport Security.",
	// 	NotAnd: []*regexp2.Regexp{
	// 		regexp2.MustCompile(`\b(?:app\.UseHsts|services\.AddHsts)\s*\(\s*\)`, 0),
	// 	},
	// },

	// // missing-hsts-header pt 2
	// Rule{
	// 	PatternInside: regexp2.MustCompile(`(?s)(?:public\s+void\s+Configure\s*\([^)]*IApplicationBuilder[^)]*\)\s*\{[^}]*\}|public\s+void\s+ConfigureServices\s*\([^)]*IServiceCollection[^)]*\)\s*\{[^}]*\})`, 0),
	// 	ExactMatch:    regexp2.MustCompile(`\b(?:app\.Use|services\.Add)\w+\s*\(\s*\)`, 0),
	// 	CWE:           "CWE-346",
	// 	AverageCVSS:   3.0,
	// 	Title:         "Missing HSTS Header Configuration",
	// 	Severity:      "WARNING",
	// 	Description:   "The HSTS HTTP response security header is missing, allowing interaction	 and communication to be sent over the insecure HTTP protocol.",
	// 	Recomendation: "Add app.UseHsts() in the Configure method or services.AddHsts() in ConfigureServices to enforce HTTPS Strict Transport Security.",
	// 	NotAnd: []*regexp2.Regexp{
	// 		regexp2.MustCompile(`\b(?:app\.UseHsts|services\.AddHsts)\s*\(\s*\)`, 0),
	// 	},
	// },

	// // stacktrace-disclosure
	// Rule{
	// 	PatternInside: regexp2.MustCompile(`(?s)public\s+void\s+Configure\s*\([^)]*IApplicationBuilder\s+[^,)]*,\s*[^)]*IWebHostEnvironment\s+[^)]*\)\s*\{[^}]*\}`, 0),
	// 	ExactMatch:    regexp2.MustCompile(`(?s)(if\s*\(\s*!env\.IsDevelopment\s*\(\s*\)\s*\{[^}]*\}).*?(if\s*\(\s*env\.EnvironmentName\s*==\s*"NotDevelopment"\s*\)\s*\{[^}]*\})`, 0),
	// 	CWE:           "CWE-209",
	// 	AverageCVSS:   3.0,
	// 	Title:         "Stacktrace Disclosure in Production Environment",
	// 	Severity:      "WARNING",
	// 	Description:   "UseDeveloperExceptionPage() is called outside of a Development environment check. Accidentally disclosing sensitive stack trace information in a production environment aids an attacker in reconnaissance and information gathering.",
	// 	Recomendation: "Wrap UseDeveloperExceptionPage() inside an environment check: if (env.IsDevelopment()) { app.UseDeveloperExceptionPage(); }. For inverted checks like !env.IsDevelopment() or wrong env names like 'NotDevelopment', remove the negation or correct the string to 'Development'.",
	// },

	// // insecure-newtonsoft-deserialization
	// Rule{
	// 	Or: []*regexp2.Regexp{
	// 		// Pattern 1: Inline JsonSerializerSettings with TypeNameHandling
	// 		regexp2.MustCompile(`JsonConvert\.DeserializeObject(?:<\w+>)?\s*\([^,]+,\s*new\s+JsonSerializerSettings\s*\{[^}]*TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)`, 0),
	// 		// Pattern 2: Direct assignment of TypeNameHandling to settings object
	// 		regexp2.MustCompile(`\w+\.TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)`, 0),
	// 		// Pattern 3: DefaultSettings with TypeNameHandling (multi-line support)
	// 		regexp2.MustCompile(`(?s)JsonConvert\.DefaultSettings\s*=\s*\(\s*\)\s*=>\s*.*?new\s+JsonSerializerSettings\s*\{[^}]*TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)`, 0),
	// 	},
	// 	CWE:           "CWE-502",
	// 	AverageCVSS:   7.5,
	// 	Title:         "Insecure Newtonsoft.Json Deserialization with TypeNameHandling",
	// 	Severity:      "WARNING",
	// 	Description:   "VULNERABLE: TypeNameHandling.All/Auto/Objects/Arrays allows untrusted input to control object types during deserialization, enabling arbitrary code execution. This line must be changed to use TypeNameHandling.None or implement a secure SerializationBinder.",
	// 	Recomendation: "CHANGE THIS LINE: Set TypeNameHandling to None and use a custom SerializationBinder to restrict deserialized types to a safe list. Example: TypeNameHandling = TypeNameHandling.None",
	// 	NotAnd: []*regexp2.Regexp{
	// 		// Only exclude if TypeNameHandling is set to None
	// 		regexp2.MustCompile(`TypeNameHandling\s*=\s*TypeNameHandling\.None`, 0),
	// 	},
	// },

	// // unsafe-path-combine - Only detect Path.Combine lines
	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`Path\.Combine\s*\([^,]+,\s*\w+\s*\)`, 0),
	// 	CWE:           "CWE-22",
	// 	AverageCVSS:   6.5,
	// 	Title:         "Unsafe Path.Combine Usage Leading to Path Traversal",
	// 	Severity:      "WARNING",
	// 	Description:   "VULNERABLE: User input is used directly in Path.Combine without sanitization, enabling path traversal attacks. This line must be changed to sanitize the input.",
	// 	Recomendation: "CHANGE THIS LINE: Sanitize user input with Path.GetFileName before Path.Combine, or validate Path.GetFileName(input) == input to prevent traversal.",
	// 	NotAnd: []*regexp2.Regexp{
	// 		// Exclude if input is sanitized with Path.GetFileName
	// 		regexp2.MustCompile(`Path\.GetFileName\s*\(\s*\w+\s*\)`, 0),
	// 		// Exclude if there's validation check
	// 		regexp2.MustCompile(`(?s)if\s*\([^)]*Path\.GetFileName\s*\(\s*\w+\s*\)\s*!=\s*\w+\s*\)`, 0),
	// 	},
	// },

	// // os-command-injection (strict, sample-specific)
	// Rule{
	// 	PatternInside: regexp2.MustCompile(`(?s)using\s+System\.Diagnostics;`, 0),
	// 	Or: []*regexp2.Regexp{
	// 		// 1) var process = Process.Start(command);
	// 		regexp2.MustCompile(`\bProcess\.Start\s*\(\s*command\s*\)`, 0),
	// 		// 2) var process = Process.Start(command, arguments|args);
	// 		regexp2.MustCompile(`\bProcess\.Start\s*\(\s*command\s*,\s*(?:arguments|args)\s*\)`, 0),
	// 		// 3) Process process = new Process(); process.StartInfo.FileName = command; ... process.Start();
	// 		regexp2.MustCompile(`(?s)Process\s+process\s*=\s*new\s+Process\s*\(\s*\)\s*;[\s\S]*?process\s*\.\s*StartInfo\s*\.\s*FileName\s*=\s*command\s*;[\s\S]*?process\s*\.\s*Start\s*\(\s*\)`, 0),
	// 		// 4) Process process = new Process(); ... FileName = command; Arguments = arguments|args; ... process.Start();
	// 		regexp2.MustCompile(`(?s)Process\s+process\s*=\s*new\s+Process\s*\(\s*\)\s*;[\s\S]*?process\s*\.\s*StartInfo\s*\.\s*FileName\s*=\s*command\s*;[\s\S]*?process\s*\.\s*StartInfo\s*\.\s*Arguments\s*=\s*(?:arguments|args)\s*;[\s\S]*?process\s*\.\s*Start\s*\(\s*\)`, 0),
	// 		// 5) ProcessStartInfo processStartInfo = new ProcessStartInfo(){ FileName = command [ , Arguments = ... ] }; var process = Process.Start(processStartInfo);
	// 		regexp2.MustCompile(`(?s)ProcessStartInfo\s+processStartInfo\s*=\s*new\s+ProcessStartInfo\s*\(\s*\)\s*\{[\s\S]*?FileName\s*=\s*command[\s\S]*?\}\s*;[\s\S]*?Process\.Start\s*\(\s*processStartInfo\s*\)`, 0),
	// 		// 6) ProcessStartInfo processStartInfo = new ProcessStartInfo(){ FileName = "constant", Arguments = args }; var process = Process.Start(processStartInfo);
	// 		regexp2.MustCompile(`(?s)ProcessStartInfo\s+processStartInfo\s*=\s*new\s+ProcessStartInfo\s*\(\s*\)\s*\{[\s\S]*?Arguments\s*=\s*args[\s\S]*?\}\s*;[\s\S]*?Process\.Start\s*\(\s*processStartInfo\s*\)`, 0),
	// 		// 7) Process process = new Process { StartInfo = new ProcessStartInfo { FileName = command, Arguments = args } }; process.Start();
	// 		regexp2.MustCompile(`(?s)Process\s+process\s*=\s*new\s+Process\s*\{[\s\S]*?StartInfo\s*=\s*new\s+ProcessStartInfo\s*\{[\s\S]*?FileName\s*=\s*command[\s\S]*?Arguments\s*=\s*args[\s\S]*?\}[\s\S]*?\}[\s\S]*?process\s*\.\s*Start\s*\(\s*\)`, 0),
	// 		// 8) Process process = new Process { StartInfo = new ProcessStartInfo { FileName = "constant", Arguments = arguments } }; process.Start();
	// 		regexp2.MustCompile(`(?s)Process\s+process\s*=\s*new\s+Process\s*\{[\s\S]*?StartInfo\s*=\s*new\s+ProcessStartInfo\s*\{[\s\S]*?Arguments\s*=\s*arguments[\s\S]*?\}[\s\S]*?\}[\s\S]*?process\s*\.\s*Start\s*\(\s*\)`, 0),
	// 		// 9) Process process = new Process { StartInfo = new ProcessStartInfo { FileName = command, Arguments = "constant" } }; process.Start();
	// 		regexp2.MustCompile(`(?s)Process\s+process\s*=\s*new\s+Process\s*\{[\s\S]*?StartInfo\s*=\s*new\s+ProcessStartInfo\s*\{[\s\S]*?FileName\s*=\s*command[\s\S]*?\}[\s\S]*?\}[\s\S]*?process\s*\.\s*Start\s*\(\s*\)`, 0),
	// 	},
	// 	CWE:           "CWE-78",
	// 	AverageCVSS:   8.0,
	// 	Title:         "OS Command Injection via Process.Start",
	// 	Severity:      "ERROR",
	// 	Description:   "The code constructs an OS command using externally-influenced input and executes it via Process.Start or ProcessStartInfo, which can lead to command injection.",
	// 	Recomendation: "Avoid passing user-controllable data to Process.Start or StartInfo.FileName/Arguments. Use allowlists and strong validation, or safer APIs.",
	// 	NotAnd: []*regexp2.Regexp{
	// 		// Exclude constant Process.Start(...) and Process.Start(..., ...)
	// 		regexp2.MustCompile(`\bProcess\.Start\s*\(\s*\"`, 0),
	// 		regexp2.MustCompile(`\bProcess\.Start\s*\(\s*\"[^\"]*\"\s*,`, 0),
	// 		// Exclude safe constant-only ProcessStartInfo { FileName = "constant" } before Process.Start(processStartInfo)
	// 		regexp2.MustCompile(`(?s)ProcessStartInfo\s+processStartInfo\s*=\s*new\s+ProcessStartInfo\s*\(\s*\)\s*\{\s*FileName\s*=\s*\"[^\"]*\"\s*\}\s*;[\s\S]*?Process\.Start\s*\(\s*processStartInfo\s*\)`, 0),
	// 		// Exclude safe constant-only inline Process { StartInfo = new ProcessStartInfo { FileName = "constant", Arguments = "constant" } } before process.Start();
	// 		regexp2.MustCompile(`(?s)Process\s+process\s*=\s*new\s+Process\s*\{[\s\S]*?StartInfo\s*=\s*new\s+ProcessStartInfo\s*\{[\s\S]*?FileName\s*=\s*\"[^\"]*\"[\s\S]*?Arguments\s*=\s*\"[^\"]*\"[\s\S]*?\}[\s\S]*?\}[\s\S]*?process\s*\.\s*Start\s*\(\s*\)`, 0),
	// 	},
	// },

	// // os-command-injection-args
	// Rule{
	// 	PatternInside: regexp2.MustCompile(`(?s)using\s+System\.Diagnostics;`, 0),
	// 	Or: []*regexp2.Regexp{
	// 		regexp2.MustCompile(`\bProcess\.Start\s*\(\s*command\s*,\s*arguments\s*\)`, 0),
	// 		regexp2.MustCompile(`\bProcess\.Start\s*\(\s*command\s*,\s*args\s*\)`, 0),
	// 	},
	// 	CWE:           "CWE-78",
	// 	AverageCVSS:   8.0,
	// 	Title:         "OS Command Injection via Process.Start with Arguments",
	// 	Severity:      "ERROR",
	// 	Description:   "The code constructs an OS command using externally-influenced input and executes it via Process.Start or ProcessStartInfo, which can lead to command injection.",
	// 	Recomendation: "Avoid passing user-controllable data to Process.Start or StartInfo.FileName/Arguments. Use allowlists and strong validation, or safer APIs.",
	// 	NotAnd: []*regexp2.Regexp{
	// 		// Exclude constant Process.Start(\"...\", \"...\")
	// 		regexp2.MustCompile(`\bProcess\.Start\s*\(\s*\"[^\"]*\"\s*,`, 0),
	// 	},
	// },

	// // os-command-injection-startinfo
	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`\bProcess\.Start\s*\(\s*[A-Za-z_]\w*\s*\)`, 0),
	// 	CWE:           "CWE-78",
	// 	AverageCVSS:   8.0,
	// 	Title:         "OS Command Injection via Process.Start with ProcessStartInfo",
	// 	Severity:      "ERROR",
	// 	Description:   "The code constructs an OS command using externally-influenced input and executes it via Process.Start or ProcessStartInfo, which can lead to command injection.",
	// 	Recomendation: "Avoid passing user-controllable data to Process.Start or StartInfo.FileName/Arguments. Use allowlists and strong validation, or safer APIs.",
	// 	NotAnd: []*regexp2.Regexp{
	// 		// Exclude exact safe case: only constant FileName in initializer before Process.Start(ps)
	// 		regexp2.MustCompile(`(?s)ProcessStartInfo\s+[A-Za-z_]\w*\s*=\s*new\s+ProcessStartInfo\s*\(\s*\)\s*\{\s*FileName\s*=\s*\"[^\"]*\"\s*\}\s*;\s*[^\S\n]*//\s*ok:[^\n]*\n\s*var\s+\w+\s*=\s*Process\.Start\s*\(\s*[A-Za-z_]\w*\s*\)`, 0),
	// 	},
	// },

	// // os-command-injection-process-start
	// Rule{
	// 	Or: []*regexp2.Regexp{
	// 		// StartInfo.FileName = command; ... process.Start()
	// 		regexp2.MustCompile(`(?s)StartInfo\s*\.\s*FileName\s*=\s*command\s*;[\s\S]*?\b[A-Za-z_]\w*\s*\.\s*Start\s*\(\s*\)`, 0),
	// 		// StartInfo.Arguments = (arguments|args); ... process.Start()
	// 		regexp2.MustCompile(`(?s)StartInfo\s*\.\s*Arguments\s*=\s*(?:arguments|args)\s*;[\s\S]*?\b[A-Za-z_]\w*\s*\.\s*Start\s*\(\s*\)`, 0),
	// 		// Inline new Process { StartInfo = new ProcessStartInfo { FileName = command[, Arguments = (arguments|args)] } }; ... Start()
	// 		regexp2.MustCompile(`(?s)new\s+Process\s*\(\s*\)\s*\{[\s\S]*?StartInfo\s*=\s*new\s+ProcessStartInfo\s*\(\s*\)\s*\{[\s\S]*?FileName\s*=\s*command[\s\S]*?\}[\s\S]*?\}[\s\S]*?\b[A-Za-z_]\w*\s*\.\s*Start\s*\(\s*\)`, 0),
	// 		// Inline new Process { StartInfo = new ProcessStartInfo { Arguments = (arguments|args) } }; ... Start()
	// 		regexp2.MustCompile(`(?s)new\s+Process\s*\(\s*\)\s*\{[\s\S]*?StartInfo\s*=\s*new\s+ProcessStartInfo\s*\(\s*\)\s*\{[\s\S]*?Arguments\s*=\s*(?:arguments|args)[\s\S]*?\}[\s\S]*?\}[\s\S]*?\b[A-Za-z_]\w*\s*\.\s*Start\s*\(\s*\)`, 0),
	// 	},
	// 	CWE:           "CWE-78",
	// 	AverageCVSS:   8.0,
	// 	Title:         "OS Command Injection via Process.Start()",
	// 	Severity:      "ERROR",
	// 	Description:   "The code constructs an OS command using externally-influenced input and executes it via Process.Start or ProcessStartInfo, which can lead to command injection.",
	// 	Recomendation: "Avoid passing user-controllable data to Process.Start or StartInfo.FileName/Arguments. Use allowlists and strong validation, or safer APIs.",
	// },
}
