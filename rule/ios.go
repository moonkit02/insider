package rule

import (
	"github.com/insidersec/insider/engine"
)

var IosRules []engine.Rule = []engine.Rule{

	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`NSTemporaryDirectory\(\),`, 0),
	// 	CWE:           "CWE-22",
	// 	AverageCVSS:   7.5,
	// 	Description:   `User use in "NSTemporaryDirectory ()" is unreliable, it can result in vulnerabilities in the directory.`,
	// 	Recomendation: "",
	// },

	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`\w+.withUnsafeBytes\s*{.*`, 0),
	// 	CWE:           "CWE-789",
	// 	AverageCVSS:   4,
	// 	Description:   "Using this implementation of '.withUnsafeBytes' can lead to the compiler's decision to use unsafe APIs, such as _malloc and _strcpy, as the method calls closing with an UnsafeRawBufferPointer.",
	// 	Recomendation: "Whenever possible, avoid using buffers or memory pointers that do not have a valid size.",
	// },

	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`canAuthenticateAgainstProtectionSpace|continueWithoutCredentialForAuthenticationChallenge|kCFStreamSSLAllowsExpiredCertificates|kCFStreamSSLAllowsAnyRoot|kCFStreamSSLAllowsExpiredRoots|validatesSecureCertificate\s*=\s*(no|NO)|allowInvalidCertificates\s*=\s*(YES|yes)`, 0),
	// 	CWE:           "CWE-295",
	// 	AverageCVSS:   7.4,
	// 	Description:   "The application allows self-signed or invalid SSL certificates. The application is vulnerable to MITM (Man-In-The-Middle) attacks.",
	// 	Recomendation: "Certificates must be carefully managed and verified to ensure that data is encrypted with the intended owner's public key.",
	// },

	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`setAllowsAnyHTTPSCertificate:\s*YES|allowsAnyHTTPSCertificateForHost|loadingUnvalidatedHTTPSPage\s*=\s*(YES|yes)`, 0),
	// 	CWE:           "CWE-295",
	// 	AverageCVSS:   7.4,
	// 	Description:   "The in-app UIWebView ignores SSL errors and accepts any SSL certificate. The application is vulnerable to attacks from MITM (Man-In-The-Middle).",
	// 	Recomendation: "Certificates must be carefully managed and verified to ensure that data is encrypted with the intended owner's public key.",
	// },

	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`kSecAttrAccessibleWhenUnlocked|kSecAttrAccessibleAfterFirstUnlock|SecItemAdd|SecItemUpdate|NSDataWritingFileProtectionComplete`, 0),
	// 	CWE:           "CWE-695",
	// 	AverageCVSS:   5,
	// 	Description:   "Local File I/O Operations.",
	// 	Recomendation: "",
	// },

	// Rule{
	// 	And: []*regexp2.Regexp{regexp2.MustCompile(`loadRequest`, 0), regexp2.MustCompile(`WebView`)}, NotAnd: []*regexp2.Regexp{regexp2.MustCompile(`WebView`)},
	// 	CWE:           "CWE-749",
	// 	AverageCVSS:   5,
	// 	Description:   "WebView Load Request.",
	// 	Recomendation: "",
	// },

	// Rule{
	// 	And: []*regexp2.Regexp{regexp2.MustCompile(`NSHTTPCookieStorage`, 0), regexp2.MustCompile(`sharedHTTPCookieStorage`)}, NotAnd: []*regexp2.Regexp{regexp2.MustCompile(`NSHTTPCookieStorage`)},
	// 	CWE:           "CWE-539",
	// 	AverageCVSS:   5.3,
	// 	Description:   "Cookie Storage.",
	// 	Recomendation: "",
	// },

	// Rule{
	// 	And: []*regexp2.Regexp{regexp2.MustCompile(`CommonDigest.h`, 0), regexp2.MustCompile(`CC_MD5`)}, NotAnd: []*regexp2.Regexp{regexp2.MustCompile(`CommonDigest.h`)},
	// 	CWE:           "CWE-327",
	// 	AverageCVSS:   7.4,
	// 	Description:   "MD5 is a weak hash, which can generate repeated hashes.",
	// 	Recomendation: "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete.",
	// },

	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`UIPasteboard.`, 0),
	// 	CWE:           "CWE-200",
	// 	AverageCVSS:   9.8,
	// 	Description:   "The application copies data to the UIPasteboard. Confidential data must not be copied to the UIPasteboard, as other applications can access it.",
	// 	Recomendation: "",
	// },

	// Rule{
	// 	And: []*regexp2.Regexp{regexp2.MustCompile(`loadHTMLString\(`, 0), regexp2.MustCompile(`WKWebView`)}, NotAnd: []*regexp2.Regexp{regexp2.MustCompile(`WKWebView`)},
	// 	CWE:           "CWE-95",
	// 	AverageCVSS:   8.8,
	// 	Description:   "User input not sanitized in 'loadHTMLString' can result in an injection of JavaScript in the context of your application, allowing access to private data.",
	// 	Recomendation: "",
	// },

	// Rule{
	// 	Or:            []*regexp2.Regexp{regexp2.MustCompile(`(?i)SHA1\(`, 0), regexp2.MustCompile(`CC_SHA1\(`)},
	// 	CWE:           "CWE-327",
	// 	AverageCVSS:   5.9,
	// 	Description:   "SHA1 is a weak hash, which can generate repeated hashes.",
	// 	Recomendation: "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete.",
	// },

	// Rule{
	// 	And:           []*regexp2.Regexp{regexp2.MustCompile(`kCCOptionECBMode`, 0), regexp2.MustCompile(`kCCAlgorithmAES`)},
	// 	CWE:           "CWE-327",
	// 	AverageCVSS:   5.9,
	// 	Description:   "The application uses ECB mode in the encryption algorithm. It is known that the ECB mode is weak, as it results in the same ciphertext for identical blocks of plain text.",
	// 	Recomendation: "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete.",
	// },

	// Rule{
	// 	And: []*regexp2.Regexp{regexp2.MustCompile(`mach/mach_init.h`, 0), regexp2.MustCompile(`MACH_PORT_VALID|mach_task_self\(\)`)}, NotAnd: []*regexp2.Regexp{regexp2.MustCompile(`mach/mach_init.h`)},
	// 	CWE:           "CWE-215",
	// 	AverageCVSS:   5,
	// 	Description:   "The application has anti-debugger using Mach Exception Ports.",
	// 	Recomendation: "",
	// },

	// Rule{
	// 	Or:            []*regexp2.Regexp{regexp2.MustCompile(`CC_MD4_Init|CC_MD4_Update|CC_MD4_Final|CC_MD4|MD4_Init`, 0), regexp2.MustCompile(`MD4_Update|MD4_Final|CC_MD5_Init|CC_MD5_Update|CC_MD5_Final|CC_MD5|MD5_Init`, 0), regexp2.MustCompile(`MD5_Update|MD5_Final|MD5Init|MD5Update|MD5Final`)},
	// 	CWE:           "CWE-327",
	// 	AverageCVSS:   5.9,
	// 	Description:   "The app is using weak encryption APIs and / or that are known to have hash conflicts.",
	// 	Recomendation: "",
	// },

	// Rule{
	// 	Or:            []*regexp2.Regexp{regexp2.MustCompile(`(?i)MD2\(`, 0), regexp2.MustCompile(`CC_MD2\(`)},
	// 	CWE:           "CWE-327",
	// 	AverageCVSS:   5.9,
	// 	Description:   "MD2 is a weak hash known to have hash collisions.",
	// 	Recomendation: "",
	// },

	// Rule{
	// 	Or:            []*regexp2.Regexp{regexp2.MustCompile(`(?i)MD6\(`, 0), regexp2.MustCompile(`CC_MD6\(`)},
	// 	CWE:           "CWE-327",
	// 	AverageCVSS:   5.9,
	// 	Description:   "MD6 is a weak hash known to have hash collisions.",
	// 	Recomendation: "",
	// },

	// Rule{
	// 	Or:            []*regexp2.Regexp{regexp2.MustCompile(`/Applications/Cydia.app`, 0), regexp2.MustCompile(`/Library/MobileSubstrate/MobileSubstrate.dylib`, 0), regexp2.MustCompile(`/usr/sbin/sshd`, 0), regexp2.MustCompile(`/etc/apt`, 0), regexp2.MustCompile(`cydia://`, 0), regexp2.MustCompile(`/var/lib/cydia`, 0), regexp2.MustCompile(`/Applications/FakeCarrier.app`, 0), regexp2.MustCompile(`/Applications/Icy.app`, 0), regexp2.MustCompile(`/Applications/IntelliScreen.app`, 0), regexp2.MustCompile(`/Applications/SBSettings.app`, 0), regexp2.MustCompile(`/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist`, 0), regexp2.MustCompile(`/System/Library/LaunchDaemons/com.ikey.bbot.plist`, 0), regexp2.MustCompile(`/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist`, 0), regexp2.MustCompile(`/etc/ssh/sshd_config`, 0), regexp2.MustCompile(`/private/var/tmp/cydia.log`, 0), regexp2.MustCompile(`/usr/libexec/ssh-keysign`, 0), regexp2.MustCompile(`/Applications/MxTube.app`, 0), regexp2.MustCompile(`/Applications/RockApp.app`, 0), regexp2.MustCompile(`/Applications/WinterBoard.app`, 0), regexp2.MustCompile(`/Applications/blackra1n.app`, 0), regexp2.MustCompile(`/Library/MobileSubstrate/DynamicLibraries/Veency.plist`, 0), regexp2.MustCompile(`/private/var/lib/apt`, 0), regexp2.MustCompile(`/private/var/lib/cydia`, 0), regexp2.MustCompile(`/private/var/mobile/Library/SBSettings/Themes`, 0), regexp2.MustCompile(`/private/var/stash`, 0), regexp2.MustCompile(`/usr/bin/sshd`, 0), regexp2.MustCompile(`/usr/libexec/sftp-server`, 0), regexp2.MustCompile(`/var/cache/apt`, 0), regexp2.MustCompile(`/var/lib/apt`, 0), regexp2.MustCompile(`/usr/sbin/frida-server`, 0), regexp2.MustCompile(`/usr/bin/cycript`, 0), regexp2.MustCompile(`/usr/local/bin/cycript`, 0), regexp2.MustCompile(`/usr/lib/libcycript.dylib`, 0), regexp2.MustCompile(`frida-server`)},
	// 	CWE:           "CWE-693",
	// 	AverageCVSS:   0,
	// 	Description:   "The application may contain Jailbreak detection mechanisms.",
	// 	Recomendation: "",
	// },

	// Rule{
	// 	And:           []*regexp2.Regexp{regexp2.MustCompile(`UIPasteboard\(`, 0), regexp2.MustCompile(`.generalPasteboard`)},
	// 	CWE:           "CWE-200",
	// 	AverageCVSS:   5,
	// 	Description:   "Set or Read Clipboard",
	// 	Recomendation: "",
	// },

	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`UIPasteboardChangedNotification|generalPasteboard\]\.string`, 0),
	// 	CWE:           " CWE-200",
	// 	AverageCVSS:   5,
	// 	Description:   "The application allows you to list the changes on the Clipboard. Some malware also lists changes to the Clipboard.",
	// 	Recomendation: "",
	// },

	// Rule{
	// 	Or:            []*regexp2.Regexp{regexp2.MustCompile(`sqlite3_exec`, 0), regexp2.MustCompile(`sqlite3_finalize`)},
	// 	CWE:           "CWE-922",
	// 	AverageCVSS:   5.5,
	// 	Description:   "The application is using SQLite. Confidential information must be encrypted",
	// 	Recomendation: "",
	// },

	// Rule{
	// 	And: []*regexp2.Regexp{regexp2.MustCompile(`NSLog\(|NSAssert\(|fprintf\(|fprintf\(|Logging\(`)}, NotAnd: []*regexp2.Regexp{regexp2.MustCompile(`\*`)},
	// 	CWE:           "CWE-532",
	// 	AverageCVSS:   7.5,
	// 	Description:   "The binary can use the NSLog function for logging. Confidential information should never be recorded.",
	// 	Recomendation: "Prevent sensitive data from being logged into production.",
	// },

	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`(?i)\.noFileProtection`, 0),
	// 	CWE:           "CWE-311",
	// 	AverageCVSS:   4.3,
	// 	Description:   "The file has no special protections associated with it.",
	// 	Recomendation: "",
	// },

	// Rule{
	// 	And:           []*regexp2.Regexp{regexp2.MustCompile(`\.TLSMinimumSupportedProtocolVersion`, 0), regexp2.MustCompile(`tls_protocol_version_t\.TLSv10|tls_protocol_version_t\.TLSv11`)},
	// 	CWE:           "CWE-757",
	// 	AverageCVSS:   7.5,
	// 	Description:   "TLS 1.3 should be used. Detected old version.",
	// 	Recomendation: "",
	// },

	// Rule{
	// 	And:           []*regexp2.Regexp{regexp2.MustCompile(`\.TLSMinimumSupportedProtocolVersion`, 0), regexp2.MustCompile(`tls_protocol_version_t\.TLSv12`)},
	// 	CWE:           "",
	// 	AverageCVSS:   0,
	// 	Description:   "TLS 1.3 should be used. Detected old version - TLS 1.2.",
	// 	Recomendation: "",
	// },

	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`strcpy\(|memcpy\(|strcat\(|strncat\(|strncpy\(|sprintf\(|vsprintf\(|gets\(`, 0),
	// 	CWE:           "CWE-676",
	// 	AverageCVSS:   2.2,
	// 	Description:   "The application may contain prohibited APIs. These APIs are insecure and should not be used.",
	// 	Recomendation: "Avoid using unsafe API (s) and never rely on data entered by the user, always sanitize the data entered.",
	// },

	// Rule{
	// 	ExactMatch:    regexp2.MustCompile(`NSFileProtectionNone`, 0),
	// 	CWE:           "CWE-311",
	// 	AverageCVSS:   4.3,
	// 	Description:   "The file has no special protections associated with it.",
	// 	Recomendation: "",
	// },
}
