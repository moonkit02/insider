package rule

import (
	"github.com/dlclark/regexp2"
	"github.com/insidersec/insider/engine"
)

var CoreRules []engine.Rule = []engine.Rule{

	Rule{
		ExactMatch:    regexp2.MustCompile(`\d{2,3}\.\d{2,3}\.\d{2,3}\.\d{2,3}`, 0),
		CWE:           "CWE-200",
		AverageCVSS:   7,
		Description:   "Credentials must not be stored in the code, an attacker could decompile the application and obtain the credential.",
		Recomendation: "There are ‘Secrets Management’ solutions that can be used to store secrets.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(?i)aws(.{0,20})?(?-i)['"][0-9a-zA-Z/+]{40}['"]`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(chave\s*=\s*['|"]\w+['|"])|(\w*[tT]oken\s*=\s*['|"]\w+['|"])|(\w*[aA][uU][tT][hH]\w*\s*=\s*['|"]\w+['|"])|(username\s*=\s*['|"]\w+['|"])|(secret\s*=\s*['|"]\w+['|"])|(chave\s*=\s*['|"]\w+['|"])`, 0),
		NotOr:         []*regexp2.Regexp{regexp2.MustCompile(`(?mi)public.*[tT]oken`, 0), regexp2.MustCompile(`(?mi)public.*[kK]ey`, 0)},
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the Git code or repository. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`-----BEGIN PRIVATE KEY-----`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`AAAA(?:[0-9A-Za-z+/])+={0,3}(?:.+@.+)`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(?i)(facebook|fb)(.{0,20})?(?-i)['"][0-9a-f]{32}['"]`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Facebook Secret Key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(?i)(facebook|fb)(.{0,20})?['"][0-9]{13,17}['"]`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Facebook Client ID. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Facebook Access Token. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(?i)twitter(.{0,20})?['"][0-9a-z]{35,44}['"]`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Twitter Secret Key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(?i)twitter(.{0,20})?['"][0-9a-z]{18,25}['"]`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Twitter Client ID. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(?i)github(.{0,20})?(?-i)['"][0-9a-zA-Z]{35,40}['"]`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "GitHub URL. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(?i)linkedin(.{0,20})?(?-i)['"][0-9a-z]{12}['"]`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "LinkedIn Client ID. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(?i)linkedin(.{0,20})?['"][0-9a-z]{16}['"]`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "LinkedIn Secret Key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`xox[baprs]-([0-9a-zA-Z]{10,48})?`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Slack API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`-----BEGIN EC PRIVATE KEY-----`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "EC key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(?i)api_key(.{0,20})?['"][0-9a-zA-Z]{32,45}['"]`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Generic API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`AIza[0-9A-Za-z\-_]{35}`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Google API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(?i)(google|gcp|youtube|drive|yt)(.{0,20})?['"][AIza[0-9a-z\-_]{35}]['"]`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Google Cloud Platform API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(?i)(google|gcp|auth)(.{0,20})?['"][0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com['"]`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Google OAuth. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`ya29\.[0-9A-Za-z\-_]+`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Google OAuth Access Token. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(?i)heroku(.{0,20})?['"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Heroku API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(?i)(mailchimp|mc)(.{0,20})?['"][0-9a-f]{32}-us[0-9]{1,2}['"]`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "MailChimp API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(?i)(mailgun|mg)(.{0,20})?['"][0-9a-z]{32}['"]`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Mailgun API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}/?.?`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Password in URL. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "PayPal Braintree Access Token. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`sk_live_[0-9a-z]{32}`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Picatic API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(?i)stripe(.{0,20})?['"][sk|rk]_live_[0-9a-zA-Z]{24}`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Stripe API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`sq0atp-[0-9A-Za-z\-_]{22}`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Square access token. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Square OAuth secret. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(?i)twilio(.{0,20})?['"][0-9a-f]{32}['"]`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "Twilio API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`, 0),
		CWE:           "CWE-918",
		AverageCVSS:   7.5,
		Description:   "Incoming Webhooks from  Slack application ",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`(password\s*=\s*['|"](.*)+['|"])|(pass\s*=\s*['|"](.*)+['|"]\s)|(pwd\s*=\s*['|"](.*)+['|"]\s)|(passwd\s*=\s*['|"](.*)+['|"]\s)|(senha\s*=\s*['|"](.*)+['|"])`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the Git code or repository. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},

	Rule{
		ExactMatch:    regexp2.MustCompile(`-----BEGIN CERTIFICATE-----`, 0),
		CWE:           "CWE-312",
		AverageCVSS:   7.4,
		Description:   "File contains sensitive information written directly, such as usernames, passwords, keys, etc.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},
}
