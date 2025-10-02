package rule_test

import (
	"testing"

	"github.com/dlclark/regexp2"
	"github.com/insidersec/insider/engine"
	"github.com/insidersec/insider/rule"
	"github.com/stretchr/testify/assert"
)

func TestRuleMatch(t *testing.T) {
	testcases := []struct {
		name   string
		input  engine.InputFile
		rules  []engine.Rule
		issues int
	}{

		{
			name:   "Test $and with not or match",
			issues: 1,
			input: engine.InputFile{
				Content: `
		setJavaScriptEnabled(true)
		foo.addJavascriptInterface(bar)
				`,
			},
			rules: []engine.Rule{
				rule.Rule{
					And: []*regexp2.Regexp{
						regexp2.MustCompile(`setJavaScriptEnabled\(true\)`, 0),
						regexp2.MustCompile(`.addJavascriptInterface\(`, 0),
					},
					NotOr: []*regexp2.Regexp{
						regexp2.MustCompile(`execSQL\(|rawQuery\(`, 0),
						regexp2.MustCompile(`.addJavascriptInterface\(`, 0),
					},
				},
			},
		},
		{
			name:   "Test $and with not and match",
			issues: 2,
			input: engine.InputFile{
				Content: `
		setJavaScriptEnabled(true)
		foo.addJavascriptInterface(bar)
				`,
			},
			rules: []engine.Rule{
				rule.Rule{
					And: []*regexp2.Regexp{
						regexp2.MustCompile(`setJavaScriptEnabled\(true\)`, 0),
						regexp2.MustCompile(`.addJavascriptInterface\(`, 0),
					},
					NotAnd: []*regexp2.Regexp{
						regexp2.MustCompile(`execSQL\(|rawQuery\(`, 0),
						regexp2.MustCompile(`.addJavascriptInterface\(`, 0),
					},
				},
			},
		},
		{
			name:   "Test $and with not and match",
			issues: 1,
			input: engine.InputFile{
				Content: `
		setJavaScriptEnabled(true)
		foo.addJavascriptInterface(bar)
				`,
			},
			rules: []engine.Rule{
				rule.Rule{
					And: []*regexp2.Regexp{
						regexp2.MustCompile(`setJavaScriptEnabled\(true\)`, 0),
						regexp2.MustCompile(`.addJavascriptInterface\(`, 0),
					},
					NotAnd: []*regexp2.Regexp{regexp2.MustCompile(`.addJavascriptInterface\(`, 0)},
				},
			},
		},
		{
			name:   "Test $and not all match",
			issues: 0,
			input: engine.InputFile{
				Content: `
		setJavaScriptEnabled(true)
				`,
			},
			rules: []engine.Rule{
				rule.Rule{
					And: []*regexp2.Regexp{
						regexp2.MustCompile(`setJavaScriptEnabled\(true\)`, 0),
						regexp2.MustCompile(`.addJavascriptInterface\(`, 0),
					},
				},
			},
		},
		{
			name:   "Test is and match rule",
			issues: 2,
			input: engine.InputFile{
				Content: `
		setJavaScriptEnabled(true)
		foo.addJavascriptInterface(bar)
				`,
			},
			rules: []engine.Rule{
				rule.Rule{
					And: []*regexp2.Regexp{
						regexp2.MustCompile(`setJavaScriptEnabled\(true\)`, 0),
						regexp2.MustCompile(`.addJavascriptInterface\(`, 0),
					},
				},
			},
		},
		{
			name:   "Test or match rule",
			issues: 1,
			input: engine.InputFile{
				Content: `
		setJavaScriptEnabled(true)
				`,
			},
			rules: []engine.Rule{
				rule.Rule{
					Or: []*regexp2.Regexp{
						regexp2.MustCompile(`setJavaScriptEnabled\(true\)`, 0),
						regexp2.MustCompile(`.addJavascriptInterface\(`, 0),
					},
				},
			},
		},
		{
			name:   "Test exact match rule",
			issues: 1,
			input: engine.InputFile{
				Content: `
		let password = "secret";
				`,
			},
			rules: []engine.Rule{
				rule.Rule{
					ExactMatch: regexp2.MustCompile(`(password\s*=\s*['|"][\w\!\@\#\$\%\&\*\(\)\s]+['|"])`, 0),
				},
			},
		},
		{
			name:   "Test not and match rule skipping report",
			issues: 0,
			input: engine.InputFile{
				Name: "node_modules/foo/bar",
				Content: `
				PasswordValidator pwdv = new PasswordValidator
		{
		RequiredLength = 8,
		RequireNonLetterOrDigit = true,
		RequireDigit = true,
		};
				`,
			},
			rules: []engine.Rule{
				rule.Rule{
					ExactMatch: regexp2.MustCompile(`new\s+PasswordValidator(?:\n*.*)*`, 0),
					NotAnd:     []*regexp2.Regexp{regexp2.MustCompile(`RequireDigit\s+=\s+true,`, 0)},
				},
			},
		},
		{
			name:   "Test not and match rule",
			issues: 1,
			input: engine.InputFile{
				Name: "node_modules/foo/bar",
				Content: `
				PasswordValidator pwdv = new PasswordValidator
		{
		RequiredLength = 8,
		RequireNonLetterOrDigit = true,
		};
				`,
			},
			rules: []engine.Rule{
				rule.Rule{
					ExactMatch: regexp2.MustCompile(`new\s+PasswordValidator(?:\n*.*)*`, 0),
					NotAnd:     []*regexp2.Regexp{regexp2.MustCompile(`RequireDigit\s+=\s+true,`, 0)},
				},
			},
		},
		{
			name:   "Test not or match rule",
			issues: 0,
			input: engine.InputFile{
				Name: "node_modules/foo/bar",
				Content: `
				PasswordValidator pwdv = new PasswordValidator
		{
		RequiredLength = 8,
		RequireNonLetterOrDigit = true,
		RequireDigit = true,
		};
				`,
			},
			rules: []engine.Rule{
				rule.Rule{
					ExactMatch: regexp2.MustCompile(`new\s+PasswordValidator(?:\n*.*)*`, 0),
					NotOr: []*regexp2.Regexp{
						regexp2.MustCompile(`RequireDigit\s+=\s+true,`, 0),
						regexp2.MustCompile(`RequireUppercase\s+=\s+true,`, 0),
					},
				},
			},
		},
		{
			name:   "Test not match rule",
			issues: 0,
			input: engine.InputFile{
				Name: "node_modules/foo/bar",
				Content: `
				PasswordValidator pwdv = new PasswordValidator
		{
		RequiredLength = 8,
		RequireNonLetterOrDigit = true,
		RequireDigit = true,
		};
				`,
			},
			rules: []engine.Rule{
				rule.Rule{
					ExactMatch: regexp2.MustCompile(`new\s+PasswordValidator(?:\n*.*)*`, 0),
					NotMatch:   regexp2.MustCompile("{}", 0),
				},
			},
		},
		{
			name:   "Test not match rule false",
			issues: 1,
			input: engine.InputFile{
				Name: "node_modules/foo/bar",
				Content: `
				PasswordValidator pwdv = new PasswordValidator {};
				`,
			},
			rules: []engine.Rule{
				rule.Rule{
					ExactMatch: regexp2.MustCompile(`new\s+PasswordValidator(?:\n*.*)*`, 0),
					NotMatch:   regexp2.MustCompile("{}", 0),
				},
			},
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			issues, err := engine.AnalyzeFile(tt.input, tt.rules)

			assert.Nil(t, err, "Expected nil error to analyze file")
			assert.Equal(t, tt.issues, len(issues))
		})
	}

}

func TestRegexIsNotMatch(t *testing.T) {
	testcases := []struct {
		name   string
		rule   rule.Rule
		result bool
	}{
		{
			name: "Test IsNotMatch return true",
			rule: rule.Rule{
				NotMatch: regexp2.MustCompile("regex-1", 0),
			},
			result: true,
		},
		{
			name:   "Test IsNotMatch return false",
			rule:   rule.Rule{},
			result: false,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.rule.IsNotMatch()
			assert.Equal(t, tt.result, r, "Expected equal results")
		})
	}

}

func TestRegexIsOrMatch(t *testing.T) {
	testcases := []struct {
		name   string
		rule   rule.Rule
		result bool
	}{
		{
			name: "Test IsNotMatch return true",
			rule: rule.Rule{
				Or: []*regexp2.Regexp{regexp2.MustCompile("regex-1", 0), regexp2.MustCompile("regex-2", 0)},
			},
			result: true,
		},
		{
			name:   "Test IsNotMatch return false",
			rule:   rule.Rule{},
			result: false,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.rule.IsOrMatch()
			assert.Equal(t, tt.result, r, "Expected equal results")
		})
	}

}

func TestRegexIsAndMatch(t *testing.T) {
	testcases := []struct {
		name   string
		rule   rule.Rule
		result bool
	}{
		{
			name: "Test IsAndMatch return true",
			rule: rule.Rule{
				And: []*regexp2.Regexp{regexp2.MustCompile("regex-1", 0), regexp2.MustCompile("regex-2", 0)},
			},
			result: true,
		},
		{
			name:   "Test IsAndMatch return false",
			rule:   rule.Rule{},
			result: false,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.rule.IsAndMatch()
			assert.Equal(t, tt.result, r, "Expected equal results")
		})
	}

}

func TestRegexHaveNotAndClause(t *testing.T) {
	testcases := []struct {
		name   string
		rule   rule.Rule
		result bool
	}{
		{
			name: "Test HaveNotAndClause return true",
			rule: rule.Rule{
				NotAnd: []*regexp2.Regexp{regexp2.MustCompile("regex-1", 0), regexp2.MustCompile("regex-2", 0)},
			},
			result: true,
		},
		{
			name:   "Test HaveNotAndClause return false",
			rule:   rule.Rule{},
			result: false,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.rule.HaveNotAndClause()
			assert.Equal(t, tt.result, r, "Expected equal results")
		})
	}

}

func TestRegexHaveNotORClause(t *testing.T) {
	testcases := []struct {
		name   string
		rule   rule.Rule
		result bool
	}{
		{
			name: "Test HaveNotORClause return true",
			rule: rule.Rule{
				NotOr: []*regexp2.Regexp{regexp2.MustCompile("regex-1", 0), regexp2.MustCompile("regex-2", 0)},
			},
			result: true,
		},
		{
			name:   "Test HaveNotORClause return false",
			rule:   rule.Rule{},
			result: false,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.rule.HaveNotORClause()
			assert.Equal(t, tt.result, r, "Expected equal results")
		})
	}

}
