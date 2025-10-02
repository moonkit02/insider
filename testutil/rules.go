package testutil

import (
	"context"
	"testing"

	"github.com/dlclark/regexp2"
	"github.com/insidersec/insider/engine"
	"github.com/insidersec/insider/rule"
)

type fakeRuleBuilder struct {
	t testing.TB
}

func (b fakeRuleBuilder) Build(ctx context.Context, techs ...engine.Language) ([]engine.Rule, error) {
	return NewTestRules(b.t), nil
}

func NewTestRuleBuilder(t testing.TB) engine.RuleBuilder {
	return fakeRuleBuilder{
		t: t,
	}
}

func NewTestRules(t testing.TB) []engine.Rule {
	return []engine.Rule{
		rule.Rule{
			ExactMatch:  regexp2.MustCompile(`(password\s*=\s*['|"][\w\!\@\#\$\%\&\*\(\)\s]+['|"])`, 0),
			Description: "foo bar baz",
			AverageCVSS: 7,
			CWE:         "CWE-312",
		},
		rule.Rule{
			Or:          []*regexp2.Regexp{regexp2.MustCompile("_srand", 0), regexp2.MustCompile("_random", 0)},
			Description: "foo bar baz",
			AverageCVSS: 4.5,
			CWE:         "CWE-338",
		},
	}
}
