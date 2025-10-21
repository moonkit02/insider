package rule

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/insidersec/insider/engine"
)

type excludeFn func(content string, rule Rule) (bool, error)

type Rule struct {
	CWE           string
	AverageCVSS   float64
	Title         string
	Severity      string
	Description   string
	Recomendation string

	Auxiliary []*regexp2.Regexp

	PatternInside *regexp2.Regexp

	PatternNotInside *regexp2.Regexp
	// And evaluate that each expresion on list is true
	And []*regexp2.Regexp

	// Or evaluate that at least one expresion is true
	Or []*regexp2.Regexp

	// ExactMatch evaluate that expresion is true
	ExactMatch *regexp2.Regexp

	// NotAnd evaluate with ExactMatch, AndExpressions and OrExpressions .
	// If all expresions on list is true the match statement turn to false
	NotAnd []*regexp2.Regexp

	// NotOr evaluate with ExactMatch, AndExpressions and OrExpressions.
	// If at least one expresion on list is true the match turn to false
	NotOr []*regexp2.Regexp

	// NotMatch evaluate that expresion is false
	NotMatch *regexp2.Regexp
}

func (r Rule) Match(inputFile engine.InputFile) ([]engine.Issue, error) {
	issues := make([]engine.Issue, 0)
	info := engine.Info{
		CWE:           r.CWE,
		Title:         r.Title,
		Severity:      r.Severity,
		CVSS:          r.AverageCVSS,
		Description:   r.Description,
		Recomendation: r.Recomendation,
	}

	if r.HaveAuxiliary() {
		hasAux, err := evaluateAuxiliary(inputFile.Content, r)
		if err != nil {
			return nil, err
		}
		if !hasAux {
			return []engine.Issue{}, nil
		}
	}

	// Get PatternInside line ranges once for all rule evaluations
	lineRanges, _ := evaluatePatternInside(inputFile.Content, r)

	notLineRanges, _ := evaluatePatternNotInside(inputFile.Content, r)

	if r.IsAndMatch() {
		i, err := runAndRule(inputFile, r, info, lineRanges, notLineRanges)
		if err != nil {
			return nil, fmt.Errorf("failed to run and rule: %w", err)
		}
		issues = append(issues, i...)
	} else if r.IsOrMatch() {
		i, err := runOrRule(inputFile, r, info, lineRanges, notLineRanges)
		if err != nil {
			return nil, fmt.Errorf("failed to run or rule: %w", err)
		}
		issues = append(issues, i...)
	} else if r.IsNotMatch() {
		i, err := runNotRule(inputFile, r.NotMatch, info, r, lineRanges, notLineRanges)
		if err != nil {
			return nil, fmt.Errorf("failed to run not rule: %w", err)
		}
		issues = append(issues, i...)
	} else {
		i, err := runSingleRule(inputFile, r.ExactMatch, info, r, lineRanges, notLineRanges)
		if err != nil {
			return nil, fmt.Errorf("failed to run single rule: %w", err)
		}
		issues = append(issues, i...)
	}
	return issues, nil
}

func (r Rule) IsMatch() bool {
	return r.ExactMatch != nil
}

func (r Rule) HaveNotORClause() bool {
	return len(r.NotOr) != 0
}

func (r Rule) HaveNotAndClause() bool {
	return len(r.NotAnd) != 0
}

func (r Rule) IsAndMatch() bool {
	return len(r.And) != 0
}

func (r Rule) IsOrMatch() bool {
	return len(r.Or) != 0
}

func (r Rule) IsNotMatch() bool {
	return r.NotMatch != nil
}

func (r Rule) HaveAuxiliary() bool {
	return len(r.Auxiliary) != 0
}

func (r Rule) HavePatternInside() bool {
	return r.PatternInside != nil
}

func (r Rule) HavePatternNotInside() bool {
	return r.PatternNotInside != nil
}

func evaluateAuxiliary(content string, rule Rule) (bool, error) {
	for _, expr := range rule.Auxiliary {
		if expr == nil {
			continue
		}
		another_expr, _ := regexp.Compile(expr.String())
		results := another_expr.FindAllStringIndex(content, -1)
		if len(results) == 0 {
			return false, nil
		}
	}
	return true, nil
}

func evaluatePatternInside(content string, rule Rule) ([]string, error) {
	if !rule.HavePatternInside() {
		return nil, nil
	}
	another_pattern, _ := regexp.Compile(rule.PatternInside.String())
	results := another_pattern.FindAllStringIndex(content, -1)
	if len(results) == 0 {
		return nil, nil
	}

	// Convert character indices to line number ranges
	lines := strings.Split(content, "\n")
	lineRanges := make([]string, 0, len(results))
	for _, result := range results {
		startLine := getLineNumber(result[0], lines) + 1 // 1-based line numbers
		endLine := getLineNumber(result[1]-1, lines) + 1 // Use end-1 to get last line of match
		if startLine <= endLine {
			lineRanges = append(lineRanges, fmt.Sprintf("%d,%d", startLine, endLine))
		}
	}

	if len(lineRanges) == 0 {
		return nil, nil
	}

	return lineRanges, nil
}

func evaluatePatternNotInside(content string, rule Rule) ([]string, error) {
	if !rule.HavePatternNotInside() {
		return nil, nil
	}
	another_pattern, _ := regexp.Compile(rule.PatternNotInside.String())
	results := another_pattern.FindAllStringIndex(content, -1)
	if len(results) == 0 {
		return nil, nil
	}

	// Convert character indices to line number ranges
	lines := strings.Split(content, "\n")
	lineRanges := make([]string, 0, len(results))
	for _, result := range results {
		startLine := getLineNumber(result[0], lines) + 1 // 1-based line numbers
		endLine := getLineNumber(result[1]-1, lines) + 1 // Use end-1 to get last line of match
		if startLine <= endLine {
			lineRanges = append(lineRanges, fmt.Sprintf("%d,%d", startLine, endLine))
		}
	}

	if len(lineRanges) == 0 {
		return nil, nil
	}

	return lineRanges, nil
}

// getLineNumber returns the 0-based line number for a given character index
func getLineNumber(index int, lines []string) int {
	// lineNum := 0
	charCount := 0
	for i, line := range lines {
		charCount += len(line) + 1 // +1 for newline
		if charCount > index {
			return i
		}
	}
	return len(lines) - 1 // Fallback to last line
}

func evaluateNotANDClause(content string, rule Rule) (bool, error) {
	finds := 0

	for _, expr := range rule.NotAnd {
		another_expr, err := regexp.Compile(expr.String())
		if err != nil {
			return false, fmt.Errorf("failed to compile NotAnd pattern: %w", err)
		}
		results := another_expr.FindAllStringIndex(content, -1)
		if results != nil {
			finds++
		}
	}

	return len(rule.NotAnd) != finds, nil
}

func evaluateNotORClause(content string, rule Rule) (bool, error) {
	for _, expr := range rule.NotOr {
		if found, err := expr.MatchString(content); err != nil {
			return false, fmt.Errorf("failed to match NotOr pattern: %w", err)
		} else if found {
			return false, nil
		}
	}
	return true, nil
}

func evaluateNotClauses(fileContent string, rule Rule) (bool, error) {
	if rule.HaveNotAndClause() {
		return evaluateNotANDClause(fileContent, rule)
	} else if rule.HaveNotORClause() {
		return evaluateNotORClause(fileContent, rule)
	}
	return true, nil
}

func runNotRule(inputFile engine.InputFile, expr *regexp2.Regexp, info engine.Info, rule Rule, lineRanges []string, notLineRanges []string) ([]engine.Issue, error) {
	issues := make([]engine.Issue, 0)

	another_expr, err := regexp.Compile(expr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to compile NotMatch pattern: %w", err)
	}
	results := another_expr.FindAllStringSubmatchIndex(inputFile.Content, -1)
	if results == nil {
		return []engine.Issue{}, nil
	}

	for _, result := range results {
		evidence := inputFile.CollectEvidenceSample(result[0])
		if rule.HavePatternInside() && !isLineWithinRanges(evidence.Line, lineRanges) {
			continue
		}

		if rule.HavePatternNotInside() && isLineWithinRanges(evidence.Line, notLineRanges) {
			continue
		}

		if isCommentOrString(inputFile.Content, result[0]) {
			continue
		}

		i := engine.Issue{
			Info:            info,
			Line:            evidence.Line,
			Column:          evidence.Column,
			Sample:          evidence.Sample,
			VulnerabilityID: evidence.UniqueHash,
			Content:         inputFile.Content[result[0]:result[1]],
		}

		issues = append(issues, i)
	}

	return issues, nil
}

func runRule(inputFile engine.InputFile, expr *regexp2.Regexp, info engine.Info, rule Rule, fn excludeFn, lineRanges []string, notLineRanges []string) ([]engine.Issue, error) {
	issues := make([]engine.Issue, 0)
	another_expr, err := regexp.Compile(expr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to compile pattern: %w", err)
	}
	results := another_expr.FindAllStringIndex(inputFile.Content, -1)
	if results == nil {
		return []engine.Issue{}, nil
	}

	for _, result := range results {
		evidence := inputFile.CollectEvidenceSample(result[0])

		if rule.HavePatternInside() {
			if len(lineRanges) == 0 || !isLineWithinRanges(evidence.Line, lineRanges) {
				continue
			}
		}

		if rule.HavePatternNotInside() {

			if len(notLineRanges) == 0 || isLineWithinRanges(evidence.Line, notLineRanges) {
				continue
			}
		}

		if isCommentOrString(inputFile.Content, result[0]) {
			continue
		}

		foundedContent := inputFile.Content[result[0]:result[1]]

		if fn != nil {
			reportIssue, err := fn(foundedContent, rule)
			if err != nil {
				return nil, err
			}
			if !reportIssue {
				return []engine.Issue{}, nil
			}
		}

		i := engine.Issue{
			Info:            info,
			Line:            evidence.Line,
			Column:          evidence.Column,
			Sample:          evidence.Sample,
			VulnerabilityID: evidence.UniqueHash,
			Content:         foundedContent,
		}

		issues = append(issues, i)
	}
	return issues, nil
}

// isCommentOrString checks if the match is within a comment or string literal
func isCommentOrString(content string, index int) bool {
	lines := strings.Split(content[:index], "\n")
	lastLine := lines[len(lines)-1]

	// Check for single-line comments (// or #)
	if strings.Contains(lastLine, "//") || strings.Contains(lastLine, "#") {
		return true
	}

	// Check for multi-line comments (/* */)
	if strings.Contains(content[:index], "/*") && !strings.Contains(content[:index], "*/") {
		return true
	}

	// Check for string literals
	if strings.Count(lastLine, "\"")%2 == 1 || strings.Count(lastLine, "'")%2 == 1 {
		return true
	}

	// Check for XML comments
	if strings.Contains(content[:index], "<!--") && !strings.Contains(content[:index], "-->") {
		return true
	}

	return false
}

// isLineWithinRanges checks if the given line number is within any of the line ranges
func isLineWithinRanges(line int, lineRanges []string) bool {
	if len(lineRanges) == 0 {
		return true
	}
	for _, rangeStr := range lineRanges {
		parts := strings.Split(rangeStr, ",")
		if len(parts) != 2 {
			continue
		}
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		end, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		if line >= start && line <= end {
			return true
		}
	}
	return false
}

func runSingleRule(inputFile engine.InputFile, expr *regexp2.Regexp, info engine.Info, r Rule, lineRanges []string, notLineRanges []string) ([]engine.Issue, error) {
	return runRule(inputFile, expr, info, r, func(content string, r Rule) (bool, error) {
		return evaluateNotClauses(content, r)
	}, lineRanges, notLineRanges)
}

func runAndRule(inputFile engine.InputFile, rule Rule, info engine.Info, lineRanges []string, notLineRanges []string) ([]engine.Issue, error) {
	allIssues := make([]engine.Issue, 0)

	for _, expr := range rule.And {
		issues, err := runRule(inputFile, expr, info, rule, nil, lineRanges, notLineRanges)
		if err != nil {
			return nil, fmt.Errorf("failed to run rule: %w", err)
		}
		if len(issues) == 0 {
			return issues, nil
		}
		if rule.HaveNotAndClause() || rule.HaveNotORClause() {
			for _, i := range issues {
				reportIssue, err := evaluateNotClauses(i.Content, rule)
				if err != nil {
					return nil, fmt.Errorf("failed to evaluate not clauses: %w", err)
				}
				if reportIssue {
					allIssues = append(allIssues, i)
				}
			}
		} else {
			allIssues = append(allIssues, issues...)
		}
	}
	return allIssues, nil
}

func runOrRule(inputFile engine.InputFile, rule Rule, info engine.Info, lineRanges []string, notLineRanges []string) ([]engine.Issue, error) {
	issues := make([]engine.Issue, 0)
	for _, rawExpression := range rule.Or {
		i, err := runSingleRule(inputFile, rawExpression, info, rule, lineRanges, notLineRanges)
		if err != nil {
			return nil, fmt.Errorf("failed to run single rule: %w", err)
		}
		if i != nil {
			issues = append(issues, i...)
		}
	}
	return issues, nil
}
