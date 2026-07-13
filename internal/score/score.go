// Package score implements repo-guardian's documented 100-point model.
package score

import (
	"github.com/ramiabukhader/repo-guardian/internal/audit"
	"github.com/ramiabukhader/repo-guardian/internal/risk"
)

const Max = 100

var healthWeights = map[string]int{
	audit.CheckREADME:              15,
	audit.CheckLicense:             10,
	audit.CheckGitignore:           5,
	audit.CheckCI:                  10,
	audit.CheckTests:               15,
	audit.CheckSecurity:            5,
	audit.CheckContributing:        5,
	audit.CheckPullRequestTemplate: 5,
}

var riskHygieneWeights = map[risk.Kind]int{
	risk.KindEnvironmentFile: 10,
	risk.KindSecretFile:      10,
	risk.KindLargeFile:       5,
	risk.KindBuildOutput:     5,
}

// Result is the score and its two transparent components.
type Result struct {
	Total             int `json:"total"`
	Maximum           int `json:"maximum"`
	HealthPoints      int `json:"health_points"`
	RiskHygienePoints int `json:"risk_hygiene_points"`
}

// Calculate applies fixed check weights and per-kind risk-hygiene deductions.
func Calculate(health audit.Result, findings []risk.Finding) Result {
	result := Result{Maximum: Max}
	awardedChecks := make(map[string]struct{})
	for _, check := range health.Checks {
		weight, defined := healthWeights[check.ID]
		if !check.Passed || !defined {
			continue
		}
		if _, awarded := awardedChecks[check.ID]; awarded {
			continue
		}
		awardedChecks[check.ID] = struct{}{}
		result.HealthPoints += weight
	}

	presentKinds := make(map[risk.Kind]struct{})
	for _, finding := range findings {
		presentKinds[finding.Kind] = struct{}{}
	}
	for kind, weight := range riskHygieneWeights {
		if _, present := presentKinds[kind]; !present {
			result.RiskHygienePoints += weight
		}
	}
	result.Total = result.HealthPoints + result.RiskHygienePoints
	return result
}
