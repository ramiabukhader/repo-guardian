package score

import (
	"testing"

	"github.com/ramiabukhader/repo-guardian/internal/audit"
	"github.com/ramiabukhader/repo-guardian/internal/risk"
)

func TestCalculatePerfectScore(t *testing.T) {
	t.Parallel()
	checks := make([]audit.Check, 0, len(healthWeights))
	for id := range healthWeights {
		checks = append(checks, audit.Check{ID: id, Passed: true})
	}
	got := Calculate(audit.Result{Checks: checks}, nil)
	if got.Total != 100 || got.HealthPoints != 70 || got.RiskHygienePoints != 30 {
		t.Fatalf("Calculate() = %#v, want 100 (70 + 30)", got)
	}
}

func TestCalculateWeightedPartialScore(t *testing.T) {
	t.Parallel()
	health := audit.Result{Checks: []audit.Check{
		{ID: audit.CheckREADME, Passed: true},
		{ID: audit.CheckTests, Passed: true},
		{ID: audit.CheckLicense, Passed: false},
	}}
	findings := []risk.Finding{{Kind: risk.KindEnvironmentFile}}
	got := Calculate(health, findings)
	if got.Total != 50 || got.HealthPoints != 30 || got.RiskHygienePoints != 20 {
		t.Fatalf("Calculate() = %#v, want 50 (30 + 20)", got)
	}
}

func TestCalculateDeductsRiskKindOnlyOnce(t *testing.T) {
	t.Parallel()
	findings := []risk.Finding{
		{Kind: risk.KindSecretFile, Path: "one.pem"},
		{Kind: risk.KindSecretFile, Path: "two.pem"},
	}
	got := Calculate(audit.Result{}, findings)
	if got.RiskHygienePoints != 20 {
		t.Fatalf("RiskHygienePoints = %d, want 20", got.RiskHygienePoints)
	}
}
