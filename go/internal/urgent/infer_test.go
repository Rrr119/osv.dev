package urgent

import (
	"testing"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestApplyInferredAffected_UsesPURL(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Id: "URGENT-1",
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Purl: "pkg:pypi/django@4.2.0",
				},
				Ranges: []*osvschema.Range{{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "4.2.11"},
					},
				}},
			},
		},
	}

	inferred := ApplyInferredAffected(vuln, &models.SourceRepository{})
	if len(inferred) != 1 {
		t.Fatalf("ApplyInferredAffected() inferred %d packages, want 1", len(inferred))
	}
	if got := vuln.GetAffected()[0].GetPackage(); got.GetEcosystem() != "PyPI" || got.GetName() != "django" {
		t.Fatalf("inferred package = %s/%s, want PyPI/django", got.GetEcosystem(), got.GetName())
	}
}

func TestApplyInferredAffected_UsesRepositoryAndSourceEcosystem(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Id: "URGENT-2",
		Affected: []*osvschema.Affected{
			{
				Ranges: []*osvschema.Range{{
					Type: osvschema.Range_GIT,
					Repo: "https://github.com/psf/requests",
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "abc123"},
					},
				}},
			},
		},
	}
	source := &models.SourceRepository{
		Name:               "urgent-pypi",
		AcceptedEcosystems: []osvconstants.Ecosystem{osvconstants.EcosystemPyPI},
	}

	inferred := ApplyInferredAffected(vuln, source)
	if len(inferred) != 1 {
		t.Fatalf("ApplyInferredAffected() inferred %d packages, want 1", len(inferred))
	}
	if got := vuln.GetAffected()[0].GetPackage(); got.GetEcosystem() != "PyPI" || got.GetName() != "requests" {
		t.Fatalf("inferred package = %s/%s, want PyPI/requests", got.GetEcosystem(), got.GetName())
	}
}

func TestApplyInferredAffected_MatchesManualLabels(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Id: "URGENT-3",
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{Purl: "pkg:npm/%40scope/widget@1.0.0"},
			},
			{
				Package: &osvschema.Package{Purl: "pkg:pypi/requests@2.0.0"},
			},
		},
		References: []*osvschema.Reference{
			{Type: osvschema.Reference_PACKAGE, Url: "https://crates.io/crates/openssl"},
		},
	}

	inferred := ApplyInferredAffected(vuln, &models.SourceRepository{})
	manual := []*osvschema.Package{
		{Ecosystem: "npm", Name: "@scope/widget"},
		{Ecosystem: "PyPI", Name: "requests"},
	}
	if !PackageMatchesManual(inferred, manual) {
		t.Fatalf("inferred packages %v do not match manual labels %v", packageNames(inferred), packageNames(manual))
	}
}

func TestApplyInferredAffected_PreservesExplicitPackages(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Id: "URGENT-4",
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{Ecosystem: "Go", Name: "example.com/module"},
				Ranges: []*osvschema.Range{{
					Type: osvschema.Range_GIT,
					Repo: "https://github.com/example/module",
				}},
			},
		},
	}

	inferred := ApplyInferredAffected(vuln, &models.SourceRepository{})
	if len(inferred) != 0 {
		t.Fatalf("ApplyInferredAffected() inferred %d packages, want 0", len(inferred))
	}
	if got := vuln.GetAffected()[0].GetPackage(); got.GetEcosystem() != "Go" || got.GetName() != "example.com/module" {
		t.Fatalf("explicit package changed to %s/%s", got.GetEcosystem(), got.GetName())
	}
}

func TestIsUrgent(t *testing.T) {
	dbSpecific, err := structpb.NewStruct(map[string]any{
		"urgent": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !IsUrgent(&osvschema.Vulnerability{DatabaseSpecific: dbSpecific}) {
		t.Error("IsUrgent() = false, want true")
	}
	if IsUrgent(&osvschema.Vulnerability{}) {
		t.Error("IsUrgent() = true for empty record, want false")
	}
	if !IsUrgentJSON([]byte(`{"database_specific":{"osv.dev":{"urgent":true}}}`)) {
		t.Error("IsUrgentJSON() = false for namespaced urgent marker, want true")
	}
}

func packageNames(packages []*osvschema.Package) []string {
	names := make([]string, 0, len(packages))
	for _, pkg := range packages {
		names = append(names, pkg.GetEcosystem()+"/"+pkg.GetName())
	}

	return names
}
