package urgent_test

import (
	"context"
	"iter"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/osv.dev/go/internal/api"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/urgent"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
	pb "osv.dev/bindings/go/api"
)

type fakeVulnerabilityStore struct {
	models.UnimplementedVulnerabilityStore

	mu     sync.RWMutex
	vulns  map[string]*osvschema.Vulnerability
	writes []models.WriteRequest
}

func (s *fakeVulnerabilityStore) Write(_ context.Context, req models.WriteRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vulns == nil {
		s.vulns = make(map[string]*osvschema.Vulnerability)
	}
	s.writes = append(s.writes, req)
	s.vulns[req.ID] = proto.Clone(req.Enriched).(*osvschema.Vulnerability)

	return nil
}

func (s *fakeVulnerabilityStore) GetFull(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	vuln, ok := s.vulns[id]
	if !ok {
		return nil, models.ErrNotFound
	}

	return proto.Clone(vuln).(*osvschema.Vulnerability), nil
}

func (s *fakeVulnerabilityStore) GetModified(_ context.Context, id string) (time.Time, error) {
	vuln, err := s.GetFull(context.Background(), id)
	if err != nil {
		return time.Time{}, err
	}

	return vuln.GetModified().AsTime(), nil
}

func (s *fakeVulnerabilityStore) MatchPackages(_ context.Context, ecosystem, name, _, _ string) iter.Seq2[models.MatchResult, error] {
	return func(yield func(models.MatchResult, error) bool) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		matched := make(map[string]struct{})
		for id, vuln := range s.vulns {
			for _, affected := range vuln.GetAffected() {
				pkg := affected.GetPackage()
				if !strings.EqualFold(pkg.GetEcosystem(), ecosystem) || !strings.EqualFold(pkg.GetName(), name) {
					continue
				}
				if _, ok := matched[id]; ok {
					continue
				}
				matched[id] = struct{}{}
				if !yield(models.MatchResult{IsMatch: true, ID: id}, nil) {
					return
				}
			}
		}
	}
}

func (s *fakeVulnerabilityStore) MatchPackagesBatch(ctx context.Context, queries []models.PackageQuery) ([]iter.Seq2[models.MatchResult, error], error) {
	results := make([]iter.Seq2[models.MatchResult, error], len(queries))
	for i, query := range queries {
		results[i] = s.MatchPackages(ctx, query.Ecosystem, query.Name, query.Version, query.Cursor)
	}

	return results, nil
}

func (s *fakeVulnerabilityStore) Ping(context.Context) error {
	return nil
}

type fakeSourceRepositoryStore struct {
	repo *models.SourceRepository
}

func (s fakeSourceRepositoryStore) Get(context.Context, string) (*models.SourceRepository, error) {
	if s.repo == nil {
		return nil, models.ErrNotFound
	}

	return s.repo, nil
}

func (s fakeSourceRepositoryStore) All(context.Context) iter.Seq2[*models.SourceRepository, error] {
	return func(yield func(*models.SourceRepository, error) bool) {
		if s.repo != nil {
			yield(s.repo, nil)
		}
	}
}

func (s fakeSourceRepositoryStore) Update(context.Context, string, *models.SourceRepository) error {
	return nil
}

func TestProcessor_UrgentSubmissionIsQueryableWithinThreshold(t *testing.T) {
	store := &fakeVulnerabilityStore{}
	processor := urgent.NewProcessor(store, fakeSourceRepositoryStore{
		repo: &models.SourceRepository{
			Name:               "urgent-feed",
			AcceptedEcosystems: []osvconstants.Ecosystem{osvconstants.EcosystemPyPI},
		},
	})
	processor.LatencyThreshold = 5 * time.Second

	start := time.Now()
	result, err := processor.IngestJSON(t.Context(), "urgent-feed", "URGENT-2026-001.json", []byte(`{
		"id": "URGENT-2026-001",
		"summary": "critical authentication bypass",
		"database_specific": {"urgent": true, "future_field": "ignored"},
		"affected": [{
			"ranges": [{
				"type": "GIT",
				"repo": "https://github.com/psf/requests",
				"events": [{"introduced": "0"}, {"fixed": "abcdef"}]
			}]
		}],
		"references": [{"type": "PACKAGE", "url": "https://pypi.org/project/requests"}]
	}`), start)
	if err != nil {
		t.Fatalf("IngestJSON() error = %v", err)
	}
	if !result.WithinThreshold {
		t.Fatalf("IngestJSON() duration %v exceeded threshold %v", result.Duration, processor.LatencyThreshold)
	}

	manual := []*osvschema.Package{{Ecosystem: "PyPI", Name: "requests"}}
	if !urgent.PackageMatchesManual(result.InferredAffected, manual) {
		t.Fatalf("inferred packages = %v, want %v", packageNames(result.InferredAffected), packageNames(manual))
	}
	if len(store.writes) != 1 {
		t.Fatalf("store writes = %d, want 1", len(store.writes))
	}

	server := api.NewServer(api.ServerOptions{VulnStore: store})
	resp, err := server.QueryAffected(t.Context(), &pb.QueryAffectedParameters{
		Query: &pb.Query{
			Package: &osvschema.Package{Ecosystem: "PyPI", Name: "requests"},
			Param:   &pb.Query_Version{},
		},
	})
	if err != nil {
		t.Fatalf("QueryAffected() error = %v", err)
	}
	if got := resp.GetVulns(); len(got) != 1 || got[0].GetId() != "URGENT-2026-001" {
		t.Fatalf("QueryAffected() returned %v, want URGENT-2026-001", got)
	}
	if elapsed := time.Since(start); elapsed > processor.LatencyThreshold {
		t.Fatalf("submission-to-query latency = %v, threshold = %v", elapsed, processor.LatencyThreshold)
	}
}

func packageNames(packages []*osvschema.Package) []string {
	names := make([]string, 0, len(packages))
	for _, pkg := range packages {
		names = append(names, pkg.GetEcosystem()+"/"+pkg.GetName())
	}

	return names
}
