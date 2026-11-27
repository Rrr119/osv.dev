package urgent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/osvutil/schema"
	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/google/osv.dev/go/internal/worker/pipeline/makesemver"
	"github.com/google/osv.dev/go/internal/worker/pipeline/namenormalize"
	"github.com/google/osv.dev/go/internal/worker/pipeline/published"
	pipelinepurl "github.com/google/osv.dev/go/internal/worker/pipeline/purl"
	"github.com/google/osv.dev/go/internal/worker/pipeline/schemaversion"
	"github.com/google/osv.dev/go/internal/worker/pipeline/sourcelink"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/ecosystem"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// DefaultLatencyThreshold is the default target for a submission to become
	// visible through the read API. The fast path does not wait on Pub/Sub,
	// batch validation, Git analysis, or external registries, so this should
	// normally be measured in seconds.
	DefaultLatencyThreshold = 2 * time.Minute

	urgentField = "urgent"
)

var validIDRegex = regexp.MustCompile(`^[a-zA-Z0-9:_.-]+$`)

// FastPipeline contains only enrichers that are local, deterministic, and
// bounded in time. It intentionally excludes Git analysis, registry lookups,
// version enumeration, and relation propagation, which are performed later by
// the normal batch worker.
var FastPipeline = []pipeline.Enricher{
	&namenormalize.Enricher{},
	&makesemver.Enricher{},
	&schemaversion.Enricher{},
	&pipelinepurl.Enricher{},
	&sourcelink.Enricher{},
	&published.Enricher{},
}

// Submission is an urgent vulnerability submitted directly to the fast lane.
type Submission struct {
	Source           string
	Path             string
	Raw              *osvschema.Vulnerability
	RawJSON          []byte
	ReceivedAt       time.Time
	SourceRepository *models.SourceRepository
}

// Result describes a completed fast-lane ingestion.
type Result struct {
	Vulnerability    *osvschema.Vulnerability
	InferredAffected []*osvschema.Package
	Duration         time.Duration
	WithinThreshold  bool
}

// Processor writes urgent vulnerabilities synchronously to the primary store.
// It is safe to share across goroutines as its fields are read-only after
// construction.
type Processor struct {
	Store             models.VulnerabilityStore
	SourceRepoStore   models.SourceRepositoryStore
	Pipeline          []pipeline.Enricher
	EcosystemProvider *ecosystem.Provider
	Now               func() time.Time
	LatencyThreshold  time.Duration
}

// NewProcessor creates a fast-lane processor using the default local pipeline.
func NewProcessor(store models.VulnerabilityStore, sourceRepoStore models.SourceRepositoryStore) *Processor {
	return &Processor{
		Store:            store,
		SourceRepoStore:  sourceRepoStore,
		Pipeline:         FastPipeline,
		LatencyThreshold: DefaultLatencyThreshold,
		Now:              time.Now,
	}
}

// IngestJSON parses and ingests an urgent JSON vulnerability without running
// the batch JSON Schema validator.
func (p *Processor) IngestJSON(ctx context.Context, source, sourcePath string, rawJSON []byte, receivedAt time.Time) (*Result, error) {
	data := bytes.ToValidUTF8(rawJSON, []byte("\uFFFD"))
	data = bytes.ReplaceAll(data, []byte{0}, []byte("\uFFFD"))
	data = schema.ReplaceJSONNullEscapes(data)

	vuln := &osvschema.Vulnerability{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, vuln); err != nil {
		return nil, fmt.Errorf("failed to parse urgent vulnerability: %w", err)
	}

	return p.Ingest(ctx, Submission{
		Source:     source,
		Path:       sourcePath,
		Raw:        vuln,
		RawJSON:    data,
		ReceivedAt: receivedAt,
	})
}

// Ingest runs the urgent fast lane: minimal validation, local enrichment,
// impact inference, and a direct atomic store write. It does not publish to
// Pub/Sub or invoke the batch validator.
func (p *Processor) Ingest(ctx context.Context, submission Submission) (*Result, error) {
	start := p.now()
	if p.Store == nil {
		return nil, errors.New("urgent processor store is required")
	}
	if submission.Raw == nil {
		return nil, errors.New("urgent vulnerability is required")
	}
	if err := validateMinimal(submission.Raw); err != nil {
		return nil, err
	}

	receivedAt := submission.ReceivedAt
	if receivedAt.IsZero() {
		receivedAt = start
	}

	sourceRepo := submission.SourceRepository
	if sourceRepo == nil && p.SourceRepoStore != nil && submission.Source != "" {
		var err error
		sourceRepo, err = p.SourceRepoStore.Get(ctx, submission.Source)
		if err != nil && !errors.Is(err, models.ErrNotFound) {
			logger.WarnContext(ctx, "Failed to load source repository for urgent ingestion; using permissive defaults",
				slog.String("source", submission.Source),
				slog.Any("error", err))
		}
	}
	if sourceRepo == nil {
		sourceRepo = permissiveSourceRepository(submission.Source)
	}

	now := start.UTC()
	raw := proto.Clone(submission.Raw).(*osvschema.Vulnerability)
	if raw.GetModified() == nil {
		raw.Modified = timestamppb.New(now)
	}

	enriched := proto.Clone(raw).(*osvschema.Vulnerability)
	inferred := ApplyInferredAffected(enriched, sourceRepo)

	params := &pipeline.EnrichParams{
		PathInSource:      submission.Path,
		SourceRepo:        sourceRepo,
		EcosystemProvider: p.EcosystemProvider,
	}
	if params.EcosystemProvider == nil {
		params.EcosystemProvider = ecosystem.DefaultProvider
	}
	for _, enricher := range p.pipeline() {
		if err := enricher.Enrich(ctx, enriched, params); err != nil {
			return nil, fmt.Errorf("failed to enrich urgent vulnerability: %w", err)
		}
	}

	if enriched.GetPublished() == nil {
		enriched.Published = timestamppb.New(raw.GetModified().AsTime())
	}
	enriched.Modified = timestamppb.New(now)
	if enriched.GetWithdrawn() != nil && enriched.GetWithdrawn().AsTime().After(now) {
		enriched.Modified = enriched.GetWithdrawn()
	}

	var rawJSON []byte
	var rawSHA256 []byte
	if len(submission.RawJSON) > 0 {
		rawJSON = submission.RawJSON
		hash := sha256.Sum256(rawJSON)
		rawSHA256 = hash[:]
	}
	if err := p.Store.Write(ctx, models.WriteRequest{
		ID:              enriched.GetId(),
		Source:          submission.Source,
		Path:            submission.Path,
		Raw:             raw,
		RawJSON:         rawJSON,
		RawSHA256:       rawSHA256,
		FetchedAt:       &receivedAt,
		Enriched:        enriched,
		AffectedCommits: models.AffectedCommitsResult{Skip: true},
	}); err != nil {
		return nil, fmt.Errorf("failed to write urgent vulnerability: %w", err)
	}

	duration := p.now().Sub(start)
	withinThreshold := p.latencyThreshold() <= 0 || duration <= p.latencyThreshold()
	if !withinThreshold {
		logger.WarnContext(ctx, "Urgent vulnerability exceeded latency threshold",
			slog.String("id", enriched.GetId()),
			slog.Duration("duration", duration),
			slog.Duration("threshold", p.latencyThreshold()))
	}

	logger.InfoContext(ctx, "Urgent vulnerability ingested",
		slog.String("id", enriched.GetId()),
		slog.String("source", submission.Source),
		slog.Duration("duration", duration),
		slog.Int("inferred_packages", len(inferred)))

	return &Result{
		Vulnerability:    enriched,
		InferredAffected: inferred,
		Duration:         duration,
		WithinThreshold:  withinThreshold,
	}, nil
}

func (p *Processor) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}

	return time.Now()
}

func (p *Processor) pipeline() []pipeline.Enricher {
	if p.Pipeline != nil {
		return p.Pipeline
	}

	return FastPipeline
}

func (p *Processor) latencyThreshold() time.Duration {
	if p.LatencyThreshold != 0 {
		return p.LatencyThreshold
	}

	return DefaultLatencyThreshold
}

// IsUrgent reports whether a vulnerability opts into the synchronous fast lane.
// It recognises database_specific.urgent and
// database_specific["osv.dev"].urgent as a boolean true.
func IsUrgent(vuln *osvschema.Vulnerability) bool {
	if vuln == nil {
		return false
	}
	if value, ok := vuln.GetDatabaseSpecific().GetFields()[urgentField]; ok && value.GetBoolValue() {
		return true
	}
	if namespace, ok := vuln.GetDatabaseSpecific().GetFields()["osv.dev"]; ok {
		if fields := namespace.GetStructValue().GetFields(); fields != nil {
			return fields[urgentField].GetBoolValue()
		}
	}

	return false
}

// IsUrgentJSON is the pre-validation equivalent of IsUrgent for importer use.
// It must not require a full schema-valid record because the fast lane is
// intentionally allowed to proceed before batch validation.
func IsUrgentJSON(rawJSON []byte) bool {
	if len(rawJSON) == 0 {
		return false
	}

	var envelope struct {
		DatabaseSpecific map[string]any `json:"database_specific"`
	}
	if err := json.Unmarshal(rawJSON, &envelope); err != nil {
		return false
	}
	if value, ok := envelope.DatabaseSpecific[urgentField].(bool); ok {
		return value
	}
	if namespace, ok := envelope.DatabaseSpecific["osv.dev"].(map[string]any); ok {
		if value, ok := namespace[urgentField].(bool); ok {
			return value
		}
	}

	return false
}

func validateMinimal(vuln *osvschema.Vulnerability) error {
	id := vuln.GetId()
	if id == "" {
		return errors.New("urgent vulnerability ID is required")
	}
	if len(id) > 100 {
		return errors.New("urgent vulnerability ID is too long")
	}
	if id == "." || id == ".." || !validIDRegex.MatchString(id) {
		return fmt.Errorf("invalid urgent vulnerability ID %q", id)
	}

	return nil
}

func permissiveSourceRepository(name string) *models.SourceRepository {
	return &models.SourceRepository{
		Name:               name,
		AcceptedEcosystems: []osvconstants.Ecosystem{"*"},
	}
}
