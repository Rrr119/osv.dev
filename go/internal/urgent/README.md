# Urgent Vulnerability Fast Lane

This package provides a synchronous, direct-to-store ingestion path for
high-priority vulnerabilities. It exists to avoid waiting for the normal
Pub/Sub worker batch, strict JSON Schema validation, Git analysis, and
external registry calls.

## Triggering

A record opts into the fast lane with:

```json
{
  "database_specific": {
    "urgent": true
  }
}
```

`database_specific["osv.dev"].urgent` is also accepted. The importer detects
the marker before strict schema validation and writes the record directly to
`models.VulnerabilityStore` instead of publishing a worker task.

Operators can also bypass the normal import schedule entirely:

```bash
GOOGLE_CLOUD_PROJECT=oss-vdb-test \
OSV_VULNERABILITIES_BUCKET=osv-test-vulnerabilities \
go run ./cmd/importer \
  -urgent-source urgent-feed \
  -urgent-file ./URGENT-2026-001.json
```

Use `-urgent-file -` to read from stdin. The command exits non-zero if the
record was stored but exceeded the configured latency threshold.

## Impact inference

`ApplyInferredAffected` fills or synthesizes affected package identities using
only local deterministic evidence:

- OSV package PURLs.
- `PACKAGE` reference URLs for PyPI, npm, crates.io, Go, RubyGems, Packagist,
  Maven Central, and `pkg:` URLs.
- Git repository URLs in affected ranges.
- The source repository's single accepted ecosystem.

It never calls an external package registry, so inference cannot add network
latency to the urgent path. When only a repository is known and the source has
no single ecosystem, the fast lane leaves package identity unchanged rather
than guessing an incorrect ecosystem.

## API compatibility

The fast lane writes the same enriched record and derived package index rows as
the normal worker. Existing `GetVulnById`, `QueryAffected`, and
`QueryAffectedBatch` APIs therefore read the record without proto or response
shape changes.

See `urgent_test.go` for the acceptance simulation: a schema-invalid record is
submitted as urgent, inferred as `PyPI/requests`, written directly, and queried
through the existing API inside the configured threshold.
