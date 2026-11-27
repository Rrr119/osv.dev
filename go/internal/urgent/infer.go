// Package urgent implements the synchronous fast-lane ingestion path for
// high-priority vulnerabilities.
package urgent

import (
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
)

type inferredCandidate struct {
	pkg  *osvschema.Package
	repo string
}

// ApplyInferredAffected fills in missing affected package identities and
// synthesizes package entries when the vulnerability only identifies a
// repository. It returns the package identities that were derived rather than
// copied verbatim from the submitted record.
//
// Inference uses only local, deterministic evidence: package PURLs, PACKAGE
// reference URLs, repository URLs, and the source repository's accepted
// ecosystem list. It deliberately does not call external package registries,
// so the fast path remains independent of network latency.
func ApplyInferredAffected(vuln *osvschema.Vulnerability, source *models.SourceRepository) []*osvschema.Package {
	if vuln == nil {
		return nil
	}

	candidates := collectCandidates(vuln, source)
	alreadyPresent := make(map[string]struct{})
	for _, affected := range vuln.GetAffected() {
		if pkg := affected.GetPackage(); pkg != nil && pkg.GetEcosystem() != "" && pkg.GetName() != "" {
			alreadyPresent[packageKey(pkg)] = struct{}{}
		}
	}

	var inferred []*osvschema.Package
	record := func(pkg *osvschema.Package) {
		if pkg == nil || pkg.GetEcosystem() == "" || pkg.GetName() == "" {
			return
		}
		key := packageKey(pkg)
		if _, ok := alreadyPresent[key]; ok {
			return
		}
		alreadyPresent[key] = struct{}{}
		inferred = append(inferred, proto.Clone(pkg).(*osvschema.Package))
	}

	for i, affected := range vuln.GetAffected() {
		candidate := candidateForAffected(affected, i, candidates, source)
		if candidate == nil {
			continue
		}

		pkg := affected.GetPackage()
		if pkg == nil {
			affected.Package = proto.Clone(candidate).(*osvschema.Package)
			record(affected.GetPackage())
			continue
		}

		changed := false
		if pkg.GetName() == "" {
			pkg.Name = candidate.GetName()
			changed = true
		}
		if pkg.GetEcosystem() == "" {
			pkg.Ecosystem = candidate.GetEcosystem()
			changed = true
		}
		if pkg.GetPurl() == "" {
			pkg.Purl = candidate.GetPurl()
			changed = true
		}
		if changed {
			record(pkg)
		}
	}

	// A record may have no affected entries at all, or only repository ranges
	// with no package field. Add synthesized entries for evidence we have not
	// already represented.
	hasPackage := false
	for _, affected := range vuln.GetAffected() {
		if affected.GetPackage().GetName() != "" {
			hasPackage = true
			break
		}
	}
	if !hasPackage {
		for _, candidate := range candidates {
			if candidate.pkg.GetName() == "" {
				continue
			}
			key := packageKey(candidate.pkg)
			if _, ok := alreadyPresent[key]; ok {
				continue
			}
			alreadyPresent[key] = struct{}{}
			cloned := proto.Clone(candidate.pkg).(*osvschema.Package)
			vuln.Affected = append(vuln.Affected, &osvschema.Affected{Package: cloned})
			inferred = append(inferred, proto.Clone(cloned).(*osvschema.Package))
		}
	}

	return inferred
}

func collectCandidates(vuln *osvschema.Vulnerability, source *models.SourceRepository) []inferredCandidate {
	var candidates []inferredCandidate
	var repos []string
	seen := make(map[string]struct{})

	add := func(pkg *osvschema.Package, repo string) {
		if pkg == nil || pkg.GetName() == "" || pkg.GetEcosystem() == "" {
			return
		}
		key := packageKey(pkg)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		candidates = append(candidates, inferredCandidate{
			pkg:  proto.Clone(pkg).(*osvschema.Package),
			repo: normalizeRepo(repo),
		})
	}
	addRepo := func(repo string) string {
		repo = strings.TrimSpace(repo)
		if repo == "" {
			return ""
		}
		normalized := normalizeRepo(repo)
		if normalized != "" && !slices.Contains(repos, normalized) {
			repos = append(repos, normalized)
		}

		return normalized
	}

	for _, affected := range vuln.GetAffected() {
		pkg := affected.GetPackage()
		if pkg != nil {
			if candidate := packageFromPURL(pkg.GetPurl(), pkg); candidate != nil {
				add(candidate, "")
			}
			if pkg.GetName() != "" {
				candidate := clonePackage(pkg)
				fillPackageEcosystem(candidate, source)
				add(candidate, "")
			}
		}
		for _, r := range affected.GetRanges() {
			repo := addRepo(r.GetRepo())
			if repo == "" {
				continue
			}
			ecosystem := singleSourceEcosystem(source)
			if ecosystem == "" {
				continue
			}
			name := repoPackageName(repo)
			if name == "" {
				continue
			}
			add(&osvschema.Package{
				Name:      name,
				Ecosystem: ecosystem,
			}, repo)
		}
	}

	for _, ref := range vuln.GetReferences() {
		pkg, repo := packageFromReference(ref.GetUrl(), source)
		if repo != "" {
			addRepo(repo)
		}
		add(pkg, repo)
	}

	for _, repo := range repos {
		ecosystem := singleSourceEcosystem(source)
		if ecosystem == "" {
			continue
		}
		name := repoPackageName(repo)
		if name == "" {
			continue
		}
		add(&osvschema.Package{
			Name:      name,
			Ecosystem: ecosystem,
		}, repo)
	}

	return candidates
}

func candidateForAffected(
	affected *osvschema.Affected,
	index int,
	candidates []inferredCandidate,
	source *models.SourceRepository,
) *osvschema.Package {
	if len(candidates) == 0 {
		return nil
	}

	var affectedRepos []string
	for _, r := range affected.GetRanges() {
		if normalized := normalizeRepo(r.GetRepo()); normalized != "" {
			affectedRepos = append(affectedRepos, normalized)
		}
	}
	for _, repo := range affectedRepos {
		for _, candidate := range candidates {
			if candidate.repo == repo {
				return candidate.pkg
			}
		}
	}

	pkg := affected.GetPackage()
	if pkg.GetName() != "" {
		for _, candidate := range candidates {
			if candidate.pkg.GetName() == pkg.GetName() {
				return candidate.pkg
			}
		}
	}

	if index < len(candidates) {
		return candidates[index].pkg
	}

	// If there is exactly one usable candidate, it is the safest fallback for
	// the remaining affected entries.
	var only *osvschema.Package
	for _, candidate := range candidates {
		if candidate.pkg.GetEcosystem() == "" && singleSourceEcosystem(source) == "" {
			continue
		}
		if only != nil {
			return nil
		}
		only = candidate.pkg
	}

	return only
}

func packageFromPURL(rawPURL string, fallback *osvschema.Package) *osvschema.Package {
	if rawPURL == "" {
		return nil
	}
	ecosystem, name, _, err := purl.Parse(rawPURL)
	if err != nil {
		return nil
	}

	pkg := &osvschema.Package{
		Name:      name,
		Ecosystem: ecosystem,
		Purl:      rawPURL,
	}
	if fallback != nil {
		if pkg.Name == "" {
			pkg.Name = fallback.GetName()
		}
		if pkg.Ecosystem == "" {
			pkg.Ecosystem = fallback.GetEcosystem()
		}
	}

	return pkg
}

func clonePackage(pkg *osvschema.Package) *osvschema.Package {
	if pkg == nil {
		return nil
	}

	return proto.Clone(pkg).(*osvschema.Package)
}

func fillPackageEcosystem(pkg *osvschema.Package, source *models.SourceRepository) {
	if pkg == nil || pkg.GetEcosystem() != "" {
		return
	}
	if ecosystem := singleSourceEcosystem(source); ecosystem != "" {
		pkg.Ecosystem = ecosystem
	}
}

func singleSourceEcosystem(source *models.SourceRepository) string {
	if source == nil {
		return ""
	}
	var ecosystems []string
	for _, ecosystem := range source.AcceptedEcosystems {
		value := strings.TrimSpace(string(ecosystem))
		if value == "" || value == "*" {
			return ""
		}
		if !slices.Contains(ecosystems, value) {
			ecosystems = append(ecosystems, value)
		}
	}
	if len(ecosystems) == 1 {
		return ecosystems[0]
	}

	return ""
}

func packageFromReference(refURL string, source *models.SourceRepository) (*osvschema.Package, string) {
	refURL = strings.TrimSpace(refURL)
	if refURL == "" {
		return nil, ""
	}
	if strings.HasPrefix(refURL, "pkg:") {
		pkg := packageFromPURL(refURL, nil)

		return pkg, ""
	}

	parsed, err := url.Parse(refURL)
	if err != nil {
		return nil, ""
	}
	host := strings.ToLower(parsed.Hostname())
	segments := splitURLPath(parsed.Path)

	registryPackage := func(ecosystem string, nameSegments int, separator string) *osvschema.Package {
		if len(segments) < nameSegments {
			return nil
		}
		name := strings.Join(segments[len(segments)-nameSegments:], separator)
		if name == "" {
			return nil
		}

		return &osvschema.Package{Name: name, Ecosystem: ecosystem}
	}

	switch host {
	case "pypi.org":
		if len(segments) >= 2 && segments[0] == "project" {
			return &osvschema.Package{Name: segments[1], Ecosystem: "PyPI"}, ""
		}
	case "www.npmjs.com", "npmjs.com":
		if len(segments) >= 2 && segments[0] == "package" {
			name := strings.Join(segments[1:], "/")
			return &osvschema.Package{Name: name, Ecosystem: "npm"}, ""
		}
	case "crates.io":
		if len(segments) >= 2 && segments[0] == "crates" {
			return &osvschema.Package{Name: segments[1], Ecosystem: "crates.io"}, ""
		}
	case "pkg.go.dev":
		name := strings.Join(segments, "/")
		if name != "" {
			return &osvschema.Package{Name: name, Ecosystem: "Go"}, ""
		}
	case "rubygems.org":
		if len(segments) >= 2 && segments[0] == "gems" {
			return &osvschema.Package{Name: segments[1], Ecosystem: "RubyGems"}, ""
		}
	case "packagist.org":
		if len(segments) >= 3 && segments[0] == "packages" {
			return &osvschema.Package{Name: segments[1] + "/" + segments[2], Ecosystem: "Packagist"}, ""
		}
	case "search.maven.org":
		if len(segments) >= 4 && segments[0] == "artifact" {
			return &osvschema.Package{Name: segments[1] + ":" + segments[2], Ecosystem: "Maven"}, ""
		}
	}

	if isRepositoryHost(host) {
		repo := host + strings.TrimSuffix(parsed.Path, "/")
		name := repoPackageName(repo)
		if name != "" {
			return &osvschema.Package{Name: name, Ecosystem: singleSourceEcosystem(source)}, repo
		}
	}

	// Maven Central URLs are sometimes written as /artifact/group/artifact or
	// /artifact/group/artifact/version.
	if host == "repo1.maven.org" {
		if pkg := registryPackage("Maven", 3, ":"); pkg != nil && len(segments) > 0 && segments[0] == "maven2" {
			group := strings.Join(segments[1:len(segments)-1], ".")
			pkg.Name = group + ":" + segments[len(segments)-1]

			return pkg, ""
		}
	}

	return nil, ""
}

func splitURLPath(rawPath string) []string {
	rawPath = strings.Trim(rawPath, "/")
	if rawPath == "" {
		return nil
	}
	parts := strings.Split(rawPath, "/")
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			cleaned = append(cleaned, part)
		}
	}

	return cleaned
}

func isRepositoryHost(host string) bool {
	return host == "github.com" || host == "gitlab.com" || host == "codeberg.org" ||
		host == "bitbucket.org" || host == "git.sr.ht"
}

func repoPackageName(repo string) string {
	normalized := normalizeRepo(repo)
	if normalized == "" {
		return ""
	}
	parts := splitURLPath(normalized)
	if len(parts) == 0 {
		return ""
	}
	name := path.Base(parts[len(parts)-1])
	name = strings.TrimSuffix(name, ".git")
	// For repository roots, github.com/owner/repo is the most useful package
	// identity. Avoid returning the host or a generic owner segment.
	if name == "" || name == "." || name == "/" {
		return ""
	}

	return name
}

func normalizeRepo(repoURL string) string {
	repoURL = strings.TrimSpace(repoURL)
	if repoURL == "" {
		return ""
	}
	parsed, err := url.Parse(repoURL)
	if err != nil {
		return repoURL
	}
	host := parsed.Host
	if host == "" {
		host = parsed.Path
		parsed.Path = ""
	}
	normalized := strings.ToLower(host + parsed.Path)
	normalized = strings.TrimRight(normalized, "/")
	normalized = strings.TrimSuffix(normalized, ".git")

	return normalized
}

func packageKey(pkg *osvschema.Package) string {
	return strings.ToLower(pkg.GetEcosystem()) + "\x1f" + strings.ToLower(pkg.GetName())
}

// PackageMatchesManual reports whether inferred and manually curated package
// identities agree. It ignores order, PURLs, and ecosystem case.
func PackageMatchesManual(inferred, manual []*osvschema.Package) bool {
	if len(inferred) != len(manual) {
		return false
	}
	keys := make([]string, 0, len(inferred))
	manualKeys := make([]string, 0, len(manual))
	for _, pkg := range inferred {
		if pkg.GetEcosystem() == "" || pkg.GetName() == "" {
			return false
		}
		keys = append(keys, packageKey(pkg))
	}
	for _, pkg := range manual {
		if pkg.GetEcosystem() == "" || pkg.GetName() == "" {
			return false
		}
		manualKeys = append(manualKeys, packageKey(pkg))
	}
	slices.Sort(keys)
	slices.Sort(manualKeys)

	return slices.Equal(keys, manualKeys)
}
