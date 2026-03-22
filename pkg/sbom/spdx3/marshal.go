package spdx3

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/mitchellh/hashstructure/v2"
	"github.com/package-url/packageurl-go"
	spdx3 "github.com/spdx/tools-golang/spdx/v3/v3_0"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/licensing/expression"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

// Marshaler converts Trivy's internal BOM representation to SPDX 3.0 JSON-LD
// documents using the tools-golang spdx/v3/v3_0 library.
type Marshaler struct {
	hasher     Hash
	appVersion string
	logger     *log.Logger
}

type Hash func(v any, format hashstructure.Format, opts *hashstructure.HashOptions) (uint64, error)

type marshalOption func(*Marshaler)

func WithHasher(hasher Hash) marshalOption {
	return func(m *Marshaler) {
		m.hasher = hasher
	}
}

func NewMarshaler(version string, opts ...marshalOption) *Marshaler {
	m := &Marshaler{
		hasher:     hashstructure.Hash,
		appVersion: version,
		logger:     log.WithPrefix("spdx3"),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// MarshalReport converts a Trivy Report into an SPDX 3.0 Document.
func (m *Marshaler) MarshalReport(ctx context.Context, report types.Report) (*Document, error) {
	bom, err := sbomio.NewEncoder().Encode(report)
	if err != nil {
		return nil, xerrors.Errorf("failed to marshal report: %w", err)
	}
	return m.Marshal(ctx, bom)
}

// Marshal converts a core.BOM into an SPDX 3.0 Document using tools-golang types.
func (m *Marshaler) Marshal(ctx context.Context, bom *core.BOM) (*Document, error) {
	now := clock.Now(ctx).UTC()

	root := bom.Root()
	if root == nil {
		return nil, xerrors.New("root component is required")
	}

	// Create the creator agent and tool
	orgAgent := &spdx3.Organization{
		Name: CreatorOrganization,
	}
	tool := &spdx3.Tool{
		Name: fmt.Sprintf("%s-%s", CreatorTool, m.appVersion),
	}

	// Create the Document using tools-golang's NewDocument which sets up
	// conformance, CreationInfo, and JSON-LD context automatically.
	doc := spdx3.NewDocument(spdx3.ProfileIdentifierType_Software, root.Name, orgAgent, tool)

	// Override the creation time with the context-provided clock
	if ci, ok := doc.CreationInfo.(*spdx3.CreationInfo); ok {
		ci.Created = now
	}

	// Add Security profile conformance
	doc.ProfileConformances = append(doc.ProfileConformances, spdx3.ProfileIdentifierType_Security)

	// Track component ID => spdx3 Package for relationship resolution
	componentPkgs := make(map[uuid.UUID]*spdx3.Package)

	// Create root package
	rootPkg := m.rootPackage(root)
	componentPkgs[root.ID()] = rootPkg

	// The root is the document's root element
	doc.RootElements = spdx3.ElementList{rootPkg}

	// Create a DESCRIBES relationship
	doc.Elements = append(doc.Elements, &spdx3.Relationship{
		From: doc,
		To:   spdx3.ElementList{rootPkg},
		Type: spdx3.RelationshipType_Describes,
	})

	// Process all non-root components
	for _, c := range bom.Components() {
		if c.Root {
			continue
		}

		pkg := m.componentPackage(c)

		// Add vulnerability external references (security advisory links)
		if vulns, ok := bom.Vulnerabilities()[c.ID()]; ok {
			for _, v := range vulns {
				if v.PrimaryURL != "" {
					pkg.ExternalRefs = append(pkg.ExternalRefs, &spdx3.ExternalRef{
						Type:     spdx3.ExternalRefType_SecurityAdvisory,
						Locators: []string{v.PrimaryURL},
					})
				}
			}
		}

		componentPkgs[c.ID()] = pkg

		// Add license relationships (SPDX 3.0 models licenses as Relationships)
		if c.Type == core.TypeLibrary && len(c.Licenses) > 0 {
			licenseExpr := m.normalizeLicense(c.Licenses)
			if licenseExpr != "" {
				le := &spdx3.LicenseExpression{
					LicenseExpression: licenseExpr,
				}
				doc.Elements = append(doc.Elements, &spdx3.Relationship{
					From: pkg,
					To:   spdx3.ElementList{le},
					Type: spdx3.RelationshipType_HasDeclaredLicense,
				})
				doc.Elements = append(doc.Elements, &spdx3.Relationship{
					From: pkg,
					To:   spdx3.ElementList{le},
					Type: spdx3.RelationshipType_HasConcludedLicense,
				})
			}
		}

		// Create file elements for this package
		m.addFileElements(c, pkg, doc)
	}

	// Create relationship elements from BOM relationships
	for id, rels := range bom.Relationships() {
		fromPkg, ok := componentPkgs[id]
		if !ok {
			continue
		}
		for _, rel := range rels {
			toPkg, ok := componentPkgs[rel.Dependency]
			if !ok {
				continue
			}
			doc.Elements = append(doc.Elements, &spdx3.Relationship{
				From: fromPkg,
				To:   spdx3.ElementList{toPkg},
				Type: m.mapRelationshipType(rel.Type),
			})
		}
	}

	// Add Security Profile: vulnerability + VEX elements
	m.addVulnerabilityElements(bom, componentPkgs, doc)

	return doc, nil
}

// rootPackage creates the root SPDX 3.0 Package element.
func (m *Marshaler) rootPackage(root *core.Component) *spdx3.Package {
	purpose := spdx3.SoftwarePurpose_Source
	if root.Type == core.TypeContainerImage {
		purpose = spdx3.SoftwarePurpose_Container
	}

	pkg := &spdx3.Package{
		Name:           root.Name,
		PrimaryPurpose: purpose,
		CopyrightText:  NoAssertionValue,
	}

	// Download location for repositories
	if root.Type == core.TypeRepository {
		pkg.DownloadLocation = spdx3.URI(fmt.Sprintf("git+%s", root.Name))
	}

	// PURL
	if root.PkgIdentifier.PURL != nil {
		purlStr := root.PkgIdentifier.PURL.String()
		pkg.PackageURL = spdx3.URI(purlStr)
		pkg.ExternalIdentifiers = append(pkg.ExternalIdentifiers, &spdx3.ExternalIdentifier{
			Type: spdx3.ExternalIdentifierType_PackageURL,
			Identifier:             purlStr,
		})
	}

	// Properties as CdxPropertiesExtension entries
	m.addPropertyExtensions(root, pkg)

	return pkg
}

// componentPackage creates an SPDX 3.0 Package for a non-root component.
func (m *Marshaler) componentPackage(c *core.Component) *spdx3.Package {
	var purpose spdx3.SoftwarePurpose
	var sourceInfo string

	switch c.Type {
	case core.TypeOS:
		purpose = spdx3.SoftwarePurpose_OperatingSystem
	case core.TypeApplication:
		purpose = spdx3.SoftwarePurpose_Application
	case core.TypeLibrary:
		purpose = spdx3.SoftwarePurpose_Library
		if c.SrcName != "" {
			sourceInfo = fmt.Sprintf("%s %s %s", SourcePackagePrefix, c.SrcName, c.SrcVersion)
		} else if c.SrcFile != "" {
			sourceInfo = fmt.Sprintf("%s %s", SourceFilePrefix, c.SrcFile)
		}
	}

	pkg := &spdx3.Package{
		Name:           spdxPkgName(c),
		Version:        c.Version,
		PrimaryPurpose: purpose,
		SourceInfo:     sourceInfo,
		CopyrightText:  NoAssertionValue,
	}

	// PURL
	if c.PkgIdentifier.PURL != nil {
		purlStr := c.PkgIdentifier.PURL.String()
		pkg.PackageURL = spdx3.URI(purlStr)
		pkg.ExternalIdentifiers = append(pkg.ExternalIdentifiers, &spdx3.ExternalIdentifier{
			Type: spdx3.ExternalIdentifierType_PackageURL,
			Identifier:             purlStr,
		})
	}

	// Supplier
	if c.Supplier != "" {
		pkg.SuppliedBy = &spdx3.Organization{
			Name: c.Supplier,
		}
	}

	// Checksums as integrity methods
	for _, f := range c.Files {
		if f.Path != "" {
			continue // File digests stored separately
		}
		for _, d := range f.Digests {
			if hash, ok := m.mapDigest(d); ok {
				pkg.VerifiedUsing = append(pkg.VerifiedUsing, hash)
			}
		}
	}

	// Properties
	m.addPropertyExtensions(c, pkg)

	return pkg
}

// addFileElements creates SPDX 3.0 File elements and CONTAINS relationships.
func (m *Marshaler) addFileElements(c *core.Component, parentPkg *spdx3.Package, doc *Document) {
	for _, f := range c.Files {
		if f.Path == "" || len(f.Digests) == 0 {
			continue
		}

		file := &spdx3.File{
			Name: f.Path,
		}

		for _, d := range f.Digests {
			if hash, ok := m.mapDigest(d); ok {
				file.VerifiedUsing = append(file.VerifiedUsing, hash)
			}
		}

		// CONTAINS relationship from package to file
		doc.Elements = append(doc.Elements, &spdx3.Relationship{
			From: parentPkg,
			To:   spdx3.ElementList{file},
			Type: spdx3.RelationshipType_Contains,
		})
	}
}

// addVulnerabilityElements creates Security profile elements.
func (m *Marshaler) addVulnerabilityElements(bom *core.BOM, componentPkgs map[uuid.UUID]*spdx3.Package, doc *Document) {
	// Track created vulnerability elements to avoid duplicates
	vulnElements := make(map[string]*spdx3.Vulnerability)

	for compID, vulns := range bom.Vulnerabilities() {
		pkg, ok := componentPkgs[compID]
		if !ok {
			continue
		}

		for _, vuln := range vulns {
			// Create vulnerability element if not already created
			vulnElem, exists := vulnElements[vuln.ID]
			if !exists {
				vulnElem = &spdx3.Vulnerability{
					Name:    vuln.ID,
					Summary: vuln.ID,
				}

				if vuln.PrimaryURL != "" {
					vulnElem.ExternalRefs = append(vulnElem.ExternalRefs, &spdx3.ExternalRef{
						Type:     spdx3.ExternalRefType_SecurityAdvisory,
						Locators: []string{vuln.PrimaryURL},
					})
				}

				vulnElements[vuln.ID] = vulnElem
			}

			// Create VEX "affected" assessment relationship
			actionStatement := ""
			if vuln.FixedVersion != "" {
				actionStatement = fmt.Sprintf("Upgrade %s to version %s", vuln.PkgName, vuln.FixedVersion)
			}

			vex := &spdx3.VexAffectedVulnAssessmentRelationship{
				Name:            fmt.Sprintf("VEX: %s affects %s", vuln.ID, vuln.PkgName),
				From:            vulnElem,
				To:              spdx3.ElementList{pkg},
				Type:            spdx3.RelationshipType_Affects,
				AssessedElement: pkg,
				ActionStatement: actionStatement,
			}

			if vuln.InstalledVersion != "" {
				vex.StatusNotes = fmt.Sprintf("Installed version: %s", vuln.InstalledVersion)
			}

			doc.Elements = append(doc.Elements, vex)
		}
	}
}

// -------------------------------------------------------------------
// Helper methods
// -------------------------------------------------------------------

func (m *Marshaler) addPropertyExtensions(c *core.Component, pkg *spdx3.Package) {
	// Properties that are already in other SPDX fields
	duplicateProperties := map[string]bool{
		core.PropertySrcName:    true,
		core.PropertySrcRelease: true,
		core.PropertySrcEpoch:   true,
		core.PropertySrcVersion: true,
		core.PropertyFilePath:   true,
	}

	var entries spdx3.CdxPropertyEntryList
	for _, p := range c.Properties {
		if duplicateProperties[p.Name] {
			continue
		}
		entries = append(entries, &spdx3.CdxPropertyEntry{
			CdxPropName:  p.Name,
			CdxPropValue: p.Value,
		})
	}
	if len(entries) > 0 {
		pkg.Extensions = append(pkg.Extensions, &spdx3.CdxPropertiesExtension{
			CdxProperties: entries,
		})
	}
}

func (m *Marshaler) mapRelationshipType(relType core.RelationshipType) spdx3.RelationshipType {
	switch relType {
	case core.RelationshipDependsOn:
		return spdx3.RelationshipType_DependsOn
	case core.RelationshipContains:
		return spdx3.RelationshipType_Contains
	case core.RelationshipDescribes:
		return spdx3.RelationshipType_Describes
	default:
		return spdx3.RelationshipType_DependsOn
	}
}

func (m *Marshaler) mapDigest(d digest.Digest) (spdx3.AnyIntegrityMethod, bool) {
	var alg spdx3.HashAlgorithm
	switch d.Algorithm() {
	case digest.SHA1:
		alg = spdx3.HashAlgorithm_Sha1
	case digest.SHA256:
		alg = spdx3.HashAlgorithm_Sha256
	case digest.MD5:
		alg = spdx3.HashAlgorithm_Md5
	default:
		return nil, false
	}
	return &spdx3.Hash{
		Algorithm: alg,
		Value:     d.Encoded(),
	}, true
}

func (m *Marshaler) normalizeLicense(licenses []string) string {
	if len(licenses) == 0 {
		return ""
	}
	license := strings.Join(licenses, " AND ")
	normalizedLicense, err := expression.Normalize(license, licensing.NormalizeLicenseExpression, expression.NormalizeForSPDX)
	if err != nil {
		m.logger.Warn("Unable to normalize SPDX 3.0 license", log.String("license", license))
		return license
	}
	return normalizedLicense.String()
}

func (m *Marshaler) calcElementID(v any) (string, error) {
	f, err := m.hasher(v, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		return "", xerrors.Errorf("could not build element ID for %+v: %w", v, err)
	}
	return strconv.FormatUint(f, 16), nil
}

func spdxPkgName(component *core.Component) string {
	if p := component.PkgIdentifier.PURL; p != nil && component.Group != "" {
		if p.Type == packageurl.TypeMaven || p.Type == packageurl.TypeGradle {
			return component.Group + ":" + component.Name
		}
		return component.Group + "/" + component.Name
	}
	return component.Name
}
