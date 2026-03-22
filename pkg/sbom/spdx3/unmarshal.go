package spdx3

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
	spdx3 "github.com/spdx/tools-golang/spdx/v3/v3_0"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
)

// SPDX3 implements the JSON unmarshaling interface for SPDX 3.0 documents
// and converts them into Trivy's core.BOM intermediate representation.
type SPDX3 struct {
	*core.BOM
	trivySBOM bool
}

// UnmarshalJSON parses an SPDX 3.0 JSON-LD document using tools-golang's
// FromJSON parser and populates the embedded core.BOM.
func (s *SPDX3) UnmarshalJSON(b []byte) error {
	if s.BOM == nil {
		s.BOM = core.NewBOM(core.Options{})
	}

	var doc Document
	if err := doc.FromJSON(bytes.NewReader(b)); err != nil {
		return xerrors.Errorf("failed to decode SPDX 3.0 JSON-LD: %w", err)
	}

	if err := s.unmarshal(&doc); err != nil {
		return xerrors.Errorf("failed to unmarshal SPDX 3.0: %w", err)
	}
	return nil
}

func (s *SPDX3) unmarshal(doc *Document) error {
	s.trivySBOM = isTrivySBOM(doc)

	// Build an index of element ID → element for relationship resolution
	rootIDs := make(map[string]bool)
	for _, re := range doc.RootElements {
		if re != nil {
			rootIDs[re.GetID()] = true
		}
	}

	// Index files by their ID for relationship processing
	fileElements := make(map[string]*spdx3.File)

	// Index package components by their SPDX ID
	components := make(map[string]*core.Component)
	elementToComp := make(map[spdx3.AnyElement]*core.Component)

	// First pass: identify files
	for _, elem := range doc.Elements {
		if file, ok := elem.(*spdx3.File); ok {
			fileElements[file.GetID()] = file
		}
	}

	// Second pass: parse packages into components
	for _, elem := range doc.Elements {
		pkg, ok := elem.(*spdx3.Package)
		if !ok {
			continue
		}

		component := s.parsePackage(pkg)

		// Check if root
		if rootIDs[pkg.GetID()] {
			component.Root = true
		}

		s.BOM.AddComponent(component)
		components[pkg.GetID()] = component
		elementToComp[pkg] = component
	}

	// Third pass: parse relationships
	for _, elem := range doc.Elements {
		rel, ok := elem.(spdx3.AnyRelationship)
		if !ok {
			continue
		}

		// Skip DESCRIBES relationships (root designation is handled above)
		if rel.GetType() == spdx3.RelationshipType_Describes {
			continue
		}

		from := rel.GetFrom()
		if from == nil {
			continue
		}

		fromComp, ok := components[from.GetID()]
		if !ok {
			continue
		}

		// Handle license relationships (HasDeclaredLicense / HasConcludedLicense)
		if rel.GetType() == spdx3.RelationshipType_HasDeclaredLicense ||
			rel.GetType() == spdx3.RelationshipType_HasConcludedLicense {
			for _, to := range rel.GetTo() {
				if le, ok := to.(*spdx3.LicenseExpression); ok && le != nil {
					expr := le.LicenseExpression
					if expr != "" && expr != NoAssertionValue && expr != NoneValue {
						fromComp.Licenses = append(fromComp.Licenses, expr)
					}
				}
			}
			continue
		}

		for _, to := range rel.GetTo() {
			if to == nil {
				continue
			}

			// Handle file CONTAINS relationships
			if rel.GetType() == spdx3.RelationshipType_Contains {
				if file, isFile := fileElements[to.GetID()]; isFile {
					fromComp.Files = append(fromComp.Files, core.File{
						Path: file.Name,
					})
					continue
				}
			}

			// Package-to-package relationship
			toComp, ok := components[to.GetID()]
			if !ok {
				continue
			}
			s.BOM.AddRelationship(fromComp, toComp, mapRelationshipType(rel.GetType()))
		}
	}

	return nil
}

// parsePackage converts an SPDX 3.0 Package to a core.Component.
func (s *SPDX3) parsePackage(pkg *spdx3.Package) *core.Component {
	component := &core.Component{
		Type:    parseComponentType(pkg),
		Name:    pkg.Name,
		Version: pkg.Version,
	}

	// Parse PURL from external identifiers
	for _, extID := range pkg.ExternalIdentifiers {
		if extID.GetType() == spdx3.ExternalIdentifierType_PackageURL {
			purl, err := packageurl.FromString(extID.GetIdentifier())
			if err == nil {
				component.PkgIdentifier.PURL = &purl
				break
			}
		}
	}

	// Fallback: try PackageURL field
	if component.PkgIdentifier.PURL == nil && pkg.PackageURL != "" {
		purl, err := packageurl.FromString(string(pkg.PackageURL))
		if err == nil {
			component.PkgIdentifier.PURL = &purl
		}
	}

	// Note: In SPDX 3.0, licenses are expressed as Relationships
	// (HasDeclaredLicense/HasConcludedLicense) and are parsed in the
	// relationship processing pass.

	// Source info
	if strings.HasPrefix(pkg.SourceInfo, SourcePackagePrefix) {
		srcPkgName := strings.TrimPrefix(pkg.SourceInfo, SourcePackagePrefix+" ")
		component.SrcName, component.SrcVersion, _ = strings.Cut(srcPkgName, " ")
	} else if strings.HasPrefix(pkg.SourceInfo, SourceFilePrefix) {
		component.SrcFile = strings.TrimPrefix(pkg.SourceInfo, SourceFilePrefix+" ")
	}

	// Supplier
	if supplier := pkg.SuppliedBy; supplier != nil {
		component.Supplier = supplier.GetName()
	}

	// Checksums from integrity methods
	var digests []digest.Digest
	for _, im := range pkg.VerifiedUsing {
		if hash, ok := im.(*spdx3.Hash); ok {
			alg := mapHashAlgorithm(hash.Algorithm)
			if alg != "" {
				digests = append(digests, digest.Digest(fmt.Sprintf("%s:%s", alg, hash.Value)))
			}
		}
	}
	if len(digests) > 0 {
		component.Files = append(component.Files, core.File{
			Digests: digests,
		})
	}

	// Properties from CdxPropertiesExtension
	for _, ext := range pkg.Extensions {
		if cdx, ok := ext.(*spdx3.CdxPropertiesExtension); ok {
			for _, prop := range cdx.CdxProperties {
				component.Properties = append(component.Properties, core.Property{
					Name:  prop.GetCdxPropName(),
					Value: prop.GetCdxPropValue(),
				})
			}
		}
	}

	return component
}

// parseComponentType determines the core.ComponentType from an SPDX 3.0 Package.
func parseComponentType(pkg *spdx3.Package) core.ComponentType {
	switch pkg.PrimaryPurpose {
	case spdx3.SoftwarePurpose_OperatingSystem:
		return core.TypeOS
	case spdx3.SoftwarePurpose_Application:
		return core.TypeApplication
	case spdx3.SoftwarePurpose_Library, spdx3.SoftwarePurpose_Framework:
		return core.TypeLibrary
	case spdx3.SoftwarePurpose_Container:
		return core.TypeContainerImage
	case spdx3.SoftwarePurpose_Source:
		return core.TypeRepository
	default:
		return core.TypeLibrary
	}
}

// mapRelationshipType converts SPDX 3.0 relationship types to core types.
func mapRelationshipType(relType spdx3.RelationshipType) core.RelationshipType {
	switch relType {
	case spdx3.RelationshipType_Describes:
		return core.RelationshipDescribes
	case spdx3.RelationshipType_Contains:
		return core.RelationshipContains
	case spdx3.RelationshipType_DependsOn:
		return core.RelationshipDependsOn
	default:
		return core.RelationshipDependsOn
	}
}

// mapHashAlgorithm converts tools-golang HashAlgorithm to a digest algorithm string.
func mapHashAlgorithm(alg spdx3.HashAlgorithm) string {
	switch alg {
	case spdx3.HashAlgorithm_Sha1:
		return "sha1"
	case spdx3.HashAlgorithm_Sha256:
		return "sha256"
	case spdx3.HashAlgorithm_Sha384:
		return "sha384"
	case spdx3.HashAlgorithm_Sha512:
		return "sha512"
	case spdx3.HashAlgorithm_Md5:
		return "md5"
	default:
		return ""
	}
}

// isTrivySBOM checks if the document was created by Trivy.
func isTrivySBOM(doc *Document) bool {
	if doc.CreationInfo == nil {
		return false
	}
	ci, ok := doc.CreationInfo.(*spdx3.CreationInfo)
	if !ok {
		return false
	}
	for _, tool := range ci.CreatedUsing {
		if tool != nil && strings.Contains(tool.GetName(), "trivy") {
			return true
		}
	}
	return false
}
