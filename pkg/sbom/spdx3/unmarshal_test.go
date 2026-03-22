package spdx3_test

import (
	"bytes"
	"testing"

	spdx3model "github.com/spdx/tools-golang/spdx/v3/v3_0"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/sbom/spdx3"
)

func TestSPDX3_UnmarshalJSON(t *testing.T) {
	testCases := []struct {
		name     string
		buildDoc func() *spdx3.Document
		validate func(t *testing.T, bom *core.BOM)
	}{
		{
			name: "basic document with packages and relationships",
			buildDoc: func() *spdx3.Document {
				org := &spdx3model.Organization{Name: "aquasecurity"}
				tool := &spdx3model.Tool{Name: "trivy-0.56.2"}
				doc := spdx3model.NewDocument(spdx3model.ProfileIdentifierType_Software, "test-image:latest", org, tool)

				rootPkg := &spdx3model.Package{
					Name:           "test-image:latest",
					PrimaryPurpose: spdx3model.SoftwarePurpose_Container,
					CopyrightText:  "NOASSERTION",
				}

				opensslPkg := &spdx3model.Package{
					Name:           "openssl",
					Version:        "1.1.1k",
					PrimaryPurpose: spdx3model.SoftwarePurpose_Library,
					PackageURL:     "pkg:deb/debian/openssl@1.1.1k",
					ExternalIdentifiers: []*spdx3model.ExternalIdentifier{
						{
							Type: spdx3model.ExternalIdentifierType_PackageURL,
							Identifier:             "pkg:deb/debian/openssl@1.1.1k",
						},
					},
					CopyrightText: "NOASSERTION",
				}

				doc.RootElements = spdx3model.ElementList{rootPkg}
				doc.Elements = append(doc.Elements,
					&spdx3model.Relationship{
						From: doc,
						To:   spdx3model.ElementList{rootPkg},
						Type: spdx3model.RelationshipType_Describes,
					},
					&spdx3model.Relationship{
						From: rootPkg,
						To:   spdx3model.ElementList{opensslPkg},
						Type: spdx3model.RelationshipType_Contains,
					},
				)

				return doc
			},
			validate: func(t *testing.T, bom *core.BOM) {
				t.Helper()

				root := bom.Root()
				require.NotNil(t, root)
				assert.Equal(t, "test-image:latest", root.Name)
				assert.Equal(t, core.TypeContainerImage, root.Type)
				assert.True(t, root.Root)

				// Check components
				components := bom.Components()
				assert.Len(t, components, 2, "should have root + openssl")

				// Find openssl package
				var opensslComp *core.Component
				for _, c := range components {
					if c.Name == "openssl" {
						opensslComp = c
						break
					}
				}
				require.NotNil(t, opensslComp)
				assert.Equal(t, "1.1.1k", opensslComp.Version)
				assert.Equal(t, core.TypeLibrary, opensslComp.Type)
				require.NotNil(t, opensslComp.PkgIdentifier.PURL)
				assert.Equal(t, "openssl", opensslComp.PkgIdentifier.PURL.Name)

				// Check relationships
				rels := bom.Relationships()
				assert.NotEmpty(t, rels)

				// Find the root's relationships
				var rootRels []core.Relationship
				for id, r := range rels {
					if id == root.ID() {
						rootRels = r
						break
					}
				}
				assert.Len(t, rootRels, 1)
				assert.Equal(t, core.RelationshipContains, rootRels[0].Type)
			},
		},
		{
			name: "document with source info parsing",
			buildDoc: func() *spdx3.Document {
				org := &spdx3model.Organization{Name: "aquasecurity"}
				tool := &spdx3model.Tool{Name: "trivy-0.56.2"}
				doc := spdx3model.NewDocument(spdx3model.ProfileIdentifierType_Software, "test-repo", org, tool)

				rootPkg := &spdx3model.Package{
					Name:           "test-repo",
					PrimaryPurpose: spdx3model.SoftwarePurpose_Source,
					CopyrightText:  "NOASSERTION",
				}

				glibcPkg := &spdx3model.Package{
					Name:           "glibc",
					Version:        "2.31-13",
					PrimaryPurpose: spdx3model.SoftwarePurpose_Library,
					SourceInfo:     "built package from: glibc 2.31-13",
					CopyrightText:  "NOASSERTION",
				}

				doc.RootElements = spdx3model.ElementList{rootPkg}
				doc.Elements = append(doc.Elements,
					&spdx3model.Relationship{
						From: rootPkg,
						To:   spdx3model.ElementList{glibcPkg},
						Type: spdx3model.RelationshipType_Contains,
					},
				)

				return doc
			},
			validate: func(t *testing.T, bom *core.BOM) {
				t.Helper()

				var glibcComp *core.Component
				for _, c := range bom.Components() {
					if c.Name == "glibc" {
						glibcComp = c
						break
					}
				}
				require.NotNil(t, glibcComp)
				assert.Equal(t, "glibc", glibcComp.SrcName)
				assert.Equal(t, "2.31-13", glibcComp.SrcVersion)
			},
		},
		{
			name: "document with file elements",
			buildDoc: func() *spdx3.Document {
				org := &spdx3model.Organization{Name: "aquasecurity"}
				tool := &spdx3model.Tool{Name: "trivy-0.56.2"}
				doc := spdx3model.NewDocument(spdx3model.ProfileIdentifierType_Software, "test-fs", org, tool)

				rootPkg := &spdx3model.Package{
					Name:           "test-fs",
					PrimaryPurpose: spdx3model.SoftwarePurpose_Source,
					CopyrightText:  "NOASSERTION",
				}

				lodashPkg := &spdx3model.Package{
					Name:           "lodash",
					Version:        "4.17.21",
					PrimaryPurpose: spdx3model.SoftwarePurpose_Library,
					CopyrightText:  "NOASSERTION",
				}

				lockFile := &spdx3model.File{
					Name: "package-lock.json",
				}

				doc.RootElements = spdx3model.ElementList{rootPkg}
				doc.Elements = append(doc.Elements,
					&spdx3model.Relationship{
						From: lodashPkg,
						To:   spdx3model.ElementList{lockFile},
						Type: spdx3model.RelationshipType_Contains,
					},
					&spdx3model.Relationship{
						From: rootPkg,
						To:   spdx3model.ElementList{lodashPkg},
						Type: spdx3model.RelationshipType_Contains,
					},
				)

				return doc
			},
			validate: func(t *testing.T, bom *core.BOM) {
				t.Helper()

				var lodashComp *core.Component
				for _, c := range bom.Components() {
					if c.Name == "lodash" {
						lodashComp = c
						break
					}
				}
				require.NotNil(t, lodashComp)
				require.Len(t, lodashComp.Files, 1)
				assert.Equal(t, "package-lock.json", lodashComp.Files[0].Path)
			},
		},
		{
			name: "document with hash integrity methods",
			buildDoc: func() *spdx3.Document {
				org := &spdx3model.Organization{Name: "aquasecurity"}
				tool := &spdx3model.Tool{Name: "trivy-0.56.2"}
				doc := spdx3model.NewDocument(spdx3model.ProfileIdentifierType_Software, "test-checksums", org, tool)

				rootPkg := &spdx3model.Package{
					Name:           "test-checksums",
					PrimaryPurpose: spdx3model.SoftwarePurpose_Source,
					CopyrightText:  "NOASSERTION",
				}

				pkg := &spdx3model.Package{
					Name:           "curl",
					Version:        "7.79.1",
					PrimaryPurpose: spdx3model.SoftwarePurpose_Library,
					CopyrightText:  "NOASSERTION",
					VerifiedUsing: []spdx3model.AnyIntegrityMethod{
						&spdx3model.Hash{
							Algorithm: spdx3model.HashAlgorithm_Sha256,
							Value: "abc123def456",
						},
					},
				}

				doc.RootElements = spdx3model.ElementList{rootPkg}
				doc.Elements = append(doc.Elements,
					&spdx3model.Relationship{
						From: rootPkg,
						To:   spdx3model.ElementList{pkg},
						Type: spdx3model.RelationshipType_Contains,
					},
				)

				return doc
			},
			validate: func(t *testing.T, bom *core.BOM) {
				t.Helper()

				var curlComp *core.Component
				for _, c := range bom.Components() {
					if c.Name == "curl" {
						curlComp = c
						break
					}
				}
				require.NotNil(t, curlComp)
				require.NotEmpty(t, curlComp.Files)
				require.NotEmpty(t, curlComp.Files[0].Digests)
				assert.Contains(t, string(curlComp.Files[0].Digests[0]), "sha256")
				assert.Contains(t, string(curlComp.Files[0].Digests[0]), "abc123def456")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Build and serialize the document to JSON-LD using tools-golang
			doc := tc.buildDoc()
			var buf bytes.Buffer
			err := doc.ToJSON(&buf)
			require.NoError(t, err)

			// Unmarshal the JSON-LD into Trivy's SPDX3 representation
			s := &spdx3.SPDX3{
				BOM: core.NewBOM(core.Options{}),
			}
			err = s.UnmarshalJSON(buf.Bytes())
			require.NoError(t, err)

			tc.validate(t, s.BOM)
		})
	}
}

func TestSPDX3_IsTrivySBOM(t *testing.T) {
	// Create a document with Trivy as the creation tool
	org := &spdx3model.Organization{Name: "aquasecurity"}
	tool := &spdx3model.Tool{Name: "trivy-0.56.2"}
	doc := spdx3model.NewDocument(spdx3model.ProfileIdentifierType_Software, "test", org, tool)

	rootPkg := &spdx3model.Package{
		Name:           "test",
		PrimaryPurpose: spdx3model.SoftwarePurpose_Source,
		CopyrightText:  "NOASSERTION",
	}
	doc.RootElements = spdx3model.ElementList{rootPkg}

	// Serialize
	var buf bytes.Buffer
	err := doc.ToJSON(&buf)
	require.NoError(t, err)

	// Unmarshal
	s := &spdx3.SPDX3{
		BOM: core.NewBOM(core.Options{}),
	}
	err = s.UnmarshalJSON(buf.Bytes())
	require.NoError(t, err)

	// The BOM should be created without error
	assert.NotNil(t, s.BOM)
}
