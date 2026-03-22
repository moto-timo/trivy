package spdx3_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/package-url/packageurl-go"
	spdx3model "github.com/spdx/tools-golang/spdx/v3/v3_0"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/clock"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"
	tspdx3 "github.com/aquasecurity/trivy/pkg/sbom/spdx3"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

func TestMarshaler_Marshal(t *testing.T) {
	testCases := []struct {
		name        string
		inputReport types.Report
		validate    func(t *testing.T, doc *tspdx3.Document)
	}{
		{
			name: "happy path for container scan",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "rails:latest",
				ArtifactType:  ftypes.TypeContainerImage,
				Metadata: types.Metadata{
					Size: 1024,
					OS: &ftypes.OS{
						Family: ftypes.CentOS,
						Name:   "8.3.2011",
						Eosl:   true,
					},
					ImageID:     "sha256:5d0da3dc976460b72c77d94c8a1ad043720b0416bfc16c52c45d4847e53fadb6",
					RepoTags:    []string{"rails:latest"},
					DiffIDs:     []string{"sha256:d871dadfb37b53ef1ca45be04fc527562b91989991a8f545345ae3be0b93f92a"},
					RepoDigests: []string{"rails@sha256:a27fd8080b517143cbbbab9dfb7c8571c40d67d534bbdee55bd6c473f432b177"},
				},
				Results: types.Results{
					{
						Target: "rails:latest (centos 8.3.2011)",
						Class:  types.ClassOSPkg,
						Type:   ftypes.CentOS,
						Packages: []ftypes.Package{
							{
								Name:    "binutils",
								Version: "2.30-93.el8",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeRPM,
										Namespace: "centos",
										Name:      "binutils",
										Version:   "2.30-93.el8",
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, doc *tspdx3.Document) {
				t.Helper()

				// Verify document name
				assert.Equal(t, "rails:latest", doc.Name)

				// Verify profile conformance includes Security
				found := false
				for _, p := range doc.ProfileConformances {
					if p == spdx3model.ProfileIdentifierType_Security {
						found = true
					}
				}
				assert.True(t, found, "should include Security profile conformance")

				// Verify root elements exist
				assert.NotEmpty(t, doc.RootElements)

				// Verify the document can be serialized to JSON-LD
				var buf bytes.Buffer
				err := doc.ToJSON(&buf)
				require.NoError(t, err)
				assert.Contains(t, buf.String(), "rails:latest")
				assert.Contains(t, buf.String(), "binutils")
			},
		},
		{
			name: "repository scan produces source purpose",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "https://github.com/aquasecurity/trivy",
				ArtifactType:  ftypes.TypeRepository,
				Results: types.Results{
					{
						Target: "package-lock.json",
						Class:  types.ClassLangPkg,
						Type:   ftypes.NodePkg,
						Packages: []ftypes.Package{
							{
								Name:    "lodash",
								Version: "4.17.21",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:    packageurl.TypeNPM,
										Name:    "lodash",
										Version: "4.17.21",
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, doc *tspdx3.Document) {
				t.Helper()

				// Verify serialization works
				var buf bytes.Buffer
				err := doc.ToJSON(&buf)
				require.NoError(t, err)
				output := buf.String()
				assert.Contains(t, output, "lodash")
				assert.Contains(t, output, "4.17.21")
			},
		},
		{
			name: "report with vulnerabilities creates VEX elements",
			inputReport: types.Report{
				SchemaVersion: report.SchemaVersion,
				ArtifactName:  "test-image:latest",
				ArtifactType:  ftypes.TypeContainerImage,
				Metadata: types.Metadata{
					OS: &ftypes.OS{
						Family: ftypes.Debian,
						Name:   "11",
					},
				},
				Results: types.Results{
					{
						Target: "test-image:latest",
						Class:  types.ClassOSPkg,
						Type:   ftypes.Debian,
						Packages: []ftypes.Package{
							{
								Name:    "openssl",
								Version: "1.1.1k-1",
								Identifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeDebian,
										Namespace: "debian",
										Name:      "openssl",
										Version:   "1.1.1k-1",
									},
								},
							},
						},
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID: "CVE-2021-3711",
								PkgName:         "openssl",
								PkgIdentifier: ftypes.PkgIdentifier{
									PURL: &packageurl.PackageURL{
										Type:      packageurl.TypeDebian,
										Namespace: "debian",
										Name:      "openssl",
										Version:   "1.1.1k-1",
									},
								},
								InstalledVersion: "1.1.1k-1",
								FixedVersion:     "1.1.1l-1",
								Vulnerability: types.Vulnerability{
									Severity: "HIGH",
								},
								PrimaryURL: "https://avd.aquasec.com/nvd/cve-2021-3711",
							},
						},
					},
				},
			},
			validate: func(t *testing.T, doc *tspdx3.Document) {
				t.Helper()

				// Verify JSON-LD output contains VEX elements
				var buf bytes.Buffer
				err := doc.ToJSON(&buf)
				require.NoError(t, err)
				output := buf.String()

				assert.Contains(t, output, "CVE-2021-3711")
				assert.Contains(t, output, "VexAffectedVulnAssessmentRelationship")
				assert.Contains(t, output, "Upgrade openssl to version 1.1.1l-1")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-000000000001")
			ctx := clock.With(clock.NewFixedClock(time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC)), t)

			marshaler := tspdx3.NewMarshaler("0.56.2")
			doc, err := marshaler.MarshalReport(ctx, tc.inputReport)
			require.NoError(t, err)

			tc.validate(t, doc)
		})
	}
}

func TestMarshaler_Marshal_EmptyReport(t *testing.T) {
	uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-000000000001")
	ctx := clock.With(clock.NewFixedClock(time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC)), t)

	inputReport := types.Report{
		SchemaVersion: 2,
		ArtifactName:  "empty",
		ArtifactType:  ftypes.TypeFilesystem,
	}

	marshaler := tspdx3.NewMarshaler("0.56.2")
	doc, err := marshaler.MarshalReport(ctx, inputReport)
	require.NoError(t, err)
	require.NotNil(t, doc)

	assert.Equal(t, "empty", doc.Name)

	// Verify it serializes without error
	var buf bytes.Buffer
	err = doc.ToJSON(&buf)
	require.NoError(t, err)
}
