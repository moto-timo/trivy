// Package spdx3 provides marshaling/unmarshaling for SPDX 3.0 JSON-LD documents
// using the tools-golang spdx/v3/v3_0 library for spec-compliant types and JSON-LD
// serialization.
//
// Trivy-specific constants and helpers are defined here; the SPDX 3.0 data model
// types (Document, Package, Relationship, Vulnerability, etc.) are imported from
// github.com/spdx/tools-golang/spdx/v3/v3_0.
package spdx3

import (
	spdx3 "github.com/spdx/tools-golang/spdx/v3/v3_0"
)

// Re-export the tools-golang Document type so callers can use spdx3.Document
// without importing tools-golang directly.
type Document = spdx3.Document

// Trivy-specific constants for SPDX 3.0 document creation.
const (
	DocumentNamespacePrefix = "https://trivy.dev"
	CreatorOrganization     = "aquasecurity"
	CreatorTool             = "trivy"
	NoAssertionValue        = "NOASSERTION"
	NoneValue               = "NONE"
	SourcePackagePrefix     = "built package from:"
	SourceFilePrefix        = "package found in:"
)
