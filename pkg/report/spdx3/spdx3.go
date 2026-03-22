package spdx3

import (
	"context"
	"io"

	"golang.org/x/xerrors"

	tspdx3 "github.com/aquasecurity/trivy/pkg/sbom/spdx3"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Writer outputs an SPDX 3.0 JSON-LD document using the tools-golang
// Document.ToJSON serializer for spec-compliant output.
type Writer struct {
	output    io.Writer
	version   string
	marshaler *tspdx3.Marshaler
}

// NewWriter creates a new SPDX 3.0 report writer.
func NewWriter(output io.Writer, version string) Writer {
	return Writer{
		output:    output,
		version:   version,
		marshaler: tspdx3.NewMarshaler(version),
	}
}

// Write marshals the report into SPDX 3.0 JSON-LD format and writes it.
// It delegates JSON-LD serialization to tools-golang's Document.ToJSON,
// which handles namespace mapping, blank node IDs, and CreationInfo propagation.
func (w Writer) Write(ctx context.Context, report types.Report) error {
	doc, err := w.marshaler.MarshalReport(ctx, report)
	if err != nil {
		return xerrors.Errorf("failed to marshal SPDX 3.0: %w", err)
	}

	// ToJSON handles:
	// - Setting CreationInfo on all elements that lack it
	// - Collecting nested element references into the root Elements slice
	// - Managing document URI prefixes and namespace mappings
	// - Outputting compact JSON-LD
	if err := doc.ToJSON(w.output); err != nil {
		return xerrors.Errorf("failed to write SPDX 3.0 JSON-LD: %w", err)
	}

	return nil
}
