package spdx3

// Bridge to expose spdx3 marshaler internals to tests in the spdx3_test package.

// NormalizeLicense exports normalizeLicense for testing.
func (m *Marshaler) NormalizeLicense(licenses []string) string {
	return m.normalizeLicense(licenses)
}
