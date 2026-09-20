// Package crypto defines CryptoProvider, the only entry point to cryptographic
// primitives. Callers never import a concrete suite directly, so the GOST and
// Curve25519 suites stay interchangeable for comparison runs.
package crypto
