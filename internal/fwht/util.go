package fwht

import "github.com/consensys/gnark-crypto/ecc/bn254"

// isPowerOfTwo returns true if n is a power of two (>0).
func isPowerOfTwo(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}

// nextPow2 returns the smallest power of two >= n (n>0).
func nextPow2(n int) int {
	if n <= 1 {
		return 1
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// PadPointsToPow2 pads an affine point slice to power-of-two length
// using the group identity (zero-value Affine == infinity).
func PadPointsToPow2(in []bn254.G1Affine) []bn254.G1Affine {
	if len(in) == 0 || isPowerOfTwo(len(in)) {
		return in
	}
	out := make([]bn254.G1Affine, nextPow2(len(in)))
	copy(out, in)
	// remaining entries are zero-value (∞) by default
	return out
}
