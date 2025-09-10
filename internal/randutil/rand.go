package randutil

import (
	"crypto/rand"

	// "github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func RandomScalars(n int) ([]fr.Element, error) {
	res := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		b, err := rand.Int(rand.Reader, fr.Modulus())
		if err != nil {
			return nil, err
		}
		var e fr.Element
		e.SetBigInt(b)
		res[i] = e
	}
	return res, nil
}

func RandomPointsG1(n int) ([]bn254.G1Affine, error) {
	res := make([]bn254.G1Affine, n)

	_, _, g1GenAff, _ := bn254.Generators()

	for i := 0; i < n; i++ {
		scalar, err := rand.Int(rand.Reader, fr.Modulus())
		if err != nil {
			return nil, err
		}
		var p bn254.G1Affine
		p.ScalarMultiplication(&g1GenAff, scalar)
		res[i] = p
	}
	return res, nil
}