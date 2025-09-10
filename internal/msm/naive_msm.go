package msm

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

var ErrLenMismatch = errors.New("points and scalars must have same length")

// NaiveMSM computes sum_i scalars[i] * points[i] in the simplest way.
func NaiveMSM(points []bn254.G1Affine, scalars []fr.Element) (bn254.G1Affine, error) {
	if len(points) != len(scalars) {
		return bn254.G1Affine{}, ErrLenMismatch
	}
	if len(points) == 0 {
		return bn254.G1Affine{}, nil
	}

	var accJ bn254.G1Jac
	for i := range points {
		var termAff bn254.G1Affine
		termAff.ScalarMultiplication(&points[i], scalars[i].BigInt(new(big.Int)))

		var termJ bn254.G1Jac
		termJ.FromAffine(&termAff)
		accJ.AddAssign(&termJ)
	}

	var out bn254.G1Affine
	out.FromJacobian(&accJ)
	return out, nil
}
