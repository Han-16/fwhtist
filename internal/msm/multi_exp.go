package msm

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// MultiExpMSM computes sum_i scalars[i] * points[i] using gnark-crypto MultiExp (fast MSM).
func MultiExpMSM(points []bn254.G1Affine, scalars []fr.Element) (bn254.G1Affine, error) {
	if len(points) != len(scalars) {
		return bn254.G1Affine{}, ErrLenMismatch
	}
	if len(points) == 0 {
		return bn254.G1Affine{}, nil
	}

	var acc bn254.G1Jac
	acc.MultiExp(points, scalars, ecc.MultiExpConfig{})

	var out bn254.G1Affine
	out.FromJacobian(&acc)
	return out, nil
}