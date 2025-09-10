// internal/fwht/parallel.go
package fwht

import (
	"errors"
	"runtime"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// MatVecHadamardPar runs FWHT in parallel.
// - len(in) must be a power of two
// - workers <= 0 => use GOMAXPROCS(0)
// Implementation: Jacobian in-place per stage.
func MatVecHadamardPar(in []bn254.G1Affine, workers int) ([]bn254.G1Affine, error) {
	n := len(in)
	if n == 0 {
		return nil, nil
	}
	if n&(n-1) != 0 {
		return nil, errors.New("MatVecHadamardPar: length must be a power of two")
	}
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 1 {
		workers = 1
	}

	// Affine -> Jacobian (once)
	outJac := make([]bn254.G1Jac, n)
	for i := 0; i < n; i++ {
		outJac[i].FromAffine(&in[i])
	}

	// Stages
	for step := 1; step < n; step <<= 1 {
		block := step << 1          // elements per block
		nb := n / block             // number of blocks at this stage
		eff := workers
		if eff > nb {
			eff = nb
		}

		if eff <= 1 || nb <= 1 {
			// serial
			for b := 0; b < nb; b++ {
				base := b * block
				for j := 0; j < step; j++ {
					a := &outJac[base+j]
					c := &outJac[base+j+step]

					tmpA := *a
					tmpC := *c

					sum := tmpA
					sum.AddAssign(&tmpC)

					negC := tmpC
					negC.Neg(&negC)
					diff := tmpA
					diff.AddAssign(&negC)

					*a = sum
					*c = diff
				}
			}
			continue
		}

		// parallel
		var wg sync.WaitGroup
		chunk := (nb + eff - 1) / eff
		for w := 0; w < eff; w++ {
			startBlock := w * chunk
			endBlock := startBlock + chunk
			if startBlock >= nb {
				break
			}
			if endBlock > nb {
				endBlock = nb
			}
			wg.Add(1)
			go func(b0, b1 int) {
				defer wg.Done()
				for b := b0; b < b1; b++ {
					base := b * block
					for j := 0; j < step; j++ {
						a := &outJac[base+j]
						c := &outJac[base+j+step]

						tmpA := *a
						tmpC := *c

						sum := tmpA
						sum.AddAssign(&tmpC)

						negC := tmpC
						negC.Neg(&negC)
						diff := tmpA
						diff.AddAssign(&negC)

						*a = sum
						*c = diff
					}
				}
			}(startBlock, endBlock)
		}
		wg.Wait()
	}

	// Jacobian -> Affine (once)
	outAff := make([]bn254.G1Affine, n)
	for i := 0; i < n; i++ {
		outAff[i].FromJacobian(&outJac[i])
	}
	return outAff, nil
}
