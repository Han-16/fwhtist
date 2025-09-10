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
// 변환(FromAffine/FromJacobian)도 parallelRange로 병렬화.
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

	// Affine -> Jacobian (parallelized)
	outJac := make([]bn254.G1Jac, n)
	parallelRange(n, workers, func(i0, i1 int) {
		for i := i0; i < i1; i++ {
			outJac[i].FromAffine(&in[i])
		}
	})

	// Stages
	for step := 1; step < n; step <<= 1 {
		block := step << 1 // elems per block
		nb := n / block    // number of blocks at this stage
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

					ta := *a
					tc := *c

					sum := ta
					sum.AddAssign(&tc)

					tc.Neg(&tc)
					diff := ta
					diff.AddAssign(&tc)

					*a = sum
					*c = diff
				}
			}
			continue
		}

		// parallel by blocks
		var wg sync.WaitGroup
		chunk := (nb + eff - 1) / eff
		for w := 0; w < eff; w++ {
			b0 := w * chunk
			if b0 >= nb {
				break
			}
			b1 := b0 + chunk
			if b1 > nb {
				b1 = nb
			}
			wg.Add(1)
			go func(b0, b1 int) {
				defer wg.Done()
				for b := b0; b < b1; b++ {
					base := b * block
					for j := 0; j < step; j++ {
						a := &outJac[base+j]
						c := &outJac[base+j+step]

						ta := *a
						tc := *c

						sum := ta
						sum.AddAssign(&tc)

						tc.Neg(&tc)
						diff := ta
						diff.AddAssign(&tc)

						*a = sum
						*c = diff
					}
				}
			}(b0, b1)
		}
		wg.Wait()
	}

	// Jacobian -> Affine (parallelized per-point)
	outAff := make([]bn254.G1Affine, n)
	parallelRange(n, workers, func(i0, i1 int) {
		for i := i0; i < i1; i++ {
			outAff[i].FromJacobian(&outJac[i])
		}
	})

	return outAff, nil
}

// MatVecHadamardParBatch runs FWHT in parallel and finishes with
// a batch Jacobian->Affine conversion (single inversion + parallel multiplies).
// - len(in) must be a power of two
// - workers <= 0 => use GOMAXPROCS(0)
func MatVecHadamardParBatch(in []bn254.G1Affine, workers int) ([]bn254.G1Affine, error) {
	n := len(in)
	if n == 0 {
		return nil, nil
	}
	if n&(n-1) != 0 {
		return nil, errors.New("MatVecHadamardParBatch: length must be a power of two")
	}
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 1 {
		workers = 1
	}

	// Affine -> Jacobian (parallelized)
	outJac := make([]bn254.G1Jac, n)
	parallelRange(n, workers, func(i0, i1 int) {
		for i := i0; i < i1; i++ {
			outJac[i].FromAffine(&in[i])
		}
	})

	// Stages (동일)
	for step := 1; step < n; step <<= 1 {
		block := step << 1
		nb := n / block
		eff := workers
		if eff > nb {
			eff = nb
		}

		if eff <= 1 || nb <= 1 {
			for b := 0; b < nb; b++ {
				base := b * block
				for j := 0; j < step; j++ {
					a := &outJac[base+j]
					c := &outJac[base+j+step]

					ta := *a
					tc := *c

					sum := ta
					sum.AddAssign(&tc)

					tc.Neg(&tc)
					diff := ta
					diff.AddAssign(&tc)

					*a = sum
					*c = diff
				}
			}
			continue
		}

		var wg sync.WaitGroup
		chunk := (nb + eff - 1) / eff
		for w := 0; w < eff; w++ {
			b0 := w * chunk
			if b0 >= nb {
				break
			}
			b1 := b0 + chunk
			if b1 > nb {
				b1 = nb
			}
			wg.Add(1)
			go func(b0, b1 int) {
				defer wg.Done()
				for b := b0; b < b1; b++ {
					base := b * block
					for j := 0; j < step; j++ {
						a := &outJac[base+j]
						c := &outJac[base+j+step]

						ta := *a
						tc := *c

						sum := ta
						sum.AddAssign(&tc)

						tc.Neg(&tc)
						diff := ta
						diff.AddAssign(&tc)

						*a = sum
						*c = diff
					}
				}
			}(b0, b1)
		}
		wg.Wait()
	}

	// Jacobian -> Affine (batch inversion + parallel multiplies)
	outAff := BatchJacToAffG1Par(outJac, workers)
	return outAff, nil
}
