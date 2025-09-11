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

	// Stages (2D 타일링: 블록×j)
	for step := 1; step < n; step <<= 1 {
		block := step << 1
		nb := n / block

		// 목표 태스크 수: 코어 여유 있게 3배
		targetTasks := workers * 3
		if targetTasks < workers {
			targetTasks = workers
		}

		type taskT struct{ b0, b1, j0, j1 int }
		tasks := make([]taskT, 0, targetTasks)

		if nb >= targetTasks {
			// 블록만 잘게 분할
			chunkB := (nb + targetTasks - 1) / targetTasks
			for b0 := 0; b0 < nb; b0 += chunkB {
				b1 := b0 + chunkB
				if b1 > nb {
					b1 = nb
				}
				tasks = append(tasks, taskT{b0: b0, b1: b1, j0: 0, j1: step})
			}
		} else {
			// nb가 작으면 j축까지 타일링
			jTiles := targetTasks / max(1, nb)
			if jTiles < 1 {
				jTiles = 1
			}
			if jTiles > step {
				jTiles = step
			}
			tile := (step + jTiles - 1) / jTiles
			for j0 := 0; j0 < step; j0 += tile {
				j1 := j0 + tile
				if j1 > step {
					j1 = step
				}
				tasks = append(tasks, taskT{b0: 0, b1: nb, j0: j0, j1: j1})
			}
		}

		// 태스크 실행
		if len(tasks) <= 1 {
			// 아주 작은 경우 직렬 처리
			for _, t := range tasks {
				for b := t.b0; b < t.b1; b++ {
					base := b * block
					for j := t.j0; j < t.j1; j++ {
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
			}
		} else {
			var wg sync.WaitGroup
			workCh := make(chan taskT, len(tasks))
			for _, t := range tasks {
				workCh <- t
			}
			close(workCh)

			W := min(workers, len(tasks))
			wg.Add(W)
			for w := 0; w < W; w++ {
				go func() {
					defer wg.Done()
					for t := range workCh {
						for b := t.b0; b < t.b1; b++ {
							base := b * block
							for j := t.j0; j < t.j1; j++ {
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
					}
				}()
			}
			wg.Wait()
		}
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
