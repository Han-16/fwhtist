package fwht

import (
	"errors"
	"runtime"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// 구간별 시간을 담는 프로파일
type FWHTProfile struct {
	N               int
	Workers         int
	Stages          int
	TAffineToJac    time.Duration
	TButterflyTotal time.Duration
	PerStage        []time.Duration // 각 stage별 시간
	TJacToAff       time.Duration   // 배치 변환(또는 per-point 변환) 시간
	TTotal          time.Duration
}

// MatVecHadamardParBatchProfile:
// - FWHT + 배치 Jacobian→Affine 변환
// - 구간별 시간을 FWHTProfile로 반환
func MatVecHadamardParBatchProfile(in []bn254.G1Affine, workers int) ([]bn254.G1Affine, FWHTProfile, error) {
	var prof FWHTProfile
	n := len(in)
	prof.N = n
	if n == 0 {
		return nil, prof, nil
	}
	if n&(n-1) != 0 {
		return nil, prof, errors.New("MatVecHadamardParBatchProfile: length must be a power of two")
	}
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 1 {
		workers = 1
	}
	prof.Workers = workers
	for t := 1; t < n; t <<= 1 {
		prof.Stages++
	}
	prof.PerStage = make([]time.Duration, prof.Stages)

	tAllStart := time.Now()

	// 1) Affine -> Jacobian (병렬)
	t0 := time.Now()
	outJac := make([]bn254.G1Jac, n)
	parallelRange(n, workers, func(i0, i1 int) {
		for i := i0; i < i1; i++ {
			outJac[i].FromAffine(&in[i])
		}
	})
	prof.TAffineToJac = time.Since(t0)

	// 2) Stages (butterfly) — 2D 타일링 적용
	var stageIdx int
	tButterStart := time.Now()
	for step := 1; step < n; step <<= 1 {
		block := step << 1
		nb := n / block

		tStage := time.Now()

		// 태스크 구성: 블록 나누기 + (필요시) j축 타일링
		type taskT struct{ b0, b1, j0, j1 int }
		tasks := make([]taskT, 0, workers*3)

		// 코어가 놀지 않도록 목표 태스크 수를 여유 있게 설정
		targetTasks := workers * 3
		if targetTasks < workers {
			targetTasks = workers
		}

		if nb >= targetTasks {
			// 블록만 잘게 쪼개도 충분
			chunkB := (nb + targetTasks - 1) / targetTasks
			for b0 := 0; b0 < nb; b0 += chunkB {
				b1 := b0 + chunkB
				if b1 > nb {
					b1 = nb
				}
				tasks = append(tasks, taskT{b0: b0, b1: b1, j0: 0, j1: step})
			}
		} else {
			// nb가 작아 병렬도가 부족 → j축까지 타일링
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
				// nb가 작으므로 동일 j-타일에 대해 모든 블록을 범위로 잡아 태스크 생성
				tasks = append(tasks, taskT{b0: 0, b1: nb, j0: j0, j1: j1})
			}
		}

		// 태스크 실행: 고정 워커 수로 채널 소비
		if len(tasks) <= 1 {
			// 직렬 처리(아주 작은 스테이지 최적화)
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

		prof.PerStage[stageIdx] = time.Since(tStage)
		stageIdx++
	}
	prof.TButterflyTotal = time.Since(tButterStart)

	// 3) Jacobian -> Affine (배치 변환 + 병렬)
	t2 := time.Now()
	outAff := BatchJacToAffG1Par(outJac, workers)
	prof.TJacToAff = time.Since(t2)

	prof.TTotal = time.Since(tAllStart)
	return outAff, prof, nil
}

// MatVecHadamardParProfile:
// - FWHT + per-point Jacobian→Affine 변환
// - 구간별 시간을 FWHTProfile로 반환
func MatVecHadamardParProfile(in []bn254.G1Affine, workers int) ([]bn254.G1Affine, FWHTProfile, error) {
	var prof FWHTProfile
	n := len(in)
	prof.N = n
	if n == 0 {
		return nil, prof, nil
	}
	if n&(n-1) != 0 {
		return nil, prof, errors.New("MatVecHadamardParProfile: length must be a power of two")
	}
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 1 {
		workers = 1
	}
	prof.Workers = workers
	for t := 1; t < n; t <<= 1 {
		prof.Stages++
	}
	prof.PerStage = make([]time.Duration, prof.Stages)

	tAllStart := time.Now()

	// 1) Affine -> Jacobian
	t0 := time.Now()
	outJac := make([]bn254.G1Jac, n)
	parallelRange(n, workers, func(i0, i1 int) {
		for i := i0; i < i1; i++ {
			outJac[i].FromAffine(&in[i])
		}
	})
	prof.TAffineToJac = time.Since(t0)

	// 2) Butterfly — 2D 타일링 적용 (per-point 변환 버전도 동일하게 개선)
	var stageIdx int
	tButterStart := time.Now()
	for step := 1; step < n; step <<= 1 {
		block := step << 1
		nb := n / block

		tStage := time.Now()

		type taskT struct{ b0, b1, j0, j1 int }
		tasks := make([]taskT, 0, workers*3)

		targetTasks := workers * 3
		if targetTasks < workers {
			targetTasks = workers
		}

		if nb >= targetTasks {
			chunkB := (nb + targetTasks - 1) / targetTasks
			for b0 := 0; b0 < nb; b0 += chunkB {
				b1 := b0 + chunkB
				if b1 > nb {
					b1 = nb
				}
				tasks = append(tasks, taskT{b0: b0, b1: b1, j0: 0, j1: step})
			}
		} else {
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

		if len(tasks) <= 1 {
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

		prof.PerStage[stageIdx] = time.Since(tStage)
		stageIdx++
	}
	prof.TButterflyTotal = time.Since(tButterStart)

	// 3) Jacobian -> Affine  (per-point FromJacobian)
	t2 := time.Now()
	outAff := make([]bn254.G1Affine, n)
	parallelRange(n, workers, func(i0, i1 int) {
		for i := i0; i < i1; i++ {
			outAff[i].FromJacobian(&outJac[i])
		}
	})
	prof.TJacToAff = time.Since(t2)

	prof.TTotal = time.Since(tAllStart)
	return outAff, prof, nil
}

