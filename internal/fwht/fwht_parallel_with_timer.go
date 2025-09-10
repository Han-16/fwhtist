package fwht
import (
    "errors"
    "runtime"
    "sync"
    "time" // 추가
    "github.com/consensys/gnark-crypto/ecc/bn254"
)

// 구간별 시간을 담는 프로파일
type FWHTProfile struct {
    N                  int
    Workers            int
    Stages             int
    TAffineToJac       time.Duration
    TButterflyTotal    time.Duration
    PerStage           []time.Duration // 각 stage별 시간
    TJacToAff          time.Duration   // 배치 변환(또는 per-point 변환) 시간
    TTotal             time.Duration
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
    prof.Stages = 0
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

    // 2) Stages (butterfly)
    var stageIdx int
    tButterStart := time.Now()
    for step := 1; step < n; step <<= 1 {
        block := step << 1
        nb := n / block
        eff := workers
        if eff > nb {
            eff = nb
        }

        tStage := time.Now()
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
        } else {
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
