// go run ./nxnfwht_compare <exp> [maxProcs] [mode] [iters]
//   exp     : n=2^exp
//   maxProcs: default NumCPU
//   mode    : const | rand (default const)
//   iters   : 각 변형을 몇 번 반복할지 (기본 3; best와 avg 출력)
package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Han-16/fwhtist/internal/fwht"
	"github.com/Han-16/fwhtist/internal/randutil"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func must(err error) { if err != nil { panic(err) } }

func pct(d, total time.Duration) float64 {
	if total == 0 { return 0 }
	return float64(d) * 100 / float64(total)
}

func eqSlices(a, b []bn254.G1Affine) bool {
	if len(a) != len(b) { return false }
	for i := range a {
		if !a[i].X.Equal(&b[i].X) || !a[i].Y.Equal(&b[i].Y) {
			return false
		}
	}
	return true
}

type runStats struct {
	best, total time.Duration
	lastProf    fwht.FWHTProfile
}

func runBatch(points []bn254.G1Affine, procs, iters int) (out []bn254.G1Affine, st runStats, err error) {
	for it := 0; it < iters; it++ {
		start := time.Now()
		var prof fwht.FWHTProfile
		out, prof, err = fwht.MatVecHadamardParBatchProfile(points, procs)
		if err != nil { return nil, st, err }
		elapsed := time.Since(start)
		if it == 0 || elapsed < st.best { st.best = elapsed }
		st.total += elapsed
		st.lastProf = prof
	}
	return out, st, nil
}

func runPerPoint(points []bn254.G1Affine, procs, iters int) (out []bn254.G1Affine, st runStats, err error) {
	for it := 0; it < iters; it++ {
		start := time.Now()
		var prof fwht.FWHTProfile
		out, prof, err = fwht.MatVecHadamardParProfile(points, procs)
		if err != nil { return nil, st, err }
		elapsed := time.Since(start)
		if it == 0 || elapsed < st.best { st.best = elapsed }
		st.total += elapsed
		st.lastProf = prof
	}
	return out, st, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./nxnfwht_compare <exp> [maxProcs] [mode] [iters]")
		return
	}
	exp, err := strconv.Atoi(os.Args[1]); must(err)
	if exp < 0 { panic("exp must be non-negative") }
	n := 1 << exp

	maxProcs := runtime.NumCPU()
	if len(os.Args) >= 3 {
		maxProcs, err = strconv.Atoi(os.Args[3-1]); must(err)
		if maxProcs <= 0 { maxProcs = runtime.NumCPU() }
	}
	runtime.GOMAXPROCS(maxProcs)

	mode := "const"
	if len(os.Args) >= 4 {
		mode = strings.ToLower(os.Args[4-1])
		if mode != "const" && mode != "rand" { panic(`mode must be "const" or "rand"`) }
	}

	iters := 3
	if len(os.Args) >= 5 {
		iters, err = strconv.Atoi(os.Args[5-1]); must(err)
		if iters < 1 { iters = 1 }
	}

	// 입력 생성
	var points []bn254.G1Affine
	switch mode {
	case "const":
		_, _, g, _ := bn254.Generators()
		points = make([]bn254.G1Affine, n)
		for i := 0; i < n; i++ { points[i] = g }
	case "rand":
		points, err = randutil.RandomPointsG1Par(n, maxProcs); must(err)
	}


	// 본 실행
	outPer, stPer, err := runPerPoint(points, maxProcs, iters); must(err)
	outBat, stBat, err  := runBatch   (points, maxProcs, iters); must(err)

	// 결과 동일성 검증
	same := eqSlices(outPer, outBat)

	// 출력
	avgPer := time.Duration(int64(stPer.total)/int64(iters))
	avgBat := time.Duration(int64(stBat.total)/int64(iters))
	speedupBest := float64(stPer.best) / float64(stBat.best)
	speedupAvg  := float64(avgPer)    / float64(avgBat)

	fmt.Printf("\n== FWHT Compare (n=%d, exp=%d, workers=%d, mode=%s, iters=%d)\n",
		n, exp, maxProcs, mode, iters)
	fmt.Printf("Correctness (per-point vs batch) : %v\n", same)

	fmt.Printf("\n-- Per-Point FromJacobian --\n")
	fmt.Printf("Best: %v | Avg: %v\n", stPer.best, avgPer)
	fmt.Printf("  Aff->Jac : %v (%.1f%%)\n", stPer.lastProf.TAffineToJac,  pct(stPer.lastProf.TAffineToJac,  stPer.lastProf.TTotal))
	fmt.Printf("  Butterfly: %v (%.1f%%)\n", stPer.lastProf.TButterflyTotal, pct(stPer.lastProf.TButterflyTotal, stPer.lastProf.TTotal))
	fmt.Printf("  Jac->Aff : %v (%.1f%%)\n", stPer.lastProf.TJacToAff,       pct(stPer.lastProf.TJacToAff,       stPer.lastProf.TTotal))
	fmt.Printf("  Total    : %v (100%%)\n",   stPer.lastProf.TTotal)

	fmt.Printf("\n-- Batch Inversion --\n")
	fmt.Printf("Best: %v | Avg: %v\n", stBat.best, avgBat)
	fmt.Printf("  Aff->Jac : %v (%.1f%%)\n", stBat.lastProf.TAffineToJac,  pct(stBat.lastProf.TAffineToJac,  stBat.lastProf.TTotal))
	fmt.Printf("  Butterfly: %v (%.1f%%)\n", stBat.lastProf.TButterflyTotal, pct(stBat.lastProf.TButterflyTotal, stBat.lastProf.TTotal))
	fmt.Printf("  Jac->Aff : %v (%.1f%%)\n", stBat.lastProf.TJacToAff,       pct(stBat.lastProf.TJacToAff,       stBat.lastProf.TTotal))
	fmt.Printf("  Total    : %v (100%%)\n",   stBat.lastProf.TTotal)

	fmt.Printf("\nSpeedup (PerPoint / Batch)  Best: %.2fx | Avg: %.2fx\n\n", speedupBest, speedupAvg)
}
