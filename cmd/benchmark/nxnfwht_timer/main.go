// go run ./nxnfwht_timer <exp> [maxProcs] [mode]
//   exp     : n=2^exp (예: 16 -> n=65536)
//   maxProcs: 기본은 runtime.NumCPU()
//   mode    : const | rand  (기본 const)
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

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func pct(d, total time.Duration) float64 {
	if total == 0 {
		return 0
	}
	return float64(d) * 100 / float64(total)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./nxnfwht_timer <exp> [maxProcs] [mode]")
		return
	}

	exp, err := strconv.Atoi(os.Args[1])
	must(err)
	if exp < 0 {
		panic("exp must be non-negative")
	}
	n := 1 << exp

	maxProcs := runtime.NumCPU()
	if len(os.Args) >= 3 {
		maxProcs, err = strconv.Atoi(os.Args[2])
		must(err)
		if maxProcs <= 0 {
			maxProcs = runtime.NumCPU()
		}
	}
	runtime.GOMAXPROCS(maxProcs)

	mode := "const"
	if len(os.Args) >= 4 {
		mode = strings.ToLower(os.Args[3])
	}
	if mode != "const" && mode != "rand" {
		panic(`mode must be "const" or "rand"`)
	}

	// 준비: 입력 포인트
	var points []bn254.G1Affine
	switch mode {
	case "const":
		_, _, g, _ := bn254.Generators()
		points = make([]bn254.G1Affine, n)
		for i := 0; i < n; i++ {
			points[i] = g
		}
	case "rand":
		points, err = randutil.RandomPointsG1Par(n, maxProcs)
		must(err)
	}

	// 워밍업 (JIT/메모리 히트)
	_, _, err = fwht.MatVecHadamardParBatchProfile(points, maxProcs)
	must(err)

	// 단일 실행 프로파일 (원하면 여러 번 돌려 평균 내도 좋음)
	_, prof, err := fwht.MatVecHadamardParBatchProfile(points, maxProcs)
	must(err)

	// 출력
	fmt.Printf("\n== FWHT Profile (n=%d, exp=%d, workers=%d, stages=%d, mode=%s)\n",
		prof.N, exp, prof.Workers, prof.Stages, mode)

	fmt.Printf("Affine -> Jacobian : %v (%.1f%%)\n",
		prof.TAffineToJac, pct(prof.TAffineToJac, prof.TTotal))

	fmt.Printf("Butterfly (total)  : %v (%.1f%%)\n",
		prof.TButterflyTotal, pct(prof.TButterflyTotal, prof.TTotal))

	for i, d := range prof.PerStage {
		fmt.Printf("  - Stage %2d        : %v (%.1f%% of total)\n",
			i, d, pct(d, prof.TTotal))
	}

	fmt.Printf("Jacobian -> Affine : %v (%.1f%%)\n",
		prof.TJacToAff, pct(prof.TJacToAff, prof.TTotal))

	fmt.Printf("Total              : %v (100.0%%)\n\n", prof.TTotal)
}
