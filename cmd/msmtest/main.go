// go run ./cmd/msmtest <exp> [iters] [maxProcs]
//   exp      : n = 2^exp
//   iters    : number of iterations (default 5)
//   maxProcs : GOMAXPROCS setting (default -1: number of CPU cores)

package main

import (
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/Han-16/fwhtist/internal/msm"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./cmd/msmtest <exp> [iters] [maxProcs]")
		return
	}
	exp, err := strconv.Atoi(os.Args[1])
	must(err)
	if exp < 0 {
		panic("exp must be non-negative")
	}
	n := 1 << exp

	iters := 5
	if len(os.Args) >= 3 {
		iters, err = strconv.Atoi(os.Args[2])
		must(err)
		if iters <= 0 {
			iters = 1
		}
	}

	maxProcs := -1
	if len(os.Args) >= 4 {
		maxProcs, err = strconv.Atoi(os.Args[3])
		must(err)
	}
	if maxProcs <= 0 {
		maxProcs = runtime.NumCPU()
	}
	runtime.GOMAXPROCS(maxProcs)

	filename := fmt.Sprintf("procs%d.txt", maxProcs)
	out, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	must(err)
	defer out.Close()

	if fi, err := out.Stat(); err == nil && fi.Size() == 0 {
		fmt.Fprintf(out, "# MSM Benchmark Results (procs=%d)\n", maxProcs)
		fmt.Fprintln(out, "# exp | n | iters | Best | Avg")
	}

	// ---- 1) s: random scalar ----
	var s fr.Element
	s.SetRandom()

	// ---- 2) scalars = [s, ..., s] ----
	scalars := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		scalars[i] = s
	}

	// ---- 3) points = [g, ..., g] ----
	_, _, g, _ := bn254.Generators() // g: G1Affine
	points := make([]bn254.G1Affine, n)
	for i := 0; i < n; i++ {
		points[i] = g
	}

	// ---- 4) expected = (n*s) * g ----
	var ns fr.Element
	ns.SetUint64(uint64(n))
	ns.Mul(&ns, &s)
	nsBytes := ns.Bytes()
	nsBig := new(big.Int).SetBytes(nsBytes[:])

	var expected bn254.G1Jac
	expected.FromAffine(&g)
	expected.ScalarMultiplication(&expected, nsBig)

	// ---- 5) warmup ----
	{
		resAff, err := msm.MultiExpMSM(points, scalars)
		must(err)
		if !equalAffineJac(resAff, expected) {
			panic("warmup: MSM result mismatch with (n*s)*g")
		}
		runtime.KeepAlive(resAff)
	}

	// ---- 6) benchmark ----
	var best, total time.Duration
	for it := 0; it < iters; it++ {
		start := time.Now()
		resAff, err := msm.MultiExpMSM(points, scalars)
		must(err)
		elapsed := time.Since(start)

		if !equalAffineJac(resAff, expected) {
			panic(fmt.Sprintf("iter %d: MSM result mismatch with (n*s)*g", it))
		}
		runtime.KeepAlive(resAff)

		if it == 0 || elapsed < best {
			best = elapsed
		}
		total += elapsed
	}
	avg := time.Duration(int64(total) / int64(iters))

	// ---- 7) summary ----
	fmt.Fprintf(out, "%d | %d | %d | %s | %s\n", exp, n, iters, best, avg)

	fmt.Printf("Appended: procs=%d, exp=%d, iters=%d\n", maxProcs, exp, iters)
}

func equalAffineJac(a bn254.G1Affine, b bn254.G1Jac) bool {
	var aj bn254.G1Jac
	aj.FromAffine(&a)
	return aj.Equal(&b)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
