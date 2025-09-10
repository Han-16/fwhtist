// go run ./cmd/msmtest <exp> [iters] [maxProcs] [mode]
//   exp      : n = 2^exp
//   iters    : number of iterations (default 5)
//   maxProcs : GOMAXPROCS setting (default -1: number of CPU cores)
//   mode     : "const" (default) or "rand"

package main

import (
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Han-16/fwhtist/internal/msm"
	"github.com/Han-16/fwhtist/internal/randutil"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./cmd/msmtest <exp> [iters] [maxProcs] [mode]")
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

	mode := "const"
	if len(os.Args) >= 5 {
		mode = strings.ToLower(os.Args[4])
	}
	if mode != "const" && mode != "rand" {
		panic(`mode must be "const" or "rand"`)
	}

	filename := fmt.Sprintf("%s_procs%d.txt", mode, maxProcs)
	out, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	must(err)
	defer out.Close()

	if fi, err := out.Stat(); err == nil && fi.Size() == 0 {
		fmt.Fprintf(out, "# MSM Benchmark Results (mode=%s, procs=%d)\n", mode, maxProcs)
		fmt.Fprintln(out, "# exp | n | iters | Best | Avg")
	}

	// ---- prepare scalars & points ----
	var scalars []fr.Element
	var points []bn254.G1Affine
	var expected bn254.G1Jac

	switch mode {
	case "const":
		// scalars = [s, ..., s]
		var s fr.Element
		s.SetRandom()
		scalars = make([]fr.Element, n)
		for i := 0; i < n; i++ {
			scalars[i] = s
		}

		// points = [g, ..., g]
		_, _, g, _ := bn254.Generators()
		points = make([]bn254.G1Affine, n)
		for i := 0; i < n; i++ {
			points[i] = g
		}

		// expected = (n*s) * g
		var ns fr.Element
		ns.SetUint64(uint64(n))
		ns.Mul(&ns, &s)
		nsBytes := ns.Bytes()
		nsBig := new(big.Int).SetBytes(nsBytes[:])

		expected.FromAffine(&g)
		expected.ScalarMultiplication(&expected, nsBig)

	case "rand":
		// random scalars
		scalars = make([]fr.Element, n)
		for i := 0; i < n; i++ {
			var s fr.Element
			s.SetRandom()
			scalars[i] = s
		}

		// random points
		var err error
		points, err = randutil.RandomPointsG1Par(n, maxProcs)
		must(err)

		expected = bn254.G1Jac{}
	}

	// ---- benchmark ----
	var best, total time.Duration
	for it := 0; it < iters; it++ {
		start := time.Now()
		resAff, err := msm.MultiExpMSM(points, scalars)
		must(err)
		elapsed := time.Since(start)

		if mode == "const" && !equalAffineJac(resAff, expected) {
			panic(fmt.Sprintf("iter %d: MSM result mismatch with (n*s)*g", it))
		}
		runtime.KeepAlive(resAff)

		if it == 0 || elapsed < best {
			best = elapsed
		}
		total += elapsed
	}
	avg := time.Duration(int64(total) / int64(iters))

	// ---- summary ----
	fmt.Fprintf(out, "%d | %d | %d | %s | %s\n", exp, n, iters, best, avg)
	fmt.Printf("Appended: mode=%s, procs=%d, exp=%d, iters=%d\n", mode, maxProcs, exp, iters)
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
