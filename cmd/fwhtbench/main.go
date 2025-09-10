// go run ./cmd/fwhtbench <exp> [iters] [maxProcs] [mode]
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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./cmd/fwhtbench <exp> [iters] [maxProcs] [mode]")
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

	// prepare points
	var points []bn254.G1Affine
	switch mode {
	case "const":
		_, _, g, _ := bn254.Generators()
		points = make([]bn254.G1Affine, n)
		for i := 0; i < n; i++ {
			points[i] = g
		}
	case "rand":
		workers := maxProcs
		if workers <= 0 {
			workers = runtime.NumCPU()
		}
		var err error
		points, err = randutil.RandomPointsG1Par(n, workers)
		must(err)
	}

	// output file: {mode}_procs_{maxProcs}.txt
	filename := fmt.Sprintf("%s_procs_%d.txt", mode, maxProcs)
	out, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	must(err)
	defer out.Close()

	if fi, err := out.Stat(); err == nil && fi.Size() == 0 {
		fmt.Fprintf(out, "# FWHT Benchmark Results (mode=%s, procs=%d)\n", mode, maxProcs)
		fmt.Fprintln(out, "# exp | n | iters | Best | Avg")
	}

	// warmup (병렬 버전 호출)
	{
		_, err := fwht.MatVecHadamardParBatch(points, maxProcs)
		must(err)
	}

	// benchmark (병렬 버전 호출)
	var best, total time.Duration
	for it := 0; it < iters; it++ {
		start := time.Now()
		_, err := fwht.MatVecHadamardParBatch(points, maxProcs)
		must(err)
		elapsed := time.Since(start)

		if it == 0 || elapsed < best {
			best = elapsed
		}
		total += elapsed
	}
	avg := time.Duration(int64(total) / int64(iters))

	fmt.Fprintf(out, "%d | %d | %d | %s | %s\n", exp, n, iters, best, avg)
	fmt.Printf("FWHT appended: mode=%s, procs=%d, exp=%d, iters=%d\n", mode, maxProcs, exp, iters)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
