package main

import (
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strconv"

	"github.com/Han-16/fwhtist/internal/fwht"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./cmd/fwhtverify <exp> [procs]")
		fmt.Println("Example: go run ./cmd/fwhtverify 10       # n = 2^10 points, procs=NumCPU()")
		fmt.Println("Example: go run ./cmd/fwhtverify 10 4     # n = 2^10 points, procs=4")
		return
	}

	exp, err := strconv.Atoi(os.Args[1])
	must(err)
	if exp < 0 {
		panic("exp must be non-negative")
	}
	n := 1 << exp

	procs := runtime.NumCPU()
	if len(os.Args) >= 3 {
		procs, err = strconv.Atoi(os.Args[2])
		must(err)
		if procs <= 0 {
			procs = runtime.NumCPU()
		}
	}
	runtime.GOMAXPROCS(procs)

	fmt.Println()
	fmt.Println("====================================== [ FWHT Verify Start ] ======================================")
	fmt.Printf("exp=%d (n = 2^%d = %d), procs=%d\n", exp, exp, n, procs)

	// ---- generate points directly (no cache) ----
	_, _, g, _ := bn254.Generators()
	points := make([]bn254.G1Affine, n)
	for i := 0; i < n; i++ {
		points[i] = g
	}

	// ---- correctness check (parallel version) ----
	ok, err := verifyDoubleFWHT(points, procs)
	must(err)
	fmt.Printf("Check H(H(p)) == n * p : %v\n", ok)

	fmt.Println("======================================= [ FWHT Verify End ] =======================================")
	fmt.Println()
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// verifyDoubleFWHT applies FWHT twice (parallel version) and checks equality with n * p
func verifyDoubleFWHT(orig []bn254.G1Affine, workers int) (bool, error) {
	hvec, err := fwht.MatVecHadamardPar(orig, workers)
	if err != nil {
		return false, err
	}
	hhvec, err := fwht.MatVecHadamardPar(hvec, workers)
	if err != nil {
		return false, err
	}

	if len(orig) != len(hhvec) {
		return false, nil
	}
	n := len(orig)

	for i := range orig {
		var lhs, rhs bn254.G1Jac
		lhs.FromAffine(&hhvec[i])

		rhs.FromAffine(&orig[i])
		rhs.ScalarMultiplication(&rhs, new(big.Int).SetUint64(uint64(n)))

		if !lhs.Equal(&rhs) {
			return false, nil
		}
	}
	return true, nil
}
