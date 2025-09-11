// package main

// import (
// 	"fmt"
// 	"math/big"
// 	"os"
// 	"runtime"
// 	"strconv"
// 	"time"

// 	"github.com/consensys/gnark-crypto/ecc/bn254"

// 	"github.com/Han-16/fwhtist/internal/fwht"
// )

// func main() {
// 	if len(os.Args) < 3 {
// 		fmt.Println("Usage: go run ./cmd/fwhtverify <exp> <workers>")
// 		fmt.Println("Example: go run ./cmd/fwhtverify 10 4   # n = 2^10 points, workers = 4")
// 		return
// 	}

// 	// exp 파싱
// 	exp, err := strconv.Atoi(os.Args[1])
// 	if err != nil || exp <= 0 {
// 		fmt.Printf("invalid exp: %v\n", os.Args[1])
// 		return
// 	}
// 	n := 1 << exp

// 	// workers 파싱
// 	workers, err := strconv.Atoi(os.Args[2])
// 	if err != nil || workers <= 0 {
// 		workers = runtime.GOMAXPROCS(0)
// 	}

// 	fmt.Printf("Running FWHT with n = 2^%d = %d points, workers = %d\n", exp, n, workers)

// 	// 입력 벡터: (i+1)*G 로 채움
// 	_, _, g1Aff, _ := bn254.Generators()
// 	input := make([]bn254.G1Affine, n)
// 	for i := 0; i < n; i++ {
// 		input[i].ScalarMultiplication(&g1Aff, big.NewInt(int64(i+1)))
// 	}

// 	// FWHT 실행
// 	start := time.Now()
// 	out, err := fwht.MatVecHadamardPar(input, workers)
// 	if err != nil {
// 		fmt.Printf("FWHT failed: %v\n", err)
// 		return
// 	}
// 	fmt.Printf("FWHT done in %s (len=%d)\n", time.Since(start), len(out))

// 	// 이중 FWHT 검증: H(H(x)) = n * x
// 	out2, err := fwht.MatVecHadamardPar(out, workers)
// 	if err != nil {
// 		fmt.Printf("FWHT second run failed: %v\n", err)
// 		return
// 	}

// 	ok := true
// 	for i := 0; i < n; i++ {
// 		var expect bn254.G1Affine
// 		expect.ScalarMultiplication(&input[i], big.NewInt(int64(n)))
// 		if !out2[i].Equal(&expect) {
// 			fmt.Printf("Mismatch at index %d\n", i)
// 			ok = false
// 			break
// 		}
// 	}
// 	if ok {
// 		fmt.Println("Check passed ✅ : FWHT(FWHT(x)) == n * x for all elements")
// 	} else {
// 		fmt.Println("Check failed ❌ : some elements mismatch")
// 	}
// }



package main

import (
	// "crypto/rand"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/Han-16/fwhtist/internal/fwht"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: go run ./cmd/fwhtverify <exp> <workers> <mode>")
		fmt.Println("Example: go run ./cmd/fwhtverify 10 4 const   # n = 2^10 points, const input")
		fmt.Println("Example: go run ./cmd/fwhtverify 10 4 rand    # n = 2^10 points, random input")
		return
	}

	// exp 파싱
	exp, err := strconv.Atoi(os.Args[1])
	if err != nil || exp <= 0 {
		fmt.Printf("invalid exp: %v\n", os.Args[1])
		return
	}
	n := 1 << exp

	// workers 파싱
	workers, err := strconv.Atoi(os.Args[2])
	if err != nil || workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}

	// mode 파싱
	mode := strings.ToLower(os.Args[3])
	if mode != "const" && mode != "rand" {
		fmt.Println("mode must be either 'const' or 'rand'")
		return
	}

	fmt.Printf("Running FWHT with n = 2^%d = %d points, workers = %d, mode=%s\n", exp, n, workers, mode)

	// 입력 벡터 준비
	_, _, g1Aff, _ := bn254.Generators()
	input := make([]bn254.G1Affine, n)

	switch mode {
	case "const":
		// 모든 원소를 동일한 생성점으로
		for i := 0; i < n; i++ {
			input[i] = g1Aff
		}
	case "rand":
		// 난수 스칼라 * G 로 채움
		for i := 0; i < n; i++ {
			// k, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 256))
			// input[i].ScalarMultiplication(&g1Aff, k)
			input[i].ScalarMultiplication(&g1Aff, big.NewInt(int64(i+1)))
		}
	}

	// FWHT 실행
	fmt.Printf("Starting FWHT...\n")
	start := time.Now()
	out, err := fwht.MatVecHadamardPar(input, workers)
	if err != nil {
		fmt.Printf("FWHT failed: %v\n", err)
		return
	}
	fmt.Printf("FWHT done in %s (len=%d)\n", time.Since(start), len(out))

	// 이중 FWHT 검증: H(H(x)) = n * x
	out2, err := fwht.MatVecHadamardPar(out, workers)
	if err != nil {
		fmt.Printf("FWHT second run failed: %v\n", err)
		return
	}

	ok := true
	for i := 0; i < n; i++ {
		var expect bn254.G1Affine
		expect.ScalarMultiplication(&input[i], big.NewInt(int64(n)))
		if !out2[i].Equal(&expect) {
			fmt.Printf("Mismatch at index %d\n", i)
			ok = false
			break
		}
	}
	if ok {
		fmt.Println("Check passed ✅ : FWHT(FWHT(x)) == n * x for all elements")
	} else {
		fmt.Println("Check failed ❌ : some elements mismatch")
	}
}
