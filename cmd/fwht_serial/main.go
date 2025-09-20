package main

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	// 본인의 모듈 경로로 바꿔주세요:
	// 예) "github.com/Han-16/fwhtist/internal/fwht"
	"github.com/Han-16/fwhtist/internal/fwht"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("사용법: go run ./cmd/fwht_serial <exponent>")
		fmt.Println("예시:  go run ./cmd/fwht_serial 10   // N=2^10=1024")
		os.Exit(1)
	}

	exp, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("오류: 입력은 정수여야 합니다.")
		os.Exit(1)
	}
	N := 1 << exp
	if N <= 0 {
		fmt.Println("오류: 2의 거듭제곱 크기는 1보다 커야 합니다.")
		os.Exit(1)
	}
	fmt.Printf("벡터 크기 N = 2^%d = %d\n", exp, N)

	// -------------------------
	// 랜덤 G1 벡터 생성
	// -------------------------
	rand.Seed(time.Now().UnixNano())

	// Generators(): g1Jac, g2Jac, g1Aff, g2Aff (에러 없음)
	g1Jac, _, g1Aff, _ := bn254.Generators()

	vec := make([]bn254.G1Affine, N)
	for i := 0; i < N; i++ {
		var s fr.Element
		if _, err := s.SetRandom(); err != nil {
			panic(err)
		}
		// fr.Element -> *big.Int
		sBig := new(big.Int)
		s.BigInt(sBig)

		// Jacobian에서 스칼라곱 후 Affine으로 변환
		var pJac bn254.G1Jac
		pJac.ScalarMultiplication(&g1Jac, sBig)
		vec[i].FromJacobian(&pJac)

		// (대안) Affine 직접 스칼라곱:
		// var pAff bn254.G1Affine
		// pAff.ScalarMultiplication(&g1Aff, sBig)
		// vec[i] = pAff
	}

	fmt.Println("Original Vector (first 5 elements):")
	for i := 0; i < int(math.Min(5, float64(N))); i++ {
		fmt.Printf("Index %d: %s\n", i, vec[i].String())
	}
	if N > 5 {
		fmt.Println("...")
	}

	// 검증용 백업
	orig := make([]bn254.G1Affine, N)
	copy(orig, vec)

	// -------------------------
	// FWHT (in-place, 직렬)
	// -------------------------
	start := time.Now()
	if err := fwht.MatVecHadamardSerialInPlace(vec); err != nil {
		fmt.Println("FWHT 에러:", err)
		os.Exit(1)
	}
	dur1 := time.Since(start)

	fmt.Println("\nTransformed Vector (first 5 elements):")
	for i := 0; i < int(math.Min(5, float64(N))); i++ {
		fmt.Printf("Index %d: %s\n", i, vec[i].String())
	}
	if N > 5 {
		fmt.Println("...")
	}
	fmt.Printf("\nFWHT 변환 시간: %v\n", dur1)

	// -------------------------
	// 이중 FWHT 검증: H(H(x)) == N * x ?
	// -------------------------
	if err := fwht.MatVecHadamardSerialInPlace(vec); err != nil {
		fmt.Println("FWHT(2) 에러:", err)
		os.Exit(1)
	}

	// expected = N * orig
	expected := make([]bn254.G1Affine, N)
	var sN fr.Element
	sN.SetUint64(uint64(N))
	nBig := new(big.Int)
	sN.BigInt(nBig)

	for i := 0; i < N; i++ {
		var oj bn254.G1Jac
		oj.FromAffine(&orig[i])

		var ej bn254.G1Jac
		ej.ScalarMultiplication(&oj, nBig)

		expected[i].FromJacobian(&ej)
	}

	verified := true
	for i := 0; i < N; i++ {
		if !vec[i].Equal(&expected[i]) {
			verified = false
			fmt.Printf("\n!!! 불일치 발견: Index %d !!!\n", i)
			fmt.Printf("H(H(x)): %s\n", vec[i].String())
			fmt.Printf("N * x:   %s\n", expected[i].String())
			break
		}
	}

	if verified {
		fmt.Println("\n✅ 검증 성공: H(H(x)) = N * x")
	} else {
		fmt.Println("\n❌ 검증 실패: H(H(x)) != N * x")
	}

	_ = g1Aff // (미사용 변수 경고 방지용; 필요 없으면 제거)
}
