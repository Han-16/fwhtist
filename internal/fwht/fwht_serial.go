package fwht

import (
	"errors"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// MatVecHadamardSerialInPlace runs FWHT in-place on a single CPU (no goroutines).
// - 입력 길이는 2의 거듭제곱이어야 함.
// - 내부 계산은 G1Jac에서 in-place로 수행하고, 마지막에 Affine으로 덮어쓴다.
// - block/step 없이, r(스테이지)와 k(버터플라이 인덱스)만 사용.
//   aIdx = ((k >> r) << (r+1)) | (k & ((1<<r)-1))
//   cIdx = aIdx + (1 << r)
func MatVecHadamardSerialInPlace(in []bn254.G1Affine) error {
	n := len(in)
	if n == 0 {
		return nil
	}
	if n&(n-1) != 0 {
		return errors.New("MatVecHadamardSerialInPlace: length must be a power of two")
	}

	// 1) Affine -> Jacobian
	buf := make([]bn254.G1Jac, n)
	for i := 0; i < n; i++ {
		buf[i].FromAffine(&in[i])
	}

	// 2) FWHT: r-stage loop + single index k loop (no block/step)
	stages := bits.Len(uint(n)) - 1 // log2(n)
	half := n >> 1                  // total butterflies per stage

	for r := 0; r < stages; r++ {
		shift := uint(r)
		mask := (1 << r) - 1
		dist := 1 << r

		for k := 0; k < half; k++ {
			// aIdx/cIdx 계산 (block/step 없이)
			aIdx := ((k >> shift) << (r + 1)) | (k & mask)
			cIdx := aIdx + dist

			a := &buf[aIdx]
			c := &buf[cIdx]

			ta := *a
			tc := *c

			// sum = ta + tc
			sum := ta
			sum.AddAssign(&tc)

			// diff = ta - tc
			tc.Neg(&tc)
			diff := ta
			diff.AddAssign(&tc)

			*a = sum
			*c = diff
		}
	}

	// 3) Jacobian -> Affine (in-place overwrite)
	for i := 0; i < n; i++ {
		in[i].FromJacobian(&buf[i])
	}
	return nil
}
