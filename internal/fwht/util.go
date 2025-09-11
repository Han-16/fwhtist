package fwht

import (
	"sync"
	"runtime"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)


// isPowerOfTwo returns true if n is a power of two (>0).
func isPowerOfTwo(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}

// nextPow2 returns the smallest power of two >= n (n>0).
func nextPow2(n int) int {
	if n <= 1 {
		return 1
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// PadPointsToPow2 pads an affine point slice to power-of-two length
// using the group identity (zero-value Affine == infinity).
func PadPointsToPow2(in []bn254.G1Affine) []bn254.G1Affine {
	if len(in) == 0 || isPowerOfTwo(len(in)) {
		return in
	}
	out := make([]bn254.G1Affine, nextPow2(len(in)))
	copy(out, in)
	// remaining entries are zero-value (∞) by default
	return out
}


// parallelRange runs fn on [0,n) split across up to workers chunks.
func parallelRange(n, workers int, fn func(i0, i1 int)) {
	if workers <= 1 || n < 1024 {
		fn(0, n)
		return
	}
	var wg sync.WaitGroup
	chunk := (n + workers - 1) / workers
	for w := 0; w < workers; w++ {
		i0 := w * chunk
		if i0 >= n {
			break
		}
		i1 := i0 + chunk
		if i1 > n {
			i1 = n
		}
		wg.Add(1)
		go func(a, b int) {
			defer wg.Done()
			fn(a, b)
		}(i0, i1)
	}
	wg.Wait()
}

// setInfinity sets affine to the point at infinity.
// (gnark-crypto convention: (0,1) used for infinity)
func setInfinity(a *bn254.G1Affine) {
	a.X.SetZero()
	a.Y.SetOne()
}


func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}


func BatchJacToAffG1Par(in []bn254.G1Jac, workers int) []bn254.G1Affine {
	n := len(in)
	out := make([]bn254.G1Affine, n)
	if n == 0 {
		return out
	}
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 1 {
		workers = 1
	}

	// 1) 수집: Z != 0 인덱스만 모은다 (Z=0 → ∞)
	type idxZ struct {
		idx int
		z   fp.Element
	}
	nonZero := make([]idxZ, 0, n)
	for i := 0; i < n; i++ {
		if in[i].Z.IsZero() {
			// ∞: gnark-crypto convention (0,1)
			out[i].X.SetZero()
			out[i].Y.SetOne()
		} else {
			nonZero = append(nonZero, idxZ{idx: i, z: in[i].Z})
		}
	}
	k := len(nonZero)
	if k == 0 {
		return out
	}

	// 2) 누적 곱(prefix products) P[j] = ∏_{t=0..j} Z_t
	acc := make([]fp.Element, k)
	acc[0] = nonZero[0].z
	for j := 1; j < k; j++ {
		acc[j].Mul(&acc[j-1], &nonZero[j].z)
	}

	// 3) 전체 곱의 역원 1/∏Z를 한 번만 계산
	var invAll fp.Element
	invAll.Inverse(&acc[k-1])

	// 4) 역전파로 모든 1/Z_j 산출
	invZ := make([]fp.Element, k)
	for j := k - 1; j >= 0; j-- {
		if j == 0 {
			invZ[0] = invAll
		} else {
			invZ[j].Mul(&invAll, &acc[j-1])
		}
		// invAll *= Z_j  (다음 역전파용)
		invAll.Mul(&invAll, &nonZero[j].z)
	}

	// 5) Affine 좌표 계산을 병렬화
	parallelRange(k, workers, func(i0, i1 int) {
		var inv2, inv3, x, y fp.Element
		for j := i0; j < i1; j++ {
			i := nonZero[j].idx

			// inv2 = (1/Z)^2, inv3 = (1/Z)^3
			inv2.Square(&invZ[j])
			inv3.Mul(&inv2, &invZ[j])

			// X = X / Z^2, Y = Y / Z^3
			x.Mul(&in[i].X, &inv2)
			y.Mul(&in[i].Y, &inv3)

			out[i].X = x
			out[i].Y = y
		}
	})

	return out
}