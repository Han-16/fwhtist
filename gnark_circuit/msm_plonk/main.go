package main

import (
	cryptoRand "crypto/rand"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"

	// ✅ PLONK 백엔드
	"github.com/consensys/gnark/backend/plonk"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	// ✅ SCS(PLONK용) 빌더
	"github.com/consensys/gnark/frontend/cs/scs"

	// ✅ KZG SRS를 위한 패키지
	"github.com/consensys/gnark-crypto/kzg"

	swemu "github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	emu "github.com/consensys/gnark/std/math/emulated"
)

// -----------------------------
// Prove: r1*G1 + r2*G2 == G3
// G1, G2, r1, r2: witness
// G3: public
// -----------------------------

type Affine = swemu.AffinePoint[emu.BN254Fp]

type Circuit struct {
	G1 Affine
	G2 Affine
	R1 emu.Element[emu.BN254Fr]
	R2 emu.Element[emu.BN254Fr]
	G3 Affine `gnark:",public"`
}

func (c *Circuit) Define(api frontend.API) error {
	// BN254 Weierstrass 가젯
	curve, err := swemu.New[emu.BN254Fp, emu.BN254Fr](api, swemu.GetBN254Params())
	if err != nil {
		return err
	}

	// P1 = r1 * G1
	P1 := curve.ScalarMul(&c.G1, &c.R1)
	// P2 = r2 * G2
	P2 := curve.ScalarMul(&c.G2, &c.R2)
	// sum = P1 + P2
	sum := curve.AddUnified(P1, P2)

	// sum == G3 (public)
	curve.AssertIsEqual(sum, &c.G3)

	return nil
}

// -----------------------------
// Helpers
// -----------------------------
func randScalar(mod *big.Int) *big.Int {
	n, err := cryptoRand.Int(cryptoRand.Reader, mod)
	if err != nil {
		log.Fatal(err)
	}
	return n
}

func printCSStats(cs constraint.ConstraintSystem) {
	fmt.Printf("#constraints = %d\n", cs.GetNbConstraints())
}

// -----------------------------
// main: compile → setup → prove → verify (PLONK)
// -----------------------------
func main() {
	field := ecc.BN254.ScalarField()

	// 1) 회로 밖에서 실제 점/스칼라 생성
	s1 := randScalar(field)
	s2 := randScalar(field)
	r1 := randScalar(field)
	r2 := randScalar(field)

	var G1, G2, G3 bn254.G1Affine
	G1.ScalarMultiplicationBase(s1)
	G2.ScalarMultiplicationBase(s2)

	// r1*G1 + r2*G2
	var r1G1, r2G2, sum bn254.G1Affine
	r1G1.ScalarMultiplication(&G1, r1)
	r2G2.ScalarMultiplication(&G2, r2)
	sum.Add(&r1G1, &r2G2)
	G3 = sum

	// 2) big.Int로 좌표/스칼라 추출
	var g1x, g1y, g2x, g2y, g3x, g3y big.Int
	G1.X.BigInt(&g1x); G1.Y.BigInt(&g1y)
	G2.X.BigInt(&g2x); G2.Y.BigInt(&g2y)
	G3.X.BigInt(&g3x); G3.Y.BigInt(&g3y)

	// 3) Witness/Public 입력 구성
	assignment := &Circuit{
		G1: Affine{
			X: emu.ValueOf[emu.BN254Fp](&g1x),
			Y: emu.ValueOf[emu.BN254Fp](&g1y),
		},
		G2: Affine{
			X: emu.ValueOf[emu.BN254Fp](&g2x),
			Y: emu.ValueOf[emu.BN254Fp](&g2y),
		},
		R1: emu.ValueOf[emu.BN254Fr](r1),
		R2: emu.ValueOf[emu.BN254Fr](r2),
		G3: Affine{
			X: emu.ValueOf[emu.BN254Fp](&g3x), // public
			Y: emu.ValueOf[emu.BN254Fp](&g3y), // public
		},
	}

	// 4) Compile (SCS → PLONK)
	t0 := time.Now()
	cs, err := frontend.Compile(field, scs.NewBuilder, new(Circuit))
	if err != nil {
		log.Fatalf("compile failed: %v", err)
	}
	fmt.Println("compile:", time.Since(t0))
	printCSStats(cs)

	// 5) Witness
	w, err := frontend.NewWitness(assignment, field)
	if err != nil {
		log.Fatalf("witness failed: %v", err)
	}
	pubW, err := w.Public()
	if err != nil {
		log.Fatalf("public witness failed: %v", err)
	}

	// 6) Setup / Prove / Verify (PLONK)
	t2 := time.Now()
	srs := kzg.NewSRS(ecc.BN254)
	if srs == nil {
		log.Fatal("failed to create SRS: nil returned")
	}

	pk, vk, err := plonk.Setup(cs, srs, srs)
	if err != nil {
		log.Fatalf("setup failed: %v", err)
	}
	fmt.Println("setup:", time.Since(t2))

	t3 := time.Now()
	proof, err := plonk.Prove(cs, pk, w)
	if err != nil {
		log.Fatalf("prove failed: %v", err)
	}
	fmt.Println("prove:", time.Since(t3))

	t4 := time.Now()
	if err := plonk.Verify(proof, vk, pubW); err != nil {
		log.Fatalf("verify failed: %v", err)
	}
	fmt.Println("verify:", time.Since(t4))

	fmt.Println("OK ✅  PLONK: r1*G1 + r2*G2 == G3 (G3 public)")
}