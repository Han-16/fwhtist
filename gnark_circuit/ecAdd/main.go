package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"

	"github.com/consensys/gnark/frontend"
	r1cs "github.com/consensys/gnark/frontend/cs/r1cs"
	scs "github.com/consensys/gnark/frontend/cs/scs"

	swemu "github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	emu "github.com/consensys/gnark/std/math/emulated"
)

type Affine = swemu.AffinePoint[emu.BN254Fp]

type EcAddCircuit struct {
	A Affine
	B Affine
	C Affine `gnark:",public"`
}

func (c *EcAddCircuit) Define(api frontend.API) error {
	// BN254 Weierstrass 가젯 초기화
	curve, err := swemu.New[emu.BN254Fp, emu.BN254Fr](api, swemu.GetBN254Params())
	if err != nil {
		return err
	}

	// C = A + B
	C := curve.AddUnified(&c.A, &c.B)

	// C == public C
	curve.AssertIsEqual(C, &c.C)
	return nil
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	field := ecc.BN254.ScalarField()

	var circuit EcAddCircuit

	// Groth16
	r1cs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit)
	must(err)
	fmt.Println("# of constraints (Groth16):", r1cs.GetNbConstraints())

	// PLONK
	scs, err := frontend.Compile(field, scs.NewBuilder, &circuit)
	must(err)
	fmt.Println("# of constraints (PLONK):", scs.GetNbConstraints())
}
