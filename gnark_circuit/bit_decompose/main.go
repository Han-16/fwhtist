package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/bits"
)

type BitDecomposeCircuitOrigin struct {
	X    frontend.Variable
	Last frontend.Variable `gnark:",public"`
}

func (c *BitDecomposeCircuitOrigin) Define(api frontend.API) error {
	xBits := bits.ToBinary(api, c.X, bits.WithNbDigits(4)) // LSB-first
	api.AssertIsEqual(xBits[0], c.Last)                    // LSB == Last
	api.Println("[Origin] Bits:", xBits)
	return nil
}

type BitDecomposeCircuitCheat struct {
	X    frontend.Variable
	Last frontend.Variable `gnark:",public"`
}

func (c *BitDecomposeCircuitCheat) Define(api frontend.API) error {
	xBits := bits.ToBinary(api, c.X, bits.WithNbDigits(5))
	api.AssertIsEqual(xBits[2], c.Last) // 2번째 비트 == Last
	api.Println("[Cheat] xBits[2]:", xBits[2])
	api.Println("[Cheat] Bits:", xBits)
	return nil
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	field := ecc.BN254.ScalarField()

	// 1) 서로 다른 회로 각각 컴파일
	var cOrigin BitDecomposeCircuitOrigin
	var cCheat BitDecomposeCircuitCheat

	csOrigin, err := frontend.Compile(field, r1cs.NewBuilder, &cOrigin)
	must(err)
	csCheat, err := frontend.Compile(field, r1cs.NewBuilder, &cCheat)
	must(err)

	fmt.Println("#constraints origin:", csOrigin.GetNbConstraints())
	fmt.Println("#constraints cheat :", csCheat.GetNbConstraints())

	// 2) 각 회로별로 Setup
	pkOrigin, vkOrigin, err := groth16.Setup(csOrigin)
	must(err)
	pkCheat, vkCheat, err := groth16.Setup(csCheat)
	must(err)

	// 3) 각 회로별로 witness 생성 (X=5=0101, Last=1)
	originWit := &BitDecomposeCircuitOrigin{X: 5, Last: 1} // [1, 0, 1, 0]
	cheatWit := &BitDecomposeCircuitCheat{X: 6, Last: 1}   // [0, 1, 1, 0]

	fullWitOrigin, err := frontend.NewWitness(originWit, field)
	must(err)
	pubWitOrigin, err := fullWitOrigin.Public()
	must(err)

	fullWitCheat, err := frontend.NewWitness(cheatWit, field)
	must(err)
	pubWitCheat, err := fullWitCheat.Public()
	must(err)

	// 4) 각 회로별로 Prove & Verify
	proofOrigin, err := groth16.Prove(csOrigin, pkOrigin, fullWitOrigin)
	must(err)
	must(groth16.Verify(proofOrigin, vkOrigin, pubWitOrigin))

	proofCheat, err := groth16.Prove(csCheat, pkCheat, fullWitCheat)
	must(err)
	must(groth16.Verify(proofCheat, vkCheat, pubWitCheat))

	fmt.Println("both proofs verified with their own vk")

	// 5) Cheat proof를 Origin vk로 검증 시도 (실패해야 함)
	proofCheat, err = groth16.Prove(csCheat, pkOrigin, fullWitCheat)
	fmt.Println("cheat proof generated with origin pk")
	if err := groth16.Verify(proofCheat, vkOrigin, pubWitOrigin); err != nil {
		fmt.Println("as expected: cheat proof does NOT verify with origin vk")
	} else {
		fmt.Println("UNEXPECTED: cheat proof verified with origin vk")
	}
}
