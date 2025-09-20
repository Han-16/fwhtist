package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// X^2 + Y^2 = Z^2
// X, Y: Private & ScalarField of BN254
// Z: Public & ScalarField of BN254

type AddMulCircuit struct {
	X frontend.Variable
	Y frontend.Variable
	Z frontend.Variable `gnark:",public"`
}

func (c *AddMulCircuit) Define(api frontend.API) error {
	Xsq := api.Mul(c.X, c.X)
	Ysq := api.Mul(c.Y, c.Y)
	Zsq := api.Mul(c.Z, c.Z)
	sum := api.Add(Xsq, Ysq)
	api.AssertIsEqual(sum, Zsq)

	return nil
}

func printCSStats(cs constraint.ConstraintSystem) {
	fmt.Printf("Number of constraints: %d\n", cs.GetNbConstraints())
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	field := ecc.BN254.ScalarField()

	fmt.Println("Compiling the AddMulCircuit circuit...")

	var circuit AddMulCircuit

	cs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit)
	must(err)
	printCSStats(cs)

	assignment := &AddMulCircuit{
		X: big.NewInt(3),
		Y: big.NewInt(4),
		Z: big.NewInt(5),
	}

	fullWitness, err := frontend.NewWitness(assignment, field)
	must(err)
	publicWitness, err := fullWitness.Public()
	must(err)

	fmt.Println("Generating keys for Groth16...")
	pk, vk, err := groth16.Setup(cs)
	must(err)

	fmt.Println("Proving...")
	proof, err := groth16.Prove(cs, pk, fullWitness)
	must(err)

	fmt.Println("Verifying proof...")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("Proof is not valid:", err)
	} else {
		fmt.Println("Proof is valid")
	}
}
