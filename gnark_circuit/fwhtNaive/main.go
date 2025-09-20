package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/bits"
)

// Hadamard Matrix: H_4 = H_2 ⊗ H_2
// H_1 = | 1 |

// H_2 = | 1  1 |
//       | 1 -1 |

// H_4 = | 1  1  1  1 |
//       | 1 -1  1 -1 |
//       | 1  1 -1 -1 |
//       | 1 -1 -1  1 |

// FWHT: Fast Walsh-Hadamard Transform
type FWHTCircuit struct {
	X     [4]frontend.Variable
	Index frontend.Variable `gnark:",public"`
	Y     frontend.Variable `gnark:",public"`
}

func (c *FWHTCircuit) Define(api frontend.API) error {
	idxBits := bits.ToBinary(api, c.Index, bits.WithNbDigits(2)) // LSB-first

	// Hadamard matrix is H_4
	// We select a row based on the public `Index`.
	// The dot product is:
	// H_4[0] · X = X[0] + X[1] + X[2] + X[3]
	// H_4[1] · X = X[0] - X[1] + X[2] - X[3]
	// H_4[2] · X = X[0] + X[1] - X[2] - X[3]
	// H_4[3] · X = X[0] - X[1] - X[2] + X[3]

	// First, compute the sums based on the first bit `idxBits[0]`
	term01 := api.Add(c.X[0], c.X[1])
	term02 := api.Sub(c.X[0], c.X[1])

	term11 := api.Add(c.X[2], c.X[3])
	term12 := api.Sub(c.X[2], c.X[3])

	// Then, use the second bit `idxBits[1]` to select the final terms
	termFinal0 := api.Select(idxBits[1], api.Sub(term01, term11), api.Add(term01, term11))
	termFinal1 := api.Select(idxBits[1], api.Sub(term02, term12), api.Add(term02, term12))

	// The final result is selected based on the first bit `idxBits[0]`
	expectedY := api.Select(idxBits[0], termFinal1, termFinal0)

	api.AssertIsEqual(expectedY, c.Y)

	return nil
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	field := ecc.BN254.ScalarField()

	var circuit FWHTCircuit
	cs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit)
	must(err)

	fmt.Println("#constraints:", cs.GetNbConstraints())

	pk, vk, err := groth16.Setup(cs)
	must(err)

	// Fix the assignment by using a primitive integer array for X.
	// `NewWitness` will correctly handle the conversion.
	assignment := FWHTCircuit{
		X:     [4]frontend.Variable{1, 2, 3, 4},
		Index: big.NewInt(2),  // `10` in binary, selecting the 3rd row (index 2)
		Y:     big.NewInt(-4), // H_4[2] · X = [1, 1, -1, -1] · [1, 2, 3, 4] = 1*1 + 1*2 + -1*3 + -1*4 = 1+2-3-4 = -4
	}

	fullWitness, err := frontend.NewWitness(&assignment, field)
	must(err)
	publicWitness, err := fullWitness.Public()
	must(err)

	fmt.Println("Generating proof...")
	proof, err := groth16.Prove(cs, pk, fullWitness)
	must(err)

	fmt.Println("Verifying proof...")
	err = groth16.Verify(proof, vk, publicWitness)
	must(err)
	fmt.Println("Proof verified!")
}
