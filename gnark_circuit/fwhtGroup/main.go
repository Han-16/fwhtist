package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	swemu "github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/bits"
	emu "github.com/consensys/gnark/std/math/emulated"
)

// Hadamard Matrix: H_4 = H_2 ⊗ H_2
// H_1 = | 1 |

// H_2 = | 1  1 |
//       | 1 -1 |

// H_4 = | 1  1  1  1 |
//       | 1 -1  1 -1 |
//       | 1  1 -1 -1 |
//       | 1 -1 -1  1 |

// FHWT: Fast Walsh-Hadamard Transform
type Affine = swemu.AffinePoint[emu.BN254Fp]
type FWHTCircuit struct {
	G     [4]Affine
	Index frontend.Variable `gnark:",public"`
	Y     Affine            `gnark:",public"`
}

func (c *FWHTCircuit) Define(api frontend.API) error {
	curve, err := swemu.New[emu.BN254Fp, emu.BN254Fr](api, swemu.GetBN254Params())
	if err != nil {
		return err
	}

	idxBits := bits.ToBinary(api, c.Index, bits.WithNbDigits(2)) // LSB-first

	// Hadamard matrix is H_4
	// We select a row based on the public `Index`.
	// The dot product is:
	// H_4[0] · G = G[0] + G[1] + G[2] + G[3]
	// H_4[1] · G = G[0] - G[1] + G[2] - G[3]
	// H_4[2] · G = G[0] + G[1] - G[2] - G[3]
	// H_4[3] · G = G[0] - G[1] - G[2] + G[3]

	// First, compute the sums based on the first bit `idxBits[0]`
	term01 := curve.AddUnified(&c.G[0], &c.G[1])
	term02 := curve.AddUnified(&c.G[0], curve.Neg(&c.G[1]))

	term11 := curve.AddUnified(&c.G[2], &c.G[3])
	term12 := curve.AddUnified(&c.G[2], curve.Neg(&c.G[3])) // Corrected: Missing parenthesis

	// Then, use the second bit `idxBits[1]` to select the final terms
	// Corrected: Use curve.Select instead of api.Select
	termFinal0 := curve.Select(idxBits[1], curve.AddUnified(term01, curve.Neg(term11)), curve.AddUnified(term01, term11))
	termFinal1 := curve.Select(idxBits[1], curve.AddUnified(term02, curve.Neg(term12)), curve.AddUnified(term02, term12))

	// The final result is selected based on the first bit `idxBits[0]`
	// Corrected: Use curve.Select instead of api.Select
	expectedY := curve.Select(idxBits[0], termFinal1, termFinal0)

	curve.AssertIsEqual(expectedY, &c.Y)
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

	fmt.Println("# of constraints:", cs.GetNbConstraints())

	_, _, g1GenAff, _ := bn254.Generators()
	var g1 bn254.G1Affine
	var g2 bn254.G1Affine
	var g3 bn254.G1Affine
	var g4 bn254.G1Affine
	var y bn254.G1Affine
	// G1 = 10*G
	g1.ScalarMultiplication(&g1GenAff, big.NewInt(100))
	// G2 = 11*G
	g2.ScalarMultiplication(&g1GenAff, big.NewInt(51))
	// G3 = 12*G
	g3.ScalarMultiplication(&g1GenAff, big.NewInt(23))
	// G4 = 13*G
	g4.ScalarMultiplication(&g1GenAff, big.NewInt(37))
	y.ScalarMultiplication(&g1GenAff, big.NewInt(91)) // g1 + g2 - g3 - g4 = 100 + 51 - 23 - 37 = 91*G
	// Witness setup
	assignment := &FWHTCircuit{
		G: [4]Affine{
			{X: emu.ValueOf[emu.BN254Fp](&g1.X), Y: emu.ValueOf[emu.BN254Fp](&g1.Y)},
			{X: emu.ValueOf[emu.BN254Fp](&g2.X), Y: emu.ValueOf[emu.BN254Fp](&g2.Y)},
			{X: emu.ValueOf[emu.BN254Fp](&g3.X), Y: emu.ValueOf[emu.BN254Fp](&g3.Y)},
			{X: emu.ValueOf[emu.BN254Fp](&g4.X), Y: emu.ValueOf[emu.BN254Fp](&g4.Y)},
		},
		Index: 2, // `10` in binary, selecting the 3rd row (index 2)
		Y: Affine{
			X: emu.ValueOf[emu.BN254Fp](&y.X),
			Y: emu.ValueOf[emu.BN254Fp](&y.Y),
		},
	}

	pk, vk, err := groth16.Setup(cs)
	must(err)

	fullWitness, err := frontend.NewWitness(assignment, field)
	must(err)
	publicWitness, err := fullWitness.Public()
	must(err)

	fmt.Println("Generating proof...")
	proof, err := groth16.Prove(cs, pk, fullWitness)
	must(err)

	fmt.Println("Verifying proof...")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("Proof verification failed:", err)
	} else {
		fmt.Println("Proof verified successfully")
	}
}
