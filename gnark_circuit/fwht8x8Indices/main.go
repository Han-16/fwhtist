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

// Hadamard Matrix: H_8 = H_4 ⊗ H_4
// H_1 = | 1 |

// H_2 = | 1  1 |
//       | 1 -1 |

// H_4 = | 1  1  1  1 |
//       | 1 -1  1 -1 |
//       | 1  1 -1 -1 |
//       | 1 -1 -1  1 |

// H_8 = | 1  1  1  1  1  1  1  1 |
//       | 1 -1  1 -1  1 -1  1 -1 |
//       | 1  1 -1 -1  1  1 -1 -1 |
//       | 1 -1 -1  1  1 -1 -1  1 |
//       | 1  1  1  1 -1 -1 -1 -1 |
//       | 1 -1  1 -1 -1  1 -1  1 |
//       | 1  1 -1 -1 -1 -1  1  1 |
//       | 1 -1 -1  1 -1  1  1 -1 |

// FHWT: Fast Walsh-Hadamard Transform
type Affine = swemu.AffinePoint[emu.BN254Fp]

// R * (Hadamard[index] * G)
type FWHTIndicesCircuit struct {
	G       [8]Affine
	Indices [3]frontend.Variable        `gnark:",public"`
	R       [3]emu.Element[emu.BN254Fr] `gnark:",public"`
	Agg     Affine                      `gnark:",public"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func (c *FWHTIndicesCircuit) Define(api frontend.API) error {
	curve, err := swemu.New[emu.BN254Fp, emu.BN254Fr](api, swemu.GetBN254Params())
	must(err)
	idx0Bits := bits.ToBinary(api, c.Indices[0], bits.WithNbDigits(3)) // LSB-first
	idx1Bits := bits.ToBinary(api, c.Indices[1], bits.WithNbDigits(3))
	idx2Bits := bits.ToBinary(api, c.Indices[2], bits.WithNbDigits(3))

	// Hadamard matrix is H_8
	// We select a row based on the public `Index`.
	// The dot product is:
	// H_8[0] · G = G[0] + G[1] + G[2] + G[3] + G[4] + G[5] + G[6] + G[7]
	// H_8[1] · G = G[0] - G[1] + G[2] - G[3] + G[4] - G[5] + G[6] - G[7]
	// H_8[2] · G = G[0] + G[1] - G[2] - G[3] + G[4] + G[5] - G[6] - G[7]
	// H_8[3] · G = G[0] - G[1] - G[2] + G[3] + G[4] - G[5] - G[6] + G[7]
	// H_8[4] · G = G[0] + G[1] + G[2] + G[3] - G[4] - G[5] - G[6] - G[7]
	// H_8[5] · G = G[0] - G[1] + G[2] - G[3] - G[4] + G[5] - G[6] + G[7]
	// H_8[6] · G = G[0] + G[1] - G[2] - G[3] - G[4] - G[5] + G[6] + G[7]
	// H_8[7] · G = G[0] - G[1] - G[2] + G[3] - G[4] + G[5] + G[6] - G[7]

	// First, compute the sums based on the first bit `idxBits[0]`
	term01 := curve.AddUnified(&c.G[0], &c.G[1])
	term02 := curve.AddUnified(&c.G[0], curve.Neg(&c.G[1]))

	term11 := curve.AddUnified(&c.G[2], &c.G[3])
	term12 := curve.AddUnified(&c.G[2], curve.Neg(&c.G[3]))

	term21 := curve.AddUnified(&c.G[4], &c.G[5])
	term22 := curve.AddUnified(&c.G[4], curve.Neg(&c.G[5]))

	term31 := curve.AddUnified(&c.G[6], &c.G[7])
	term32 := curve.AddUnified(&c.G[6], curve.Neg(&c.G[7]))
	// Then, use the second bit `idxBits[1]` to select the final terms
	// Corrected: Use curve.Select instead of api.Select
	sum0 := curve.Select(idx0Bits[1], curve.AddUnified(term01, curve.Neg(term11)), curve.AddUnified(term01, term11))
	sum1 := curve.Select(idx0Bits[1], curve.AddUnified(term02, curve.Neg(term12)), curve.AddUnified(term02, term12))
	sum2 := curve.Select(idx0Bits[1], curve.AddUnified(term21, curve.Neg(term31)), curve.AddUnified(term21, term31))
	sum3 := curve.Select(idx0Bits[1], curve.AddUnified(term22, curve.Neg(term32)), curve.AddUnified(term22, term32))

	// Then, use the third bit `idxBits[2]` to select the final terms
	termFinal0 := curve.Select(idx0Bits[2], curve.AddUnified(sum0, curve.Neg(sum2)), curve.AddUnified(sum0, sum2))
	termFinal1 := curve.Select(idx0Bits[2], curve.AddUnified(sum1, curve.Neg(sum3)), curve.AddUnified(sum1, sum3))

	// The final result is selected based on the first bit `idxBits[0]`
	// Corrected: Use curve.Select instead of api.Select
	Y0 := curve.Select(idx0Bits[0], termFinal1, termFinal0)

	// Repeat the above for idx1Bits
	term01 = curve.AddUnified(&c.G[0], &c.G[1])
	term02 = curve.AddUnified(&c.G[0], curve.Neg(&c.G[1]))

	term11 = curve.AddUnified(&c.G[2], &c.G[3])
	term12 = curve.AddUnified(&c.G[2], curve.Neg(&c.G[3]))

	term21 = curve.AddUnified(&c.G[4], &c.G[5])
	term22 = curve.AddUnified(&c.G[4], curve.Neg(&c.G[5]))

	term31 = curve.AddUnified(&c.G[6], &c.G[7])
	term32 = curve.AddUnified(&c.G[6], curve.Neg(&c.G[7]))

	// Then, use the second bit `idxBits[1]` to select the final terms
	// Corrected: Use curve.Select instead of api.Select
	sum0 = curve.Select(idx1Bits[1], curve.AddUnified(term01, curve.Neg(term11)), curve.AddUnified(term01, term11))
	sum1 = curve.Select(idx1Bits[1], curve.AddUnified(term02, curve.Neg(term12)), curve.AddUnified(term02, term12))
	sum2 = curve.Select(idx1Bits[1], curve.AddUnified(term21, curve.Neg(term31)), curve.AddUnified(term21, term31))
	sum3 = curve.Select(idx1Bits[1], curve.AddUnified(term22, curve.Neg(term32)), curve.AddUnified(term22, term32))

	// Then, use the third bit `idxBits[2]` to select the final terms
	termFinal0 = curve.Select(idx1Bits[2], curve.AddUnified(sum0, curve.Neg(sum2)), curve.AddUnified(sum0, sum2))
	termFinal1 = curve.Select(idx1Bits[2], curve.AddUnified(sum1, curve.Neg(sum3)), curve.AddUnified(sum1, sum3))

	// The final result is selected based on the first bit `idxBits[0]`
	// Corrected: Use curve.Select instead of api.Select
	Y1 := curve.Select(idx1Bits[0], termFinal1, termFinal0)

	// Repeat the above for idx2Bits
	term01 = curve.AddUnified(&c.G[0], &c.G[1])
	term02 = curve.AddUnified(&c.G[0], curve.Neg(&c.G[1]))

	term11 = curve.AddUnified(&c.G[2], &c.G[3])
	term12 = curve.AddUnified(&c.G[2], curve.Neg(&c.G[3]))

	term21 = curve.AddUnified(&c.G[4], &c.G[5])
	term22 = curve.AddUnified(&c.G[4], curve.Neg(&c.G[5]))

	term31 = curve.AddUnified(&c.G[6], &c.G[7])
	term32 = curve.AddUnified(&c.G[6], curve.Neg(&c.G[7]))

	// Then, use the second bit `idxBits[1]` to select the final terms
	// Corrected: Use curve.Select instead of api.Select
	sum0 = curve.Select(idx2Bits[1], curve.AddUnified(term01, curve.Neg(term11)), curve.AddUnified(term01, term11))
	sum1 = curve.Select(idx2Bits[1], curve.AddUnified(term02, curve.Neg(term12)), curve.AddUnified(term02, term12))
	sum2 = curve.Select(idx2Bits[1], curve.AddUnified(term21, curve.Neg(term31)), curve.AddUnified(term21, term31))
	sum3 = curve.Select(idx2Bits[1], curve.AddUnified(term22, curve.Neg(term32)), curve.AddUnified(term22, term32))

	// Then, use the third bit `idxBits[2]` to select the final terms
	termFinal0 = curve.Select(idx2Bits[2], curve.AddUnified(sum0, curve.Neg(sum2)), curve.AddUnified(sum0, sum2))
	termFinal1 = curve.Select(idx2Bits[2], curve.AddUnified(sum1, curve.Neg(sum3)), curve.AddUnified(sum1, sum3))

	// The final result is selected based on the first bit `idxBits[0]`
	// Corrected: Use curve.Select instead of api.Select
	Y2 := curve.Select(idx2Bits[0], termFinal1, termFinal0)

	// Now, we have Y0, Y1, Y2
	// We need to compute R[0]*Y0 + R[1]*Y1 + R[2]*Y2
	R0Y0 := curve.ScalarMul(Y0, &c.R[0])
	R1Y1 := curve.ScalarMul(Y1, &c.R[1])
	R2Y2 := curve.ScalarMul(Y2, &c.R[2])

	sumR0R1 := curve.AddUnified(R0Y0, R1Y1)
	finalAgg := curve.AddUnified(sumR0R1, R2Y2)

	curve.AssertIsEqual(finalAgg, &c.Agg)
	return nil
}

func main() {
	field := ecc.BN254.ScalarField()

	cs, err := frontend.Compile(field, r1cs.NewBuilder, &FWHTIndicesCircuit{})
	must(err)
	fmt.Println("# of constraints:", cs.GetNbConstraints())

	var g1, g2, g3, g4, g5, g6, g7, g8 bn254.G1Affine
	g1.ScalarMultiplicationBase(big.NewInt(100))
	g2.ScalarMultiplicationBase(big.NewInt(51))
	g3.ScalarMultiplicationBase(big.NewInt(23))
	g4.ScalarMultiplicationBase(big.NewInt(37))
	g5.ScalarMultiplicationBase(big.NewInt(13))
	g6.ScalarMultiplicationBase(big.NewInt(123))
	g7.ScalarMultiplicationBase(big.NewInt(76))
	g8.ScalarMultiplicationBase(big.NewInt(24))

	// y0: g1 + g2 + g3 + g4 + g5 + g6 + g7 + g8 = 100 + 51 + 23 + 37 + 13 + 123 + 76 + 24 = 447*G
	// y1: g1 - g2 + g3 - g4 - g5 + g6 - g7 + g8 = 100 - 51 + 23 - 37 - 13 + 123 - 76 + 24 = 93*G
	// y2: g1 + g2 - g3 - g4 - g5 - g6 + g7 + g8 = 100 + 51 - 23 - 37 - 13 - 123 + 76 + 24 = 55*G
	// r0*y0 + r1*y1 + r2*y2 = 45*447 + 23*93 + 19*55 = 20085 + 2139 + 1045 = 23299*G
	var Agg bn254.G1Affine
	Agg.ScalarMultiplicationBase(big.NewInt(23299))

	assignment := &FWHTIndicesCircuit{
		G: [8]Affine{
			{X: emu.ValueOf[emu.BN254Fp](g1.X), Y: emu.ValueOf[emu.BN254Fp](g1.Y)},
			{X: emu.ValueOf[emu.BN254Fp](g2.X), Y: emu.ValueOf[emu.BN254Fp](g2.Y)},
			{X: emu.ValueOf[emu.BN254Fp](g3.X), Y: emu.ValueOf[emu.BN254Fp](g3.Y)},
			{X: emu.ValueOf[emu.BN254Fp](g4.X), Y: emu.ValueOf[emu.BN254Fp](g4.Y)},
			{X: emu.ValueOf[emu.BN254Fp](g5.X), Y: emu.ValueOf[emu.BN254Fp](g5.Y)},
			{X: emu.ValueOf[emu.BN254Fp](g6.X), Y: emu.ValueOf[emu.BN254Fp](g6.Y)},
			{X: emu.ValueOf[emu.BN254Fp](g7.X), Y: emu.ValueOf[emu.BN254Fp](g7.Y)},
			{X: emu.ValueOf[emu.BN254Fp](g8.X), Y: emu.ValueOf[emu.BN254Fp](g8.Y)},
		},
		Indices: [3]frontend.Variable{0, 5, 6}, // 011, 101, 110
		R: [3]emu.Element[emu.BN254Fr]{
			emu.ValueOf[emu.BN254Fr](big.NewInt(45)),
			emu.ValueOf[emu.BN254Fr](big.NewInt(23)),
			emu.ValueOf[emu.BN254Fr](big.NewInt(19)),
		},
		Agg: Affine{X: emu.ValueOf[emu.BN254Fp](Agg.X), Y: emu.ValueOf[emu.BN254Fp](Agg.Y)},
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
	must(err)
	fmt.Println("proof is valid")
}
