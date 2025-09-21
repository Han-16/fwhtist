package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"math/bits"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	//"github.com/consensys/gnark/frontend/cs/scs"
	swemu "github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	gnarkbits "github.com/consensys/gnark/std/math/bits"
	emu "github.com/consensys/gnark/std/math/emulated"
)

// Defines constants for the circuit.
const (
	// Number of bits to represent an index for the matrix.
	NumBits = 10 // 2^10 = 1024
	// Size of the Hadamard matrix and the G vector.
	MatrixSize = 1 << NumBits
	// Number of indices to select and process from the Hadamard transform result.
	NumIndices = 18
)

// Affine represents a point on the BN254 curve in affine coordinates.
type Affine = swemu.AffinePoint[emu.BN254Fp]

// FWHTIndicesCircuit defines the ZK-SNARK circuit.
// It proves the computation of R * (Hadamard[index] * G) for a set of indices.
type FWHTIndicesCircuit struct {
	// --- Private Witness ---
	// The secret vector of elliptic curve points.
	G [MatrixSize]Affine

	// --- Public Witness ---
	// The publicly known indices of the Hadamard matrix rows to be used.
	Indices [NumIndices]frontend.Variable `gnark:",public"`
	// The publicly known scalars for the final linear combination.
	R [NumIndices]emu.Element[emu.BN254Fr] `gnark:",public"`
	// The publicly known final aggregated result of the computation.
	Agg Affine `gnark:",public"`
}

// must is a helper function to panic on error.
func must(err error) {
	if err != nil {
		panic(err)
	}
}

// computeFWHTRow computes the product of a specific row of the Hadamard matrix
// and the vector G using the Fast Walsh-Hadamard Transform (FWHT) algorithm inside the circuit.
func computeFWHTRow(curve *swemu.Curve[emu.BN254Fp, emu.BN254Fr], g []Affine, indexBits []frontend.Variable) *Affine {
	// Slice to store the results of the current computation stage.
	currentStageG := make([]*Affine, len(g))
	for i := range g {
		currentStageG[i] = &g[i]
	}

	numStages := len(indexBits) // For a 1024x1024 matrix, there are 10 stages.

	// Iterate through each stage of the FWHT.
	for s := 0; s < numStages; s++ {
		// Slice to store the results of the next stage.
		// The size of the vector is halved at each stage.
		nextStageG := make([]*Affine, len(currentStageG)/2)

		// Perform the butterfly operation by pairing elements from the current stage.
		for i := 0; i < len(nextStageG); i++ {
			p1 := currentStageG[2*i]
			p2 := currentStageG[2*i+1]

			// Pre-compute (p1 + p2) and (p1 - p2).
			termAdd := curve.AddUnified(p1, p2)
			termSub := curve.AddUnified(p1, curve.Neg(p2))

			// Select the addition or subtraction result based on the s-th bit of the index.
			// This selective combination is the core of the FWHT.
			// Since indexBits is LSB-first, we use indexBits[s].
			nextStageG[i] = curve.Select(indexBits[s], termSub, termAdd)
		}
		currentStageG = nextStageG
	}

	// After all stages, only the final result (a single point) remains.
	return currentStageG[0]
}

// Define defines the logic of the circuit.
func (c *FWHTIndicesCircuit) Define(api frontend.API) error {
	curve, err := swemu.New[emu.BN254Fp, emu.BN254Fr](api, swemu.GetBN254Params())
	must(err)

	// Slice to store the intermediate results (Y_i = H[i] * G).
	Ys := make([]*Affine, NumIndices)

	// Iterate through each of the specified indices to perform the FWHT calculation.
	for i := 0; i < NumIndices; i++ {
		// Convert the integer index to its binary representation (10 bits).
		idxBits := gnarkbits.ToBinary(api, c.Indices[i], gnarkbits.WithNbDigits(NumBits))

		// Call the helper function to compute the FWHT result for the current index.
		Ys[i] = computeFWHTRow(curve, c.G[:], idxBits)
	}

	// Final aggregation: R[0]*Y[0] + R[1]*Y[1] + ... + R[17]*Y[17].
	// Initialize the sum with the first term.
	finalAgg := curve.ScalarMul(Ys[0], &c.R[0])

	// Add the remaining terms to the sum.
	for i := 1; i < NumIndices; i++ {
		term := curve.ScalarMul(Ys[i], &c.R[i])
		finalAgg = curve.AddUnified(finalAgg, term)
	}

	// Assert that the computed final result equals the public input Agg.
	// This is the main constraint of the circuit.
	curve.AssertIsEqual(finalAgg, &c.Agg)
	return nil
}

// hadamardTransformRow computes the standard Hadamard transform for a single row
// outside the circuit. This is used to generate the witness (the expected result).
func hadamardTransformRow(g []bn254.G1Affine, rowIndex int) bn254.G1Affine {
	var result bn254.G1Affine

	// The value of H[i][j] is (-1)^(<i,j>), where <i,j> is the bitwise dot product
	// of the binary representations of i and j. This is equivalent to popcount(i & j) % 2.
	for j := 0; j < MatrixSize; j++ {
		// Count the number of set bits (popcount) after a bitwise AND between i and j.
		popcount := bits.OnesCount(uint(rowIndex & j))

		// Add or subtract the point g[j] based on the popcount.
		if j == 0 {
			if popcount%2 == 1 {
				result.Neg(&g[j])
			} else {
				result = g[j]
			}
		} else {
			if popcount%2 == 1 {
				result.Add(&result, new(bn254.G1Affine).Neg(&g[j]))
			} else {
				result.Add(&result, &g[j])
			}
		}
	}
	return result
}

func main() {
	field := ecc.BN254.ScalarField()

	// 1. Compile the circuit.
	var circuit FWHTIndicesCircuit
	fmt.Println("Compiling circuit...")
	t0 := time.Now()
	cs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit)
	fmt.Println("Circuit compiled in:", time.Since(t0))
	must(err)
	fmt.Println("# of constraints:", cs.GetNbConstraints())

	// 2. Prepare data for witness generation.
	// --- Generate G vector ---
	var g [MatrixSize]bn254.G1Affine
	gAffine := [MatrixSize]Affine{}
	fmt.Println("Generating G vector (1024 points)...")
	t1 := time.Now()
	for i := 0; i < MatrixSize; i++ {
		// Generate random points on the BN254 curve.
		randomScalar, err := rand.Int(rand.Reader, field)
		must(err)
		g[i].ScalarMultiplicationBase(randomScalar)
		//g[i].ScalarMultiplicationBase(big.NewInt(int64(i*3 + 5)))
		gAffine[i] = Affine{
			X: emu.ValueOf[emu.BN254Fp](g[i].X),
			Y: emu.ValueOf[emu.BN254Fp](g[i].Y),
		}
	}
	fmt.Println("G vector generated in:", time.Since(t1))

	// --- Generate Indices and R vectors ---
	indices := [NumIndices]frontend.Variable{0, 88, 123, 256, 311, 404, 512, 589, 666, 721, 789, 811, 888, 901, 955, 999, 1001, 1023}
	r := [NumIndices]emu.Element[emu.BN254Fr]{}
	rBig := [NumIndices]*big.Int{}
	fmt.Println("Generating R vector (18 scalars)...")
	t2 := time.Now()
	for i := 0; i < NumIndices; i++ {
		// Generate random scalars for R.
		rBig[i], err = rand.Int(rand.Reader, field)
		must(err)
		//rBig[i] = big.NewInt(int64(i*5 + 3))
		r[i] = emu.ValueOf[emu.BN254Fr](rBig[i])
	}
	fmt.Println("R vector generated in:", time.Since(t2))

	// 3. Pre-compute the final result (Agg) for the Public Witness.
	fmt.Println("Calculating expected Agg value...")
	var aggCalculator bn254.G1Affine
	var aggInitialized bool
	t3 := time.Now()
	for i := 0; i < NumIndices; i++ {
		rowIndex := indices[i].(int)
		// Y_i = H[rowIndex] * G
		y := hadamardTransformRow(g[:], rowIndex)

		// term = R_i * Y_i
		var term bn254.G1Affine
		term.ScalarMultiplication(&y, rBig[i])

		if !aggInitialized {
			aggCalculator = term
			aggInitialized = true
		} else {
			aggCalculator.Add(&aggCalculator, &term)
		}
	}
	fmt.Println("Agg value calculated in:", time.Since(t3))

	// 4. Assign the witness.
	// This includes both private (G) and public (Indices, R, Agg) inputs.
	fmt.Println("Preparing witness assignment...")
	t4 := time.Now()
	assignment := &FWHTIndicesCircuit{
		G:       gAffine,
		Indices: indices,
		R:       r,
		Agg:     Affine{X: emu.ValueOf[emu.BN254Fp](aggCalculator.X), Y: emu.ValueOf[emu.BN254Fp](aggCalculator.Y)},
	}

	// 5. Generate the witness.
	fmt.Println("Generating witness...")
	fullWitness, err := frontend.NewWitness(assignment, field)
	must(err)
	publicWitness, err := fullWitness.Public()
	must(err)
	fmt.Println("Witness generated in:", time.Since(t4))

	// 6. Groth16 Setup, Prove and Verify
	fmt.Println("Setting up Groth16...")
	t5 := time.Now()
	pk, vk, err := groth16.Setup(cs)
	fmt.Println("Groth16 setup in:", time.Since(t5))
	must(err)

	fmt.Println("Generating proof...")
	t6 := time.Now()
	proof, err := groth16.Prove(cs, pk, fullWitness)
	fmt.Println("Proof generated in:", time.Since(t6))
	must(err)

	fmt.Println("Verifying proof...")
	t7 := time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	fmt.Println("Proof verified in:", time.Since(t7))
	must(err)
	fmt.Println("proof is valid")
}
