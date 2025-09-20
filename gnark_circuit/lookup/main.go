package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/bits"
)

// Hadamard matrix (8x8)
var H = [8][8]int{
	{1, 1, 1, 1, 1, 1, 1, 1},
	{1, -1, 1, -1, 1, -1, 1, -1},
	{1, 1, -1, -1, 1, 1, -1, -1},
	{1, -1, -1, 1, 1, -1, -1, 1},
	{1, 1, 1, 1, -1, -1, -1, -1},
	{1, -1, 1, -1, -1, 1, -1, 1},
	{1, 1, -1, -1, -1, -1, 1, 1},
	{1, -1, -1, 1, -1, 1, 1, -1},
}

type DotProductLookupCircuit struct {
	Indices [3]frontend.Variable `gnark:",public"`
	Result  [3]frontend.Variable `gnark:",public"`
	X       [8]frontend.Variable `gnark:",secret"`
}

func (c *DotProductLookupCircuit) Define(api frontend.API) error {
	const n = 8 // Matrix dimension

	// Convert H matrix to frontend.Variable
	hVars := make([][n]frontend.Variable, n)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			hVars[i][j] = frontend.Variable(H[i][j])
		}
	}

	// Iterate through each requested row index
	for i := 0; i < len(c.Indices); i++ {
		// Decompose the current index into 3 bits
		indexBits := bits.ToBinary(api, c.Indices[i], bits.WithNbDigits(3))
		b0, b1, b2 := indexBits[0], indexBits[1], indexBits[2]

		// Select the correct row from H using nested Lookups
		// First, select the half of the table based on b2 (MSB)
		// If b2=0, select rows 0-3. If b2=1, select rows 4-7.
		var selectedRow [n]frontend.Variable
		for j := 0; j < n; j++ {
			// Use b0 and b1 to select from two pairs of rows
			var i0, i1, i2, i3 frontend.Variable
			i0 = hVars[0][j]
			i1 = hVars[1][j]
			i2 = hVars[2][j]
			i3 = hVars[3][j]
			term0_3 := api.Lookup2(b0, b1, i0, i1, i2, i3)

			i0 = hVars[4][j]
			i1 = hVars[5][j]
			i2 = hVars[6][j]
			i3 = hVars[7][j]
			term4_7 := api.Lookup2(b0, b1, i0, i1, i2, i3)

			selectedRow[j] = api.Select(b2, term4_7, term0_3)
		}

		// Perform the dot product
		dotProduct := frontend.Variable(0)
		for j := 0; j < n; j++ {
			// Since H values are 1 or -1, we can avoid api.Mul
			isOne := api.IsZero(api.Sub(selectedRow[j], 1))
			term := api.Select(isOne, c.X[j], api.Neg(c.X[j]))
			dotProduct = api.Add(dotProduct, term)
		}

		// Assert that the calculated dot product is correct
		api.AssertIsEqual(dotProduct, c.Result[i])
	}

	return nil
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	field := ecc.BN254.ScalarField()
	var circuit DotProductLookupCircuit

	// For compilation, variables must be initialized
	cs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit)
	must(err)

	fmt.Println("Number of constraints:", cs.GetNbConstraints())

	// Example Witness
	// Indices = [1, 2, 5]
	// X = [1, 2, 3, 4, 5, 6, 7, 8]
	//
	// Result for Index 1 (row 1):
	// {1, -1, 1, -1, 1, -1, 1, -1}
	// dot = 1-2+3-4+5-6+7-8 = -4
	//
	// Result for Index 2 (row 2):
	// {1, 1, -1, -1, 1, 1, -1, -1}
	// dot = 1+2-3-4+5+6-7-8 = -8
	//
	// Result for Index 5 (row 5):
	// {1, -1, 1, -1, -1, 1, -1, 1}
	// dot = 1-2+3-4-5+6-7+8 = 0

	assignment := &DotProductLookupCircuit{
		Indices: [3]frontend.Variable{1, 2, 5},
		X:       [8]frontend.Variable{1, 2, 3, 4, 5, 6, 7, 8},
		Result:  [3]frontend.Variable{-4, -8, 0},
	}

	fullWitness, err := frontend.NewWitness(assignment, field)
	must(err)
	publicWitness, err := fullWitness.Public()
	must(err)

	fmt.Println("Generating keys...")
	pk, vk, err := groth16.Setup(cs)
	must(err)

	fmt.Println("Generating proof...")
	proof, err := groth16.Prove(cs, pk, fullWitness)
	must(err)

	fmt.Println("Verifying proof...")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("Verification failed:", err)
	} else {
		fmt.Println("Verification successful!")
	}
}
