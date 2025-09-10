package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/Han-16/fwhtist/internal/randutil"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage : go run main.go <exp>")
		fmt.Println("Example: go run main.go 10   # generates 2^10 = 1024 scalars")
		return
	}

	exp, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("Invalid exponent:", os.Args[1])
		return
	}

	n := 1 << exp // 2^exp

	scalars, err := randutil.RandomScalars(n)
	if err != nil {
		fmt.Println("Error generating random scalars:", err)
		return
	}

	fmt.Printf("Generated %d random scalars:\n", n)
	for i, scalar := range scalars {
		fmt.Printf("Scalar %d: %s\n", i, scalar.String())
	}

	fmt.Println("=============================")

	points, err := randutil.RandomPointsG1(n)

	if err != nil {
		fmt.Println("Error generating random G1 points:", err)
		return
	}

	fmt.Printf("Generated %d random G1 points:\n", n)
	for i, point := range points {
		fmt.Printf("Point %d: %s\n", i, point.String())
	}

}