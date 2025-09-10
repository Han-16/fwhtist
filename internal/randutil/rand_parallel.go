package randutil

import (
	"crypto/rand"
	"runtime"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// RandomScalarsPar generates n random scalars in parallel.
// If workers <= 0, it defaults to runtime.NumCPU().
// It returns a slice of length n (possibly empty if n<=0).
func RandomScalarsPar(n, workers int) ([]fr.Element, error) {
	if n <= 0 {
		return []fr.Element{}, nil
	}
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	out := make([]fr.Element, n)
	jobs := make(chan int, workers*2)

	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once

	// workers
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				// NOTE: crypto/rand.Reader is safe for concurrent use.
				bi, err := rand.Int(rand.Reader, fr.Modulus())
				if err != nil {
					errOnce.Do(func() { firstErr = err })
					continue
				}
				var e fr.Element
				e.SetBigInt(bi)
				out[i] = e
			}
		}()
	}

	// enqueue jobs
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// RandomPointsG1Par generates n random G1 points in parallel.
// Each point is (random scalar) * G1 generator (affine).
// If workers <= 0, it defaults to runtime.NumCPU().
// It returns a slice of length n (possibly empty if n<=0).
func RandomPointsG1Par(n, workers int) ([]bn254.G1Affine, error) {
	if n <= 0 {
		return []bn254.G1Affine{}, nil
	}
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	out := make([]bn254.G1Affine, n)

	// G1 generator (affine)
	_, _, g1GenAff, _ := bn254.Generators()

	jobs := make(chan int, workers*2)

	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once

	// workers
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				// draw random scalar in Fr
				bi, err := rand.Int(rand.Reader, fr.Modulus())
				if err != nil {
					errOnce.Do(func() { firstErr = err })
					continue
				}
				// point = bi * G
				var p bn254.G1Affine
				p.ScalarMultiplication(&g1GenAff, bi)
				out[i] = p
			}
		}()
	}

	// enqueue jobs
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}
