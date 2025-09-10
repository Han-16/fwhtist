package cache

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)


type scalarFile struct {
	Exp     int      `json:"exp"`
	N       int      `json:"n"`
	Scalars []string `json:"scalars_hex"` // hex (no 0x prefix)
}

type pointFile struct {
	Exp    int      `json:"exp"`
	N      int      `json:"n"`
	Points []string `json:"points_b64"` // base64(G1Affine.Marshal())
}

func ScalarPath(exp int) (string, error) {
	dir := filepath.Join(".", "data", "scalars")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("make scalars dir: %w", err)
	}
	filename := fmt.Sprintf("exp_%d_scalar.json", exp)
	return filepath.Join(dir, filename), nil
}

func PointPath(exp int) (string, error) {
	dir := filepath.Join(".", "data", "points")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("make points dir: %w", err)
	}
	filename := fmt.Sprintf("exp_%d_point.json", exp)
	return filepath.Join(dir, filename), nil
}

func SaveScalars(path string, exp int, scalars []fr.Element) error {
	sf := scalarFile{
		Exp:     exp,
		N:       len(scalars),
		Scalars: make([]string, len(scalars)),
	}
	for i := range scalars {
		sf.Scalars[i] = scalars[i].BigInt(new(big.Int)).Text(16)
	}
	data, err := json.MarshalIndent(&sf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func LoadScalars(path string) ([]fr.Element, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	var sf scalarFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, 0, err
	}
	if sf.N != len(sf.Scalars) {
		return nil, sf.Exp, fmt.Errorf("scalar cache malformed: n=%d, got %d scalars", sf.N, len(sf.Scalars))
	}
	out := make([]fr.Element, sf.N)
	for i := range out {
		bi, ok := new(big.Int).SetString(sf.Scalars[i], 16)
		if !ok {
			return nil, sf.Exp, fmt.Errorf("invalid scalar hex at %d", i)
		}
		out[i].SetBigInt(bi)
	}
	return out, sf.Exp, nil
}

func SavePoints(path string, exp int, points []bn254.G1Affine) error {
	pf := pointFile{
		Exp:    exp,
		N:      len(points),
		Points: make([]string, len(points)),
	}
	for i := range points {
		b := points[i].Marshal()
		pf.Points[i] = base64.StdEncoding.EncodeToString(b)
	}
	data, err := json.MarshalIndent(&pf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func LoadPoints(path string) ([]bn254.G1Affine, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	var pf pointFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, 0, err
	}
	if pf.N != len(pf.Points) {
		return nil, pf.Exp, fmt.Errorf("point cache malformed: n=%d, got %d points", pf.N, len(pf.Points))
	}
	out := make([]bn254.G1Affine, pf.N)
	for i := range out {
		raw, err := base64.StdEncoding.DecodeString(pf.Points[i])
		if err != nil {
			return nil, pf.Exp, fmt.Errorf("invalid point b64 at %d: %w", i, err)
		}
		if err := out[i].Unmarshal(raw); err != nil {
			return nil, pf.Exp, fmt.Errorf("unmarshal point %d: %w", i, err)
		}
	}
	return out, pf.Exp, nil
}

func LoadOrCreateScalars(
	exp, n int,
	genScalars func(int) ([]fr.Element, error),
) ([]fr.Element, bool, error) {

	spath, err := ScalarPath(exp)
	if err != nil {
		return nil, false, err
	}

	if fi, err := os.Stat(spath); err == nil && !fi.IsDir() {
		fmt.Printf("Scalar cache found for exp=%d → trying to load...\n", exp)
		sc, fileExp, err := LoadScalars(spath)
		if err == nil && len(sc) == n && fileExp == exp {
			fmt.Println("✅ Successfully loaded scalars from cache.")
			return sc, true, nil
		}
		fmt.Println("⚠️  Scalar cache invalid; regenerating scalars...")
	}

	scalars, err := genScalars(n)
	if err != nil {
		return nil, false, err
	}
	fmt.Printf("Saving scalars to: %s\n", spath)
	if err := SaveScalars(spath, exp, scalars); err != nil {
		return nil, false, err
	}
	return scalars, false, nil
}

func LoadOrCreatePoints(
	exp, n int,
	genPoints func(int) ([]bn254.G1Affine, error),
) ([]bn254.G1Affine, bool, error) {

	ppath, err := PointPath(exp)
	if err != nil {
		return nil, false, err
	}

	if fi, err := os.Stat(ppath); err == nil && !fi.IsDir() {
		fmt.Printf("Point cache found for exp=%d → trying to load...\n", exp)
		pt, fileExp, err := LoadPoints(ppath)
		if err == nil && len(pt) == n && fileExp == exp {
			fmt.Println("✅ Successfully loaded points from cache.")
			return pt, true, nil
		}
		fmt.Println("⚠️  Point cache invalid; regenerating points...")
	}

	points, err := genPoints(n)
	if err != nil {
		return nil, false, err
	}
	fmt.Printf("Saving points to: %s\n", ppath)
	if err := SavePoints(ppath, exp, points); err != nil {
		return nil, false, err
	}
	return points, false, nil
}

func LoadOrCreateInputs(
	exp, n int,
	genScalars func(int) ([]fr.Element, error),
	genPoints func(int) ([]bn254.G1Affine, error),
) ([]fr.Element, []bn254.G1Affine, bool, error) {

	sc, sFromCache, err := LoadOrCreateScalars(exp, n, genScalars)
	if err != nil {
		return nil, nil, false, err
	}
	pt, pFromCache, err := LoadOrCreatePoints(exp, n, genPoints)
	if err != nil {
		return nil, nil, false, err
	}
	return sc, pt, (sFromCache && pFromCache), nil
}
