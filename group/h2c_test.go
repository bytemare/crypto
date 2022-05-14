package group

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type vectors struct {
	Ciphersuite string `json:"ciphersuite"`
	group       Group
	Dst         string   `json:"dst"`
	Vectors     []vector `json:"vectors"`
}

type vector struct {
	*vectors
	P struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"P"`
	Msg string `json:"msg"`
}

func ecFromGroup(g Group) elliptic.Curve {
	switch g {
	case P256Sha256:
		return elliptic.P256()
	case P384Sha384:
		return elliptic.P384()
	case P521Sha512:
		return elliptic.P521()
	}
	panic(nil)
}

func vectorToNistBig(x, y string) (*big.Int, *big.Int) {
	xb, ok := new(big.Int).SetString(x, 0)
	if !ok {
		panic("invalid x")
	}

	yb, ok := new(big.Int).SetString(y, 0)
	if !ok {
		panic("invalid y")
	}

	return xb, yb
}

func decodeEd25519(x, y string) []byte {
	xb, err := hex.DecodeString(x)
	if err != nil {
		panic(err)
	}

	yb, err := hex.DecodeString(y)
	if err != nil {
		panic(err)
	}

	yb = reverse(yb)
	isXNeg := int(xb[31] & 1)
	yb[31] |= byte(isXNeg << 7)

	//q, err := new(edwards25519.Point).SetBytes(yb)
	//if err != nil {
	//	panic(err)
	//}

	q, err := Edwards25519Sha512.NewElement().Decode(yb)
	if err != nil {
		panic(err)
	}

	return q.Bytes()
}

func reverse(b []byte) []byte {
	l := len(b) - 1
	for i := 0; i < len(b)/2; i++ {
		b[i], b[l-i] = b[l-i], b[i]
	}

	return b
}

func (v *vector) run(t *testing.T) {
	var expected string
	switch {
	case v.group == P256Sha256 || v.group == P384Sha384 || v.group == P521Sha512:
		e := ecFromGroup(v.group)
		x, y := vectorToNistBig(v.P.X, v.P.Y)
		expected = hex.EncodeToString(elliptic.MarshalCompressed(e, x, y))
	case v.group == Curve25519Sha512:
		exp, _ := hex.DecodeString(v.P.X[2:])
		expected = hex.EncodeToString(reverse(exp))
	case v.group == Edwards25519Sha512:
		expected = hex.EncodeToString(decodeEd25519(v.P.X[2:], v.P.Y[2:]))
	default:
		return
	}

	p := v.group.HashToGroup([]byte(v.Msg), []byte(v.Dst))

	if hex.EncodeToString(p.Bytes()) != expected {
		t.Fatalf("Unexpected HashToGroup output.\n\tExpected %q\n\tgot %q", expected, hex.EncodeToString(p.Bytes()))
	}
}

func (v *vectors) runCiphersuite(t *testing.T) {
	for _, vector := range v.Vectors {
		vector.vectors = v
		t.Run(v.Ciphersuite, vector.run)
	}
}

func TestHashToGroupVectors(t *testing.T) {
	groups := testGroups()
	getGroup := func(ciphersuite string) (Group, bool) {
		for _, group := range groups {
			if group.h2c == ciphersuite {
				return group.id, true
			}
		}
		return 0, false
	}
	if err := filepath.Walk("vectors",
		func(path string, info os.FileInfo, err error) error {
			if strings.HasSuffix(path, "NU_.json") {
				return nil
			}

			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}
			file, errOpen := os.Open(path)
			if errOpen != nil {
				t.Fatal(errOpen)
			}

			defer file.Close()

			val, errRead := ioutil.ReadAll(file)
			if errRead != nil {
				t.Fatal(errRead)
			}

			var v vectors
			errJSON := json.Unmarshal(val, &v)
			if errJSON != nil {
				t.Fatal(errJSON)
			}

			group, ok := getGroup(v.Ciphersuite)
			if !ok {
				t.Logf("Unsupported ciphersuite. Got %q", v.Ciphersuite)
				return nil
			}

			v.group = group
			t.Run(v.Ciphersuite, v.runCiphersuite)

			return nil
		}); err != nil {
		t.Fatalf("error opening vector files: %v", err)
	}
}
