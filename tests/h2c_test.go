// SPDX-License-Group: MIT
//
// Copyright (C) 2020-2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group_test

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"

	"github.com/bytemare/crypto"
	edwards255192 "github.com/bytemare/crypto/internal/edwards25519"
)

const hashToCurveVectorsFileLocation = "h2c"

type h2cVectors struct {
	Ciphersuite string      `json:"ciphersuite"`
	Dst         string      `json:"dst"`
	Vectors     []h2cVector `json:"vectors"`
	group       crypto.Group
}

type h2cVector struct {
	*h2cVectors
	P struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"P"`
	Q0 struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"Q0"`
	Q1 struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"Q1"`
	Msg string   `json:"msg"`
	U   []string `json:"u"`
}

func ecFromGroup(g crypto.Group) elliptic.Curve {
	switch g {
	case crypto.P256Sha256:
		return elliptic.P256()
	case crypto.P384Sha384:
		return elliptic.P384()
	case crypto.P521Sha512:
		return elliptic.P521()
	default:
		panic("invalid nist group")
	}
}

func vectorToBig(x, y string) (*big.Int, *big.Int) {
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

func affineToEdwards(t *testing.T, a string) *field.Element {
	aBytes, err := hex.DecodeString(a[2:])
	if err != nil {
		t.Fatal(err)
	}

	// reverse
	for i, j := 0, len(aBytes)-1; j > i; i++ {
		aBytes[i], aBytes[j] = aBytes[j], aBytes[i]
		j--
	}

	u := &field.Element{}
	if _, err := u.SetBytes(aBytes); err != nil {
		t.Fatal(err)
	}

	return u
}

func vectorToEdwards25519(t *testing.T, x, y string) *edwards25519.Point {
	u, v := affineToEdwards(t, x), affineToEdwards(t, y)
	return edwards255192.AffineToEdwards(u, v)
}

func vectorToSecp256k1(x, y string) []byte {
	var output [33]byte

	yb, _ := hex.DecodeString(y[2:])
	yint := new(big.Int).SetBytes(yb)
	output[0] = byte(2 | yint.Bit(0)&1)

	xb, _ := hex.DecodeString(x[2:])
	copy(output[1:], xb)

	return output[:]
}

func (v *h2cVector) run(t *testing.T) {
	var expected string

	switch v.group {
	case crypto.P256Sha256, crypto.P384Sha384, crypto.P521Sha512:
		e := ecFromGroup(v.group)
		x, y := vectorToBig(v.P.X, v.P.Y)
		expected = hex.EncodeToString(elliptic.MarshalCompressed(e, x, y))
	case crypto.Edwards25519Sha512:
		p := vectorToEdwards25519(t, v.P.X, v.P.Y)
		expected = hex.EncodeToString(p.Bytes())
	case crypto.Secp256k1:
		expected = hex.EncodeToString(vectorToSecp256k1(v.P.X, v.P.Y))
	}

	switch v.Ciphersuite[len(v.Ciphersuite)-3:] {
	case "RO_":
		p := v.group.HashToGroup([]byte(v.Msg), []byte(v.Dst))
		if err := verifyEncoding(p, "HashToGroup", expected); err != nil {
			t.Fatal(err)
		}
	case "NU_":
		p := v.group.EncodeToGroup([]byte(v.Msg), []byte(v.Dst))
		if err := verifyEncoding(p, "EncodeToGroup", expected); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("ciphersuite not recognized")
	}
}

func verifyEncoding(p *crypto.Element, function, expected string) error {
	if hex.EncodeToString(p.Encode()) != expected {
		return fmt.Errorf("Unexpected %s output.\n\tExpected %q\n\tgot %q",
			function,
			expected,
			hex.EncodeToString(p.Encode()),
		)
	}

	return nil
}

func (v *h2cVectors) runCiphersuite(t *testing.T) {
	for _, vector := range v.Vectors {
		vector.h2cVectors = v
		t.Run(v.Ciphersuite, vector.run)
	}
}

func TestHashToGroupVectors(t *testing.T) {
	getGroup := func(ciphersuite string) (crypto.Group, bool) {
		for _, group := range testTable {
			if group.h2c == ciphersuite || group.e2c == ciphersuite {
				return group.group, true
			}
		}
		return 0, false
	}

	if err := filepath.Walk(hashToCurveVectorsFileLocation,
		func(path string, info os.FileInfo, err error) error {
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

			defer func(file *os.File) {
				err := file.Close()
				if err != nil {
					t.Logf("error closing file: %v", err)
				}
			}(file)

			val, errRead := io.ReadAll(file)
			if errRead != nil {
				t.Fatal(errRead)
			}

			var v h2cVectors
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
