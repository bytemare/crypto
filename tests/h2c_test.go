// SPDX-License-Group: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group_test

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/bytemare/crypto"
)

type vectors struct {
	Ciphersuite string `json:"ciphersuite"`
	group       crypto.Group
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

func (v *vector) run(t *testing.T) {
	var expected string
	if v.group == crypto.P256Sha256 || v.group == crypto.P384Sha384 || v.group == crypto.P521Sha512 {
		e := ecFromGroup(v.group)
		x, y := vectorToNistBig(v.P.X, v.P.Y)
		expected = hex.EncodeToString(elliptic.MarshalCompressed(e, x, y))
	}

	switch v.Ciphersuite[len(v.Ciphersuite)-3:] {
	case "RO_":
		p := v.group.HashToGroup([]byte(v.Msg), []byte(v.Dst))

		if hex.EncodeToString(p.Encode()) != expected {
			t.Fatalf("Unexpected HashToGroup output.\n\tExpected %q\n\tgot %q", expected, hex.EncodeToString(p.Encode()))
		}
	case "NU_":
		p := v.group.EncodeToGroup([]byte(v.Msg), []byte(v.Dst))

		if hex.EncodeToString(p.Encode()) != expected {
			t.Fatalf("Unexpected EncodeToGroup output.\n\tExpected %q\n\tgot %q", expected, hex.EncodeToString(p.Encode()))
		}
	default:
		t.Fatal("ciphersuite not recognized")
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
	getGroup := func(ciphersuite string) (crypto.Group, bool) {
		for _, group := range groups {
			if group.h2c == ciphersuite || group.e2c == ciphersuite {
				return group.id, true
			}
		}
		return 0, false
	}
	if err := filepath.Walk("vectors",
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
