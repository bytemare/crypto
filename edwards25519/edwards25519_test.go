// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package edwards25519

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/edwards25519"

	"github.com/bytemare/crypto/internal"
)

type vectors struct {
	Ciphersuite string   `json:"ciphersuite"`
	Dst         string   `json:"dst"`
	Vectors     []vector `json:"vectors"`
}

func TestID(t *testing.T) {
	group := New()
	element := group.Base().Mult(group.NewScalar().Random())
	encoded := element.Bytes()
	decoded, err := group.NewElement().Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reencoded := decoded.Bytes()

	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("expected equality when en/decoding element")
	}

	t.Log("here")
	t.Log(element.Bytes())
	t.Log(decoded.Bytes())
	if !element.Sub(decoded).IsIdentity() {
		t.Log(reencoded)
		t.Log(element.Bytes())
		t.Log(decoded.Bytes())
		t.Fatal("expected equality when en/decoding element")
	}
}

type vector struct {
	*vectors
	P struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"P"`
	Msg string `json:"msg"`
}

func decodePoint(x, y string) *edwards25519.Point {
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

	q, err := new(edwards25519.Point).SetBytes(yb)
	if err != nil {
		panic(err)
	}

	return q
}

func (v *vector) run(t *testing.T) {
	var p internal.Element
	if v.Ciphersuite == H2C {
		p = Group{}.HashToGroup([]byte(v.Msg), []byte(v.Dst))
	}
	if v.Ciphersuite == E2C {
		p = Group{}.EncodeToGroup([]byte(v.Msg), []byte(v.Dst))
	}

	q := decodePoint(v.P.X[2:], v.P.Y[2:])
	if q.Equal(p.(*Element).element) != 1 {
		t.Fatalf("Unexpected HashToGroup output."+
			"\n\tExpected %q\n\tgot %q", hex.EncodeToString(q.Bytes()), hex.EncodeToString(p.Bytes()))
	}
}

func TestHashToEdwards25519(t *testing.T) {
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

			if H2C != v.Ciphersuite && E2C != v.Ciphersuite {
				t.Fatalf("Wrong ciphersuite. Got %q", v.Ciphersuite)
			}
			for _, vc := range v.Vectors {
				vc.vectors = &v
				t.Run(v.Ciphersuite, vc.run)
			}

			return nil
		}); err != nil {
		t.Fatalf("error opening vector files: %v", err)
	}
}
