// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package edwards25519

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"filippo.io/edwards25519"
)

type vectors struct {
	Ciphersuite string `json:"ciphersuite"`
	Dst         string `json:"dst"`
	Vectors     []struct {
		P struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"P"`
		Msg string `json:"msg"`
	} `json:"vectors"`
}

func reverse(b []byte) []byte {
	l := len(b) - 1
	for i := 0; i < len(b)/2; i++ {
		b[i], b[l-i] = b[l-i], b[i]
	}

	return b
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

func (v *vectors) run(t *testing.T) {
	if H2C != v.Ciphersuite {
		t.Fatalf("Wrong ciphersuite. Expected %q, got %q", v.Ciphersuite, H2C)
	}
	for _, vector := range v.Vectors {
		p := Group{}.HashToGroup([]byte(vector.Msg), []byte(v.Dst))
		q := decodePoint(vector.P.X[2:], vector.P.Y[2:])
		if q.Equal(p.(*Element).element) != 1 {
			t.Fatalf("Unexpected HashToGroup output. Expected %q, got %q", hex.EncodeToString(q.Bytes()), hex.EncodeToString(p.Bytes()))
		}
	}
}

func TestHashToEdwards25519(t *testing.T) {
	file, errOpen := os.Open("vectors.json")
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

	v.run(t)
}
