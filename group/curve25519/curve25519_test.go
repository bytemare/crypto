// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package curve25519

import (
	"encoding/hex"
	"testing"
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

func (v *vectors) run(t *testing.T) {
	if H2C != v.Ciphersuite {
		t.Fatalf("Wrong ciphersuite. Expected %q, got %q", v.Ciphersuite, H2C)
	}
	for _, vector := range v.Vectors {
		p := Group{}.HashToGroup([]byte(vector.Msg), []byte(v.Dst))
		if hex.EncodeToString(reverse(p.Bytes())) != vector.P.X[2:] {
			t.Fatalf("Unexpected HashToGroup output. Expected %q, got %q", vector.P.X, hex.EncodeToString(p.Bytes()))
		}
	}
}

//func TestHashToCurve25519(t *testing.T) {
//	file, errOpen := os.Open("vectors.json")
//	if errOpen != nil {
//		t.Fatal(errOpen)
//	}
//
//	defer file.Close()
//
//	val, errRead := ioutil.ReadAll(file)
//	if errRead != nil {
//		t.Fatal(errRead)
//	}
//
//	var v vectors
//	errJSON := json.Unmarshal(val, &v)
//	if errJSON != nil {
//		t.Fatal(errJSON)
//	}
//
//	v.run(t)
//}
