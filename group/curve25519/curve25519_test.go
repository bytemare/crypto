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
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/bytemare/crypto/group/internal"
)

type vectors struct {
	Ciphersuite string   `json:"ciphersuite"`
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

func (v *vector) run(t *testing.T) {
	var p internal.Element
	if v.Ciphersuite == H2C {
		p = Group{}.HashToGroup([]byte(v.Msg), []byte(v.Dst))
	}
	if v.Ciphersuite == E2C {
		p = Group{}.EncodeToGroup([]byte(v.Msg), []byte(v.Dst))
	}

	exp, _ := hex.DecodeString(v.P.X[2:])

	if hex.EncodeToString(p.Bytes()) != hex.EncodeToString(reverse(exp)) {
		t.Fatalf("Unexpected HashToGroup output.\n\tExpected %q\n\tot %q", hex.EncodeToString(reverse(exp)), hex.EncodeToString(p.Bytes()))
	}
}

func TestHashToCurve25519(t *testing.T) {
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
