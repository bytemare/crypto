// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/bytemare/crypto/internal/ristretto"
)

type h2gTestBytes struct {
	x, dst, p []byte
}

type h2gTest struct {
	x   string
	dst string
	p   string
}

func (h *h2gTest) decode() (*h2gTestBytes, error) {
	b := &h2gTestBytes{}
	var err error

	b.x, err = hex.DecodeString(h.x)
	if err != nil {
		return nil, err
	}

	b.dst, err = hex.DecodeString(h.dst)
	if err != nil {
		return nil, err
	}

	b.p, err = hex.DecodeString(h.p)
	if err != nil {
		return nil, err
	}

	return b, err
}

var h2gTests = []h2gTest{
	{
		x:   "68656c6c6f",
		dst: "564f50524630362d48617368546f47726f75702d000001",
		p:   "723c88cc59988d39889aa607b6696d423e7718a36d4825e0f940b3c3a534396a",
	},
	{
		x:   "776f726c64",
		dst: "564f50524630362d48617368546f47726f75702d000001",
		p:   "a47c0a13c42a26ab06e60d2e251ba591334a289f4fdfe3b17ed3321a9527f44c",
	},
}

func TestRistretto_HashToGroup(t *testing.T) {
	for i, test := range h2gTests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			v, err := test.decode()
			if err != nil {
				t.Fatalf("%d : %v", i, err)
			}

			e := ristretto.Group{}.HashToGroup(v.x, v.dst)

			if !bytes.Equal(e.Encode(), v.p) {
				t.Fatalf(
					"Mappings do not match.\n\tExpected: %v\n\tActual: %v\n",
					hex.EncodeToString(v.p),
					hex.EncodeToString(e.Encode()),
				)
			}
		})
	}
}
