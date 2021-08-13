// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package other

import (
	"bytes"
	"testing"

	tests2 "github.com/bytemare/crypto/internal/tests"

	H2C "github.com/armfazh/h2c-go-ref"
)

var (
	dst       = []byte("TestApp-V00-CS123")
	testInput = []byte("input datafqverqvbdbq")
)

func TestPointEncoding(t *testing.T) {
	for id := range curves {
		t.Run(string(id), func(t *testing.T) {
			h := New(id)
			e := h.HashToGroup(testInput, dst)
			b := e.Bytes()
			n, err := h.NewElement().Decode(b)
			if err != nil {
				t.Fatal(err)
			}

			ne := e.(*Point)
			nn := n.(*Point)

			if !ne.point.IsEqual(nn.point) {
				t.Fatal("expected assertion to be true")
			}
		})
	}
}

func testPointArithmetic(t *testing.T, suite H2C.SuiteID, input []byte) {
	g := New(suite)

	// Test Addition and Subtraction
	base := g.Base()
	if hasPanic, _ := tests2.ExpectPanic(nil, func() {
		base.Add(nil)
	}); !hasPanic {
		t.Fatal("expected panic")
	}

	a := base.Add(base)
	if hasPanic, _ := tests2.ExpectPanic(nil, func() {
		a.Sub(nil)
	}); !hasPanic {
		t.Fatal("expected panic")
	}
	sub := a.Sub(base)
	if !bytes.Equal(sub.Bytes(), base.Bytes()) {
		t.Fatal("not equal")
	}

	// Test Multiplication and inversion
	base = g.Base()
	s := g.HashToScalar(input, nil)
	penc := base.Bytes()
	senc := s.Bytes()
	m := base.Mult(s)
	if m.IsIdentity() {
		t.Fatal("base mult s is identity")
	}
	e, err := g.MultBytes(senc, penc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Bytes(), e.Bytes()) {
		t.Fatal("not equal")
	}
	if hasPanic, err := tests2.ExpectPanic(errParamNilScalar, func() {
		m.InvertMult(nil)
	}); !hasPanic {
		t.Fatalf("expected panic: %v", err)
	}
	i := m.InvertMult(s)
	if !bytes.Equal(i.Bytes(), base.Bytes()) {
		t.Fatal("not equal")
	}

	// Test identity
	id := base.Sub(base)
	if !id.IsIdentity() {
		t.Fatal("expected assertion to be true")
	}
}

func TestPointArithmetic(t *testing.T) {
	for id := range curves {
		t.Run(string(id), func(t *testing.T) {
			testPointArithmetic(t, id, testInput)
		})
	}
}
