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
	errPanic "github.com/bytemare/crypto/internal"
	"testing"
)

func TestScalar_Arithmetic(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *group) {
		testScalarArithmetic(t, group.id)
	})
}

func testScalarArithmetic(t *testing.T, g Group) {
	s := g.NewScalar().Random()

	// Expect panic when adding a nil Scalar.
	if hasPanic, _ := errPanic.ExpectPanic(nil, func() {
		s.Add(nil)
	}); !hasPanic {
		t.Fatal("expected panic")
	}

	// Expect panic when subtracting a nil Element.
	if hasPanic, _ := errPanic.ExpectPanic(nil, func() {
		s.Sub(nil)
	}); !hasPanic {
		t.Fatal("expected panic")
	}

	// Test zero Scalar
	zero := s.Sub(s)
	if !zero.IsZero() {
		t.Fatal("expected zero scalar")
	}

	if !bytes.Equal(s.Add(g.NewScalar()).Bytes(), s.Bytes()) {
		t.Fatal("expected no change in adding zero scalar")
	}
	if !bytes.Equal(s.Sub(g.NewScalar()).Bytes(), s.Bytes()) {
		t.Fatal("not equal")
	}

	// Test Multiplication and inversion
	s = g.NewScalar().Random()
	sqr := s.Mult(s)
	i := s.Invert().Mult(sqr)
	if !bytes.Equal(i.Bytes(), s.Bytes()) {
		t.Fatal("expected equality")
	}
}

func TestScalar_Decode(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *group) {
		testScalarDecoding(t, group.id)
	})
}

func testScalarDecoding(t *testing.T, g Group) {
	s := g.NewScalar().Random()
	enc := s.Bytes()
	dec, err := g.NewScalar().Decode(enc)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	if !dec.Sub(s).IsZero() {
		t.Fatal("expected assertion to be true")
	}
}
