// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group_test

import (
	"testing"

	"github.com/bytemare/crypto"
)

func TestScalar_Arithmetic(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *group) {
		testScalarArithmetic(t, group.id)
	})
}

func testScalarArithmetic(t *testing.T, g crypto.Group) {
	s := g.NewScalar().Random()

	// Adding and subtracting nil must yield the same element
	if s.Add(nil).Equal(s) != 1 {
		t.Fatal("expected equality")
	}

	if s.Sub(nil).Equal(s) != 1 {
		t.Fatal("expected equality")
	}

	// Test zero Scalar
	zero := g.NewScalar()
	if !zero.IsZero() {
		t.Fatal("expected zero scalar")
	}

	s = g.NewScalar().Random()

	zero = s.Sub(s)
	if !zero.IsZero() {
		t.Fatal("expected zero scalar")
	}

	if s.Add(zero).Equal(s) != 1 {
		t.Fatal("expected no change in adding zero scalar")
	}
	if s.Add(zero).Equal(s) != 1 {
		t.Fatal("not equal")
	}

	// Test Multiplication and inversion
	s = g.NewScalar().Random()
	sqr := s.Mult(s)

	i := s.Invert().Mult(sqr)
	if i.Equal(s) != 1 {
		t.Fatal("expected equality")
	}

	if !s.Multiply(nil).IsZero() {
		t.Fatal("expected zero")
	}
}

func TestScalar_Decode(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *group) {
		testScalarDecoding(t, group.id)
	})
}

func testScalarDecoding(t *testing.T, g crypto.Group) {
	s := g.NewScalar().Random()
	enc := s.Bytes()
	dec, err := g.NewScalar().Decode(enc)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	if !dec.Sub(s).IsZero() {
		t.Fatal("expected assertion to be true")
	}

	_, err = g.NewScalar().Decode(nil)
	if err == nil {
		t.Fatal("expected error on nil input")
	}
}
