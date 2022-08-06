// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group_test

import (
	"encoding/hex"
	"testing"

	"github.com/bytemare/crypto"
)

func TestScalar_Arithmetic(t *testing.T) {
	testAllGroups(t, func(t2 *testing.T, group *testGroup) {
		scalarTestZero(t, group.id)
		scalarTestOne(t, group.id)
		scalarTestRandom(t, group.id)
		scalarTestAdd(t, group.id)
		scalarTestSubtract(t, group.id)
		scalarTestMultiply(t, group.id)
		scalarTestInvert(t, group.id)
	})
}

func scalarTestZero(t *testing.T, g crypto.Group) {
	zero := g.NewScalar()
	if !zero.IsZero() {
		t.Fatal("expected zero scalar")
	}

	s := g.NewScalar().Random()
	if !s.Subtract(s).IsZero() {
		t.Fatal("expected zero scalar")
	}

	s = g.NewScalar().Random()
	if s.Add(zero).Equal(s) != 1 {
		t.Fatal("expected no change in adding zero scalar")
	}

	s = g.NewScalar().Random()
	if s.Add(zero).Equal(s) != 1 {
		t.Fatal("not equal")
	}
}

func scalarTestOne(t *testing.T, g crypto.Group) {
	one := g.NewScalar().One()
	m := one.Copy()
	if one.Equal(m.Mult(m)) != 1 {
		t.Fatal("expected equality")
	}
}

func scalarTestRandom(t *testing.T, g crypto.Group) {
	r := g.NewScalar().Random()
	if r.Equal(g.NewScalar().Zero()) == 1 {
		t.Fatalf("random scalar is zero: %v", hex.EncodeToString(r.Encode()))
	}
}

func scalarTestAdd(t *testing.T, g crypto.Group) {
	r := g.NewScalar().Random()
	cpy := r.Copy()
	if r.Add(nil).Equal(cpy) != 1 {
		t.Fatal("expected equality")
	}
}

func scalarTestSubtract(t *testing.T, g crypto.Group) {
	r := g.NewScalar().Random()
	cpy := r.Copy()
	if r.Subtract(nil).Equal(cpy) != 1 {
		t.Fatal("expected equality")
	}
}

func scalarTestMultiply(t *testing.T, g crypto.Group) {
	s := g.NewScalar().Random()
	if !s.Multiply(nil).IsZero() {
		t.Fatal("expected zero")
	}
}

func scalarTestInvert(t *testing.T, g crypto.Group) {
	s := g.NewScalar().Random()
	sqr := s.Copy().Mult(s)

	i := s.Invert().Mult(sqr)
	if i.Equal(s) != 1 {
		t.Fatal("expected equality")
	}

	cpy := sqr.Copy()
	if s.One().Equal(cpy.Mult(sqr.Invert())) != 1 {
		t.Fatal("expected equality")
	}
}

func TestScalar_Decode(t *testing.T) {
	testAllGroups(t, func(t2 *testing.T, group *testGroup) {
		testScalarDecoding(t, group.id)
	})
}

func testScalarDecoding(t *testing.T, g crypto.Group) {
	s := g.NewScalar().Random()
	enc := s.Encode()

	dec := g.NewScalar()
	if err := dec.Decode(enc); err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	if !dec.Subtract(s).IsZero() {
		t.Fatal("expected assertion to be true")
	}

	if g.NewScalar().Decode(nil) == nil {
		t.Fatal("expected error on nil input")
	}
}
