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
	"github.com/bytemare/crypto/internal"
)

func TestScalar_WrongInput(t *testing.T) {
	exec := func(f func(*crypto.Scalar) *crypto.Scalar, arg *crypto.Scalar) func() {
		return func() {
			f(arg)
		}
	}

	equal := func(f func(*crypto.Scalar) int, arg *crypto.Scalar) func() {
		return func() {
			f(arg)
		}
	}

	testAll(t, func(t2 *testing.T, group *testGroup) {
		scalar := group.id.NewScalar()
		methods := []func(arg *crypto.Scalar) *crypto.Scalar{
			scalar.Add, scalar.Subtract, scalar.Multiply, scalar.Set,
		}

		var wrongGroup crypto.Group

		switch group.id {
		case crypto.Ristretto255Sha512:
			wrongGroup = crypto.P256Sha256
		case crypto.P256Sha256, crypto.P384Sha384, crypto.P521Sha512:
			wrongGroup = crypto.Ristretto255Sha512

			// Add a special test for nist groups, using a different field
			wrongfield := ((group.id + 1) % 3) + 3
			if err := testPanic("wrong field", internal.ErrWrongField, exec(scalar.Add, wrongfield.NewScalar())); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("Invalid group id %d", group.id)
		}

		for _, f := range methods {
			if err := testPanic("wrong group", internal.ErrCastScalar, exec(f, wrongGroup.NewScalar())); err != nil {
				t.Fatal(err)
			}
		}

		if err := testPanic("wrong group", internal.ErrCastScalar, equal(scalar.Equal, wrongGroup.NewScalar())); err != nil {
			t.Fatal(err)
		}

	})
}

func testScalarCopySet(t *testing.T, scalar, other *crypto.Scalar) {
	// Verify they don't point to the same thing
	if &scalar == &other {
		t.Fatalf("Pointer to the same scalar")
	}

	// Verify whether they are equivalent
	if scalar.Equal(other) != 1 {
		t.Fatalf("Expected equality")
	}

	// Verify than operations on one don't affect the other
	scalar.Add(scalar)
	if scalar.Equal(other) == 1 {
		t.Fatalf("Unexpected equality")
	}

	other.Invert()
	if scalar.Equal(other) == 1 {
		t.Fatalf("Unexpected equality")
	}
}

func TestScalarCopy(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		random := group.id.NewScalar().Random()
		cpy := random.Copy()
		testScalarCopySet(t, random, cpy)
	})
}

func TestScalarSet(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		random := group.id.NewScalar().Random()
		other := group.id.NewScalar()
		other.Set(random)
		testScalarCopySet(t, random, other)
	})
}

func TestScalar_Arithmetic(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		scalarTestZero(t, group.id)
		scalarTestOne(t, group.id)
		scalarTestEqual(t, group.id)
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
	if one.Equal(m.Multiply(m)) != 1 {
		t.Fatal(expectedEquality)
	}
}

func scalarTestRandom(t *testing.T, g crypto.Group) {
	r := g.NewScalar().Random()
	if r.Equal(g.NewScalar().Zero()) == 1 {
		t.Fatalf("random scalar is zero: %v", hex.EncodeToString(r.Encode()))
	}
}

func scalarTestEqual(t *testing.T, g crypto.Group) {
	zero := g.NewScalar().Zero()
	zero2 := g.NewScalar().Zero()

	if zero.Equal(zero2) != 1 {
		t.Fatal(expectedEquality)
	}

	random := g.NewScalar().Random()
	cpy := random.Copy()
	if random.Equal(cpy) != 1 {
		t.Fatal(expectedEquality)
	}

	random2 := g.NewScalar().Random()
	if random.Equal(random2) == 1 {
		t.Fatal("unexpected equality")
	}
}

func scalarTestAdd(t *testing.T, g crypto.Group) {
	r := g.NewScalar().Random()
	cpy := r.Copy()
	if r.Add(nil).Equal(cpy) != 1 {
		t.Fatal(expectedEquality)
	}
}

func scalarTestSubtract(t *testing.T, g crypto.Group) {
	r := g.NewScalar().Random()
	cpy := r.Copy()
	if r.Subtract(nil).Equal(cpy) != 1 {
		t.Fatal(expectedEquality)
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
	sqr := s.Copy().Multiply(s)

	i := s.Copy().Invert().Multiply(sqr)
	if i.Equal(s) != 1 {
		t.Fatal(expectedEquality)
	}

	s = g.NewScalar().Random()
	square := s.Copy().Multiply(s)
	inv := square.Copy().Invert()
	if s.One().Equal(square.Multiply(inv)) != 1 {
		t.Fatal(expectedEquality)
	}
}
