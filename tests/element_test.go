// SPDX-License-Group: MIT
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
	"github.com/bytemare/crypto/internal"
)

const (
	expectedEquality = "expected equality"
	expectedIdentity = "expected identity"
	wrongGroup       = "wrong group"
)

func TestElement_SetCopy(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		g := group.id
		base := g.Base()

		set := g.NewElement().Set(base)
		if set.Equal(base) != 1 {
			t.Fatal(expectedEquality)
		}

		cpy := base.Copy()
		if cpy.Equal(base) != 1 {
			t.Fatal(expectedEquality)
		}
	})
}

func TestElement_WrongInput(t *testing.T) {
	exec := func(f func(*crypto.Element) *crypto.Element, arg *crypto.Element) func() {
		return func() {
			_ = f(arg)
		}
	}

	equal := func(f func(*crypto.Element) int, arg *crypto.Element) func() {
		return func() {
			f(arg)
		}
	}

	mult := func(f func(*crypto.Scalar) *crypto.Element, arg *crypto.Scalar) func() {
		return func() {
			f(arg)
		}
	}

	testAll(t, func(t2 *testing.T, group *testGroup) {
		element := group.id.NewElement()
		var alternativeGroup crypto.Group

		switch group.id {
		case crypto.Ristretto255Sha512:
			alternativeGroup = crypto.P256Sha256
		case crypto.P256Sha256, crypto.P384Sha384, crypto.P521Sha512:
			alternativeGroup = crypto.Ristretto255Sha512
		default:
			t.Fatalf("Invalid group id %d", group.id)
		}

		if err := testPanic(wrongGroup, internal.ErrCastElement, exec(element.Add, alternativeGroup.NewElement())); err != nil {
			t.Fatal(err)
		}

		if err := testPanic(wrongGroup, internal.ErrCastElement, exec(element.Subtract, alternativeGroup.NewElement())); err != nil {
			t.Fatal(err)
		}

		if err := testPanic(wrongGroup, internal.ErrCastElement, exec(element.Set, alternativeGroup.NewElement())); err != nil {
			t.Fatal(err)
		}

		if err := testPanic(wrongGroup, internal.ErrCastElement, equal(element.Equal, alternativeGroup.NewElement())); err != nil {
			t.Fatal(err)
		}
	})

	// Specifically test Ristretto
	if err := testPanic(wrongGroup, internal.ErrCastScalar, mult(crypto.Ristretto255Sha512.NewElement().Multiply, crypto.P384Sha384.NewScalar())); err != nil {
		t.Fatal(err)
	}
}

func TestElement_Arithmetic(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		elementTestEqual(t, group.id)
		elementTestAdd(t, group.id)
		elementTestDouble(t, group.id)
		elementTestSubstract(t, group.id)
		elementTestMultiply(t, group.id)
		elementTestInversion(t, group.id)
		elementTestIdentity(t, group.id)
	})
}

func elementTestEqual(t *testing.T, g crypto.Group) {
	base := g.Base()
	base2 := g.Base()

	if base.Equal(base2) != 1 {
		t.Fatal(expectedEquality)
	}

	random := g.NewElement().Multiply(g.NewScalar().Random())
	cpy := random.Copy()
	if random.Equal(cpy) != 1 {
		t.Fatal()
	}
}

func elementTestAdd(t *testing.T, g crypto.Group) {
	// Verify whether add yields the same element when given nil
	base := g.Base()
	cpy := base.Copy()
	if cpy.Add(nil).Equal(base) != 1 {
		t.Fatal(expectedEquality)
	}
}

func elementTestDouble(t *testing.T, g crypto.Group) {
	// Verify whether double works like adding
	base := g.Base()

	double := g.Base().Add(base)
	if double.Equal(base.Double()) != 1 {
		t.Fatal(expectedEquality)
	}
}

func elementTestSubstract(t *testing.T, g crypto.Group) {
	base := g.Base()

	// Verify whether subtrating yields the same element when given nil.
	if base.Subtract(nil).Equal(base) != 1 {
		t.Fatal(expectedEquality)
	}

	// Verify whether subtracting and then adding yields the same element.
	base2 := base.Add(base).Subtract(base)
	if base.Equal(base2) != 1 {
		t.Fatal(expectedEquality)
	}
}

func elementTestMultiply(t *testing.T, g crypto.Group) {
	scalar := g.NewScalar().Random()

	// Random scalar mult must not yield identity
	m := g.Base().Multiply(scalar)
	if m.IsIdentity() {
		t.Fatal("random scalar multiplication is identity")
	}

	// base = base * 1
	base := g.Base()
	if base.Equal(g.Base().Multiply(scalar.One())) != 1 {
		t.Fatal(expectedEquality)
	}

	// base * 0 = id
	if !g.Base().Multiply(scalar.Zero()).IsIdentity() {
		t.Fatal(expectedIdentity)
	}

	// base * nil = id
	if !g.Base().Multiply(nil).IsIdentity() {
		t.Fatal(expectedIdentity)
	}
}

func elementTestInversion(t *testing.T, g crypto.Group) {
	scalar := g.NewScalar().Random()
	base := g.Base()
	m := g.Base().Multiply(scalar)
	inv := m.Multiply(scalar.Invert())

	if inv.Equal(base) != 1 {
		t.Fatal(expectedEquality)
	}
}

func elementTestIdentity(t *testing.T, g crypto.Group) {
	id := g.NewElement()
	if !id.IsIdentity() {
		t.Fatal(expectedIdentity)
	}

	base := g.Base()
	if id.Equal(base.Subtract(base)) != 1 {
		t.Fatal(expectedIdentity)
	}

	sub1 := g.Base().Double().Negate().Add(g.Base().Double())
	sub2 := g.Base().Subtract(g.Base())
	if sub1.Equal(sub2) != 1 {
		t.Fatal(expectedEquality)
	}

	if id.Equal(base.Multiply(nil)) != 1 {
		t.Fatal(expectedIdentity)
	}

	if id.Equal(base.Multiply(g.NewScalar().Zero())) != 1 {
		t.Fatal(expectedIdentity)
	}

	base = g.Base()
	neg := base.Copy().Negate()
	base.Add(neg)
	if id.Equal(base) != 1 {
		t.Fatal(expectedIdentity)
	}
}
