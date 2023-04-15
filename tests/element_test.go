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
	errExpectedEquality = "expected equality"
	errExpectedIdentity = "expected identity"
	errWrongGroup       = "wrong group"
)

func testElementCopySet(t *testing.T, element, other *crypto.Element) {
	// Verify they don't point to the same thing
	if &element == &other {
		t.Fatalf("Pointer to the same scalar")
	}

	// Verify whether they are equivalent
	if element.Equal(other) != 1 {
		t.Fatalf("Expected equality")
	}

	// Verify than operations on one don't affect the other
	element.Add(element)
	if element.Equal(other) == 1 {
		t.Fatalf("Unexpected equality")
	}

	other.Double().Double()
	if element.Equal(other) == 1 {
		t.Fatalf("Unexpected equality")
	}
}

func TestElementCopy(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		base := group.group.Base()
		cpy := base.Copy()
		testElementCopySet(t, base, cpy)
	})
}

func TestElementSet(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		base := group.group.Base()
		other := group.group.NewElement()
		other.Set(base)
		testElementCopySet(t, base, other)
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
		element := group.group.NewElement()
		var alternativeGroup crypto.Group

		switch group.group {
		// The following is arbitrary, and simply aims at confusing identifiers
		case crypto.Ristretto255Sha512, crypto.Edwards25519Sha512:
			alternativeGroup = crypto.P256Sha256
		case crypto.P256Sha256, crypto.P384Sha384, crypto.P521Sha512, crypto.Secp256k1:
			alternativeGroup = crypto.Ristretto255Sha512
		default:
			t.Fatalf("Invalid group id %d", group.group)
		}

		if err := testPanic(errWrongGroup, internal.ErrCastElement, exec(element.Add, alternativeGroup.NewElement())); err != nil {
			t.Fatal(err)
		}

		if err := testPanic(errWrongGroup, internal.ErrCastElement, exec(element.Subtract, alternativeGroup.NewElement())); err != nil {
			t.Fatal(err)
		}

		if err := testPanic(errWrongGroup, internal.ErrCastElement, exec(element.Set, alternativeGroup.NewElement())); err != nil {
			t.Fatal(err)
		}

		if err := testPanic(errWrongGroup, internal.ErrCastElement, equal(element.Equal, alternativeGroup.NewElement())); err != nil {
			t.Fatal(err)
		}
	})

	// Specifically test Ristretto
	if err := testPanic(errWrongGroup, internal.ErrCastScalar, mult(crypto.Ristretto255Sha512.NewElement().Multiply, crypto.P384Sha384.NewScalar())); err != nil {
		t.Fatal(err)
	}
}

func TestElement_EncodedLength(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		encodedElement := group.group.NewElement().Base().Multiply(group.group.NewScalar().Random()).Encode()
		if len(encodedElement) != group.elementLength {
			t.Fatalf("Encode() is expected to return %d bytes, but returned %d bytes", group.elementLength, encodedElement)
		}
	})
}

func TestElement_Arithmetic(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		elementTestEqual(t, group.group)
		elementTestDouble(t, group.group)
		elementTestAdd(t, group.group)
		elementTestSubstract(t, group.group)
		elementTestMultiply(t, group.group)
		elementTestIdentity(t, group.group)
	})
}

func elementTestEqual(t *testing.T, g crypto.Group) {
	base := g.Base()
	base2 := g.Base()

	if base.Equal(base2) != 1 {
		t.Fatal(errExpectedEquality)
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
		t.Fatal(errExpectedEquality)
	}

	// Verify whether add yields the same element when given identity
	base = g.Base()
	cpy = base.Copy()
	if cpy.Add(g.NewElement()).Equal(base) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Verify whether add yields the identity given the negative
	base = g.Base()
	negative := g.Base().Negate()
	identity := g.NewElement()
	if base.Add(negative).Equal(identity) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Verify whether add yields the same when adding to identity
	base = g.Base()
	identity = g.NewElement()
	if identity.Add(base).Equal(base) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Verify whether add yields the double when adding to itself
	base = g.Base()
	double := g.Base().Double()
	if base.Add(base).Equal(double) != 1 {
		t.Fatal(errExpectedEquality)
	}

	//three := g.NewScalar().One()
	//three.Add(three)
	//three.Add(g.NewScalar().One())
	//
	//exp := g.Base().Multiply(three)
	//e := g.Base().Add(g.Base()).Add(g.Base())
	//
	//if e.Equal(exp) != 1 {
	//	t.Fatal(errExpectedEquality)
	//}
}

func elementTestDouble(t *testing.T, g crypto.Group) {
	// Verify whether double works like adding
	base := g.Base()
	double := g.Base().Add(g.Base())
	if double.Equal(base.Double()) != 1 {
		t.Fatal(errExpectedEquality)
	}

	two := g.NewScalar().One().Add(g.NewScalar().One())
	mult := g.Base().Multiply(two)
	if mult.Equal(double) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

func elementTestSubstract(t *testing.T, g crypto.Group) {
	base := g.Base()

	// Verify whether subtrating yields the same element when given nil.
	if base.Subtract(nil).Equal(base) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Verify whether subtracting and then adding yields the same element.
	base2 := base.Add(base).Subtract(base)
	if base.Equal(base2) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

func elementTestMultiply(t *testing.T, g crypto.Group) {
	scalar := g.NewScalar()

	// base = base * 1
	base := g.Base()
	mult := g.Base().Multiply(scalar.One())
	if base.Equal(mult) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Random scalar mult must not yield identity
	scalar = g.NewScalar().Random()
	m := g.Base().Multiply(scalar)
	if m.IsIdentity() {
		t.Fatal("random scalar multiplication is identity")
	}

	// 2 * base = base + base
	twoG := g.Base().Add(g.Base())
	two := g.NewScalar().One().Add(g.NewScalar().One())
	mult = g.Base().Multiply(two)

	if mult.Equal(twoG) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// base * 0 = id
	if !g.Base().Multiply(scalar.Zero()).IsIdentity() {
		t.Fatal(errExpectedIdentity)
	}

	// base * nil = id
	if !g.Base().Multiply(nil).IsIdentity() {
		t.Fatal(errExpectedIdentity)
	}
}

func elementTestIdentity(t *testing.T, g crypto.Group) {
	id := g.NewElement()
	if !id.IsIdentity() {
		t.Fatal(errExpectedIdentity)
	}

	base := g.Base()
	if id.Equal(base.Subtract(base)) != 1 {
		t.Fatal(errExpectedIdentity)
	}

	sub1 := g.Base().Double().Negate().Add(g.Base().Double())
	sub2 := g.Base().Subtract(g.Base())
	if sub1.Equal(sub2) != 1 {
		t.Fatal(errExpectedEquality)
	}

	if id.Equal(base.Multiply(nil)) != 1 {
		t.Fatal(errExpectedIdentity)
	}

	if id.Equal(base.Multiply(g.NewScalar().Zero())) != 1 {
		t.Fatal(errExpectedIdentity)
	}

	base = g.Base()
	neg := base.Copy().Negate()
	base.Add(neg)
	if id.Equal(base) != 1 {
		t.Fatal(errExpectedIdentity)
	}
}
