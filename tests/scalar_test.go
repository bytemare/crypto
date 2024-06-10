// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"slices"
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

	testAll(t, func(group *testGroup) {
		scalar := group.group.NewScalar()
		methods := []func(arg *crypto.Scalar) *crypto.Scalar{
			scalar.Add, scalar.Subtract, scalar.Multiply, scalar.Set,
		}

		var wrongGroup crypto.Group

		switch group.group {
		// The following is arbitrary, and simply aims at confusing identifiers
		case crypto.Ristretto255Sha512, crypto.Edwards25519Sha512, crypto.Secp256k1:
			wrongGroup = crypto.P256Sha256
		case crypto.P256Sha256, crypto.P384Sha384, crypto.P521Sha512:
			wrongGroup = crypto.Ristretto255Sha512

			// Add a special test for nist groups, using a different field
			wrongfield := ((group.group + 1) % 3) + 3
			if err := testPanic("wrong field", internal.ErrWrongField, exec(scalar.Add, wrongfield.NewScalar())); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("Invalid group id %d", group.group)
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
		t.Fatalf(errUnExpectedEquality)
	}

	other.Invert()
	if scalar.Equal(other) == 1 {
		t.Fatalf(errUnExpectedEquality)
	}

	// Verify setting to nil sets to 0
	if scalar.Set(nil).Equal(other.Zero()) != 1 {
		t.Error(errExpectedEquality)
	}
}

func TestScalarCopy(t *testing.T) {
	testAll(t, func(group *testGroup) {
		random := group.group.NewScalar().Random()
		cpy := random.Copy()
		testScalarCopySet(t, random, cpy)
	})
}

func TestScalarSet(t *testing.T) {
	testAll(t, func(group *testGroup) {
		random := group.group.NewScalar().Random()
		other := group.group.NewScalar()
		other.Set(random)
		testScalarCopySet(t, random, other)
	})
}

func TestScalar_SetUInt64(t *testing.T) {
	testAll(t, func(group *testGroup) {
		s := group.group.NewScalar().SetUInt64(0)
		if !s.IsZero() {
			t.Fatal("expected 0")
		}

		s.SetUInt64(1)
		if s.Equal(group.group.NewScalar().One()) != 1 {
			t.Fatal("expected 1")
		}

		// uint64 max value is 18,446,744,073,709,551,615
		s.SetUInt64(math.MaxUint64)
		ref := make([]byte, group.group.ScalarLength())

		switch group.group {
		case crypto.Ristretto255Sha512, crypto.Edwards25519Sha512:
			binary.LittleEndian.PutUint64(ref, math.MaxUint64)
		default:
			binary.BigEndian.PutUint64(ref[group.group.ScalarLength()-8:], math.MaxUint64)
		}

		if bytes.Compare(ref, s.Encode()) != 0 {
			t.Fatalf("expected %q, got %q", hex.EncodeToString(ref), s.Hex())
		}
	})
}

func TestScalar_EncodedLength(t *testing.T) {
	testAll(t, func(group *testGroup) {
		encodedScalar := group.group.NewScalar().Random().Encode()
		if len(encodedScalar) != group.scalarLength {
			t.Fatalf(
				"Encode() is expected to return %d bytes, but returned %d bytes",
				group.scalarLength,
				encodedScalar,
			)
		}
	})
}

func TestScalar_Decode_OutOfBounds(t *testing.T) {
	testAll(t, func(group *testGroup) {
		decodeErrPrefix := "scalar Decode: "
		unmarshallBinaryErrPrefix := "scalar UnmarshalBinary: "
		switch group.group {
		case crypto.Ristretto255Sha512:
			unmarshallBinaryErrPrefix += "ristretto: "
		case crypto.P256Sha256, crypto.P384Sha384, crypto.P521Sha512:
			unmarshallBinaryErrPrefix += "nist: "
		case crypto.Edwards25519Sha512:
			unmarshallBinaryErrPrefix += "edwards25519: "
		case crypto.Secp256k1:
			break
		}

		// Decode invalid length
		errMessage := "invalid scalar length"
		encoded := make([]byte, 2)
		big.NewInt(1).FillBytes(encoded)

		expected := errors.New(decodeErrPrefix + errMessage)
		if err := group.group.NewScalar().Decode(encoded); err == nil || err.Error() != expected.Error() {
			t.Errorf("expected error %q, got %v", expected, err)
		}

		expected = errors.New(unmarshallBinaryErrPrefix + errMessage)
		if err := group.group.NewScalar().UnmarshalBinary(encoded); err == nil || err.Error() != expected.Error() {
			t.Errorf("expected error %q, got %v", expected, err)
		}

		// Decode a scalar higher than order
		errMessage = "invalid scalar encoding"
		encoded = make([]byte, group.group.ScalarLength())

		order, ok := new(big.Int).SetString(group.group.Order(), 0)
		if !ok {
			t.Errorf("setting int in base %d failed: %v", 0, group.group.Order())
		}

		order.Add(order, big.NewInt(1))
		order.FillBytes(encoded)

		expected = errors.New(decodeErrPrefix + errMessage)
		if err := group.group.NewScalar().Decode(encoded); err == nil || err.Error() != expected.Error() {
			t.Errorf("expected error %q, got %v", expected, err)
		}

		expected = errors.New(unmarshallBinaryErrPrefix + errMessage)
		if err := group.group.NewScalar().UnmarshalBinary(encoded); err == nil || err.Error() != expected.Error() {
			t.Errorf("expected error %q, got %v", expected, err)
		}
	})
}

func TestScalar_Arithmetic(t *testing.T) {
	testAll(t, func(group *testGroup) {
		scalarTestZero(t, group.group)
		scalarTestOne(t, group.group)
		scalarTestEqual(t, group.group)
		scalarTestLessOrEqual(t, group.group)
		scalarTestRandom(t, group.group)
		scalarTestAdd(t, group.group)
		scalarTestSubtract(t, group.group)
		scalarTestMultiply(t, group.group)
		scalarTestPow(t, group.group)
		scalarTestInvert(t, group.group)
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
		t.Fatal(errExpectedEquality)
	}
}

func scalarTestRandom(t *testing.T, g crypto.Group) {
	r := g.NewScalar().Random()
	if r.Equal(g.NewScalar().Zero()) == 1 {
		t.Fatalf("random scalar is zero: %v", r.Hex())
	}
}

func scalarTestEqual(t *testing.T, g crypto.Group) {
	zero := g.NewScalar().Zero()
	zero2 := g.NewScalar().Zero()

	if g.NewScalar().Random().Equal(nil) != 0 {
		t.Fatal(errUnExpectedEquality)
	}

	if zero.Equal(zero2) != 1 {
		t.Fatal(errExpectedEquality)
	}

	random := g.NewScalar().Random()
	cpy := random.Copy()
	if random.Equal(cpy) != 1 {
		t.Fatal(errExpectedEquality)
	}

	random2 := g.NewScalar().Random()
	if random.Equal(random2) == 1 {
		t.Fatal(errUnExpectedEquality)
	}
}

func scalarTestLessOrEqual(t *testing.T, g crypto.Group) {
	zero := g.NewScalar().Zero()
	one := g.NewScalar().One()
	two := g.NewScalar().One().Add(one)

	if g.NewScalar().Random().LessOrEqual(nil) != 0 {
		t.Fatal(errUnExpectedEquality)
	}

	if zero.LessOrEqual(one) != 1 {
		t.Fatal("expected 0 < 1")
	}

	if one.LessOrEqual(two) != 1 {
		t.Fatal("expected 1 < 2")
	}

	if one.LessOrEqual(zero) == 1 {
		t.Fatal("expected 1 > 0")
	}

	if two.LessOrEqual(one) == 1 {
		t.Fatal("expected 2 > 1")
	}

	if two.LessOrEqual(two) != 1 {
		t.Fatal("expected 2 == 2")
	}

	s := g.NewScalar().Random()
	r := s.Copy().Add(g.NewScalar().One())

	if s.LessOrEqual(r) != 1 {
		t.Fatal("expected s < s + 1")
	}
}

func scalarTestAdd(t *testing.T, g crypto.Group) {
	r := g.NewScalar().Random()
	cpy := r.Copy()
	if r.Add(nil).Equal(cpy) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

func scalarTestSubtract(t *testing.T, g crypto.Group) {
	r := g.NewScalar().Random()
	cpy := r.Copy()
	if r.Subtract(nil).Equal(cpy) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

func scalarTestMultiply(t *testing.T, g crypto.Group) {
	s := g.NewScalar().Random()
	if !s.Multiply(nil).IsZero() {
		t.Fatal("expected zero")
	}
}

func scalarTestPow(t *testing.T, g crypto.Group) {
	// s**nil = 1
	s := g.NewScalar().Random()
	if s.Pow(nil).Equal(g.NewScalar().One()) != 1 {
		t.Fatal("expected s**nil = 1")
	}

	// s**0 = 1
	s = g.NewScalar().Random()
	zero := g.NewScalar().Zero()
	if s.Pow(zero).Equal(g.NewScalar().One()) != 1 {
		t.Fatal("expected s**0 = 1")
	}

	// s**1 = s
	s = g.NewScalar().Random()
	exp := g.NewScalar().One()
	if s.Copy().Pow(exp).Equal(s) != 1 {
		t.Fatal("expected s**1 = s")
	}

	// s**2 = s*s
	s = g.NewScalar().One()
	s.Add(s.Copy().One())
	s2 := s.Copy().Multiply(s)
	exp.SetUInt64(2)

	if s.Pow(exp).Equal(s2) != 1 {
		t.Fatal("expected s**2 = s*s")
	}

	// s**3 = s*s*s
	s = g.NewScalar().Random()
	s3 := s.Copy().Multiply(s)
	s3.Multiply(s)
	exp.SetUInt64(3)

	if s.Pow(exp).Equal(s3) != 1 {
		t.Fatal("expected s**3 = s*s*s")
	}

	// 5**7 = 78125 = 00000000 00000001 00110001 00101101 = 1 49 45
	result := g.NewScalar().SetUInt64(uint64(math.Pow(5, 7)))
	s.SetUInt64(5)
	exp.SetUInt64(7)

	res := s.Pow(exp)
	if res.Equal(result) != 1 {
		t.Fatal("expected 5**7 = 78125")
	}

	// 3**255 = 11F1B08E87EC42C5D83C3218FC83C41DCFD9F4428F4F92AF1AAA80AA46162B1F71E981273601F4AD1DD4709B5ACA650265A6AB
	iBase := big.NewInt(3)
	iExp := big.NewInt(255)
	result = bigIntExp(t, g, iBase, iExp)

	s.SetUInt64(3)
	exp.SetUInt64(255)

	res = s.Pow(exp)
	if res.Equal(result) != 1 {
		t.Fatal(
			"expected 3**255 = " +
				"11F1B08E87EC42C5D83C3218FC83C41DCFD9F4428F4F92AF1AAA80AA46162B1F71E981273601F4AD1DD4709B5ACA650265A6AB",
		)
	}

	// 7945232487465**513
	iBase.SetInt64(7945232487465)
	iExp.SetInt64(513)
	result = bigIntExp(t, g, iBase, iExp)

	s.SetUInt64(7945232487465)
	exp.SetUInt64(513)

	res = s.Pow(exp)
	if res.Equal(result) != 1 {
		t.Fatal("expect equality on 7945232487465**513")
	}

	// random**random
	s.Random()
	exp.Random()

	switch g {
	// These are in little-endian
	case crypto.Ristretto255Sha512, crypto.Edwards25519Sha512:
		e := s.Encode()
		for i, j := 0, len(e)-1; i < j; i++ {
			e[i], e[j] = e[j], e[i]
			j--
		}
		iBase.SetBytes(e)

		e = exp.Encode()
		for i, j := 0, len(e)-1; i < j; i++ {
			e[i], e[j] = e[j], e[i]
			j--
		}
		iExp.SetBytes(e)

	default:
		iBase.SetBytes(s.Encode())
		iExp.SetBytes(exp.Encode())
	}

	result = bigIntExp(t, g, iBase, iExp)

	if s.Pow(exp).Equal(result) != 1 {
		t.Fatal("expected equality on random numbers")
	}
}

func bigIntExp(t *testing.T, g crypto.Group, base, exp *big.Int) *crypto.Scalar {
	order, ok := new(big.Int).SetString(g.Order(), 0)
	if !ok {
		t.Fatal(ok)
	}

	r := new(big.Int).Exp(base, exp, order)

	b := make([]byte, g.ScalarLength())
	r.FillBytes(b)

	if g == crypto.Ristretto255Sha512 || g == crypto.Edwards25519Sha512 {
		slices.Reverse(b)
	}

	result := g.NewScalar()
	if err := result.Decode(b); err != nil {
		t.Fatal(err)
	}

	return result
}

func scalarTestInvert(t *testing.T, g crypto.Group) {
	s := g.NewScalar().Random()
	sqr := s.Copy().Multiply(s)

	i := s.Copy().Invert().Multiply(sqr)
	if i.Equal(s) != 1 {
		t.Fatal(errExpectedEquality)
	}

	s = g.NewScalar().Random()
	square := s.Copy().Multiply(s)
	inv := square.Copy().Invert()
	if s.One().Equal(square.Multiply(inv)) != 1 {
		t.Fatal(errExpectedEquality)
	}
}
