// SPDX-License-Group: MIT
//
// Copyright (C) 2020-2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group_test

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/bytemare/crypto"
)

const consideredAvailableFmt = "%v is considered available when it must not"

func TestAvailability(t *testing.T) {
	testAll(t, func(group *testGroup) {
		if !group.group.Available() {
			t.Errorf("'%s' is not available, but should be", group.group.String())
		}
	})
}

func TestNonAvailability(t *testing.T) {
	errInvalidID := errors.New("invalid group identifier")

	oob := crypto.Group(0)
	if oob.Available() {
		t.Errorf(consideredAvailableFmt, oob)
	}

	d := crypto.Group(2) // decaf448
	if d.Available() {
		t.Errorf(consideredAvailableFmt, d)
	}

	if err := testPanic("decaf availability", errInvalidID,
		func() { _ = d.String() }); err != nil {
		t.Fatal(err)
	}

	oob = crypto.Secp256k1 + 1
	if oob.Available() {
		t.Errorf(consideredAvailableFmt, oob)
	}

	if err := testPanic("oob availability", errInvalidID,
		func() { _ = oob.String() }); err != nil {
		t.Fatal(err)
	}

	oob++
	if err := testPanic("oob availability", errInvalidID,
		func() { _ = oob.String() }); err != nil {
		t.Fatal(err)
	}
}

func TestGroup_Base(t *testing.T) {
	testAll(t, func(group *testGroup) {
		if hex.EncodeToString(group.group.Base().Encode()) != group.basePoint {
			t.Fatalf("Got wrong base element\n\tgot : %s\n\twant: %s",
				hex.EncodeToString(group.group.Base().Encode()),
				group.basePoint)
		}
	})
}

func TestDST(t *testing.T) {
	app := "app"
	version := uint8(1)
	tests := map[crypto.Group]string{
		crypto.Ristretto255Sha512: app + "-V01-CS01-",
		crypto.P256Sha256:         app + "-V01-CS03-",
		crypto.P384Sha384:         app + "-V01-CS04-",
		crypto.P521Sha512:         app + "-V01-CS05-",
		crypto.Edwards25519Sha512: app + "-V01-CS06-",
		crypto.Secp256k1:          app + "-V01-CS07-",
	}

	testAll(t, func(group *testGroup) {
		res := string(group.group.MakeDST(app, version))
		test := tests[group.group] + group.h2c
		if res != test {
			t.Errorf("Wrong DST. want %q, got %q", res, test)
		}
	})
}

func TestGroup_String(t *testing.T) {
	testAll(t, func(group *testGroup) {
		res := group.group.String()
		ref := group.h2c
		if res != ref {
			t.Errorf("Wrong DST. want %q, got %q", ref, res)
		}
	})
}

func TestGroup_NewScalar(t *testing.T) {
	testAll(t, func(group *testGroup) {
		s := group.group.NewScalar().Encode()
		for _, b := range s {
			if b != 0 {
				t.Fatalf("expected zero scalar, but got %v", hex.EncodeToString(s))
			}
		}
	})
}

func TestGroup_NewElement(t *testing.T) {
	testAll(t, func(group *testGroup) {
		e := hex.EncodeToString(group.group.NewElement().Encode())
		ref := group.identity

		if e != ref {
			t.Fatalf("expected identity element %v, but got %v", ref, e)
		}
	})
}

func TestGroup_ScalarLength(t *testing.T) {
	testAll(t, func(group *testGroup) {
		if int(group.group.ScalarLength()) != group.scalarLength {
			t.Fatalf("expected encoded scalar length %d, but got %d", group.scalarLength, group.group.ScalarLength())
		}
	})
}

func TestGroup_ElementLength(t *testing.T) {
	testAll(t, func(group *testGroup) {
		if group.group.ElementLength() != group.elementLength {
			t.Fatalf("expected encoded element length %d, but got %d", group.elementLength, group.group.ElementLength())
		}
	})
}

func TestHashToScalar(t *testing.T) {
	testAll(t, func(group *testGroup) {
		sv := decodeScalar(t, group.group, group.hashToCurve.hashToScalar)

		s := group.group.HashToScalar(group.hashToCurve.input, group.hashToCurve.dst)
		if s.Equal(sv) != 1 {
			t.Error(errExpectedEquality)
		}
	})
}

func TestHashToScalar_NoDST(t *testing.T) {
	testAll(t, func(group *testGroup) {
		data := []byte("input data")

		// Nil DST
		if err := testPanic("nil dst", errors.New("zero-length DST"), func() {
			_ = group.group.HashToScalar(data, nil)
		}); err != nil {
			t.Error(fmt.Errorf("%s: %w)", errNoPanic, err))
		}

		// Zero length DST
		if err := testPanic("zero-length dst", errors.New("zero-length DST"), func() {
			_ = group.group.HashToScalar(data, []byte{})
		}); err != nil {
			t.Error(fmt.Errorf("%s: %w)", errNoPanic, err))
		}
	})
}

func TestHashToGroup(t *testing.T) {
	testAll(t, func(group *testGroup) {
		ev := decodeElement(t, group.group, group.hashToCurve.hashToGroup)

		e := group.group.HashToGroup(group.hashToCurve.input, group.hashToCurve.dst)
		if e.Equal(ev) != 1 {
			t.Error(errExpectedEquality)
		}
	})
}

func TestHashToGroup_NoDST(t *testing.T) {
	testAll(t, func(group *testGroup) {
		data := []byte("input data")

		// Nil DST
		if err := testPanic("nil dst", errors.New("zero-length DST"), func() {
			_ = group.group.HashToGroup(data, nil)
		}); err != nil {
			t.Error(fmt.Errorf("%s: %w)", errNoPanic, err))
		}

		// Zero length DST
		if err := testPanic("zero-length dst", errors.New("zero-length DST"), func() {
			_ = group.group.HashToGroup(data, []byte{})
		}); err != nil {
			t.Error(fmt.Errorf("%s: %w)", errNoPanic, err))
		}
	})
}
