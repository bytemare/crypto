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
	"log"
	"testing"

	"github.com/bytemare/crypto"
)

const consideredAvailableFmt = "%v is considered available when it must not"

func TestAvailability(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		if !group.group.Available() {
			t.Errorf("'%s' is not available, but should be", group.group.String())
		}
	})
}

func TestNonAvailability(t *testing.T) {
	oob := crypto.Group(0)
	if oob.Available() {
		t.Errorf(consideredAvailableFmt, oob)
	}

	oob = crypto.Edwards448 + 1
	if oob.Available() {
		t.Errorf(consideredAvailableFmt, oob)
	}
}

func TestGroup_BaseEncoding(t *testing.T) {
	baseEncoded := hex.EncodeToString(crypto.Decaf448Shake256.Base().Encode())
	log.Printf("base: %v", baseEncoded)

	hexEncoded := "6666666666666666666666666666666666666666666666666666666633333333333333333333333333333333333333333333333333333333"
	encoded, _ := hex.DecodeString(hexEncoded)

	e := crypto.Decaf448Shake256.NewElement()
	if err := e.Decode(encoded); err != nil {
		t.Fatal(err)
	}

	reencoded := hex.EncodeToString(e.Encode())
	log.Printf("reencoded: %v", reencoded)
	if reencoded != hexEncoded {
		t.Fatal("expected equality")
	}

	base := crypto.Decaf448Shake256.Base()
	if base.Equal(e) != 1 {
		t.Fatal("expected equality")
	}
}

func TestGroup_Base(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {

		encoded, err := hex.DecodeString(group.basePoint)
		if err != nil {
			t.Fatal(err)
		}

		base := group.group.NewElement()
		if err = base.Decode(encoded); err != nil {
			t.Fatal(err)
		}

		if base.Equal(group.group.Base()) != 1 {
			t.Fatal(errExpectedEquality)
		}

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
		crypto.Decaf448Shake256:   app + "-V01-CS02-",
		crypto.P256Sha256:         app + "-V01-CS03-",
		crypto.P384Sha384:         app + "-V01-CS04-",
		crypto.P521Sha512:         app + "-V01-CS05-",
		crypto.Edwards25519Sha512: app + "-V01-CS06-",
		crypto.Secp256k1:          app + "-V01-CS07-",
		crypto.Curve448:           app + "-V01-CS08-",
		crypto.Edwards448:         app + "-V01-CS09-",
	}

	testAll(t, func(t2 *testing.T, group *testGroup) {
		res := string(group.group.MakeDST(app, version))
		test := tests[group.group] + group.h2c
		if res != test {
			t.Errorf("Wrong DST %v. want %q, got %q", group.name, res, test)
		}
	})
}

func TestGroup_String(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		res := group.group.String()
		ref := group.h2c
		if res != ref {
			log.Printf("Group %v", group.group)
			t.Errorf("Wrong DST. want %q, got %q", ref, res)
		}
	})
}

func TestGroup_NewScalar(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		s := group.group.NewScalar().Encode()
		for _, b := range s {
			if b != 0 {
				t.Fatalf("expected zero scalar, but got %v", hex.EncodeToString(s))
			}
		}
	})
}

func TestGroup_NewElement(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		e := hex.EncodeToString(group.group.NewElement().Encode())
		ref := group.identity

		if e != ref {
			t.Fatalf("expected identity element %v, but got %v", ref, e)
		}
	})
}

func TestGroup_ScalarLength(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		if group.group.ScalarLength() != group.scalarLength {
			t.Fatalf("expected encoded scalar length %d, but got %d", group.scalarLength, group.group.ScalarLength())
		}
	})
}

func TestGroup_ElementLength(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		if group.group.ElementLength() != group.elementLength {
			t.Fatalf("%d / %v : expected encoded element length %d, but got %d", group.group, group.group, group.elementLength, group.group.ElementLength())
		}
	})
}
