// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package hash

import (
	"crypto"
	"testing"

	tests2 "github.com/bytemare/cryptotools/internal/tests"
)

type data struct {
	message []byte
	secret  []byte
	key     map[int]string
	salt    []byte
	info    []byte
}

var testData = &data{
	message: []byte("This is the message."),
	secret:  []byte("secret"),
	key: map[int]string{
		32: "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b",
		64: "bd2b1aaf7ef4f09be9f52ce2d8d599674d81aa9d6a4421696dc4d93dd0619d682ce56b4d64a9ef097761ced99e0f67265b5f76085e5b0ee7ca4696b2ad6fe2b2",
	},
	salt: nil,
	info: []byte("contextInfo"),
}

func TestAvailability(t *testing.T) {
	for id := range registeredHashing {
		if !id.Available() {
			t.Errorf("%v is not available, but should be", id)
		}
	}

	wrong := Hashing(crypto.MD4)
	if wrong.Available() {
		t.Errorf("%v is considered available when it should not", wrong)
	}
}

func TestID(t *testing.T) {
	ids := []struct {
		Hashing
		crypto.Hash
	}{
		{
			SHA256,
			crypto.SHA256,
		},
		{
			SHA512,
			crypto.SHA512,
		},
		{
			SHA3_256,
			crypto.SHA3_256,
		},
		{
			SHA3_512,
			crypto.SHA3_512,
		},
	}

	for _, id := range ids {
		if id.Hash != id.Hashing.GetCryptoID() {
			t.Fatalf("GetCryptoID match error: %q vs. %q", id.Hash, id.Hashing.GetCryptoID())
		}

		if id.Hashing != FromCrypto(id.Hash) {
			t.Fatalf("FromCrypto matching error: %q vs. %q", id.Hashing, FromCrypto(id.Hash))
		}
	}
}

func TestHash(t *testing.T) {
	for _, id := range []Hashing{SHA256, SHA512, SHA3_256, SHA3_512} {
		h := id.Get()

		hh := h.Hash(testData.message)

		if len(hh) != h.OutputSize() {
			t.Errorf("#%v : invalid hash output length length. Expected %d, got %d", id, h.OutputSize(), len(hh))
		}
	}

	for _, id := range []Extensible{SHAKE128, SHAKE256, BLAKE2XB, BLAKE2XS} {
		h := id.Get()

		hh := h.Hash(h.minOutputSize, testData.message)

		if len(hh) != h.minOutputSize {
			t.Errorf("#%v : invalid hash output length length. Expected %d, got %d", id, 32, len(hh))
		}
	}
}

func TestSmallXOFOutput(t *testing.T) {
	for _, id := range []Extensible{SHAKE128, SHAKE256, BLAKE2XB, BLAKE2XS} {
		h := id.Get()

		if hasPanic, _ := tests2.ExpectPanic(nil, func() {
			_ = h.Hash(h.minOutputSize-1, testData.message)
		}); !hasPanic {
			t.Fatal("expected panic")
		}

	}
}
