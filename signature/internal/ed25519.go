// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal holds different signature mechanisms.
package internal

import (
	"crypto"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"fmt"
	"io"
)

// Ed25519 implements the Signature interfaces and wraps crypto/ed22519.
type Ed25519 struct {
	sk ed25519.PrivateKey
	pk ed25519.PublicKey
}

// NewEd25519 returns an empty Ed25519 structure.
func NewEd25519() *Ed25519 {
	return &Ed25519{
		sk: nil,
		pk: nil,
	}
}

// SetPrivateKey loads the given private key and sets the public key accordingly.
func (ed *Ed25519) SetPrivateKey(privateKey []byte) {
	if len(privateKey) != ed25519.SeedSize {
		panic("Ed25519 invalid private key size")
	}

	ed.sk = ed25519.NewKeyFromSeed(privateKey)
	ed.pk = make([]byte, ed25519.PublicKeySize)
	copy(ed.pk, ed.sk[ed25519.PublicKeySize:])
}

// GenerateKey generates a fresh private/public key pair and stores it in ed.
func (ed *Ed25519) GenerateKey() {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := cryptorand.Read(seed); err != nil {
		// We can as well not panic and try again in a loop
		panic(fmt.Errorf("unexpected error in generating random bytes : %w", err))
	}
	ed.SetPrivateKey(seed)
}

// GetPrivateKey returns the private key (without the public key part).
func (ed *Ed25519) GetPrivateKey() []byte {
	return ed.sk.Seed()
}

// GetPublicKey returns the public key.
func (ed *Ed25519) GetPublicKey() []byte {
	return ed.pk
}

// Public implements the Signer.Public() function.
func (ed *Ed25519) Public() crypto.PublicKey {
	return crypto.PublicKey(ed.pk)
}

// SignatureLength returns the byte size of a signature.
func (ed *Ed25519) SignatureLength() uint {
	return ed25519.SignatureSize
}

// SignMessage uses the private key in ed to sign the input. The input doesn't need to be hashed beforehand.
func (ed *Ed25519) SignMessage(message ...[]byte) []byte {
	length := 0
	for _, in := range message {
		length += len(in)
	}

	buf := make([]byte, 0, length)

	for _, in := range message {
		buf = append(buf, in...)
	}

	return ed25519.Sign(ed.sk, buf)
}

// Sign implements the Signer.Sign() function.
func (ed *Ed25519) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return ed.sk.Sign(rand, digest, opts)
}

// Verify checks whether signature of the message is valid given the public key.
func (ed *Ed25519) Verify(publicKey, message, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}
