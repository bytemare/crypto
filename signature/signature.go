// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package signature provides additional abstraction and modularity to digital signature schemes of built-in implementations
package signature

import (
	"crypto"
	"io"

	"github.com/bytemare/crypto/signature/internal"
)

// Identifier indicates the signature scheme to be used.
type Identifier byte

const (
	// Ed25519 indicates usage of the Ed25519 signature scheme.
	Ed25519 Identifier = iota + 1

	sEd25519 = "Ed25519"
)

// String implements the Stringer() interface for the Signature algorithm.
func (i Identifier) String() string {
	switch i {
	case Ed25519:
		return sEd25519
	default:
		return ""
	}
}

// Signature abstracts digital signature operations, wrapping built-in implementations.
type Signature interface {
	// GenerateKey generates a fresh signing key and stores it internally.
	GenerateKey()

	// GetPrivateKey returns the private key.
	GetPrivateKey() []byte

	// GetPublicKey returns the public key.
	GetPublicKey() []byte

	// Public implements the Signer.Public() function.
	Public() crypto.PublicKey

	// SetPrivateKey loads the given private key and sets the public key accordingly.
	SetPrivateKey(privateKey []byte)

	// SignatureLength returns the byte size of a signature.
	SignatureLength() uint

	// SignMessage uses the internal private key to sign the message. The message argument doesn't need to be hashed beforehand.
	SignMessage(message ...[]byte) []byte

	// Sign implements the Signer.Sign() function.
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)

	// Verify checks whether signature of the message is valid given the public key.
	Verify(publicKey, message, signature []byte) bool
}

// New returns a Signature implementation to the specified scheme.
func (i Identifier) New() Signature {
	switch i {
	case Ed25519:
		return internal.NewEd25519()
	default:
		panic("invalid identifier")
	}
}

// Sign returns the signature of message (concatenated, if using a variadic argument) using secretKey.
func (i Identifier) Sign(secretKey []byte, message ...[]byte) []byte {
	s := i.New()
	s.SetPrivateKey(secretKey)

	return s.SignMessage(message...)
}

// Verify checks whether signature of the message is valid given the public key.
func (i Identifier) Verify(publicKey, message, signature []byte) bool {
	return i.New().Verify(publicKey, message, signature)
}

// SignatureLength returns the byte size of a signature.
func (i Identifier) SignatureLength() uint {
	return i.New().SignatureLength()
}
