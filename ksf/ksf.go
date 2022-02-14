// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package ksf provides an interface to key stretching functions, a.k.a password key derivation functions.
package ksf

import "errors"

var errParams = errors.New("invalid amount of parameters")

// Identifier is used to specify the key stretching function to be used.
type Identifier byte

const (
	// Argon2id password kdf function.
	Argon2id Identifier = 1 + iota

	// Scrypt password kdf function.
	Scrypt

	// PBKDF2Sha512 PBKDF2 password kdf function using SHA-512.
	PBKDF2Sha512

	// Bcrypt password kdf function.
	Bcrypt

	maxID
)

// Available reports whether the given kdf function is linked into the binary.
func (i Identifier) Available() bool {
	return i > 0 && i < maxID
}

// Get returns a KSF with default parameters.
func (i Identifier) Get() *KSF {
	if i == 0 || i >= maxID {
		return nil
	}

	return &KSF{constructors[i-1]()}
}

// Harden uses default parameters for the key derivation function over the input password and salt.
func (i Identifier) Harden(password, salt []byte, length int) []byte {
	return i.Get().Harden(password, salt, length)
}

// String returns the string name of the hashing function.
func (i Identifier) String() string {
	return i.Get().String()
}

type constructor func() keyStretchingFunction

var constructors [maxID - 1]constructor

func (i Identifier) register(c constructor) {
	constructors[i-1] = c
}

func init() {
	Argon2id.register(argon2idNew)
	Scrypt.register(scryptKSFNew)
	PBKDF2Sha512.register(pbkdf2New)
	Bcrypt.register(bcryptNew)
}

type keyStretchingFunction interface {
	// Harden uses default parameters for the key derivation function over the input password and salt.
	Harden(password, salt []byte, length int) []byte

	// Parameterize replaces the functions parameters with the new ones. Must match the amount of parameters.
	Parameterize(parameters ...int)

	// String returns the string name of the function and its parameters.
	String() string

	params() []int
}

// KSF allows customisation of the underlying key stretching function.
type KSF struct {
	keyStretchingFunction
}

// Set sets m's key stretching function to the specified one and returns m. Returns nil if the identifier is invalid.
func (m *KSF) Set(i Identifier) *KSF {
	if i == 0 || i >= maxID {
		return nil
	}

	m.keyStretchingFunction = constructors[i-1]()

	return m
}
