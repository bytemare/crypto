// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package hash

import (
	"errors"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/sha3"
)

// Extendable identifies Extendable-Output Functions.
type Extendable byte

const (
	// SHAKE128 identifies the SHAKE128 Extendable-Output Function.
	SHAKE128 Extendable = 1 + iota

	// SHAKE256 identifies the SHAKE256 Extendable-Output Function.
	SHAKE256

	// BLAKE2XB identifies the BLAKE2XB Extendable-Output Function.
	BLAKE2XB

	// BLAKE2XS identifies the BLAKE2XS Extendable-Output Function.
	BLAKE2XS

	maxXOF

	// string IDs for the hash functions.
	shake128 = "SHAKE128"
	shake256 = "SHAKE256"
	blake2xb = "BLAKE2XB"
	blake2xs = "BLAKE2XS"

	// block size in bytes.
	blockSHAKE128 = 1344 / 8
	blockSHAKE256 = 1088 / 8
)

type xofParams struct {
	parameters
	newHashFunc newXOF
}

var registeredXOF map[Extendable]*xofParams

// Get returns a pointer to an initialized Hash structure for the according has primitive.
func (e Extendable) Get() *ExtendableHash {
	p := registeredXOF[e]
	h := p.newHashFunc()
	h.Extendable = e

	return h
}

// Available reports whether the given hash function is linked into the binary.
func (e Extendable) Available() bool {
	return e < maxXOF && registeredXOF[e] != nil
}

// BlockSize returns the hash's block size.
func (e Extendable) BlockSize() int {
	return registeredXOF[e].blockSize
}

// Extendable returns whether the hash function is extendable, therefore always true. This is only to comply to the
// Identifier interface.
func (e Extendable) Extendable() bool {
	return true
}

// Hash returns the hash of the input arguments on the hash's secure minimum output length.
func (e Extendable) Hash(input ...[]byte) []byte {
	return e.Get().Hash(e.MinOutputSize(), input...)
}

// MinOutputSize returns the minimal output length necessary to guarantee its bit security level.
func (e Extendable) MinOutputSize() int {
	return e.Get().minOutputSize
}

// SecurityLevel returns the hash function's bit security level.
func (e Extendable) SecurityLevel() int {
	return registeredXOF[e].security
}

// String returns the hash function's common name.
func (e Extendable) String() string {
	return registeredXOF[e].name
}

func (e Extendable) register(f newXOF, name string, blockSize, outputSize, security int) {
	registeredXOF[e] = &xofParams{
		parameters: parameters{
			name:       name,
			blockSize:  blockSize,
			outputSize: outputSize,
			security:   security,
		},
		newHashFunc: f,
	}
}

type newXOF func() *ExtendableHash

func init() {
	registeredXOF = make(map[Extendable]*xofParams)

	SHAKE128.register(newShake(sha3.NewShake128, size256), shake128, blockSHAKE128, size256, sec128)
	SHAKE256.register(newShake(sha3.NewShake256, size512), shake256, blockSHAKE256, size512, sec256)
	BLAKE2XB.register(newBlake2xb(), blake2xb, 0, size256, sec128)
	BLAKE2XS.register(newBlake2xs(), blake2xs, 0, size256, sec128)
}

var errSmallOutputSize = errors.New("requested output size too small")

// XOF defines the interface to hash functions that
// support arbitrary-length output.
type XOF interface {
	// Writer Write absorbs more data into the hash's state. It panics if called
	// after Read.
	io.Writer

	// Reader Read reads more output from the hash. It returns io.EOF if the limit
	// has been reached.
	io.Reader

	// Clone returns a copy of the XOF in its current state.
	Clone() XOF

	// Reset resets the XOF to its initial state.
	Reset()
}

type blake2bXOF struct {
	blake2b.XOF
}

func (b blake2bXOF) Clone() XOF {
	return blake2bXOF{b.XOF.Clone()}
}

type blake2sXOF struct {
	blake2s.XOF
}

func (b blake2sXOF) Clone() XOF {
	return blake2sXOF{b.XOF.Clone()}
}

type shake struct {
	sha3.ShakeHash
}

func (s shake) Clone() XOF {
	return shake{s.ShakeHash.Clone()}
}

func newShake(f func() sha3.ShakeHash, minOutputSize int) newXOF {
	return func() *ExtendableHash {
		return &ExtendableHash{XOF: &shake{f()}, minOutputSize: minOutputSize}
	}
}

func newBlake2xb() newXOF {
	h, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	if err != nil {
		panic(err)
	}

	return func() *ExtendableHash {
		return &ExtendableHash{XOF: &blake2bXOF{h}, minOutputSize: size256}
	}
}

func newBlake2xs() newXOF {
	h, err := blake2s.NewXOF(blake2s.OutputLengthUnknown, nil)
	if err != nil {
		panic(err)
	}

	return func() *ExtendableHash {
		return &ExtendableHash{XOF: &blake2sXOF{h}, minOutputSize: size256}
	}
}

// ExtendableHash wraps extendable output functions.
type ExtendableHash struct {
	Extendable
	XOF
	minOutputSize int
}

// Hash returns the hash of the input argument with size output length.
func (h *ExtendableHash) Hash(size int, input ...[]byte) []byte {
	if size < h.minOutputSize {
		panic(errSmallOutputSize)
	}

	h.Reset()

	for _, i := range input {
		_, _ = h.Write(i)
	}

	output := make([]byte, size)
	_, _ = h.XOF.Read(output)

	return output
}

// Write implements io.Writer.
func (h *ExtendableHash) Write(p []byte) (n int, err error) {
	return h.XOF.Write(p)
}

// Read returns size bytes from the current hash.
func (h *ExtendableHash) Read(size int) []byte {
	if size < h.minOutputSize {
		panic(errSmallOutputSize)
	}

	output := make([]byte, size)
	_, _ = h.XOF.Read(output)

	return output
}

// Reset resets the Hash to its initial state.
func (h *ExtendableHash) Reset() {
	h.XOF.Reset()
}
