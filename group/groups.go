// SPDX-License-Group: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package group exposes a prime-order elliptic curve groups with additional hash-to-curve operations.
package group

import (
	"errors"
	"fmt"

	H2C "github.com/armfazh/h2c-go-ref"

	"github.com/bytemare/cryptotools/group/curve25519"
	"github.com/bytemare/cryptotools/group/edwards25519"
	"github.com/bytemare/cryptotools/group/internal"
	"github.com/bytemare/cryptotools/group/other"
	"github.com/bytemare/cryptotools/group/ristretto"
)

// Group defines registered groups for use in the implementation.
type Group byte

const (
	// Ristretto255Sha512 identifies the Ristretto255 group with SHA2-512 hash-to-group hashing.
	Ristretto255Sha512 Group = 1 + iota

	// decaf448 is not implemented.
	decaf448

	// P256Sha256 identifies a group over P256 with SHA2-512 hash-to-group hashing.
	P256Sha256

	// P384Sha512 identifies a group over P384 with SHA2-512 hash-to-group hashing.
	P384Sha512

	// P521Sha512 identifies a group over P521 with SHA2-512 hash-to-group hashing.
	P521Sha512

	// Curve25519Sha512 identifies a group over Curve25519 with SHA2-512 hash-to-group hashing.
	Curve25519Sha512

	// Edwards25519Sha512 identifies a group over Edwards25519 with SHA2-512 hash-to-group hashing.
	Edwards25519Sha512

	// Curve448Sha512 identifies a group over Curve448 with SHA2-512 hash-to-group hashing.
	Curve448Sha512

	// Edwards448Sha512 identifies a group over Edwards448 with SHA2-512 hash-to-group hashing.
	Edwards448Sha512

	// Secp256k1Sha256 identifies a group over Secp256k1 with SHA2-512 hash-to-group hashing.
	Secp256k1Sha256

	maxID
)

const dstfmt = "%s-V%s-CS%s-%s"

var (
	registered   map[Group]*params
	errInvalidID = errors.New("invalid group identifier")
)

// Available reports whether the given Group is linked into the binary.
func (i Group) Available() bool {
	return i > 0 && i < maxID && registered[i] != nil
}

// MakeDST builds a domain separation tag in the form of <app>-V<version>-CS<id>-<hash-to-curve-ID>, or returns an error.
func (i Group) MakeDST(app, version string) ([]byte, error) {
	if !i.Available() {
		panic(errInvalidID)
	}

	p := registered[i]

	return []byte(fmt.Sprintf(dstfmt, app, version, p.id, p.h2cID)), nil
}

// String returns the hash-to-curve string identifier of the ciphersuite.
func (i Group) String() string {
	if !i.Available() {
		panic(errInvalidID)
	}

	return registered[i].h2cID
}

type params struct {
	id    Group
	h2cID string
	internal.Group
}

func (i Group) register(identifier string, g internal.Group) {
	registered[i] = &params{
		id:    i,
		h2cID: identifier,
		Group: g,
	}
}

func newCurve(id H2C.SuiteID) (string, internal.Group) {
	return string(id), other.New(id)
}

func init() {
	registered = make(map[Group]*params)

	Ristretto255Sha512.register(ristretto.H2C, ristretto.Ristretto255Sha512{})
	P256Sha256.register(newCurve(H2C.P256_XMDSHA256_SSWU_RO_))
	P384Sha512.register(newCurve(H2C.P384_XMDSHA512_SSWU_RO_))
	P521Sha512.register(newCurve(H2C.P521_XMDSHA512_SSWU_RO_))
	Curve25519Sha512.register(curve25519.H2C, curve25519.Group{})
	Edwards25519Sha512.register(edwards25519.H2C, edwards25519.Group{})
	Curve448Sha512.register(newCurve(H2C.Curve448_XMDSHA512_ELL2_RO_))
	Edwards448Sha512.register(newCurve(H2C.Edwards448_XMDSHA512_ELL2_RO_))
	Secp256k1Sha256.register(newCurve(H2C.Secp256k1_XMDSHA256_SSWU_RO_))
}

// NewScalar returns a new, empty, scalar.
func (i Group) NewScalar() *Scalar {
	if !i.Available() {
		panic(errInvalidID)
	}

	return newScalar(registered[i].NewScalar())
}

// NewElement returns a new, empty, element.
func (i Group) NewElement() *Point {
	if !i.Available() {
		panic(errInvalidID)
	}

	return newPoint(registered[i].NewElement())
}

// ElementLength returns the byte size of an encoded element.
func (i Group) ElementLength() int {
	if !i.Available() {
		panic(errInvalidID)
	}

	return registered[i].ElementLength()
}

// Identity returns the group's identity element.
func (i Group) Identity() *Point {
	if !i.Available() {
		panic(errInvalidID)
	}

	return newPoint(registered[i].Identity())
}

// HashToGroup allows arbitrary input to be safely mapped to the curve of the Group.
func (i Group) HashToGroup(input, dst []byte) *Point {
	if !i.Available() {
		panic(errInvalidID)
	}

	return newPoint(registered[i].HashToGroup(input, dst))
}

// HashToScalar allows arbitrary input to be safely mapped to the field.
func (i Group) HashToScalar(input, dst []byte) *Scalar {
	if !i.Available() {
		panic(errInvalidID)
	}

	return newScalar(registered[i].HashToScalar(input, dst))
}

// Base returns the group's base point a.k.a. canonical generator.
func (i Group) Base() *Point {
	if !i.Available() {
		panic(errInvalidID)
	}

	return newPoint(registered[i].Base())
}

// MultBytes allows []byte encodings of a scalar and an element of the Group to be multiplied.
func (i Group) MultBytes(scalar, element []byte) (*Point, error) {
	if !i.Available() {
		panic(errInvalidID)
	}

	p, err := registered[i].MultBytes(scalar, element)
	if err != nil {
		return nil, err
	}

	return &Point{p}, nil
}
