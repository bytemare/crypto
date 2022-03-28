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

	"github.com/bytemare/crypto/group/curve25519"
	"github.com/bytemare/crypto/group/edwards25519"
	"github.com/bytemare/crypto/group/internal"
	"github.com/bytemare/crypto/group/other"
	"github.com/bytemare/crypto/group/ristretto"
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

	// P384Sha384 identifies a group over P384 with SHA2-384 hash-to-group hashing.
	P384Sha384

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
)

const dstfmt = "%s-V%s-CS%s-%s"

var (
	registered   map[Group]*params
	errInvalidID = errors.New("invalid group identifier")
)

// Available reports whether the given Group is linked into the binary.
func (i Group) Available() bool {
	_, ok := registered[i]
	return ok
}

func (i Group) get() *params {
	p, ok := registered[i]
	if !ok {
		panic(errInvalidID)
	}

	return p
}

// MakeDST builds a domain separation tag in the form of <app>-V<version>-CS<id>-<hash-to-curve-ID>,
// and returns no error.
func (i Group) MakeDST(app, version string) []byte {
	p := i.get()
	return []byte(fmt.Sprintf(dstfmt, app, version, p.id, p.h2cID))
}

// String returns the hash-to-curve string identifier of the ciphersuite.
func (i Group) String() string {
	return i.get().h2cID
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

	Ristretto255Sha512.register(ristretto.H2C, ristretto.Group{})
	P256Sha256.register(newCurve(H2C.P256_XMDSHA256_SSWU_RO_))
	P384Sha384.register(newCurve(H2C.P384_XMDSHA384_SSWU_RO_))
	P521Sha512.register(newCurve(H2C.P521_XMDSHA512_SSWU_RO_))
	Curve25519Sha512.register(curve25519.H2C, curve25519.Group{})
	Edwards25519Sha512.register(edwards25519.H2C, edwards25519.Group{})
	Curve448Sha512.register(newCurve(H2C.Curve448_XMDSHA512_ELL2_RO_))
	Edwards448Sha512.register(newCurve(H2C.Edwards448_XMDSHA512_ELL2_RO_))
	Secp256k1Sha256.register(newCurve(H2C.Secp256k1_XMDSHA256_SSWU_RO_))
}

// NewScalar returns a new, empty, scalar.
func (i Group) NewScalar() *Scalar {
	return newScalar(i.get().NewScalar())
}

// NewElement returns a new, empty, element.
func (i Group) NewElement() *Point {
	return newPoint(i.get().NewElement())
}

// ElementLength returns the byte size of an encoded element.
func (i Group) ElementLength() int {
	return i.get().ElementLength()
}

// Identity returns the group's identity element.
func (i Group) Identity() *Point {
	return newPoint(i.get().Identity())
}

// HashToGroup allows arbitrary input to be safely mapped to the curve of the Group.
func (i Group) HashToGroup(input, dst []byte) *Point {
	return newPoint(i.get().HashToGroup(input, dst))
}

// EncodeToGroup allows arbitrary input to be safely mapped to the curve of the Group.
func (i Group) EncodeToGroup(input, dst []byte) *Point {
	return newPoint(i.get().HashToGroup(input, dst))
}

// HashToScalar allows arbitrary input to be safely mapped to the field.
func (i Group) HashToScalar(input, dst []byte) *Scalar {
	return newScalar(i.get().HashToScalar(input, dst))
}

// Base returns the group's base point a.k.a. canonical generator.
func (i Group) Base() *Point {
	return newPoint(i.get().Base())
}

// MultBytes allows []byte encodings of a scalar and an element of the Group to be multiplied.
func (i Group) MultBytes(scalar, element []byte) (*Point, error) {
	p, err := i.get().MultBytes(scalar, element)
	if err != nil {
		return nil, err
	}

	return &Point{p}, nil
}
