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
	"sync"

	H2C "github.com/armfazh/h2c-go-ref"

	"github.com/bytemare/crypto/group/curve25519"
	"github.com/bytemare/crypto/group/edwards25519"
	"github.com/bytemare/crypto/group/internal"
	"github.com/bytemare/crypto/group/old"
	"github.com/bytemare/crypto/group/other"
	"github.com/bytemare/crypto/group/ristretto"
)

// Group identifies prime-order groups over elliptic curves with hash-to-group operations.
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

	// Curve448Shake256 identifies a group over Curve448 with Shake256 hash-to-group hashing.
	//Curve448Shake256

	// Edwards448Shake256 identifies a group over Edwards448 with Shake256 hash-to-group hashing.
	//Edwards448Shake256

	maxID

	dstfmt               = "%s-V%02d-CS%02d-%s"
	minLength            = 0
	recommendedMinLength = 16
)

var (
	once          [maxID - 1]sync.Once
	groups        [maxID - 1]*params
	errInvalidID  = errors.New("invalid group identifier")
	errZeroLenDST = errors.New("zero-length DST")
)

type params struct {
	h2cID string
	internal.Group
}

// Available reports whether the given Group is linked into the binary.
func (g Group) Available() bool {
	return 0 < g && g < maxID
}

func (g Group) get() *params {
	if !g.Available() {
		panic(errInvalidID)
	}

	once[g-1].Do(g.init)

	return groups[g-1]
}

// MakeDST builds a domain separation tag in the form of <app>-V<version>-CS<id>-<hash-to-curve-ID>,
// and returns no error.
func (g Group) MakeDST(app string, version uint8) []byte {
	p := g.get()
	return []byte(fmt.Sprintf(dstfmt, app, version, g, p.h2cID))
}

// String returns the hash-to-curve string identifier of the ciphersuite.
func (g Group) String() string {
	return g.get().h2cID
}

// NewScalar returns a new, empty, scalar.
func (g Group) NewScalar() *Scalar {
	return newScalar(g.get().NewScalar())
}

// NewElement returns the identity point (point at infinity).
func (g Group) NewElement() *Point {
	return newPoint(g.get().NewElement())
}

// ElementLength returns the byte size of an encoded element.
func (g Group) ElementLength() uint {
	return g.get().ElementLength()
}

func checkDST(dst []byte) {
	if len(dst) < recommendedMinLength {
		if len(dst) == minLength {
			panic(errZeroLenDST)
		}
	}
}

// HashToGroup allows arbitrary input to be safely mapped to the curve of the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) HashToGroup(input, dst []byte) *Point {
	checkDST(dst)
	return newPoint(g.get().HashToGroup(input, dst))
}

// EncodeToGroup allows arbitrary input to be safely mapped to the curve of the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) EncodeToGroup(input, dst []byte) *Point {
	checkDST(dst)
	return newPoint(g.get().HashToGroup(input, dst))
}

// HashToScalar allows arbitrary input to be safely mapped to the field.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) HashToScalar(input, dst []byte) *Scalar {
	checkDST(dst)
	return newScalar(g.get().HashToScalar(input, dst))
}

// Base returns the group's base point a.k.a. canonical generator.
func (g Group) Base() *Point {
	return newPoint(g.get().Base())
}

// MultBytes allows []byte encodings of a scalar and an element of the Group to be multiplied.
func (g Group) MultBytes(scalar, element []byte) (*Point, error) {
	p, err := g.get().MultBytes(scalar, element)
	if err != nil {
		return nil, err
	}

	return &Point{p}, nil
}

func newH2Cgroup(id H2C.SuiteID) (string, func() internal.Group) {
	get := func() internal.Group {
		return other.New(id)
	}
	return string(id), get
}

func (g Group) initGroup(h2cID string, get func() internal.Group) {
	groups[g-1] = &params{
		h2cID: h2cID,
		Group: get(),
	}
}

func (g Group) init() {
	switch g {
	case Ristretto255Sha512:
		g.initGroup(ristretto.H2C, ristretto.New)
	case P256Sha256:
		g.initGroup(old.H2CP256, old.P256)
	case P384Sha384:
		g.initGroup(old.H2CP384, old.P384)
	case P521Sha512:
		g.initGroup(old.H2CP521, old.P521)
	case Curve25519Sha512:
		g.initGroup(curve25519.H2C, curve25519.New)
	case Edwards25519Sha512:
		g.initGroup(edwards25519.H2C, edwards25519.New)
		//case Curve448Shake256:
		//	g.initGroup(newH2Cgroup(H2C.Curve448_XOFSHAKE256_ELL2_RO_))
		//case Edwards448Shake256:
		//	g.initGroup(newH2Cgroup(H2C.Edwards448_XOFSHAKE256_ELL2_RO_))
	}
}
