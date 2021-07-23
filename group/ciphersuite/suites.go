// Package ciphersuite identifies a list of prime-order elliptic curve groups coupled with hashing functions implementing
// group operations over elliptic curves, as well as HashToGroup() and HashToScalar() per Hash-to-curve.
package ciphersuite

import (
	"fmt"

	"github.com/bytemare/cryptotools/internal"

	H2C "github.com/armfazh/h2c-go-ref"

	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite/internal/hash2curve"
	"github.com/bytemare/cryptotools/group/ciphersuite/internal/ristretto"
	"github.com/bytemare/cryptotools/hash"
)

// Identifier defines registered groups for use in the implementation.
type Identifier byte

const (
	// Ristretto255Sha512 identifies the Ristretto255 group with SHA2-512 hash-to-group hashing.
	Ristretto255Sha512 Identifier = 1 + iota

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

	// BLS12381G1Sha256 identifies a group over BLS12381G1 with SHA2-512 hash-to-group hashing.
	// BLS12381G1Sha256

	// BLS12381G2Sha256 identifies a group over BLS12381G2 with SHA2-512 hash-to-group hashing.
	// BLS12381G2Sha256

	maxID

	// Default falls back to Ristretto255.
	Default = Ristretto255Sha512
)

const dstfmt = "%s-V%s-CS%s-%s"

var (
	registered       map[Identifier]*params
	errInvalidID     = internal.ParameterError("invalid ciphersuite identifier")
	errUnavailableID = internal.ParameterError("ciphersuite unavailable")
)

// Available reports whether the given Identifier is linked into the binary.
func (i Identifier) Available() bool {
	return i > 0 && i < maxID && registered[i] != nil
}

// MakeDST builds a domain separation tag in the form of <app>-V<version>-CS<id>-<hash-to-curve-ID>, or returns an error.
func (i Identifier) MakeDST(app, version string) ([]byte, error) {
	if !i.Available() {
		panic(errInvalidID)
	}

	if i == Identifier(0) || i >= maxID {
		return nil, errInvalidID
	}

	if !i.Available() {
		return nil, errUnavailableID
	}

	p := registered[i]

	return []byte(fmt.Sprintf(dstfmt, app, version, p.id, p.h2cID)), nil
}

// String returns the hash-to-curve string identifier of the ciphersuite.
func (i Identifier) String() string {
	if !i.Available() {
		panic(errInvalidID)
	}

	if i == Identifier(0) || i >= maxID {
		panic(errInvalidID)
	}

	p := registered[i]

	return string(p.h2cID)
}

type newGroup func() group.Group

type params struct {
	id    Identifier
	h2cID H2C.SuiteID
	newGroup
}

func (i Identifier) register(identifier H2C.SuiteID, g newGroup) {
	registered[i] = &params{
		id:       i,
		h2cID:    identifier,
		newGroup: g,
	}
}

func newRistretto(_ hash.Identifier) newGroup {
	return func() group.Group {
		return nil
	}
}

func newCurve(id H2C.SuiteID) (H2C.SuiteID, newGroup) {
	return id, func() group.Group {
		return hash2curve.New(id)
	}
}

func init() {
	registered = make(map[Identifier]*params)

	Ristretto255Sha512.register("ristretto255_XMD:SHA-512_R255MAP_RO_", newRistretto(hash.SHA512))
	P256Sha256.register(newCurve(H2C.P256_XMDSHA256_SSWU_RO_))
	P384Sha512.register(newCurve(H2C.P384_XMDSHA512_SSWU_RO_))
	P521Sha512.register(newCurve(H2C.P521_XMDSHA512_SSWU_RO_))
	Curve25519Sha512.register(newCurve(H2C.Curve25519_XMDSHA512_ELL2_RO_))
	Edwards25519Sha512.register(newCurve(H2C.Edwards25519_XMDSHA512_ELL2_RO_))
	Curve448Sha512.register(newCurve(H2C.Curve448_XMDSHA512_ELL2_RO_))
	Edwards448Sha512.register(newCurve(H2C.Edwards448_XMDSHA512_ELL2_RO_))
	Secp256k1Sha256.register(newCurve(H2C.Secp256k1_XMDSHA256_SSWU_RO_))
}

/*

 */

func (i Identifier) NewScalar() group.Scalar {
	if !i.Available() {
		panic(errInvalidID)
	}

	if i == Ristretto255Sha512 {
		return ristretto.NewScalar()
	}

	return registered[i].newGroup().NewScalar()
}

func (i Identifier) NewElement() group.Element {
	if !i.Available() {
		panic(errInvalidID)
	}

	if i == Ristretto255Sha512 {
		return ristretto.NewElement()
	}

	return registered[i].newGroup().NewElement()
}

func (i Identifier) ElementLength() int {
	if !i.Available() {
		panic(errInvalidID)
	}

	if i == Ristretto255Sha512 {
		return ristretto.ElementLength()
	}

	return registered[i].newGroup().ElementLength()
}

func (i Identifier) Identity() group.Element {
	if !i.Available() {
		panic(errInvalidID)
	}

	if i == Ristretto255Sha512 {
		return ristretto.Identity()
	}

	return registered[i].newGroup().Identity()
}

func (i Identifier) HashToGroup(input, dst []byte) group.Element {
	if !i.Available() {
		panic(errInvalidID)
	}

	if i == Ristretto255Sha512 {
		return ristretto.HashToGroup(input, dst)
	}

	return registered[i].newGroup().HashToGroup(input, dst)
}

func (i Identifier) HashToScalar(input, dst []byte) group.Scalar {
	if !i.Available() {
		panic(errInvalidID)
	}

	if i == Ristretto255Sha512 {
		return ristretto.HashToScalar(input, dst)
	}

	return registered[i].newGroup().HashToScalar(input, dst)
}

func (i Identifier) Base() group.Element {
	if !i.Available() {
		panic(errInvalidID)
	}

	if i == Ristretto255Sha512 {
		return ristretto.Base()
	}

	return registered[i].newGroup().Base()
}

func (i Identifier) MultBytes(scalar, element []byte) (group.Element, error) {
	if !i.Available() {
		panic(errInvalidID)
	}

	if i == Ristretto255Sha512 {
		return ristretto.MultBytes(scalar, element)
	}

	return registered[i].newGroup().MultBytes(scalar, element)
}
