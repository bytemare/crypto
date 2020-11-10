package hashtogroup

import (
	"errors"
	"fmt"

	H2C "github.com/armfazh/h2c-go-ref"

	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/hashtogroup/group"
	"github.com/bytemare/cryptotools/hashtogroup/internal/hash2curve"
	"github.com/bytemare/cryptotools/hashtogroup/internal/ristretto"
)

// Ciphersuite defines registered groups for use in the implementation.
type Ciphersuite byte

const (
	// Ristretto255Sha512 identifies the Ristretto255 group with SHA2-512 hash-to-group hashing.
	Ristretto255Sha512 Ciphersuite = 1 + iota

	// Ristretto255Sha3512 identifies the Ristretto255 group with SHA3-512 hash-to-group hashing.
	Ristretto255Sha3512

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
	registered       map[Ciphersuite]*params
	errInvalidID     = errors.New("invalid ciphersuite identifier")
	errUnavailableID = errors.New("ciphersuite unavailable")
	errZeroLenDST    = errors.New("zero-length DST")
	errShortDST      = errors.New("DST is shorter than recommended length")
)

// Get returns a Group interface implementing struct to the given cipher suite.
func (i Ciphersuite) Get(dst []byte) group.Group {
	if i == 0 || i >= maxID {
		panic(errInvalidID)
	}

	if len(dst) == group.DstMinLength {
		panic(errZeroLenDST)
	} else if len(dst) < group.DstRecommendedMinLength {
		panic(errShortDST)
	}

	return registered[i].newGroup(dst)
}

// Available reports whether the given Ciphersuite is linked into the binary.
func (i Ciphersuite) Available() bool {
	return i > 0 && i < maxID && registered[i] != nil
}

// MakeDST builds a domain separation tag in the form of <app>-V<version>-CS<id>-<hash-to-curve-ID>, or returns an error.
func (i Ciphersuite) MakeDST(app, version string) ([]byte, error) {
	if i == Ciphersuite(0) || i >= maxID {
		return nil, errInvalidID
	}

	if !i.Available() {
		return nil, errUnavailableID
	}

	p := registered[i]

	return []byte(fmt.Sprintf(dstfmt, app, version, p.id, p.h2cID)), nil
}

// String returns the hash-to-curve string identifier of the ciphersuite.
func (i Ciphersuite) String() string {
	if i == Ciphersuite(0) || i >= maxID {
		panic(errInvalidID)
	}

	p := registered[i]

	return string(p.h2cID)
}

type newGroup func(dst []byte) group.Group

type params struct {
	id    Ciphersuite
	h2cID H2C.SuiteID
	newGroup
}

func (i Ciphersuite) register(identifier H2C.SuiteID, g newGroup) {
	registered[i] = &params{
		id:       i,
		h2cID:    identifier,
		newGroup: g,
	}
}

func newRistretto(identifier hash.Identifier) newGroup {
	return func(dst []byte) group.Group {
		return ristretto.New(identifier, dst)
	}
}

func newCurve(id H2C.SuiteID) (H2C.SuiteID, newGroup) {
	return id, func(dst []byte) group.Group {
		return hash2curve.New(id, dst)
	}
}

func init() {
	registered = make(map[Ciphersuite]*params)

	Ristretto255Sha512.register("ristretto255_XMD:SHA-512_R255MAP_RO_", newRistretto(hash.SHA512))
	Ristretto255Sha3512.register("ristretto255_XMD:SHA3-512_R255MAP_RO_", newRistretto(hash.SHA3_512))
	P256Sha256.register(newCurve(H2C.P256_XMDSHA256_SSWU_RO_))
	P384Sha512.register(newCurve(H2C.P384_XMDSHA512_SSWU_RO_))
	P521Sha512.register(newCurve(H2C.P521_XMDSHA512_SSWU_RO_))
	Curve25519Sha512.register(newCurve(H2C.Curve25519_XMDSHA512_ELL2_RO_))
	Edwards25519Sha512.register(newCurve(H2C.Edwards25519_XMDSHA512_ELL2_RO_))
	Curve448Sha512.register(newCurve(H2C.Curve448_XMDSHA512_ELL2_RO_))
	Edwards448Sha512.register(newCurve(H2C.Edwards448_XMDSHA512_ELL2_RO_))
	Secp256k1Sha256.register(newCurve(H2C.Secp256k1_XMDSHA256_SSWU_RO_))
}
