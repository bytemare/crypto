package internal

import (
	"errors"
	"github.com/bytemare/crypto/group/internal"
	"math/big"
)

var (
	errParamNegScalar    = errors.New("negative scalar")
	errParamScalarTooBig = errors.New("scalar too big")
)

// Scalar implements the Scalar interface for NIST group scalars.
type Scalar struct {
	s *big.Int
	f *field
}

func NewScalar(g Group) *Scalar {
	return &Scalar{
		s: g.scalarField.Zero(),
		f: g.scalarField,
	}
}

// Random sets s to a random scalar in the field.
func (s *Scalar) Random() *Scalar {
	s.s = s.f.Random()
	return s
}

// Add sets s to s1 + s2, and returns s.
func (s *Scalar) Add(s1, s2 *Scalar) *Scalar {
	if s1 == nil || s2 == nil {
		panic(internal.ErrParamNilScalar)
	}

	if !s1.f.IsEqual(s2.f) {
		panic("incompatible fields")
	}

	s.s = s.f.add(s1.s, s2.s)

	return s
}

// Sub sets s to s1 - s2, and returns s.
func (s *Scalar) Sub(s1, s2 *Scalar) *Scalar {
	if s1 == nil || s2 == nil {
		panic(internal.ErrParamNilScalar)
	}

	if !s1.f.IsEqual(s2.f) {
		panic("incompatible fields")
	}

	s.s = s.f.sub(s1.s, s2.s)

	return s
}

// Mult sets s to s * scalar, and returns s.
func (s *Scalar) Mult(s1, s2 *Scalar) *Scalar {
	if s1 == nil || s2 == nil {
		panic(internal.ErrParamNilScalar)
	}

	if !s1.f.IsEqual(s2.f) {
		panic("incompatible fields")
	}

	s.s = s.f.Mul(s1.s, s2.s)

	return s
}

// Invert set s to the modular inverse ( s^-1 = 1 mod N ) of scalar, and returns s.
func (s *Scalar) Invert(scalar *Scalar) *Scalar {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}

	if !s.f.IsEqual(scalar.f) {
		panic("incompatible fields")
	}

	s.s = s.f.Inv(scalar.s)

	return s
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return s.f.AreEqual(s.s, s.f.Zero())
}

// Copy returns a copy of the Scalar.
func (s *Scalar) Copy() *Scalar {
	return &Scalar{
		s: new(big.Int).Set(s.s),
		f: s.f,
	}
}

// Decode decodes the input and sets the current scalar to its value, and returns it.
func (s *Scalar) Decode(in []byte) (*Scalar, error) {
	if len(in) == 0 {
		return nil, internal.ErrParamNilScalar
	}

	// warning - SetBytes interprets the input as a non-signed integer, so this will always be negative
	e := new(big.Int).SetBytes(in)
	if e.Sign() < 0 {
		return nil, errParamNegScalar
	}

	if s.f.Order().Cmp(e) <= 0 {
		return nil, errParamScalarTooBig
	}

	s.s = s.f.Element(e)

	return s, nil
}

// Bytes returns the byte encoding of the scalar.
func (s *Scalar) Bytes() []byte {
	return s.s.Bytes()
}
