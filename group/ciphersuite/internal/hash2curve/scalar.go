// Package hash2curve wraps an hash-to-curve implementation and exposes functions for operations on points and scalars.
package hash2curve

import (
	"crypto/rand"
	"math/big"

	"github.com/armfazh/tozan-ecc/field"

	"github.com/bytemare/cryptotools/group"
)

// Scalar implements the Scalar interface for Hash-to-Curve field elements.
type Scalar struct {
	s field.Elt
	f field.Field
}

func scalar(f field.Field) group.Scalar {
	return &Scalar{
		s: f.Zero(),
		f: f,
	}
}

// Equal returns whether the input scalar is equal to the receiver.
func (s *Scalar) Equal(s2 *Scalar) bool {
	return s.f.AreEqual(s.s, s2.s)
}

// Random sets the current scalar to a new random scalar and returns it.
func (s *Scalar) Random() group.Scalar {
	s.s = s.f.Rand(rand.Reader)

	return s
}

// Add returns the sum of the scalars, and does not change the receiver.
func (s *Scalar) Add(scalar group.Scalar) group.Scalar {
	if scalar == nil {
		return s
	}

	sc, ok := scalar.(*Scalar)
	if !ok {
		panic("could not cast to same group scalar : wrong group ?")
	}

	return &Scalar{
		s: s.f.Add(s.s, sc.s),
		f: s.f,
	}
}

// Sub returns the difference between the scalars, and does not change the receiver.
func (s *Scalar) Sub(scalar group.Scalar) group.Scalar {
	if scalar == nil {
		return s
	}

	sc, ok := scalar.(*Scalar)
	if !ok {
		panic("could not cast to same group scalar : wrong group ?")
	}

	return &Scalar{
		s: s.f.Sub(s.s, sc.s),
		f: s.f,
	}
}

// Mult returns the multiplication of the scalars, and does not change the receiver.
func (s *Scalar) Mult(scalar group.Scalar) group.Scalar {
	if scalar == nil {
		panic("multiplying scalar with nil element")
	}

	sc, ok := scalar.(*Scalar)
	if !ok {
		panic("could not cast to same group scalar : wrong group ?")
	}

	return &Scalar{
		s: s.f.Mul(s.s, sc.s),
		f: s.f,
	}
}

// Invert returns the scalar's modular inverse ( 1 / scalar ).
func (s *Scalar) Invert() group.Scalar {
	return &Scalar{
		s: s.f.Inv(s.s),
		f: s.f,
	}
}

// Copy returns a copy of the Scalar.
func (s *Scalar) Copy() group.Scalar {
	return &Scalar{
		s: s.s.Copy(),
		f: s.f,
	}
}

// Decode decodes the input an sets the current scalar to its value, and returns it.
func (s *Scalar) Decode(in []byte) (group.Scalar, error) {
	if len(in) == 0 {
		return nil, errParamNilScalar
	}

	// todo: warning - SetBytes interprets the input as a non-signed integer
	e := new(big.Int).SetBytes(in)
	if e.Sign() < 0 {
		return nil, errParamNegScalar
	}

	if s.f.Order().Cmp(e) <= 0 {
		return nil, errParamScalarTooBig
	}

	s.s = s.f.Elt(e)

	return s, nil
}

// Bytes returns the byte encoding of the scalar.
func (s *Scalar) Bytes() []byte {
	return s.s.Polynomial()[0].Bytes()
}
