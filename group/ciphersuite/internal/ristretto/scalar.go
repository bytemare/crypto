// Package ristretto allows simple and abstracted operations in the Ristretto255 group
package ristretto

import (
	"github.com/gtank/ristretto255"

	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/utils"
)

const (
	canonicalEncodingLength = 32
)

// Scalar implements the Scalar interface for Ristretto255 group scalars.
type Scalar struct {
	Scalar *ristretto255.Scalar
}

// Random sets the current scalar to a new random scalar and returns it.
func (s *Scalar) Random() group.Scalar {
	random := utils.RandomBytes(ristrettoInputLength)
	s.Scalar.FromUniformBytes(random)

	return s
}

// Add returns the sum of the scalars, and does not change the receiver.
func (s *Scalar) Add(scalar group.Scalar) group.Scalar {
	if scalar == nil {
		return s
	}

	sc, ok := scalar.(*Scalar)
	if !ok {
		panic(errCastScalar)
	}

	return &Scalar{Scalar: ristretto255.NewScalar().Add(s.Scalar, sc.Scalar)}
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

	return &Scalar{Scalar: ristretto255.NewScalar().Subtract(s.Scalar, sc.Scalar)}
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

	return &Scalar{Scalar: ristretto255.NewScalar().Multiply(s.Scalar, sc.Scalar)}
}

// Invert returns the scalar's modular inverse ( 1 / scalar ).
func (s *Scalar) Invert() group.Scalar {
	return &Scalar{ristretto255.NewScalar().Invert(s.Scalar)}
}

func (s *Scalar) copy() *Scalar {
	return &Scalar{ristretto255.NewScalar().Add(ristretto255.NewScalar(), s.Scalar)}
}

// Copy returns a copy of the Scalar.
func (s *Scalar) Copy() group.Scalar {
	return s.copy()
}

// Decode decodes the input an sets the current scalar to its value, and returns it.
func (s *Scalar) Decode(in []byte) (group.Scalar, error) {
	sc, err := decodeScalar(in)
	if err != nil {
		return nil, err
	}

	s.Scalar = sc

	return s, nil
}

// Bytes returns the byte encoding of the scalar.
func (s *Scalar) Bytes() []byte {
	return s.Scalar.Encode(nil)
}

func decodeScalar(scalar []byte) (*ristretto255.Scalar, error) {
	if len(scalar) == 0 {
		return nil, errParamNilScalar
	}

	if len(scalar) != canonicalEncodingLength {
		return nil, errParamScalarLength
	}

	s := ristretto255.NewScalar()
	if err := s.Decode(scalar); err != nil {
		return nil, err
	}

	return s, nil
}
