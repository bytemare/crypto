package ed25519

import (
	"filippo.io/edwards25519"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite/internal"
	"github.com/bytemare/cryptotools/utils"
)

const inputLength = 64
const canonicalEncodingLength = 32

type Scalar struct {
	scalar *edwards25519.Scalar
}

// Random sets the current scalar to a new random scalar and returns it.
func (s *Scalar) Random() group.Scalar {
	_, err := s.scalar.SetUniformBytes(utils.RandomBytes(inputLength))
	if err != nil {
		panic(err)
	}

	return s
}

// Add returns the sum of the scalars, and does not change the receiver.
func (s *Scalar) Add(scalar group.Scalar) group.Scalar {
	if scalar == nil {
		return s
	}

	sc, ok := scalar.(*Scalar)
	if !ok {
		panic(internal.ErrCastScalar)
	}

	return &Scalar{scalar: edwards25519.NewScalar().Add(s.scalar, sc.scalar)}
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

	return &Scalar{scalar: edwards25519.NewScalar().Subtract(s.scalar, sc.scalar)}
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

	return &Scalar{scalar: edwards25519.NewScalar().Multiply(s.scalar, sc.scalar)}
}

// Invert returns the scalar's modular inverse ( 1 / scalar ).
func (s *Scalar) Invert() group.Scalar {
	return &Scalar{edwards25519.NewScalar().Invert(s.scalar)}
}

// Copy returns a copy of the Scalar.
func (s *Scalar) Copy() group.Scalar {
	return &Scalar{edwards25519.NewScalar().Add(edwards25519.NewScalar(), s.scalar)}
}

func decodeScalar(scalar []byte) (*edwards25519.Scalar, error) {
	if len(scalar) == 0 {
		return nil, internal.ErrParamNilScalar
	}

	if len(scalar) != canonicalEncodingLength {
		return nil, internal.ErrParamScalarLength
	}

	return edwards25519.NewScalar().SetCanonicalBytes(scalar)
}

// Decode decodes the input an sets the current scalar to its value, and returns it.
func (s *Scalar) Decode(in []byte) (group.Scalar, error) {
	sc, err := decodeScalar(in)
	if err != nil {
		return nil, err
	}

	s.scalar = sc

	return s, nil
}

// Bytes returns the byte encoding of the element.
func (s *Scalar) Bytes() []byte {
	return s.scalar.Bytes()
}
