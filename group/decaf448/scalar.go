package decaf448

import (
	curve "github.com/bytemare/crypto/group/edwards448"

	fp "github.com/bytemare/crypto/group/twistedEdwards448/field"
	"math/bits"
)

type dScl struct{ k curve.Scalar }

func (s *dScl) String() string                 { return s.k.String() }
func (s *dScl) SetUint64(n uint64)             { s.k.SetUint64(n) }
func (s *dScl) Set(a Scalar) Scalar            { s.k = a.(*dScl).k; return s }
func (s *dScl) Copy() Scalar                   { return &dScl{k: s.k} }
func (s *dScl) Add(a, b Scalar) Scalar         { s.k.Add(&a.(*dScl).k, &b.(*dScl).k); return s }
func (s *dScl) Sub(a, b Scalar) Scalar         { s.k.Sub(&a.(*dScl).k, &b.(*dScl).k); return s }
func (s *dScl) Mul(a, b Scalar) Scalar         { s.k.Mul(&a.(*dScl).k, &b.(*dScl).k); return s }
func (s *dScl) Neg(a Scalar) Scalar            { s.k.Neg(&a.(*dScl).k); return s }
func (s *dScl) Inv(a Scalar) Scalar            { s.k.Inv(&a.(*dScl).k); return s }
func (s *dScl) MarshalBinary() ([]byte, error) { return s.k.MarshalBinary() }
func (s *dScl) UnmarshalBinary(b []byte) error { return s.k.UnmarshalBinary(b) }
func (s *dScl) IsEqual(a Scalar) bool          { return s.k.IsEqual(&a.(*dScl).k) == 1 }

func ctAbs(z, x *fp.Elt) {
	minusX := &fp.Elt{}
	fp.Neg(minusX, x)
	*z = *x
	fp.Cmov(z, minusX, uint(fp.Parity(x)))
}

// isLessThan returns 1 if 0 <= x < y, and assumes that slices are of the
// same length and are interpreted in little-endian order.
func isLessThan(x, y []byte) int {
	i := len(x) - 1
	for i > 0 && x[i] == y[i] {
		i--
	}
	xi := int(x[i])
	yi := int(y[i])
	return ((xi - yi) >> (bits.UintSize - 1)) & 1
}

var (
	// aMinusD is paramA-paramD = (-1)-(-39081) = 39082.
	aMinusD = fp.Elt{0xaa, 0x98}
	// aMinusTwoD is paramA-2*paramD = (-1)-2*(-39081) = 78163.
	aMinusTwoD = fp.Elt{0x53, 0x31, 0x01}
	// sqrtMinusD is the smallest root of sqrt(paramD) = sqrt(39081).
	sqrtMinusD = fp.Elt{
		0x36, 0x27, 0x57, 0x45, 0x0f, 0xef, 0x42, 0x96,
		0x52, 0xce, 0x20, 0xaa, 0xf6, 0x7b, 0x33, 0x60,
		0xd2, 0xde, 0x6e, 0xfd, 0xf4, 0x66, 0x9a, 0x83,
		0xba, 0x14, 0x8c, 0x96, 0x80, 0xd7, 0xa2, 0x64,
		0x4b, 0xd5, 0xb8, 0xa5, 0xb8, 0xa7, 0xf1, 0xa1,
		0xa0, 0x6a, 0xa2, 0x2f, 0x72, 0x8d, 0xf6, 0x3b,
		0x68, 0xf7, 0x24, 0xeb, 0xfb, 0x62, 0xd9, 0x22,
	}
	// invSqrtMinusD is the smallest root of sqrt(1/paramD) = sqrt(1/39081).
	invSqrtMinusD = fp.Elt{
		0x2c, 0x68, 0x78, 0xb8, 0x5e, 0xbb, 0xaf, 0x53,
		0xf3, 0x94, 0x9e, 0xf1, 0x79, 0x24, 0xbb, 0xef,
		0x15, 0xba, 0x1f, 0xc2, 0xe2, 0x7e, 0x70, 0xbe,
		0x1a, 0x52, 0xa6, 0x28, 0xf1, 0x56, 0xba, 0xd6,
		0xa7, 0x27, 0x5b, 0x3a, 0x0c, 0x95, 0x90, 0x5a,
		0x07, 0xc8, 0xca, 0x0b, 0x5a, 0xe3, 0x2b, 0x90,
		0x57, 0xc0, 0x22, 0xe2, 0x52, 0x06, 0xf4, 0x6e,
	}
)
