package edwards448

import (
	"crypto/subtle"
	"encoding/binary"
	ted "github.com/bytemare/crypto/group/twistedEdwards448"
)

type Scalar struct{ k ted.Scalar }

func (z Scalar) String() string         { return z.k.String() }
func (z *Scalar) Add(x, y *Scalar)      { z.k.Add(&x.k, &y.k) }
func (z *Scalar) Sub(x, y *Scalar)      { z.k.Sub(&x.k, &y.k) }
func (z *Scalar) Mul(x, y *Scalar)      { z.k.Mul(&x.k, &y.k) }
func (z *Scalar) Neg(x *Scalar)         { z.k.Neg(&x.k) }
func (z *Scalar) Inv(x *Scalar)         { z.k.Inv(&x.k) }
func (z *Scalar) IsEqual(x *Scalar) int { return subtle.ConstantTimeCompare(z.k[:], x.k[:]) }
func (z *Scalar) SetUint64(n uint64)    { z.k = ted.Scalar{}; binary.LittleEndian.PutUint64(z.k[:], n) }

// UnmarshalBinary recovers the scalar from its byte representation in big-endian order.
func (z *Scalar) UnmarshalBinary(b []byte) error { return z.k.UnmarshalBinary(b) }

// MarshalBinary returns the scalar byte representation in big-endian order.
func (z *Scalar) MarshalBinary() ([]byte, error) { return z.k.MarshalBinary() }

// ToBytesLE returns the scalar byte representation in little-endian order.
func (z *Scalar) ToBytesLE() []byte { return z.k.ToBytesLE() }

// ToBytesBE returns the scalar byte representation in big-endian order.
func (z *Scalar) ToBytesBE() []byte { return z.k.ToBytesBE() }

// FromBytesLE stores z = x mod order, where x is a number stored in little-endian order.
func (z *Scalar) FromBytesLE(x []byte) { z.k.FromBytesLE(x) }

// FromBytesBE stores z = x mod order, where x is a number stored in big-endian order.
func (z *Scalar) FromBytesBE(x []byte) { z.k.FromBytesBE(x) }
