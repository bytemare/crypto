package decaf448

import (
	"crypto/subtle"
	curve "github.com/bytemare/crypto/group/edwards448"
	fp "github.com/bytemare/crypto/group/twistedEdwards448/field"
	"io"
)

type dElt struct{ p curve.Point }

func (e dElt) String() string                   { return e.p.String() }
func (e *dElt) Set(a Element) Element           { e.p = a.(*dElt).p; return e }
func (e *dElt) Copy() Element                   { return &dElt{e.p} }
func (e *dElt) Add(a, b Element) Element        { e.Set(a); e.p.Add(&b.(*dElt).p); return e }
func (e *dElt) Dbl(a Element) Element           { e.Set(a); e.p.Double(); return e }
func (e *dElt) Neg(a Element) Element           { e.Set(a); e.p.Neg(); return e }
func (e *dElt) Mul(a Element, s Scalar) Element { e.p.ScalarMult(&s.(*dScl).k, &a.(*dElt).p); return e }
func (e *dElt) MulGen(s Scalar) Element {
	k := &s.(*dScl).k
	k2 := &curve.Scalar{}
	k2.Add(k, k) // Since decaf.Generator() == 2*goldilocks.Generator().
	e.p.ScalarBaseMult(k2)
	return e
}

func (e *dElt) IsIdentity() bool {
	// From Decaf, Section 4.5 - Equality
	// In particular, for a curve of cofactor exactly 4,
	// a point (X : Y : Z : T ) is equal to the identity precisely when X = 0.
	return fp.IsZero(&e.p.X) == 1
}

func (e *dElt) IsEqual(a Element) bool {
	// Section 5.3.3 - Equals
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448-03#section-5.3.3
	aa := a.(*dElt)
	l, r := &fp.Elt{}, &fp.Elt{}
	fp.Mul(l, &e.p.X, &aa.p.Y)
	fp.Mul(r, &aa.p.X, &e.p.Y)
	fp.Sub(l, l, r)
	return fp.IsZero(l) == 1
}

func (e *dElt) MarshalBinaryCompress() ([]byte, error) { return e.MarshalBinary() }
func (e *dElt) MarshalBinary() ([]byte, error) {
	var encS [fp.Size]byte
	err := e.marshalBinary(encS[:])
	return encS[:], err
}

func (e *dElt) marshalBinary(enc []byte) error {
	// Section 5.3.2 - Encode
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448-03#section-5.3.2
	x, ta, tb, z := &e.p.X, &e.p.Ta, &e.p.Tb, &e.p.Z
	t, u1, u2, u3 := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	v, ir, rt, w, s := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}

	one := fp.One()
	fp.Mul(t, ta, tb)              // t = ta*tb
	plus, minus := *x, *t          //
	fp.AddSub(&plus, &minus)       // (plus,minus) = (x+t,x-t)
	fp.Mul(u1, &plus, &minus)      // u1 = (x+t)*(x-t)
	fp.Square(v, x)                // v = u1 * ONE_MINUS_D * x0^2
	fp.Mul(v, v, &aMinusD)         //
	fp.Mul(v, v, u1)               //
	_ = fp.InvSqrt(ir, &one, v)    // ir = sqrt(1/v)
	fp.Mul(w, ir, u1)              // rt = CT_ABS(ir * u1 * SQRT_MINUS_D)
	fp.Mul(w, w, &sqrtMinusD)      //
	ctAbs(rt, w)                   //
	fp.Mul(u2, rt, z)              // u2 = INVSQRT_MINUS_D * rt * z0 - t0
	fp.Mul(u2, u2, &invSqrtMinusD) //
	fp.Sub(u2, u2, t)              //
	fp.Mul(u3, x, u2)              // s = CT_ABS(ONE_MINUS_D * ir * x0 * u2)
	fp.Mul(u3, u3, ir)             //
	fp.Mul(u3, u3, &aMinusD)       //
	ctAbs(s, u3)                   //

	return fp.ToBytes(enc[:], s)
}

func (e *dElt) UnmarshalBinary(data []byte) error {
	// Section 5.3.1 - Decode
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448-03#section-5.3.1
	if len(data) < fp.Size {
		return io.ErrShortBuffer
	}

	p := fp.P()
	s := &fp.Elt{}
	copy(s[:], data[:fp.Size])
	isLessThanP := isLessThan(s[:], p[:])
	isPositiveS := 1 - fp.Parity(s)

	one := fp.One()
	paramD := curve.ParamD()

	x, y := &fp.Elt{}, &fp.Elt{}
	ss, u1, u2, u3 := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	ir, v, w := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}

	fp.Square(ss, s)                // ss = s^2
	fp.Add(u1, &one, ss)            // u1 = 1 - a*s^2
	fp.Mul(u2, ss, &paramD)         // u2 = d*s^2
	fp.Add(u2, u2, u2)              //    = 2*d*s^2
	fp.Add(u2, u2, u2)              //    = 4*d*s^2
	fp.Square(v, u1)                // v  = u1^2 = (1 + a*s^2)^2
	fp.Sub(u2, v, u2)               // u2 = u1^2 - 4*d*s^2
	fp.Mul(w, u2, v)                // w  = u2 * u1^2
	isQR := fp.InvSqrt(ir, &one, w) // ir = sqrt(1/(u2 * u1^2))
	fp.Mul(w, s, ir)                // w  = ir*u1
	fp.Mul(w, w, u1)                //    = s*ir*u1
	fp.Mul(w, w, &sqrtMinusD)       //    = s*ir*u1*sqrt(-d)
	fp.Add(w, w, w)                 //    = 2*s*ir*u1*sqrt(-d)
	ctAbs(u3, w)                    // u3 = CT_ABS(w)
	fp.Mul(x, u3, ir)               // x  = u3 * ir * u2 * INVSQRT_MINUS_D
	fp.Mul(x, x, u2)                //
	fp.Mul(x, x, &invSqrtMinusD)    //
	fp.Sub(y, &one, ss)             // y  = (1 - a*s^2) * ir * u1
	fp.Mul(y, y, ir)                //
	fp.Mul(y, y, u1)                //

	b0 := isPositiveS
	b1 := isLessThanP
	b2 := isQR
	b := uint(subtle.ConstantTimeEq(int32(4*b2+2*b1+b0), 0b111))
	fp.Cmov(&e.p.X, x, b)
	fp.Cmov(&e.p.Y, y, b)
	fp.Cmov(&e.p.Ta, x, b)
	fp.Cmov(&e.p.Tb, y, b)
	fp.Cmov(&e.p.Z, &one, b)
	if b == 0 {
		return ErrInvalidDecoding
	}
	return nil
}
