package decaf448

import (
	curve "github.com/bytemare/crypto/group/edwards448"
	fp "github.com/bytemare/crypto/group/twistedEdwards448/field"
	"io"
)

// Decaf448 is a quotient group generated from the edwards448 curve.
var Decaf448 = decaf448{}

type decaf448 struct{}

func (g decaf448) String() string      { return "decaf448" }
func (g decaf448) Params() *Params     { return &Params{fp.Size, fp.Size, curve.ScalarSize} }
func (g decaf448) NewElement() Element { return g.Identity() }
func (g decaf448) NewScalar() Scalar   { return new(dScl) }
func (g decaf448) Identity() Element   { return &dElt{curve.Identity()} }
func (g decaf448) Order() Scalar       { r := &dScl{}; r.k.FromBytesLE(curve.Order()); return r }
func (g decaf448) Generator() Element {
	e := curve.Generator()
	e.Double() // Since decaf.Generator() == 2*goldilocks.Generator().
	return &dElt{e}
}

func (g decaf448) RandomElement(rd io.Reader) Element {
	b := make([]byte, fp.Size)
	if n, err := io.ReadFull(rd, b); err != nil || n != len(b) {
		panic(err)
	}
	return g.HashToElement(b, nil)
}

func (g decaf448) RandomScalar(rd io.Reader) Scalar {
	b := make([]byte, fp.Size)
	if n, err := io.ReadFull(rd, b); err != nil || n != len(b) {
		panic(err)
	}
	return g.HashToScalar(b, nil)
}

func (g decaf448) RandomNonZeroScalar(rd io.Reader) Scalar {
	zero := g.NewScalar()
	for {
		s := g.RandomScalar(rd)
		if !s.IsEqual(zero) {
			return s
		}
	}
}

func (g decaf448) HashToElementNonUniform(data, dst []byte) Element {
	return g.HashToElement(data, dst)
}

func (g decaf448) HashToElement(data, dst []byte) Element {
	// Compliaint with draft-irtf-cfrg-hash-to-curve.
	// Appendix C - Hashing to decaf448
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-14#appendix-C
	// SuiteID: decaf448_XOF:SHAKE256_D448MAP_RO_
	var buf [2 * fp.Size]byte
	exp := expander.NewExpanderXOF(xof.SHAKE256, 224, dst)
	uniformBytes := exp.Expand(data, 2*fp.Size)
	copy(buf[:], uniformBytes)
	return g.oneway(&buf)
}

func (g decaf448) HashToScalar(data, dst []byte) Scalar {
	// Section 5.4 - Scalar field
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448-03#section-5.4
	exp := expander.NewExpanderXOF(xof.SHAKE256, 224, dst)
	uniformBytes := exp.Expand(data, 64)
	s := new(dScl)
	s.k.FromBytesLE(uniformBytes)
	return s
}

func (g decaf448) oneway(data *[2 * fp.Size]byte) *dElt {
	// Complaiant with draft-irtf-cfrg-ristretto255-decaf448-03
	// Section 5.3.4 - One-way Map
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448-03#section-5.3.4
	var buf [fp.Size]byte
	copy(buf[:], data[:fp.Size])
	p1 := g.mapFunc(&buf)
	copy(buf[:], data[fp.Size:2*fp.Size])
	p2 := g.mapFunc(&buf)
	p1.Add(&p2)
	return &dElt{p: p1}
}

func (g decaf448) mapFunc(data *[fp.Size]byte) (P curve.Point) {
	t := (*fp.Elt)(data)
	fp.Modp(t)

	one := fp.One()
	d := curve.ParamD()

	r, u0, u1, u2, v := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	tv, sgn, s := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	w0, w1, w2, w3 := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}

	fp.Square(r, t)                        // r = -t^2
	fp.Neg(r, r)                           //
	fp.Sub(u0, r, &one)                    // u0 = d * (r-1)
	fp.Mul(u0, u0, &d)                     //
	fp.Add(u1, u0, &one)                   // u1 = (u0 + 1) * (u0 - r)
	fp.Sub(u0, u0, r)                      //
	fp.Mul(u1, u1, u0)                     //
	fp.Add(u2, r, &one)                    // u2 = (r + 1) * u1
	fp.Mul(u2, u2, u1)                     //
	isQR := fp.InvSqrt(v, &aMinusTwoD, u2) // (isQR, v) = sqrt(ONE_MINUS_TWO_D / (r + 1) * u1)
	fp.Mul(tv, t, v)                       // v = CT_SELECT(v IF isQR ELSE t * v)
	fp.Cmov(v, tv, uint(1-isQR))           //
	fp.Neg(sgn, &one)                      //  sgn = CT_SELECT(1 IF isQR ELSE -1)
	fp.Cmov(sgn, &one, uint(isQR))         //
	fp.Add(s, r, &one)                     // s = v * (r + 1)
	fp.Mul(s, s, v)                        //
	ctAbs(w0, s)                           // w0 = 2 * CT_ABS(s)
	fp.Add(w0, w0, w0)                     //
	fp.Square(w1, s)                       // w1 = s^2 + 1
	fp.Sub(w2, w1, &one)                   // w2 = s^2 - 1
	fp.Add(w1, w1, &one)                   //
	fp.Sub(w3, r, &one)                    // w3 = v_prime * s * (r - 1) * ONE_MINUS_TWO_D + sgn
	fp.Mul(w3, w3, s)                      //
	fp.Mul(w3, w3, v)                      //
	fp.Mul(w3, w3, &aMinusTwoD)            //
	fp.Add(w3, w3, sgn)                    //
	fp.Mul(&P.X, w0, w3)                   // X = w0 * w3
	fp.Mul(&P.Y, w2, w1)                   // Y = w2 * w1
	fp.Mul(&P.Z, w1, w3)                   // Z = w1 * w3
	P.Ta, P.Tb = *w0, *w2                  // T = w0 * w2

	return P
}
