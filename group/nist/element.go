package nist

import (
	"crypto/subtle"
	"filippo.io/nistec"
)

type NistECPoint[Point any] interface {
	Add(p1, p2 Point) Point
	BytesCompressed() []byte
	Double(p Point) Point
	ScalarBaseMult(scalar []byte) (Point, error)
	ScalarMult(p Point, scalar []byte) (Point, error)
	Select(p1, p2 Point, cond int) Point
	Set(p Point) Point
	SetBytes(b []byte) (Point, error)
	SetGenerator() Point
}

func NewP256Point() *Element[*nistec.P256Point] {
	return &Element[*nistec.P256Point]{p: nistec.NewP256Point(), new: nistec.NewP256Point}
}

func NewP384Point() *Element[*nistec.P384Point] {
	return &Element[*nistec.P384Point]{p: nistec.NewP384Point(), new: nistec.NewP384Point}
}

func NewP521Point() *Element[*nistec.P521Point] {
	return &Element[*nistec.P521Point]{p: nistec.NewP521Point(), new: nistec.NewP521Point}
}

type Element[Point NistECPoint[Point]] struct {
	p   Point
	new func() Point
}

func (e *Element[Point]) Add(element *Element[Point]) *Element[Point] {
	e.p.Add(e.p, element.p)
	return e
}

func (e *Element[Point]) Sub(_ *Element[Point]) *Element[Point] {
	panic("subtraction for NIST elements not implemented")
}

func (e *Element[Point]) Mult(scalar Scalar) *Element[Point] {
	if _, err := e.p.ScalarMult(e.p, scalar.Bytes()); err != nil {
		panic(err)
	}

	return e
}

func (e *Element[Point]) InvertMult(scalar Scalar) *Element[Point] {
	return e.Mult(scalar.Invert())
}

func (e *Element[Point]) IsIdentity() bool {
	b := e.p.BytesCompressed()
	i := e.new().BytesCompressed()
	return subtle.ConstantTimeCompare(b, i) == 1
}

func (e *Element[Point]) Copy() *Element[Point] {
	p, err := e.new().SetBytes(e.p.BytesCompressed())
	if err != nil {
		panic(err)
	}

	return &Element[Point]{
		p:   p,
		new: e.new,
	}
}

func (e *Element[Point]) Decode(in []byte) (*Element[Point], error) {
	if _, err := e.p.SetBytes(in); err != nil {
		return nil, err
	}

	return e, nil
}

func (e *Element[Point]) Bytes() []byte {
	return e.p.BytesCompressed()
}
