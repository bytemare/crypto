package internal

import (
	"crypto/subtle"
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

type Element[Point NistECPoint[Point]] struct {
	p     Point
	group *Group[Point]
}

func (e *Element[Point]) Add(p, q *Element[Point]) *Element[Point] {
	e.p.Add(p.p, q.p)
	return e
}

func (e *Element[Point]) negate(p *Element[Point]) Point {
	b := p.Bytes() // get the compressed encoding of p. p[0] denotes the sign of y.
	switch b[0] {
	case 0x02:
		b[0] = 0x03
	case 0x03:
		b[0] = 0x02
	}
	n := e.group.curve.newPoint()
	if _, err := n.SetBytes(b); err != nil {
		panic(err)
	}

	return n
}

func (e *Element[Point]) Sub(p, q *Element[Point]) *Element[Point] {
	e.p = e.negate(q)
	e.p.Add(e.p, p.p)

	return e
}

func (e *Element[Point]) Mult(scalar *Scalar, element *Element[Point]) *Element[Point] {
	if _, err := e.p.ScalarMult(element.p, scalar.Bytes()); err != nil {
		panic(err)
	}

	return e
}

func (e *Element[Point]) InvertMult(scalar *Scalar) *Element[Point] {
	return e.Mult(e.group.NewScalar().Invert(scalar), e)
}

func (e *Element[Point]) IsIdentity() bool {
	b := e.p.BytesCompressed()
	i := e.group.curve.newPoint().BytesCompressed()
	return subtle.ConstantTimeCompare(b, i) == 1
}

func (e *Element[Point]) Copy() *Element[Point] {
	p, err := e.group.curve.newPoint().SetBytes(e.p.BytesCompressed())
	if err != nil {
		panic(err)
	}

	return &Element[Point]{
		p:     p,
		group: e.group,
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
