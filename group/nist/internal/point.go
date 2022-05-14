package internal

import (
	"crypto/elliptic"
	"errors"
	"math/big"
)

var errParamDecPoint = errors.New("could not decode point")

type Point struct {
	curve *Curve
	x     *big.Int
	y     *big.Int
}

func (p *Point) setIdentity() *Point {
	p.x = big.NewInt(0)
	p.y = big.NewInt(0)

	return p
}

func (p *Point) isEqual(q *Point) bool {
	return p.curve.field.IsEqual(q.curve.field) &&
		p.curve.field.AreEqual(p.x, q.x) &&
		p.curve.field.AreEqual(p.y, q.y)
}

func (p *Point) neg() *Point {
	if p.IsIdentity() {
		return p
	}

	return &Point{
		curve: p.curve,
		x:     p.x,
		y:     p.curve.field.neg(p.y),
	}
}

func (p *Point) isTwoTorsion() bool {
	return p.curve.field.IsZero(p.y)
}

// Set sets p to u, and returns p.
func (p *Point) Set(u *Point) *Point {
	p.x.Set(u.x)
	p.y.Set(u.y)

	return p
}

// Add sets p to u + v, and returns p.
func (p *Point) Add(u, v *Point) *Point {
	switch {
	case u.IsIdentity():
		return p.Set(v)
	case v.IsIdentity():
		return p.Set(u)
	case u.isEqual(v.neg()): // i.e. sum is 0
		return p.setIdentity()
	case u.isEqual(v):
		return p.double(u)
	}

	f := u.curve.field

	if f.AreEqual(u.x, v.x) {
		panic("wrong inputs")
	}

	var t0, t1, l *big.Int
	t0 = f.sub(v.y, u.y) // (y2-y1)
	t1 = f.sub(v.x, u.x) // (x2-x1)
	t1 = f.Inv(t1)       // 1/(x2-x1)
	l = f.Mul(t0, t1)    // l = (y2-y1)/(x2-x1)

	t0 = f.Square(l)    // l^2
	t0 = f.sub(t0, u.x) // l^2-x1
	x := f.sub(t0, v.x) // x' = l^2-x1-x2

	t0 = f.sub(u.x, x)  // x1-x3
	t0 = f.Mul(t0, l)   // l(x1-x3)
	y := f.sub(t0, u.y) // y3 = l(x1-x3)-y1

	p.x, p.y = x, y

	return p
}

// Sub sets p to u - v, and returns p.
func (p *Point) Sub(u, v *Point) *Point {
	return p.Add(u, v.neg())
}

// double sets p to 2 * u,  and returns p.
func (p *Point) double(u *Point) *Point {
	if u.IsIdentity() || u.isTwoTorsion() {
		return u
	}

	F := u.curve.field
	var t0, t1, ll *big.Int
	t0 = F.Square(u.x)                       // x^2
	t0 = F.Mul(t0, F.Element(big.NewInt(3))) // 3x^2
	t0 = F.add(t0, u.curve.a)                // 3x^2+A
	t1 = F.add(u.y, u.y)                     // 2y
	t1 = F.Inv(t1)                           // 1/2y
	ll = F.Mul(t0, t1)                       // l = (3x^2+2A)/(2y)

	t0 = F.Square(ll)   // l^2
	t0 = F.sub(t0, u.x) // l^2-x
	x := F.sub(t0, u.x) // x' = l^2-2x

	t0 = F.sub(u.x, x)  // x-x'
	t0 = F.Mul(t0, ll)  // l(x-x')
	y := F.sub(t0, u.y) // y3 = l(x-x')-y1

	p.x, p.y = x, y

	return p
}

// Mult sets p to scalar * point, and returns p.
func (p *Point) Mult(s *Scalar, point *Point) *Point {
	p.setIdentity()
	// double-and-Add
	for i := s.s.BitLen() - 1; i >= 0; i-- {
		p.double(p)
		if s.s.Bit(i) != 0 {
			p.Add(p, point)
		}
	}

	return p
}

func (p *Point) IsIdentity() bool {
	x := p.x == nil || p.x.Cmp(zero) == 0
	y := p.y == nil || p.y.Cmp(zero) == 0

	return x || y
}

func (p *Point) Copy() *Point {
	return &Point{
		curve: p.curve,
		x:     new(big.Int).Set(p.x),
		y:     new(big.Int).Set(p.y),
	}
}

func (p *Point) Decode(input []byte) (*Point, error) {
	x, y := elliptic.UnmarshalCompressed(p.curve.ell(), input)
	if x == nil {
		return nil, errParamDecPoint
	}

	p.x, p.y = x, y

	return p, nil
}

func pointLen(bitLen int) uint {
	byteLen := (bitLen + 7) / 8
	return uint(1 + byteLen)
}

func encodeSignPrefix(x, y *big.Int, pointLen uint) []byte {
	compressed := make([]byte, pointLen)
	compressed[0] = byte(y.Bit(0)) | 2
	x.FillBytes(compressed[1:])

	return compressed
}

func (p *Point) Bytes() []byte {
	return encodeSignPrefix(p.x, p.y, pointLen(p.curve.field.BitLen()))
}
