// Package hash2curve wraps an hash-to-curve implementation and exposes functions for operations on points and scalars.
package hash2curve

import (
	nist "crypto/elliptic"
	"fmt"
	"math/big"

	Curve "github.com/armfazh/h2c-go-ref/curve"
	C "github.com/armfazh/tozan-ecc/curve"
	"github.com/armfazh/tozan-ecc/field"

	"github.com/bytemare/cryptotools/group"
)

// Point implements the Element interface for Hash-to-Curve points.
type Point struct {
	*Hash2Curve
	point C.Point
}

// Add adds the argument to the receiver, sets the receiver to the result and returns it.
func (p *Point) Add(element group.Element) group.Element {
	if element == nil {
		panic("element is nil")
	}

	po, ok := element.(*Point)
	if !ok {
		panic("could not cast to same group element : wrong group ?")
	}

	return &Point{
		Hash2Curve: p.Hash2Curve,
		point:      p.GetCurve().Add(p.point, po.point),
	}
}

// Sub subtracts the argument from the receiver, sets the receiver to the result and returns it.
func (p *Point) Sub(element group.Element) group.Element {
	if element == nil {
		panic("element is nil")
	}

	pt, ok := element.(*Point)
	if !ok {
		panic("could not cast to same group element : wrong group ?")
	}

	return &Point{
		Hash2Curve: p.Hash2Curve,
		point:      p.GetCurve().Add(p.point, p.GetCurve().Neg(pt.point)),
	}
}

// Mult returns the scalar multiplication of the receiver element with the given scalar.
func (p *Point) Mult(scalar group.Scalar) group.Element {
	sc, ok := scalar.(*Scalar)
	if !ok {
		panic("could not cast to hash2curve scalar")
	}

	if !p.GetHashToScalar().GetScalarField().IsEqual(sc.f) {
		panic("cannot multiply with scalar from a different field")
	}

	return &Point{
		Hash2Curve: p.Hash2Curve,
		point:      p.GetCurve().ScalarMult(p.point, sc.s.Polynomial()[0]),
	}
}

// InvertMult returns the scalar multiplication of the receiver element with the inverse of the given scalar.
func (p *Point) InvertMult(s group.Scalar) group.Element {
	if s == nil {
		panic(errParamNilScalar)
	}

	return p.Mult(s.Invert())
}

// IsIdentity returns whether the element is the Group's identity element.
func (p *Point) IsIdentity() bool {
	return p.point.IsIdentity()
}

// Copy returns a copy of the element.
func (p *Point) Copy() group.Element {
	return &Point{
		Hash2Curve: p.Hash2Curve,
		point:      p.point.Copy(),
	}
}

// Bytes returns the compressed byte encoding of the element.
func (p *Point) Bytes() []byte {
	x := p.point.X().Polynomial()[0]
	y := p.point.Y().Polynomial()[0]

	if p.id == Curve.Edwards25519 {
		return encodeEd25519(x, y)
	}

	return encodeSignPrefix(x, y, p.GetCurve().Field().BitLen())
}

// Decode decodes the input an sets the current element to its value, and returns it.
func (p *Point) Decode(input []byte) (e group.Element, err error) {
	if p.id == Curve.P256 || p.id == Curve.P384 || p.id == Curve.P521 {
		x, y := nist.UnmarshalCompressed(h2cToNist(p.id), input)
		if x == nil {
			return nil, errParamDecPoint
		}

		if err := p.set(x, y); err != nil {
			return nil, err
		}

		return p, nil
	}

	if p.id == Curve.Edwards25519 {
		x, y, err := decodeEd25519(input)
		if err != nil {
			return nil, err
		}

		if err := p.set(x, y); err != nil {
			return nil, err
		}

		return p, nil
	}

	// Extract x
	x, err := getX(p.GetCurve().Field(), input)
	if err != nil {
		return nil, err
	}

	// Compute y^2
	y := p.solver(x)
	y.ModSqrt(y, p.GetCurve().Field().Order())

	if y == nil {
		return nil, errParamYNotSquare
	}

	// Set the sign
	if byte(y.Bit(0)) != input[0]&1 {
		y.Neg(y).Mod(y, p.GetCurve().Field().Order())
	}

	// Verify the point is on curve
	if err := isOnCurve(x, y, p.GetCurve().Field().Order(), p.solver); err != nil {
		return nil, err
	}

	if err := p.set(x, y); err != nil {
		return nil, err
	}

	return p, nil
}

func (p *Point) set(x, y *big.Int) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()

	X := p.GetCurve().Field().Elt(x)
	Y := p.GetCurve().Field().Elt(y)

	p.point = p.GetCurve().NewPoint(X, Y)

	return err
}

func getX(f field.Field, input []byte) (*big.Int, error) {
	byteLen := (f.BitLen() + 7) / 8
	if len(input) != 1+byteLen {
		return nil, errParamInvalidSize
	}

	if input[0] != 2 && input[0] != 3 {
		return nil, errParamInvalidFormat
	}

	x := new(big.Int).SetBytes(input[1:])
	if x.Cmp(f.Order()) >= 0 {
		return nil, errParamDecXExceeds
	}

	return x, nil
}
