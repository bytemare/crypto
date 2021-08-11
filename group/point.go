// Package group exposes a prime-order elliptic curve groups with additional hash-to-curve operations.
package group

import (
	"github.com/bytemare/cryptotools/group/internal"
)

// Point represents a point on the curve of the prime-order group.
type Point struct {
	internal.Point
}

func newPoint(p internal.Point) *Point {
	return &Point{p}
}

// Add returns the sum of the Points, and does not change the receiver.
func (p *Point) Add(point *Point) *Point {
	return &Point{p.Point.Add(point.Point)}
}

// Sub returns the difference between the Points, and does not change the receiver.
func (p *Point) Sub(point *Point) *Point {
	return &Point{p.Point.Sub(point.Point)}
}

// Mult returns the scalar multiplication of the receiver point with the given scalar.
func (p *Point) Mult(scalar *Scalar) *Point {
	return &Point{p.Point.Mult(scalar.Scalar)}
}

// InvertMult returns the scalar multiplication of the receiver point with the inverse of the given scalar.
func (p *Point) InvertMult(scalar *Scalar) *Point {
	return &Point{p.Point.InvertMult(scalar.Scalar)}
}

// IsIdentity returns whether the point is the Group's identity point.
func (p *Point) IsIdentity() bool {
	return p.Point.IsIdentity()
}

// Copy returns a copy of the point.
func (p *Point) Copy() *Point {
	return &Point{p.Point.Copy()}
}

// Decode decodes the input an sets the current point to its value, and returns it.
func (p *Point) Decode(in []byte) (*Point, error) {
	q, err := p.Point.Decode(in)
	if err != nil {
		return nil, err
	}

	return &Point{q}, nil
}

// Bytes returns the compressed byte encoding of the point.
func (p *Point) Bytes() []byte {
	return p.Point.Bytes()
}
