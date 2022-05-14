package twistedEdwards448

import (
	"filippo.io/edwards25519"
	field "github.com/bytemare/crypto/group/twistedEdwards448/field"
)

func fe() *field.Elt {
	return &field.Elt{}
}

// MapToEdwards maps the field element to a point on Edwards25519.
func MapToEdwards(e *field.Elt) *edwards25519.Point {
	u, v := Elligator2Montgomery(e)
	x, y := MontgomeryToEdwards(u, v)

	return AffineToEdwards(x, y)
}

// Elligator2Montgomery implements the Elligator2 mapping to Curve25519.
func Elligator2Montgomery(e *field.Elt) (x, y *field.Elt) {
	t1 := fe().Square(e)   // u^2
	t1.Multiply(t1, two)   // t1 = 2u^2
	e1 := t1.Equal(minOne) //
	t1.Swap(zero, e1)      // if 2u^2 == -1, t1 = 0

	x1 := fe().Add(t1, one) // t1 + 1
	x1.Invert(x1)           // 1 / (t1 + 1)
	x1.Multiply(x1, minA)   // x1 = -A / (t1 + 1)

	gx1 := fe().Add(x1, a) // x1 + A
	gx1.Multiply(gx1, x1)  // x1 * (x1 + A)
	gx1.Add(gx1, one)      // x1 * (x1 + A) + 1
	gx1.Multiply(gx1, x1)  // x1 * (x1 * (x1 + A) + 1)

	x2 := fe().Negate(x1) // -x1
	x2.Subtract(x2, a)    // -x2 - A

	gx2 := fe().Multiply(t1, gx1) // t1 * gx1

	root1, _isSquare := fe().SqrtRatio(gx1, one) // root1 = (+) sqrt(gx1)
	negRoot1 := fe().Negate(root1)               // negRoot1 = (-) sqrt(gx1)
	root2, _ := fe().SqrtRatio(gx2, one)         // root2 = (+) sqrt(gx2)

	// if gx1 is square, set the point to (x1, -root1)
	// if not, set the point to (x2, +root2)
	if _isSquare == 1 {
		x = x1
		y = negRoot1 // set sgn0(y) == 1, i.e. negative
	} else {
		x = x2
		y = root2 // set sgn0(y) == 0, i.e. positive
	}

	return x, y
}

// AffineToEdwards takes the affine coordinates of an Edwards25519 and returns a pointer to Point represented in
// extended projective coordinates.
func AffineToEdwards(x, y *field.Elt) *edwards25519.Point {
	t := fe().Multiply(x, y)

	p, err := new(edwards25519.Point).SetExtendedCoordinates(x, y, fe().One(), t)
	if err != nil {
		panic(err)
	}

	return p
}

// MontgomeryToEdwards lifts a Curve25519 point to its Edwards25519 equivalent.
func MontgomeryToEdwards(u, v *field.Elt) (x, y *field.Elt) {
	x = fe().Invert(v)
	x.Multiply(x, u)
	x.Multiply(x, invsqrtD)

	y = MontgomeryUToEdwardsY(u)

	return
}

// MontgomeryUToEdwardsY transforms a Curve25519 x (or u) coordinate to an Edwards25519 y coordinate.
func MontgomeryUToEdwardsY(u *field.Elt) *field.Elt {
	u1 := fe().Subtract(u, one)
	u2 := fe().Add(u, one)

	return u1.Multiply(u1, u2.Invert(u2))
}
