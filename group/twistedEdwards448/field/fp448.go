// Package fp448 provides prime field arithmetic over GF(2^448-2^224-1).
package fp448

import (
	"crypto/subtle"
	"errors"
)

// Size in bytes of an element.
const Size = 56

// Elt is a prime field element.
type Elt [Size]byte

func (e Elt) String() string { return BytesLe2Hex(e[:]) }

// p is the prime modulus 2^448-2^224-1.
var p = Elt{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

// P returns the prime modulus 2^448-2^224-1.
func P() Elt { return p }

// ToBytes stores in b the little-endian byte representation of x.
func (e *Elt) ToBytes(b []byte, x *Elt) error {
	if len(b) != Size {
		return errors.New("wrong size")
	}
	Modp(x)
	copy(b, x[:])
	return nil
}

// IsEqual returns 1 if x is equal to y; otherwise 0.
func (e *Elt) IsEqual(x, y *Elt) int { Modp(x); Modp(y); return subtle.ConstantTimeCompare(x[:], y[:]) }

// IsZero returns 1 if x is equal to 0; otherwise 0.
func (e *Elt) IsZero(x *Elt) int { Modp(x); z := Elt{}; return subtle.ConstantTimeCompare(x[:], z[:]) }

// IsOne returns true if x is equal to 1; otherwise 0.
func (e *Elt) IsOne(x *Elt) int { Modp(x); o := Elt{1}; return subtle.ConstantTimeCompare(x[:], o[:]) }

// Parity returns the last bit of x.
func (e *Elt) Parity(x *Elt) int { Modp(x); return int(x[0] & 1) }

// SetOne assigns x=1.
func (e *Elt) SetOne(x *Elt) { *x = Elt{1} }

// One returns the 1 element.
func (e *Elt) One() (x Elt) { x = Elt{1}; return }

// Neg calculates z = -x.
func (e *Elt) Neg(z, x *Elt) { Sub(z, &p, x) }

// Modp ensures that z is between [0,p-1].
func (e *Elt) Modp(z *Elt) { Sub(z, z, &p) }

// InvSqrt calculates z = sqrt(x/y) iff x/y is a quadratic-residue. If so,
// isQR = 1; otherwise, isQR = 0, since x/y is a quadratic non-residue,
// and z = sqrt(-x/y).
func (e *Elt) InvSqrt(z, x, y *Elt) (isQR int) {
	// First note that x^(2(k+1)) = x^(p-1)/2 * x = legendre(x) * x
	// so that's x if x is a quadratic residue and -x otherwise.
	// Next, y^(6k+3) = y^(4k+2) * y^(2k+1) = y^(p-1) * y^((p-1)/2) = legendre(y).
	// So the z we compute satisfies z^2 y = x^(2(k+1)) y^(6k+3) = legendre(x)*legendre(y).
	// Thus if x and y are quadratic residues, then z is indeed sqrt(x/y).
	t0, t1 := &Elt{}, &Elt{}
	Mul(t0, x, y)         // x*y
	Square(t1, y)         // y^2
	Mul(t1, t0, t1)       // x*y^3
	powPminus3div4(z, t1) // (x*y^3)^k
	Mul(z, z, t0)         // z = x*y*(x*y^3)^k = x^(k+1) * y^(3k+1)

	// Check if x/y is a quadratic residue
	Square(t0, z)  // z^2
	Mul(t0, t0, y) // y*z^2
	Sub(t0, t0, x) // y*z^2-x
	return IsZero(t0)
}

// Inv calculates z = 1/x mod p.
func (e *Elt) Inv(z, x *Elt) {
	// Calculates z = x^(4k+1) = x^(p-3+1) = x^(p-2) = x^-1, where k = (p-3)/4.
	t := &Elt{}
	powPminus3div4(t, x) // t = x^k
	Square(t, t)         // t = x^2k
	Square(t, t)         // t = x^4k
	Mul(z, t, x)         // z = x^(4k+1)
}

// powPminus3div4 calculates z = x^k mod p, where k = (p-3)/4.
func powPminus3div4(z, x *Elt) {
	x0, x1 := &Elt{}, &Elt{}
	Square(z, x)
	Mul(z, z, x)
	Square(x0, z)
	Mul(x0, x0, x)
	Square(z, x0)
	Square(z, z)
	Square(z, z)
	Mul(z, z, x0)
	Square(x1, z)
	for i := 0; i < 5; i++ {
		Square(x1, x1)
	}
	Mul(x1, x1, z)
	Square(z, x1)
	for i := 0; i < 11; i++ {
		Square(z, z)
	}
	Mul(z, z, x1)
	Square(z, z)
	Square(z, z)
	Square(z, z)
	Mul(z, z, x0)
	Square(x1, z)
	for i := 0; i < 26; i++ {
		Square(x1, x1)
	}
	Mul(x1, x1, z)
	Square(z, x1)
	for i := 0; i < 53; i++ {
		Square(z, z)
	}
	Mul(z, z, x1)
	Square(z, z)
	Square(z, z)
	Square(z, z)
	Mul(z, z, x0)
	Square(x1, z)
	for i := 0; i < 110; i++ {
		Square(x1, x1)
	}
	Mul(x1, x1, z)
	Square(z, x1)
	Mul(z, z, x)
	for i := 0; i < 223; i++ {
		Square(z, z)
	}
	Mul(z, z, x1)
}

// Cmov assigns y to x if n is 1.
func (e *Elt) Cmov(x, y *Elt, n uint) { cmovGeneric(x, y, n) }

// Cswap interchanges x and y if n is 1.
func (e *Elt) Cswap(x, y *Elt, n uint) { cswapGeneric(x, y, n) }

// Add calculates z = x+y mod p.
func (e *Elt) Add(z, x, y *Elt) { addGeneric(z, x, y) }

// Sub calculates z = x-y mod p.
func (e *Elt) Sub(z, x, y *Elt) { subGeneric(z, x, y) }

// AddSub calculates (x,y) = (x+y mod p, x-y mod p).
func (e *Elt) AddSub(x, y *Elt) { addsubGeneric(x, y) }

// Mul calculates z = x*y mod p.
func (e *Elt) Mul(z, x, y *Elt) { mulGeneric(z, x, y) }

// Square calculates z = x^2 mod p.
func (e *Elt) Square(x *Elt) { sqrGeneric(z, x) }
