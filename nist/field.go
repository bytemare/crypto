package nist

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

type field struct {
	prime       *big.Int
	pMinus1div2 *big.Int // used in IsSquare
	pMinus2     *big.Int // used for field big.Int inversion
	exp         *big.Int
}

func NewField(prime *big.Int) *field {
	// pMinus1div2 is used to determine whether a big Int is a quadratic square.
	pMinus1div2 := big.NewInt(1)
	pMinus1div2.Sub(prime, pMinus1div2)
	pMinus1div2.Rsh(pMinus1div2, 1)

	// pMinus2 is used for modular inversion.
	pMinus2 := big.NewInt(2)
	pMinus2.Sub(prime, pMinus2)

	// precompute e = (p + 1) / 4
	exp := big.NewInt(1)
	exp.Add(prime, exp)
	exp.Rsh(exp, 2)

	return &field{
		prime:       prime,
		pMinus1div2: pMinus1div2,
		pMinus2:     pMinus2,
		exp:         exp,
	}
}

// Zero returns the Zero big.Int of the finite field.
func (f field) Zero() *big.Int {
	return new(big.Int).Set(zero)
}

// One returns the One big.Int of the finite field.
func (f field) One() *big.Int {
	return new(big.Int).Set(one)
}

// Element returns an big.Int of the field based on the input integer.
func (f field) Element(i *big.Int) *big.Int {
	return new(big.Int).Set(i)
}

// Random returns a random field big.Int.
func (f field) Random() *big.Int {
	e, err := rand.Int(rand.Reader, f.prime)
	if err != nil {
		// We can as well not panic and try again in a loop
		panic(fmt.Errorf("unexpected error in generating random bytes : %w", err))
	}

	return e
}

// Order returns the size of the field.
func (f field) Order() *big.Int {
	return new(big.Int).Set(f.prime)
}

func (f field) Ext() uint {
	return 1
}

// BitLen of prime Order.
func (f field) BitLen() int {
	return f.prime.BitLen()
}

// AreEqual returns whether both elements are equal.
func (f field) AreEqual(f1, f2 *big.Int) bool {
	return f.IsZero(f.sub(f1, f2))
}

// IsZero returns whether the big.Int is equivalent to Zero.
func (f field) IsZero(e *big.Int) bool {
	return e.Sign() == 0
}

// IsSquare returns whether the big.Int is a quadratic square.
func (f field) IsSquare(e *big.Int) bool {
	return f.AreEqual(f.Exp(e, f.pMinus1div2), f.One())
}

func (f field) IsEqual(f2 *field) bool {
	return f.prime.Cmp(f2.prime) == 0
}

func (f field) mod(x *big.Int) *big.Int {
	return x.Mod(x, f.prime)
}

func (f field) neg(x *big.Int) *big.Int {
	return f.mod(new(big.Int).Neg(x))
}

func (f field) Add(x, y *big.Int) *big.Int {
	return f.mod(new(big.Int).Add(x, y))
}

func (f field) sub(x, y *big.Int) *big.Int {
	return f.mod(new(big.Int).Sub(x, y))
}

// Returns x*y.
func (f field) Mul(x, y *big.Int) *big.Int {
	return f.mod(new(big.Int).Mul(x, y))
}

// Returns x^2.
func (f field) Square(x *big.Int) *big.Int {
	return f.mod(new(big.Int).Mul(x, x))
}

// Returns 1/x.
func (f field) Inv(x *big.Int) *big.Int {
	return f.Exp(x, f.pMinus2)
}

// Returns x^n.
func (f field) Exp(x, n *big.Int) *big.Int {
	return new(big.Int).Exp(x, n, f.prime)
}

func (f field) CMov(x, y *big.Int, b bool) *big.Int {
	z := new(big.Int)
	if b {
		z.Set(y)
	} else {
		z.Set(x)
	}

	return z
}

func (f field) Sgn0(x *big.Int) int {
	return int(x.Bit(0))
}

func sqrt3mod4(f *field, e *big.Int) *big.Int {
	return f.Exp(e, f.exp)
}

func (f field) Sqrt(e *big.Int) *big.Int {
	return sqrt3mod4(&f, e)
}
