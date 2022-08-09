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

// Zero sets res to the Zero big.Int of the finite field.
func (f field) Zero(res *big.Int) *big.Int {
	return res.Set(zero)
}

// One sets res to the One big.Int of the finite field.
func (f field) One(res *big.Int) *big.Int {
	return res.Set(one)
}

// Random sets res to a random field big.Int.
func (f field) Random(res *big.Int) *big.Int {
	e, err := rand.Int(rand.Reader, f.prime)
	if err != nil {
		// We can as well not panic and try again in a loop
		panic(fmt.Errorf("unexpected error in generating random bytes : %w", err))
	}

	res.Set(e)

	return res
}

// Order returns the size of the field.
func (f field) Order() *big.Int {
	return f.prime
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
	return f.IsZero(f.sub(&big.Int{}, f1, f2))
}

// IsZero returns whether the big.Int is equivalent to Zero.
func (f field) IsZero(e *big.Int) bool {
	return e.Sign() == 0
}

// IsSquare returns whether the big.Int is a quadratic square.
func (f field) IsSquare(e *big.Int) bool {
	return f.AreEqual(f.Exp(&big.Int{}, e, f.pMinus1div2), f.One(&big.Int{}))
}

func (f field) IsEqual(f2 *field) bool {
	return f.prime.Cmp(f2.prime) == 0
}

func (f field) mod(x *big.Int) *big.Int {
	return x.Mod(x, f.prime)
}

func (f field) neg(res, x *big.Int) *big.Int {
	return f.mod(res.Neg(x))
}

func (f field) Add(res, x, y *big.Int) *big.Int {
	return f.mod(res.Add(x, y))
}

func (f field) sub(res, x, y *big.Int) *big.Int {
	return f.mod(res.Sub(x, y))
}

// Returns x*y.
func (f field) Mul(res, x, y *big.Int) *big.Int {
	return f.mod(res.Mul(x, y))
}

// Returns x^2.
func (f field) Square(res, x *big.Int) *big.Int {
	return f.mod(res.Mul(x, x))
}

// Returns 1/x.
func (f field) Inv(res, x *big.Int) *big.Int {
	return f.Exp(res, x, f.pMinus2)
}

// Returns x^n.
func (f field) Exp(res, x, n *big.Int) *big.Int {
	return res.Exp(x, n, f.prime)
}

func (f field) CMov(res, x, y *big.Int, b bool) *big.Int {
	if b {
		res.Set(y)
	} else {
		res.Set(x)
	}

	return res
}

func (f field) Sgn0(x *big.Int) int {
	return int(x.Bit(0))
}

func (f field) sqrt3mod4(res, e *big.Int) *big.Int {
	return f.Exp(res, e, f.exp)
}

func (f field) Sqrt(res, e *big.Int) *big.Int {
	return f.sqrt3mod4(res, e)
}
