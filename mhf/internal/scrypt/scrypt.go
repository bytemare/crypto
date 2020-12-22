// Package scrypt provides a PasswordHashingFunction implementation, based on scrypt
// i.e. password hashing functions and parameters for use in asymmetric/augmented PAKEs
package scrypt

import (
	"fmt"

	"golang.org/x/crypto/scrypt"

	"github.com/bytemare/cryptotools/utils"
)

const (
	n = 32768
	r = 8
	p = 1

	bufSize = 100

	// scrypt internals.
	// maxInt = int(^uint(0) >> 1).
)

// Scrypt holds the parameters to the scrypt MHF.
type Scrypt struct {
	N      int
	R      int
	P      int
	Keylen int
}

// func init() {
//	// Operate tests here in order to avoid errors on calling scrypt
//	if n <= 1 || n&(n-1) != 0 {
//		panic("scrypt: N must be > 1 and a power of 2")
//	}
//
//	if uint64(r)*uint64(p) >= 1<<30 || r > maxInt/128/p || r > maxInt/256 || n > maxInt/128/r {
//		panic("scrypt: parameters are too large")
//	}
// }

// New returns an initialised Scrypt struct with default values.
func New(keylen int) *Scrypt {
	s := &Scrypt{
		N:      n, // consider setting N to the highest power of 2 you can derive within 100 milliseconds
		R:      r,
		P:      p,
		Keylen: keylen,
	}

	return s
}

// Hash runs the MHF over the input and internal parameters.
func (s *Scrypt) Hash(password, salt []byte) []byte {
	k, err := scrypt.Key(password, salt, s.N, s.R, s.P, s.Keylen)
	if err != nil {
		panic(fmt.Errorf("unexpected error : %w", err))
	}

	return k
}

// HashVar accepts variadic input as salt, appends it and forwards it to the Hash function.
func (s *Scrypt) HashVar(password []byte, salt ...[]byte) []byte {
	i := utils.Concatenate(bufSize, salt...)

	return s.Hash(password, i)
}
