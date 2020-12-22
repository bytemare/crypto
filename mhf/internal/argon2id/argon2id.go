// Package argon2id provides a PasswordHashingFunction implementation, based on Argon2id
// i.e. password hashing functions and parameters for use in asymmetric/augmented PAKEs
package argon2id

import (
	"golang.org/x/crypto/argon2"

	"github.com/bytemare/cryptotools/internal"
	"github.com/bytemare/cryptotools/utils"
)

const (
	time    = 1
	memory  = 64 * 1024
	threads = 4

	bufSize = 100

	uint32Max = (1 << 32) - 1
)

// Argon2id holds the parameters to the argon2id MHF.
type Argon2id struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	Keylen  int
}

var ErrKeyLen = internal.ParameterError("out of bounds key length, expected uint32")

// New returns an initialised Argon2id struct with default values.
func New(keylen int) *Argon2id {
	if keylen < 0 || keylen > uint32Max {
		panic(ErrKeyLen)
	}

	return &Argon2id{
		Time:    time,
		Memory:  memory,
		Threads: threads,
		Keylen:  keylen,
	}
}

// Hash runs the MHF over the input and internal parameters.
func (a *Argon2id) Hash(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, a.Time, a.Memory, a.Threads, uint32(a.Keylen))
}

// HashVar accepts variadic input as salt, appends it and forwards it to the Hash function.
func (a *Argon2id) HashVar(password []byte, salt ...[]byte) []byte {
	i := utils.Concatenate(bufSize, salt...)

	return a.Hash(password, i)
}
