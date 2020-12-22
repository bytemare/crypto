// Package mhf provides an interface to memory hard functions.
package mhf

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/mhf/internal/argon2id"
	"github.com/bytemare/cryptotools/mhf/internal/scrypt"
)

// Identifier is used to specify the memory hard function to be used.
type Identifier byte

const (
	// Argon2id password hash function.
	Argon2id Identifier = 1 + iota

	// Scrypt password hash function.
	Scrypt

	maxID

	argon2ids = "Argon2id"
	scrypts   = "Scrypt"

	// Default is set to Argon2id.
	Default = Argon2id

	// DefaultLength is the default output length in bytes.
	DefaultLength = 64
)

var registered = make([]newMHF, maxID)

// Get returns a newly instantiated PasswordKDF with keyLen output length.
func (i Identifier) Get(keyLen int) PasswordKDF {
	return registered[i](keyLen)
}

// Available reports whether the given hash function is linked into the binary.
func (i Identifier) Available() bool {
	return (i == Argon2id || i == Scrypt) && registered[i] != nil
}

// String returns the string name of the hashing function.
func (i Identifier) String() string {
	switch i {
	case Argon2id:
		return argon2ids

	case Scrypt:
		return scrypts

	default:
		panic("unknown identifier")
	}
}

func (i Identifier) register(n newMHF) {
	registered[i] = n
}

type newMHF func(keylen int) PasswordKDF

func init() {
	Argon2id.register(newArgon2id())
	Scrypt.register(newScrypt())
}

func newArgon2id() newMHF {
	return func(keylen int) PasswordKDF {
		return argon2id.New(keylen)
	}
}

func newScrypt() newMHF {
	return func(keylen int) PasswordKDF {
		return scrypt.New(keylen)
	}
}

// PasswordKDF defines the interface to access supported password hashing functions.
type PasswordKDF interface {

	// Hash operates the underlying memory hard function over the password using the salt.
	Hash(password, salt []byte) []byte

	// HashVar is a wrapper to Hash but allows variadic input for the salt that will be concatenated before hashing.
	HashVar(password []byte, salt ...[]byte) []byte
}

func (i Identifier) getStruct() PasswordKDF {
	switch i {
	case Argon2id:
		return &argon2id.Argon2id{}

	case Scrypt:
		return &scrypt.Scrypt{}

	default:
		panic("unknown identifier")
	}
}

// Decode attempts to reconstruct the encoded PasswordKDF and returns it.
func (i Identifier) Decode(encoded []byte, enc encoding.Encoding) (PasswordKDF, error) {
	s := i.getStruct()

	a, err := enc.Decode(encoded, s)
	if err != nil {
		return nil, err
	}

	return a.(PasswordKDF), nil
}
