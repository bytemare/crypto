// Package mhf provides an interface to memory hard functions, a.k.a password key derivation functions.
package mhf

import "errors"

var errParams = errors.New("invalid amount of parameters")

// Identifier is used to specify the memory hard function to be used.
type Identifier byte

const (
	// Argon2id password kdf function.
	Argon2id Identifier = 1 + iota

	// Scrypt password kdf function.
	Scrypt

	// PBKDF2Sha512 PBKDF2 password kdf function using SHA-512.
	PBKDF2Sha512

	// Bcrypt password kdf function.
	Bcrypt

	maxID
)

// Available reports whether the given kdf function is linked into the binary.
func (i Identifier) Available() bool {
	return i > 0 && i < maxID
}

// Get returns an MHF with default parameters.
func (i Identifier) Get() *MHF {
	if i == 0 || i >= maxID {
		return nil
	}

	return &MHF{constructors[i-1]()}
}

// Harden uses default parameters for the key derivation function over the input password and salt.
func (i Identifier) Harden(password, salt []byte, length int) []byte {
	return i.Get().Harden(password, salt, length)
}

// String returns the string name of the hashing function.
func (i Identifier) String() string {
	return i.Get().String()
}

type constructor func() memoryHardFunction

var constructors [maxID - 1]constructor

func (i Identifier) register(c constructor) {
	constructors[i-1] = c
}

func init() {
	Argon2id.register(argon2idNew)
	Scrypt.register(scryptmhfNew)
	PBKDF2Sha512.register(pbkdf2New)
	Bcrypt.register(bcryptNew)
}

type memoryHardFunction interface {
	// Harden uses default parameters for the key derivation function over the input password and salt.
	Harden(password, salt []byte, length int) []byte

	// Parameterize replaces the functions parameters with the new ones. Must match the amount of parameters.
	Parameterize(parameters ...int)

	// Returns the string name of the function and its parameters
	String() string

	params() []int
}

// MHF allows customisation of the underlying memory-hard function.
type MHF struct {
	memoryHardFunction
}

// Set sets m's memory-hard function to the specified one and returns m. Returns nil if the identifier is invalid.
func (m *MHF) Set(i Identifier) *MHF {
	if i == 0 || i >= maxID {
		return nil
	}

	m.memoryHardFunction = constructors[i-1]()

	return m
}
