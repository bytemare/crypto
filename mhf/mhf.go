// Package mhf provides an interface to memory hard functions, a.k.a password key derivation functions.
package mhf

import (
	"errors"

	"github.com/bytemare/cryptotools/encoding"
)

var errAssertMHF = errors.New("could not assert to MHF")

// MemoryHardFunction present MHF for other definitions outside this package.
type MemoryHardFunction interface {
	// Available reports whether the given kdf function is linked into the binary.
	Available() bool

	// Harden uses default parameters for the key derivation function over the input password and salt.
	Harden(password, salt []byte, length int) []byte

	// HardenParam wraps and calls the key derivation function
	HardenParam(password, salt []byte, time, memory, threads, length int) []byte

	// DefaultParameters returns a pointer to a MHF struct containing
	// the standard recommended default parameters for the kdf.
	DefaultParameters() *Parameters

	// String returns the string name of the hashing function.
	String() string
}

// MHF is used to specify the memory hard function to be used.
type MHF byte

const (
	// Argon2id password kdf function.
	Argon2id MHF = 1 + iota

	// Scrypt password kdf function.
	Scrypt

	// PBKDF2Sha512 PBKDF2 password kdf function using SHA-512.
	PBKDF2Sha512

	// Bcrypt password kdf function.
	Bcrypt

	maxID

	// Default is set to Argon2id.
	Default = Argon2id

	// DefaultLength is the default output length in bytes.
	DefaultLength = 64
)

var (
	names                [maxID - 1]string
	params               [maxID - 1]parameters
	functions            [maxID - 1]kdf
	defaultHashFunctions [maxID - 1]defaultHash
)

type (
	kdf         func(password, salt []byte, time, memory, threads, length int) []byte
	parameters  func() *Parameters
	defaultHash func(password, salt []byte, length int) []byte
)

// Available reports whether the given kdf function is linked into the binary.
func (i MHF) Available() bool {
	return i > 0 && i < maxID
}

// Harden uses default parameters for the key derivation function over the input password and salt.
func (i MHF) Harden(password, salt []byte, length int) []byte {
	return defaultHashFunctions[i-1](password, salt, length)
}

// HardenParam wraps and calls the key derivation function
func (i MHF) HardenParam(password, salt []byte, time, memory, threads, length int) []byte {
	return functions[i-1](password, salt, time, memory, threads, length)
}

// DefaultParameters returns a pointer to a MHF struct containing
// the standard recommended default parameters for the kdf.
func (i MHF) DefaultParameters() *Parameters {
	return params[i-1]()
}

// String returns the string name of the hashing function.
func (i MHF) String() string {
	return names[i-1]
}

func (i MHF) register(def defaultHash, k kdf, p parameters, name string) {
	defaultHashFunctions[i-1] = def
	functions[i-1] = k
	params[i-1] = p
	names[i-1] = name
}

func init() {
	Argon2id.register(defaultArgon2id, argon2id, argon2idParams, argon2ids)
	Scrypt.register(defaultScrypt, scryptf, scryptParams, scrypts)
	PBKDF2Sha512.register(defaultPBKDF2, pbkdf, pbkdfParams, pbkdf2s)
	Bcrypt.register(defaultBcrypt, bcryptf, bcryptParams, bcrypts)
}

// Parameters represents a memory-hard functions and its parameters.
type Parameters struct {
	ID        MHF `json:"i"`
	Time      int `json:"n"`
	Memory    int `json:"r"`
	Threads   int `json:"p"`
	KeyLength int `json:"l"`
}

// Hash calls the underlying memory hard function with the internally stored parameters on the given arguments.
func (p *Parameters) Hash(password, salt []byte) []byte {
	return p.ID.HardenParam(password, salt, p.Time, p.Memory, p.Threads, p.KeyLength)
}

// Encode encodes m to the given encoding, allowing for storage of the parameters.
func (p *Parameters) Encode(enc encoding.Encoding) ([]byte, error) {
	return enc.Encode(p)
}

// String implements the Stringer() interface. It joins string representations of the parameters if available,
// and returns the resulting string.
func (p *Parameters) String() string {
	switch p.ID {
	case Argon2id:
		return argon2idString(p)
	case Scrypt:
		return scryptString(p)
	case PBKDF2Sha512:
		return pbkdfString(p)
	case Bcrypt:
		return bcryptString(p)
	default:
		return ""
	}
}

// Decode attempts to reconstruct the encoded MHF and its parameters.
func Decode(encoded []byte, enc encoding.Encoding) (*Parameters, error) {
	d, err := enc.Decode(encoded, &Parameters{})
	if err != nil {
		return nil, err
	}

	m, ok := d.(*Parameters)
	if !ok {
		return nil, errAssertMHF
	}

	return m, nil
}
