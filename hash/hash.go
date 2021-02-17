package hash

var (
	// output size in bytes.
	size256 = 32
	size512 = 64

	// security level in bits.
	sec128 = 128
	sec256 = 256
)

// parameters serves internal parameterization of the hash functions.
type parameters struct {
	blockSize  int
	outputSize int
	security   int
	id         Identifier
	name       string
}

// Identifier exposes general information about hashing functions.
type Identifier interface {
	Available() bool
	BlockSize() int
	Extensible() bool
	Hash(input ...[]byte) []byte
	SecurityLevel() int
	String() string
}
