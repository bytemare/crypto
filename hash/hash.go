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
	id         identifier
	name       string
}

type identifier interface {
	Available() bool
	BlockSize() int
	SecurityLevel() int
	String() string
}
