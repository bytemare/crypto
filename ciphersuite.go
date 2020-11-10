package cryptotools

import (
	"fmt"

	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/hashtogroup"
	"github.com/bytemare/cryptotools/hashtogroup/group"
	"github.com/bytemare/cryptotools/ihf"
	"github.com/bytemare/cryptotools/internal"
)

const (
	defGroup  = hashtogroup.Default
	defHash   = hash.Default
	defIHF    = ihf.Default
	defIHFLen = ihf.DefaultLength
)

var (
	errInvalidGroupID = internal.ParameterError("invalid HashToGroup identifier")
	errInvalidHashID  = internal.ParameterError("invalid Hash identifier")
	errInvalidIHFID   = internal.ParameterError("invalid IHF identifier")
	errShortDST       = internal.ParameterError("DST is too short (nil or zero-length)")
)

// Ciphersuite joins cryptographic hash functions and acts as an abstraction layer to these underlying functions.
type Ciphersuite struct {
	Parameters *Parameters

	group.Group
	*hash.Hash
	IHF ihf.PasswordKDF
}

// Parameters identifies the components of a Ciphersuite.
type Parameters struct {
	Group  hashtogroup.Ciphersuite `json:"group"`
	Hash   hash.Identifier         `json:"hash"`
	IHF    ihf.Identifier          `json:"ihf"`
	IHFLen byte                    `json:"len"`
}

// CiphersuiteEncoding is the 4-byte representation of a ciphersuite.
type CiphersuiteEncoding = [4]byte

// String implements the Stringer() interface. It joins string representations of the parameters if available,
// and returns the resulting string.
func (p *Parameters) String() string {
	return fmt.Sprintf("%s-%s-%s-%v", p.Group, p.Hash, p.IHF, p.IHFLen)
}

// Encode returns the 4-byte representation of the ciphersuite parameters.
func (p *Parameters) Encode() CiphersuiteEncoding {
	return CiphersuiteEncoding{
		byte(p.Group),
		byte(p.Hash),
		byte(p.IHF),
		p.IHFLen,
	}
}

// New returns a new Ciphersuite with initialised components.
// The input parameter csp can be nil, and strong default ciphersuite
// components will be used. The structure can be only partially
// filled with desired components, and unset values will be set to strong defaults.
func New(csp *Parameters, dst []byte) (*Ciphersuite, error) {
	if len(dst) <= group.DstMinLength {
		return nil, errShortDST
	}

	csp, err := patchCipherSuite(csp)
	if err != nil {
		return nil, err
	}

	return &Ciphersuite{
		Parameters: csp,
		Group:      csp.Group.Get(dst),
		IHF:        csp.IHF.Get(int(csp.IHFLen)),
		Hash:       csp.Hash.Get(),
	}, nil
}

func checkValues(g hashtogroup.Ciphersuite, h hash.Identifier, i ihf.Identifier) error {
	if !g.Available() {
		return errInvalidGroupID
	}

	if !h.Available() {
		return errInvalidHashID
	}

	if !i.Available() {
		return errInvalidIHFID
	}

	return nil
}

// ReadCiphersuite interprets a ciphersuite encoding.
func ReadCiphersuite(suite CiphersuiteEncoding) (*Parameters, error) {
	if err := checkValues(
		hashtogroup.Ciphersuite(suite[0]),
		hash.Identifier(suite[1]),
		ihf.Identifier(suite[2])); err != nil {
		return nil, err
	}

	return &Parameters{
		Group:  hashtogroup.Ciphersuite(suite[0]),
		Hash:   hash.Identifier(suite[1]),
		IHF:    ihf.Identifier(suite[2]),
		IHFLen: suite[3],
	}, nil
}

func patchCipherSuite(p *Parameters) (*Parameters, error) {
	if p == nil {
		return &Parameters{
			Group:  defGroup,
			Hash:   defHash,
			IHF:    defIHF,
			IHFLen: defIHFLen,
		}, nil
	}

	// todo: somehow fail if some values are set but not others (i.e.e all 0 or not)

	if p.Group == 0 {
		p.Group = defGroup
	}

	if p.Hash == 0 {
		p.Hash = defHash
	}

	if p.IHF == 0 {
		p.IHF = defIHF
	}

	if p.IHFLen == 0 {
		p.IHFLen = defIHFLen
	}

	if err := checkValues(p.Group, p.Hash, p.IHF); err != nil {
		return nil, err
	}

	return p, nil
}
