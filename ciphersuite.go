package cryptotools

import (
	"fmt"

	"github.com/bytemare/cryptotools/group/ciphersuite"

	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/internal"
	"github.com/bytemare/cryptotools/mhf"
)

const (
	defGroup  = ciphersuite.Default
	defHash   = hash.Default
	defMHF    = mhf.Default
)

var (
	errInvalidGroupID = internal.ParameterError("invalid HashToGroup identifier")
	errInvalidHashID  = internal.ParameterError("invalid Hash identifier")
	errInvalidMHFID   = internal.ParameterError("invalid MHF identifier")
	errShortDST       = internal.ParameterError("DST is too short (nil or zero-length)")
)

// Ciphersuite joins cryptographic hash functions and acts as an abstraction layer to these underlying functions.
type Ciphersuite struct {
	Parameters *Parameters

	group.Group
	*hash.Hash
	mhf.MHF
}

// Parameters identifies the components of a Ciphersuite.
type Parameters struct {
	Group  ciphersuite.Identifier `json:"group"`
	Hash   hash.Identifier        `json:"hash"`
	MHF    mhf.MHF                `json:"mhf"`
}

// CiphersuiteEncoding is the 3-byte representation of a ciphersuite.
type CiphersuiteEncoding = [3]byte

// String implements the Stringer() interface. It joins string representations of the parameters if available,
// and returns the resulting string.
func (p *Parameters) String() string {
	return fmt.Sprintf("%s-%s-%s", p.Group, p.Hash, p.MHF)
}

// Encode returns the 4-byte representation of the ciphersuite parameters.
func (p *Parameters) Encode() CiphersuiteEncoding {
	return CiphersuiteEncoding{
		byte(p.Group),
		byte(p.Hash),
		byte(p.MHF),
	}
}

// New returns a new Ciphersuite with initialised components.
// The input parameter csp can be nil, and strong default ciphersuite
// components will be used. The structure can be only partially
// filled with desired components, and unset values will be set to strong defaults.
func New(csp *Parameters, dst []byte) (*Ciphersuite, error) {
	if len(dst) <= group.DstRecommendedMinLength {
		return nil, errShortDST
	}

	csp, err := patchCipherSuite(csp)
	if err != nil {
		return nil, err
	}

	return &Ciphersuite{
		Parameters: csp,
		Group:      csp.Group.Get(dst),
		MHF:        csp.MHF,
		Hash:       csp.Hash.Get(),
	}, nil
}

func checkValues(g ciphersuite.Identifier, h hash.Identifier, i mhf.MHF) error {
	if !g.Available() {
		return errInvalidGroupID
	}

	if !h.Available() {
		return errInvalidHashID
	}

	if !i.Available() {
		return errInvalidMHFID
	}

	return nil
}

// ReadCiphersuite interprets a ciphersuite encoding.
func ReadCiphersuite(suite CiphersuiteEncoding) (*Parameters, error) {
	if err := checkValues(
		ciphersuite.Identifier(suite[0]),
		hash.Identifier(suite[1]),
		mhf.MHF(suite[2])); err != nil {
		return nil, err
	}

	return &Parameters{
		Group:  ciphersuite.Identifier(suite[0]),
		Hash:   hash.Identifier(suite[1]),
		MHF:    mhf.MHF(suite[2]),
	}, nil
}

func patchCipherSuite(p *Parameters) (*Parameters, error) {
	if p == nil {
		return &Parameters{
			Group:  defGroup,
			Hash:   defHash,
			MHF:    defMHF,
		}, nil
	}

	// todo: somehow fail if some values are set but not others (i.e. all 0 or not)

	if p.Group == 0 {
		p.Group = defGroup
	}

	if p.Hash == 0 {
		p.Hash = defHash
	}

	if p.MHF == 0 {
		p.MHF = defMHF
	}

	if err := checkValues(p.Group, p.Hash, p.MHF); err != nil {
		return nil, err
	}

	return p, nil
}
