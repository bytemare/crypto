package mhf

import (
	"fmt"

	"golang.org/x/crypto/scrypt"
)

const (
	scrypts      = "Scrypt"
	scryptFormat = "%s(%d-%d-%d)"
)

var (
	defaultScryptn = 32768
	defaultScryptr = 8
	defaultScryptp = 1
)

type scryptmhf struct {
	n, r, p int
}

func scryptmhfNew() memoryHardFunction {
	return &scryptmhf{
		n: defaultScryptn,
		r: defaultScryptr,
		p: defaultScryptp,
	}
}

func (s *scryptmhf) Harden(password, salt []byte, length int) []byte {
	k, err := scrypt.Key(password, salt, s.n, s.r, s.p, length)
	if err != nil {
		panic(fmt.Errorf("unexpected error : %w", err))
	}

	return k
}

// Parameterize replaces the functions parameters with the new ones. Must match the amount of parameters.
func (s *scryptmhf) Parameterize(parameters ...int) {
	if len(parameters) != 3 {
		panic(errParams)
	}

	s.n = parameters[0]
	s.r = parameters[1]
	s.p = parameters[2]
}

func (s *scryptmhf) String() string {
	return fmt.Sprintf(scryptFormat, scrypts, s.n, s.r, s.p)
}

func (s *scryptmhf) params() []int {
	return []int{s.n, s.r, s.p}
}
