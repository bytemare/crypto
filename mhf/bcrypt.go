package mhf

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	bcryptFormat      = "%s(%d)"
	bcrypts           = "Bcrypt"
	defaultBcryptCost = 10
)

type bcryptmhf struct {
	time int
}

func bcryptNew() memoryHardFunction {
	return &bcryptmhf{
		time: defaultBcryptCost,
	}
}

func (b *bcryptmhf) Harden(password, _ []byte, _ int) []byte {
	h, err := bcrypt.GenerateFromPassword(password, b.time)
	if err != nil {
		panic(err)
	}

	return h
}

// Parameterize replaces the functions parameters with the new ones. Must match the amount of parameters.
func (b *bcryptmhf) Parameterize(parameters ...int) {
	if len(parameters) != 1 {
		panic(errParams)
	}

	b.time = parameters[0]
}

func (b *bcryptmhf) String() string {
	return fmt.Sprintf(bcryptFormat, bcrypts, b.time)
}

func (b *bcryptmhf) params() []int {
	return []int{b.time}
}
