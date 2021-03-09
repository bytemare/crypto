package mhf

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	argon2ids      = "Argon2id"
	argon2idFormat = "%s(%d-%d-%d)"
)

var (
	defaultArgon2idTime    = 1
	defaultArgon2idMemory  = 64 * 1024
	defaultArgon2idThreads = 4
)

type argon2mhf struct {
	time, memory, threads int
}

func argon2idNew() memoryHardFunction {
	return &argon2mhf{
		time:    defaultArgon2idTime,
		memory:  defaultArgon2idMemory,
		threads: defaultArgon2idThreads,
	}
}

func (a *argon2mhf) Harden(password, salt []byte, length int) []byte {
	return argon2.IDKey(password, salt, uint32(a.time), uint32(a.memory), uint8(a.threads), uint32(length))
}

// Parameterize replaces the functions parameters with the new ones. Must match the amount of parameters.
func (a *argon2mhf) Parameterize(parameters ...int) {
	if len(parameters) != 3 {
		panic(errParams)
	}

	a.time = parameters[0]
	a.memory = parameters[1]
	a.threads = parameters[2]
}

func (a *argon2mhf) String() string {
	return fmt.Sprintf(argon2idFormat, argon2ids, a.time, a.memory, a.threads)
}

func (a *argon2mhf) params() []int {
	return []int{a.time, a.memory, a.threads}
}
