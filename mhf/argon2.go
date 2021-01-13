package mhf

import "golang.org/x/crypto/argon2"

const argon2ids = "Argon2id"

var (
	defaultArgon2idTime    = 1
	defaultArgon2idMemory  = 64 * 1024
	defaultArgon2idThreads = 4
)

func defaultArgon2id(password, salt []byte, length int) []byte {
	return argon2id(password, salt, defaultArgon2idTime, defaultArgon2idMemory, defaultArgon2idThreads, length)
}

func argon2id(password, salt []byte, time, memory, threads, length int) []byte {
	return argon2.IDKey(password, salt, uint32(time), uint32(memory), uint8(threads), uint32(length))
}

func argon2idParams() *Parameters {
	return &Parameters{
		ID:        Argon2id,
		Time:      defaultArgon2idTime,
		Memory:    defaultArgon2idMemory,
		Threads:   defaultArgon2idThreads,
		KeyLength: DefaultLength,
	}
}
