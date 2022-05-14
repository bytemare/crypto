package group

import (
	"bytes"
	"testing"
)

func benchAll(t *testing.B, f func(*testing.B, *group)) {
	for _, group := range testGroups() {
		t.Run(group.name, func(t *testing.B) {
			f(t, group)
		})
	}
}

func BenchmarkHashToGroup(b *testing.B) {
	msg := make([]byte, 256)
	dst := make([]byte, 10)
	benchAll(b, func(b *testing.B, group *group) {
		b.SetBytes(int64(len(msg)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			group.id.HashToGroup(msg, dst)
		}
	})
}

func BenchmarkScalarBaseMult(b *testing.B) {
	benchAll(b, func(b *testing.B, group *group) {
		priv := group.id.NewScalar().Random()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = group.id.Base().Mult(priv)
			// to do : Prevent the compiler from optimizing out the operation.
		}
	})
}

func BenchmarkScalarMult(b *testing.B) {
	benchAll(b, func(b *testing.B, group *group) {
		priv := group.id.NewScalar().Random()
		pub := group.id.Base().Mult(group.id.NewScalar().Random())
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			pub = pub.Mult(priv)
		}
	})
}

func BenchmarkMarshalUnmarshal(b *testing.B) {
	benchAll(b, func(b *testing.B, group *group) {
		pub := group.id.Base().Mult(group.id.NewScalar().Random())
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := pub.Bytes()
			pk, err := group.id.NewElement().Decode(buf)
			if err != nil {
				b.Fatal(err)
			}
			if !bytes.Equal(buf, pk.Bytes()) {
				b.Error("Unmarshal output different from Marshal input")
			}
		}
	})
}
