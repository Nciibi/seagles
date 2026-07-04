package breaker

import (
	"errors"
	"testing"
)

func BenchmarkExecute_Success(b *testing.B) {
	br := New(Options{Name: "bench", MaxFailures: 100})
	fn := func() error { return nil }

	for i := 0; i < b.N; i++ {
		br.Execute(fn)
	}
}

func BenchmarkExecute_Mixed(b *testing.B) {
	br := New(Options{Name: "bench", MaxFailures: 50})
	errFn := func() error { return errors.New("fail") }
	okFn := func() error { return nil }

	for i := 0; i < b.N; i++ {
		if i%3 == 0 {
			br.Execute(errFn)
		} else {
			br.Execute(okFn)
		}
	}
}
