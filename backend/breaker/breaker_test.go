package breaker

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewBreakerDefaults(t *testing.T) {
	b := New(Options{Name: "test"})
	if b.State() != StateClosed {
		t.Fatalf("expected StateClosed, got %v", b.State())
	}
	if b.maxFailures != 5 {
		t.Fatalf("expected maxFailures 5, got %d", b.maxFailures)
	}
	if b.resetTimeout != 30*time.Second {
		t.Fatalf("expected resetTimeout 30s, got %v", b.resetTimeout)
	}
}

func TestExecuteSuccess(t *testing.T) {
	b := New(Options{Name: "test", MaxFailures: 3, ResetTimeout: time.Second})
	err := b.Execute(func() error { return nil })
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if b.State() != StateClosed {
		t.Fatalf("expected StateClosed after success, got %v", b.State())
	}
}

func TestExecuteFailuresOpenCircuit(t *testing.T) {
	b := New(Options{Name: "test", MaxFailures: 3, ResetTimeout: 5 * time.Second})
	expectedErr := errors.New("fail")

	for i := 0; i < 3; i++ {
		err := b.Execute(func() error { return expectedErr })
		if err != expectedErr {
			t.Fatalf("iter %d: expected %v, got %v", i, expectedErr, err)
		}
	}

	if b.State() != StateOpen {
		t.Fatalf("expected StateOpen after %d failures, got %v", 3, b.State())
	}

	err := b.Execute(func() error { return nil })
	if err != ErrCircuitOpen {
		t.Fatalf("expected ErrCircuitOpen, got %v", err)
	}
}

func TestHalfOpenSuccessCloses(t *testing.T) {
	b := New(Options{Name: "test", MaxFailures: 2, ResetTimeout: 50 * time.Millisecond})

	b.Execute(func() error { return errors.New("fail") })
	b.Execute(func() error { return errors.New("fail") })

	if b.State() != StateOpen {
		t.Fatalf("expected StateOpen, got %v", b.State())
	}

	time.Sleep(60 * time.Millisecond)

	err := b.Execute(func() error { return nil })
	if err != nil {
		t.Fatalf("expected nil in half-open, got %v", err)
	}
	if b.State() != StateClosed {
		t.Fatalf("expected StateClosed after half-open success, got %v", b.State())
	}
}

func TestHalfOpenFailureReopens(t *testing.T) {
	b := New(Options{Name: "test", MaxFailures: 2, ResetTimeout: 50 * time.Millisecond})

	b.Execute(func() error { return errors.New("fail") })
	b.Execute(func() error { return errors.New("fail") })

	time.Sleep(60 * time.Millisecond)

	b.Execute(func() error { return errors.New("still fail") })

	if b.State() != StateOpen {
		t.Fatalf("expected StateOpen after half-open failure, got %v", b.State())
	}
}

func TestOnStateChange(t *testing.T) {
	var transitions []string
	onChange := func(name string, from, to State) {
		transitions = append(transitions, from.String()+"->"+to.String())
	}

	b := New(Options{
		Name:          "test",
		MaxFailures:   2,
		ResetTimeout:  50 * time.Millisecond,
		OnStateChange: onChange,
	})

	b.Execute(func() error { return errors.New("fail") })
	b.Execute(func() error { return errors.New("fail") })

	if len(transitions) < 1 || transitions[len(transitions)-1] != "closed->open" {
		t.Fatalf("expected closed->open transition, got %v", transitions)
	}

	time.Sleep(60 * time.Millisecond)
	b.Execute(func() error { return nil })

	if len(transitions) < 2 || transitions[len(transitions)-1] != "half-open->closed" {
		t.Fatalf("expected half-open->closed transition, got %v", transitions)
	}
}

func TestReset(t *testing.T) {
	b := New(Options{Name: "test", MaxFailures: 2, ResetTimeout: time.Minute})

	b.Execute(func() error { return errors.New("fail") })
	b.Execute(func() error { return errors.New("fail") })

	if b.State() != StateOpen {
		t.Fatalf("expected StateOpen, got %v", b.State())
	}

	b.Reset()
	if b.State() != StateClosed {
		t.Fatalf("expected StateClosed after Reset, got %v", b.State())
	}

	err := b.Execute(func() error { return nil })
	if err != nil {
		t.Fatalf("expected nil after reset, got %v", err)
	}
}

func TestConcurrentAccess(t *testing.T) {
	b := New(Options{Name: "concurrent", MaxFailures: 10, ResetTimeout: time.Second})

	var ops int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := b.Execute(func() error {
				atomic.AddInt32(&ops, 1)
				return nil
			})
			if err != nil && err != ErrCircuitOpen {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	if b.State() != StateClosed {
		t.Fatalf("expected StateClosed, got %v", b.State())
	}
	if atomic.LoadInt32(&ops) != 20 {
		t.Fatalf("expected 20 ops, got %d", atomic.LoadInt32(&ops))
	}
}

func TestImmediateOpenWhenMaxReachedDuringCheck(t *testing.T) {
	var checkedState State
	b := New(Options{
		Name:        "test",
		MaxFailures: 2,
	})

	b.failures = 2
	atomic.StoreInt32(&b.state, int32(StateClosed))

	err := b.Execute(func() error { return nil })
	if err != ErrCircuitOpen {
		t.Fatalf("expected ErrCircuitOpen, got %v", err)
	}
	_ = checkedState
}
