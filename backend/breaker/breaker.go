package breaker

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

type State int32

const (
	StateClosed State = iota
	StateHalfOpen
	StateOpen
)

var (
	ErrCircuitOpen = errors.New("circuit breaker is open")
)

type Breaker struct {
	name          string
	maxFailures   int
	resetTimeout  time.Duration
	failures      int32
	lastFailure   atomic.Value
	state         int32
	mu            sync.Mutex
	onStateChange func(name string, from, to State)
}

type Options struct {
	Name          string
	MaxFailures   int
	ResetTimeout  time.Duration
	OnStateChange func(name string, from, to State)
}

func New(opts Options) *Breaker {
	if opts.MaxFailures <= 0 {
		opts.MaxFailures = 5
	}
	if opts.ResetTimeout <= 0 {
		opts.ResetTimeout = 30 * time.Second
	}
	b := &Breaker{
		name:         opts.Name,
		maxFailures:  opts.MaxFailures,
		resetTimeout: opts.ResetTimeout,
		onStateChange: opts.OnStateChange,
	}
	b.lastFailure.Store(time.Time{})
	return b
}

func (b *Breaker) State() State {
	return State(atomic.LoadInt32(&b.state))
}

func (b *Breaker) setState(s State) {
	old := b.State()
	atomic.StoreInt32(&b.state, int32(s))
	if b.onStateChange != nil && old != s {
		b.onStateChange(b.name, old, s)
	}
}

func (b *Breaker) Execute(fn func() error) error {
	if b.State() == StateOpen {
		lastFail := b.lastFailure.Load().(time.Time)
		if time.Since(lastFail) > b.resetTimeout {
			b.setState(StateHalfOpen)
		} else {
			return ErrCircuitOpen
		}
	}

	b.mu.Lock()
	currentFailures := atomic.LoadInt32(&b.failures)
	if currentFailures >= int32(b.maxFailures) && b.State() == StateClosed {
		b.setState(StateOpen)
		b.lastFailure.Store(time.Now())
		b.mu.Unlock()
		return ErrCircuitOpen
	}
	b.mu.Unlock()

	err := fn()

	if err != nil {
		atomic.AddInt32(&b.failures, 1)
		b.lastFailure.Store(time.Now())
		if atomic.LoadInt32(&b.failures) >= int32(b.maxFailures) {
			b.setState(StateOpen)
		}
	} else {
		if b.State() == StateHalfOpen {
			b.setState(StateClosed)
		}
		atomic.StoreInt32(&b.failures, 0)
	}

	return err
}

func (b *Breaker) Reset() {
	atomic.StoreInt32(&b.failures, 0)
	b.setState(StateClosed)
	b.lastFailure.Store(time.Time{})
}
