// Package events carries in-process notifications between backend
// components. Publishers (alerts, scanners) never import the API layer, and
// the API layer forwards subscribed events to WebSocket clients. This keeps
// the dependency graph acyclic while making real-time push observable.
package events

import "sync"

// Canonical event type names. Clients switch on these values.
const (
	AlertCreated  = "alert.created"
	ScanCompleted = "scan.completed"
	ScanFailed    = "scan.failed"
	ScanSkipped   = "scan.skipped"
)

type Event struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type subscription struct {
	id uint64
	fn func(Event)
}

var (
	mu            sync.RWMutex
	nextID        uint64
	subscriptions []subscription
)

// Subscribe registers a listener. Listeners are called synchronously by
// Publish, so they must not block. The returned function removes the listener.
func Subscribe(fn func(Event)) func() {
	mu.Lock()
	defer mu.Unlock()
	nextID++
	id := nextID
	subscriptions = append(subscriptions, subscription{id: id, fn: fn})
	return func() {
		mu.Lock()
		defer mu.Unlock()
		for i, sub := range subscriptions {
			if sub.id == id {
				subscriptions = append(subscriptions[:i], subscriptions[i+1:]...)
				return
			}
		}
	}
}

// Publish delivers an event to every current subscriber. Subscribers are
// copied under the read lock so a listener can subscribe or unsubscribe
// without deadlocking.
func Publish(e Event) {
	mu.RLock()
	listeners := make([]func(Event), 0, len(subscriptions))
	for _, sub := range subscriptions {
		listeners = append(listeners, sub.fn)
	}
	mu.RUnlock()
	for _, fn := range listeners {
		fn(e)
	}
}
