package events

import "testing"

func TestPublishDeliversToSubscribers(t *testing.T) {
	var got []string
	unsub := Subscribe(func(e Event) { got = append(got, e.Type) })
	defer unsub()

	Publish(Event{Type: AlertCreated})
	Publish(Event{Type: ScanCompleted})

	if len(got) != 2 || got[0] != AlertCreated || got[1] != ScanCompleted {
		t.Fatalf("unexpected events: %v", got)
	}
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	calls := 0
	unsub := Subscribe(func(Event) { calls++ })
	unsub()
	Publish(Event{Type: AlertCreated})
	if calls != 0 {
		t.Fatalf("unsubscribed listener was called %d times", calls)
	}
}

func TestSubscriberCanSubscribeDuringPublish(t *testing.T) {
	var nestedCalled bool
	unsubOuter := Subscribe(func(Event) {
		if !nestedCalled {
			Subscribe(func(Event) { nestedCalled = true })
		}
	})
	defer unsubOuter()

	Publish(Event{Type: AlertCreated}) // must not deadlock
	Publish(Event{Type: AlertCreated}) // listener added during the first publish now runs
	if !nestedCalled {
		t.Fatal("nested subscriber was never called")
	}
}
