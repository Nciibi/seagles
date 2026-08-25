package cache

import (
	"testing"
	"time"
)

func TestNewCache(t *testing.T) {
	c := New(time.Minute)
	if c == nil {
		t.Fatal("expected non-nil cache")
	}
	if c.Count() != 0 {
		t.Fatalf("expected empty cache, got %d items", c.Count())
	}
}

func TestSetAndGet(t *testing.T) {
	c := New(5 * time.Minute)
	c.Set("key1", "value1")

	var result string
	err := c.Get("key1", &result)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result != "value1" {
		t.Fatalf("expected 'value1', got '%s'", result)
	}
}

func TestGetNotFound(t *testing.T) {
	c := New(time.Minute)
	var result string
	err := c.Get("nonexistent", &result)
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGetExpired(t *testing.T) {
	c := New(50 * time.Millisecond)
	c.Set("key", "value")

	time.Sleep(60 * time.Millisecond)

	var result string
	err := c.Get("key", &result)
	if err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestSetTTL(t *testing.T) {
	c := New(5 * time.Minute)
	c.SetTTL("key", "value", 50*time.Millisecond)

	var result string
	err := c.Get("key", &result)
	if err != nil {
		t.Fatalf("expected nil before TTL expiry, got %v", err)
	}

	time.Sleep(60 * time.Millisecond)

	err = c.Get("key", &result)
	if err != ErrExpired {
		t.Fatalf("expected ErrExpired after custom TTL, got %v", err)
	}
}

func TestDelete(t *testing.T) {
	c := New(time.Minute)
	c.Set("key", "value")
	c.Delete("key")

	var result string
	err := c.Get("key", &result)
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after Delete, got %v", err)
	}
}

func TestClear(t *testing.T) {
	c := New(time.Minute)
	c.Set("a", 1)
	c.Set("b", 2)
	c.Clear()

	if c.Count() != 0 {
		t.Fatalf("expected 0 items after Clear, got %d", c.Count())
	}
}

func TestCount(t *testing.T) {
	c := New(time.Minute)
	if c.Count() != 0 {
		t.Fatalf("expected 0, got %d", c.Count())
	}
	c.Set("a", 1)
	if c.Count() != 1 {
		t.Fatalf("expected 1, got %d", c.Count())
	}
	c.Set("b", 2)
	if c.Count() != 2 {
		t.Fatalf("expected 2, got %d", c.Count())
	}
}

func TestStructValue(t *testing.T) {
	c := New(time.Minute)
	type Person struct {
		Name string
		Age  int
	}
	c.Set("person", Person{Name: "Alice", Age: 30})

	var p Person
	err := c.Get("person", &p)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if p.Name != "Alice" || p.Age != 30 {
		t.Fatalf("expected {Alice 30}, got {%s %d}", p.Name, p.Age)
	}
}

func TestSliceValue(t *testing.T) {
	c := New(time.Minute)
	c.Set("list", []int{1, 2, 3})

	var result []int
	err := c.Get("list", &result)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(result) != 3 || result[0] != 1 || result[2] != 3 {
		t.Fatalf("expected [1 2 3], got %v", result)
	}
}

func TestPreconfiguredCaches(t *testing.T) {
	if DefaultCache == nil {
		t.Fatal("DefaultCache should not be nil")
	}
	if StatsCache == nil {
		t.Fatal("StatsCache should not be nil")
	}
	if DeviceCache == nil {
		t.Fatal("DeviceCache should not be nil")
	}
}

func TestCacheError(t *testing.T) {
	e1 := &CacheError{"test error"}
	if e1.Error() != "test error" {
		t.Fatalf("expected 'test error', got '%s'", e1.Error())
	}
	if ErrNotFound.Error() != "key not found" {
		t.Fatalf("expected 'key not found', got '%s'", ErrNotFound.Error())
	}
	if ErrExpired.Error() != "key expired" {
		t.Fatalf("expected 'key expired', got '%s'", ErrExpired.Error())
	}
}
