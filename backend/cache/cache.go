package cache

import (
	"encoding/json"
	"sync"
	"time"
)

type item struct {
	value      interface{}
	expiration int64
}

type Cache struct {
	mu    sync.RWMutex
	items map[string]item
	ttl   time.Duration
}

func New(ttl time.Duration) *Cache {
	c := &Cache{
		items: make(map[string]item),
		ttl:   ttl,
	}
	go c.cleanup()
	return c
}

func (c *Cache) Get(key string, dest interface{}) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	it, found := c.items[key]
	if !found {
		return ErrNotFound
	}

	if time.Now().UnixNano() > it.expiration {
		return ErrExpired
	}

	b, err := json.Marshal(it.value)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dest)
}

func (c *Cache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = item{
		value:      value,
		expiration: time.Now().Add(c.ttl).UnixNano(),
	}
}

func (c *Cache) SetTTL(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = item{
		value:      value,
		expiration: time.Now().Add(ttl).UnixNano(),
	}
}

func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]item)
}

func (c *Cache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *Cache) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now().UnixNano()
		for k, v := range c.items {
			if now > v.expiration {
				delete(c.items, k)
			}
		}
		c.mu.Unlock()
	}
}

var (
	ErrNotFound = &CacheError{"key not found"}
	ErrExpired  = &CacheError{"key expired"}
)

type CacheError struct {
	msg string
}

func (e *CacheError) Error() string {
	return e.msg
}

var DefaultCache = New(5 * time.Minute)
var StatsCache = New(30 * time.Second)
var DeviceCache = New(2 * time.Minute)
