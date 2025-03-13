package utils

import (
    "container/list"
    "runtime"
    "sync"
    "time"

    "github.com/shirou/gopsutil/v3/mem"
)

// MemoryMonitor monitors system memory usage
type MemoryMonitor struct {
    maxMemoryGB float64
    interval    time.Duration
    stopChan    chan struct{}
}

// NewMemoryMonitor creates a new memory monitor
func NewMemoryMonitor(maxMemoryGB float64, interval time.Duration) *MemoryMonitor {
    return &MemoryMonitor{
        maxMemoryGB: maxMemoryGB,
        interval:    interval,
        stopChan:    make(chan struct{}),
    }
}

// Start starts monitoring memory usage
func (mm *MemoryMonitor) Start() {
    go func() {
        ticker := time.NewTicker(mm.interval)
        defer ticker.Stop()

        for {
            select {
            case <-ticker.C:
                v, err := mem.VirtualMemory()
                if err != nil {
                    GetLogger().Errorf("Failed to get memory stats: %v", err)
                    continue
                }

                usedGB := float64(v.Used) / (1024 * 1024 * 1024)
                if usedGB > mm.maxMemoryGB {
                    GetLogger().Warnf("Memory usage (%.2f GB) exceeds limit (%.2f GB), triggering GC", usedGB, mm.maxMemoryGB)
                    runtime.GC()
                }
            case <-mm.stopChan:
                return
            }
        }
    }()
}

// Stop stops the memory monitor
func (mm *MemoryMonitor) Stop() {
    close(mm.stopChan)
}

// LRUCache implements a thread-safe LRU cache
type LRUCache struct {
    capacity int
    cache    map[interface{}]*list.Element
    ll       *list.List
    mutex    sync.RWMutex
}

type entry struct {
    key   interface{}
    value interface{}
}

// NewLRUCache creates a new LRU cache with the specified capacity
func NewLRUCache(capacity int) *LRUCache {
    return &LRUCache{
        capacity: capacity,
        cache:    make(map[interface{}]*list.Element),
        ll:       list.New(),
    }
}

// Get retrieves a value from the cache
func (c *LRUCache) Get(key interface{}) (interface{}, bool) {
    c.mutex.RLock()
    defer c.mutex.RUnlock()

    if elem, ok := c.cache[key]; ok {
        c.ll.MoveToFront(elem)
        return elem.Value.(*entry).value, true
    }
    return nil, false
}

// Put adds a value to the cache
func (c *LRUCache) Put(key, value interface{}) {
    c.mutex.Lock()
    defer c.mutex.Unlock()

    if elem, ok := c.cache[key]; ok {
        c.ll.MoveToFront(elem)
        elem.Value.(*entry).value = value
        return
    }

    if c.ll.Len() >= c.capacity {
        oldest := c.ll.Back()
        if oldest != nil {
            c.ll.Remove(oldest)
            delete(c.cache, oldest.Value.(*entry).key)
        }
    }

    elem := c.ll.PushFront(&entry{key, value})
    c.cache[key] = elem
} 