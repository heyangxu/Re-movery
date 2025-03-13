package utils

import (
    "sync"
)

// Job represents a unit of work
type Job interface {
    Execute() error
}

// WorkerPool manages a pool of workers for parallel processing
type WorkerPool struct {
    numWorkers int
    jobs       chan Job
    results    chan error
    wg         sync.WaitGroup
    stopChan   chan struct{}
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(numWorkers int, queueSize int) *WorkerPool {
    return &WorkerPool{
        numWorkers: numWorkers,
        jobs:       make(chan Job, queueSize),
        results:    make(chan error, queueSize),
        stopChan:   make(chan struct{}),
    }
}

// Start starts the worker pool
func (wp *WorkerPool) Start() {
    for i := 0; i < wp.numWorkers; i++ {
        wp.wg.Add(1)
        go wp.worker()
    }
}

// worker processes jobs from the job queue
func (wp *WorkerPool) worker() {
    defer wp.wg.Done()

    for {
        select {
        case job := <-wp.jobs:
            if job == nil {
                return
            }
            err := job.Execute()
            wp.results <- err
        case <-wp.stopChan:
            return
        }
    }
}

// Submit submits a job to the worker pool
func (wp *WorkerPool) Submit(job Job) {
    wp.jobs <- job
}

// Stop stops the worker pool
func (wp *WorkerPool) Stop() {
    close(wp.stopChan)
    wp.wg.Wait()
    close(wp.jobs)
    close(wp.results)
}

// Results returns the results channel
func (wp *WorkerPool) Results() <-chan error {
    return wp.results
} 