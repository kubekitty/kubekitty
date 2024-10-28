package ui

import (
	"fmt"
	"strings"
	"time"
)

// ProgressIndicator represents a progress indicator for long-running operations
type ProgressIndicator struct {
	message string
	done    chan bool
}

// NewProgressIndicator creates a new progress indicator
func NewProgressIndicator(message string) *ProgressIndicator {
	return &ProgressIndicator{
		message: message,
		done:    make(chan bool),
	}
}

// Start starts showing the progress indicator
func (p *ProgressIndicator) Start() {
	go func() {
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		i := 0
		for {
			select {
			case <-p.done:
				return
			default:
				frame := frames[i%len(frames)]
				fmt.Printf("\r%s %s %s", MagnifierEmoji, frame, info(p.message))
				time.Sleep(100 * time.Millisecond)
				i++
			}
		}
	}()
}

// Stop stops the progress indicator
func (p *ProgressIndicator) Stop() {
	p.done <- true
	fmt.Print("\r" + strings.Repeat(" ", len(p.message)+10) + "\r")
}
