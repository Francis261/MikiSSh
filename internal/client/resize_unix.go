//go:build !windows

package client

import (
	"os"
	"os/signal"
	"syscall"
)

// watchResize pushes a resize frame whenever the local terminal changes size.
// It blocks for the life of the session, like every other session goroutine.
func (c *cli) watchResize() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	defer signal.Stop(ch)
	for range ch {
		c.sendResize()
	}
}
