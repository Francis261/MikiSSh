//go:build windows

package client

// watchResize is a no-op on Windows: console resizes arrive as window buffer
// events rather than as signals, so there is nothing to subscribe to here.
//
// The session stays usable regardless — the initial geometry is sent
// unconditionally once authentication succeeds, and a RESIZE sent by the peer
// is still honoured. Only the spontaneous local-update path is absent.
func (c *cli) watchResize() {
	<-c.doneCh
}
