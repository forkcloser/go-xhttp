package retry

import "time"

const (
	// DefaultBackoff is the wait before the first retry under Options that
	// name no Backoff.
	DefaultBackoff = 500 * time.Millisecond
	// DefaultMaxBackoff is the longest wait before a retry under Options
	// that name no MaxBackoff.
	DefaultMaxBackoff = 30 * time.Second
)
