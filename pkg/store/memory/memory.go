package memory

import (
	github.com/hainesc/roster/pkg/store
)

type Memory struct {
}

// Memory implements the Store interface
var _ store.Store = &Memory{}
