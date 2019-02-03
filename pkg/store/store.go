package store

import (
	"github.com/hainesc/roster/pkg/keys"
)
type Store interface {
	RotateKeys() error
	GetKeys() (keys.Keys, error)
}
