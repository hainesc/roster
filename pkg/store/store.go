package store

import (
	"github.com/hainesc/roster/pkg/client"
	"github.com/hainesc/roster/pkg/keys"
)
type Store interface {
	RotateKeys() error
	GetKeys() (keys.Keys, error)
	CreateClient(client.Client) error
	GetClient(string) (client.Client, error)
	Signup(string, string) error
	Check(string, string) error
	WriteCodeID(string) error
}
