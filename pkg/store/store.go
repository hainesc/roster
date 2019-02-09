package store

import (
	"github.com/hainesc/roster/pkg/client"
	"github.com/hainesc/roster/pkg/code"
	"github.com/hainesc/roster/pkg/keys"
)
type Store interface {
	RotateKeys() error
	GetKeys() (keys.Keys, error)
	CreateClient(client.Client) error
	GetClient(string) (client.Client, error)
	Signup(string, string) error
	Check(string, string) error
	Exists(string) bool
	WriteCodeID(string, code.Code) error
	GetCode(string) (code.Code, error)
	DeleteCode(string) error
}
