package memory

import (
	"fmt"
	"crypto/rsa"
	"github.com/hainesc/roster/pkg/client"
	"github.com/hainesc/roster/pkg/code"
	"github.com/hainesc/roster/pkg/keys"

	"github.com/hainesc/roster/pkg/store"
	"gopkg.in/square/go-jose.v2"
)

type Memory struct {
	k keys.Keys
	clients map[string]client.Client
	users map[string]string
	codes map[string]code.Code
}

func NewMemory() *Memory {
	return &Memory{
		clients: make(map[string]client.Client),
		users: make(map[string]string),
		codes: make(map[string]code.Code),
	}
}
// Memory implements the Store interface
var _ store.Store = &Memory{}

func (m *Memory) RotateKeys() error {
	// TODO: just generator a rsa key, no rotation implemented.
	tmp, _ := keys.RS256.Generator()
	key := tmp.(*rsa.PrivateKey)
	priv := &jose.JSONWebKey{
		Key: key,
		KeyID: "1",
		Algorithm: "RS256",
		Use: "sig",
	}
	pub := &jose.JSONWebKey{
		Key: key.Public(),
		KeyID: "1",
		Algorithm: "RS256",
		Use: "sig",
	}

	m.k = keys.Keys{
		SigningKey: priv,
		SigningKeyPub: pub,
	}
	return nil
}

func (m *Memory) GetKeys() (keys.Keys, error) {
	// TODO:
	return m.k, nil
}

func (m *Memory) CreateClient(c client.Client) error {
	m.clients[c.ID] = c
	return nil
}

func (m *Memory) GetClient(client_id string) (client.Client, error) {
	return m.clients[client_id], nil
}

func (m *Memory) Signup(username, password string) error {
	m.users[username] = password
	return nil
}

func (m *Memory) Check(username, password string) error {
	if m.users[username] == password {
		return nil
	}
	return fmt.Errorf("User not found or password is wrong")
}

func (m *Memory) WriteCodeID(codeID string, c code.Code) error {
	m.codes[codeID] = c
	return nil
}

func (m *Memory) GetCode(codeID string) (code.Code, error) {
	return m.codes[codeID], nil
}

func (m *Memory) DeleteCode(codeID string) error {
	delete(m.codes, codeID)
	return nil
}
