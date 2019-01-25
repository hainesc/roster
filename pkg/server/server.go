package server

import (
	"context"
	"net/http"
	"github.com/hainesc/roster/pkg/config"
	"github.com/hainesc/roster/pkg/handler/discovery"
	"github.com/hainesc/roster/pkg/handler/auth"
	"github.com/hainesc/roster/pkg/handler/token"
	"github.com/hainesc/roster/pkg/handler/keys"
	"github.com/hainesc/roster/pkg/handler/user"
	"github.com/hainesc/roster/pkg/handler/revoke"
)

type Server struct {
}

// NewServer constructs a server from the provided config.
func NewServer(ctx context.Context, c *config.RosterConf) (*Server, error) {
	return &Server{}, nil
}

func (s *Server) Serve() error {
	// http.Handle("/", http.FileServer(http.Dir("./cockscomb")))
	http.Handle("/.well-known/openid-configuration", discovery.NewDiscoveryHandler())
	http.Handle(discovery.AuthPath, auth.NewAuthHandler())
	http.Handle(discovery.TokenPath, token.NewTokenHandler())
	http.Handle(discovery.KeysPath, keys.NewKeysHandler())
	http.Handle(discovery.UserPath, user.NewUserHandler())
	http.Handle(discovery.RevokePath, revoke.NewRevokeHandler())
	http.ListenAndServe(":5566", nil)
	return nil
}
