package server

import (
	"context"
	"fmt"
	"net/http"
	"time"
	"github.com/hainesc/roster/pkg/config"
	"github.com/hainesc/roster/pkg/handler/discovery"
	"github.com/hainesc/roster/pkg/handler"
	"github.com/hainesc/roster/pkg/store"
	"github.com/hainesc/roster/pkg/store/memory"
)

type Server struct {
	stor store.Store
}

// NewServer constructs a server from the provided config.
func NewServer(ctx context.Context, c *config.RosterConf) (*Server, error) {
	return &Server{
		stor: &memory.Memory{},
	}, nil
}

func (s *Server) Serve() error {
	oidc := handler.NewOIDCHandler(s.stor)
	go s.RotateKeysPeriodly(context.TODO())
	// http.Handle("/", http.FileServer(http.Dir("./cockscomb")))
	http.HandleFunc("/.well-known/openid-configuration", oidc.HandleDiscovery)
	http.HandleFunc(discovery.KeysPath, oidc.HandleJWTS)
	http.HandleFunc(discovery.AuthPath, oidc.HandleAuth)
	// TODO:
	// http.Handle(discovery.TokenPath, token.NewTokenHandler())
	// http.Handle(discovery.UserPath, user.NewUserHandler())
	// http.Handle(discovery.RevokePath, revoke.NewRevokeHandler())
	// http.Handle("/signin", )
	// http.Handle("/signup", )
	// http.Handle("/clients") client_register.
	// http.Handle("/logout")
	return http.ListenAndServe(":5566", nil)
}

func (s *Server) RotateKeysPeriodly(ctx context.Context) {
	if err := s.stor.RotateKeys(); err != nil {
		fmt.Println("failed to init keys")
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second * 3600 * 24 * 30):
			if err := s.stor.RotateKeys(); err != nil {
				fmt.Println("failed to rotate keys")
			}
		}
	}
}
