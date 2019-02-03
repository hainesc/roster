package server

import (
	"context"
	"fmt"
	"net/http"
	"time"
	"github.com/hainesc/roster/pkg/config"
	"github.com/hainesc/roster/pkg/handler/discovery"
	"github.com/hainesc/roster/pkg/handler/keys"
	// "github.com/hainesc/roster/pkg/handler/auth"
	// "github.com/hainesc/roster/pkg/handler/token"
	// "github.com/hainesc/roster/pkg/handler/user"
	// "github.com/hainesc/roster/pkg/handler/revoke"
	// k1 "github.com/hainesc/roster/pkg/keys"
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
	go s.RotateKeysPeriodly(context.TODO())
	// http.Handle("/", http.FileServer(http.Dir("./cockscomb")))
	http.Handle("/.well-known/openid-configuration", discovery.NewDiscoveryHandler())
	http.Handle(discovery.KeysPath, keys.NewKeysHandler(s.stor))
	// TODO:
	// http.Handle(discovery.AuthPath, auth.NewAuthHandler())
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
		case <-time.After(time.Second * 30):
			if err := s.stor.RotateKeys(); err != nil {
				fmt.Println("failed to rotate keys")
			}
		}
	}
}
