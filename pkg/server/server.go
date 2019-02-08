package server

import (
	"context"
	"fmt"
	"net/http"
	"time"
	"github.com/hainesc/roster/pkg/config"
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
		stor: memory.NewMemory(),
	}, nil
}

func (s *Server) Serve() error {
	oidc := handler.NewOIDCHandler(s.stor)
	go s.RotateKeysPeriodly(context.TODO())
	http.HandleFunc("/.well-known/openid-configuration", oidc.HandleDiscovery)
	http.HandleFunc("/jwts", oidc.HandleJWTS)
	http.HandleFunc("/auth", oidc.HandleAuth)
	http.HandleFunc("/clients", oidc.HandleClient)
	http.HandleFunc("/signup", oidc.HandleSignup)
	http.HandleFunc("/signin", oidc.HandleSignin)
	http.HandleFunc("/signin/identifier", oidc.HandleSignID)
	http.HandleFunc("/signin/consent", oidc.HandleConsent)
	http.HandleFunc("/me", oidc.HandleMe)

	return http.ListenAndServe(":80", nil)
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
