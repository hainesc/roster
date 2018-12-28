package server

import (
	"context"
	"net/http"
	"github.com/hainesc/roster/pkg/config"
	"github.com/hainesc/roster/pkg/handler/discovery"
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
	http.ListenAndServe(":5566", nil)
	return nil
}
