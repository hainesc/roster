package claims

// Claims represents the ID Token claims supported by the server.
type Claims struct {
	UserID        string
	Username      string
	Email         string
	EmailVerified bool

	Groups []string
}
