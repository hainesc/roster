package claims

// Claims represents the ID Token claims supported by the server.
type Claims struct {
	UserID        string
	Username      string
	Email         string
	EmailVerified bool

	Groups []string
}

type IDTokenClaims struct {
	Issuer           string   `json:"iss"`
	Subject          string   `json:"sub"`
	Audience         []string `json:"aud"`
	Expiry           int64    `json:"exp"`
	IssuedAt         int64    `json:"iat"`
	AuthorizingParty string   `json:"azp,omitempty"`
	Nonce            string   `json:"nonce,omitempty"`

	AccessTokenHash string `json:"at_hash,omitempty"`

	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`

	Groups []string `json:"groups,omitempty"`

	Name string `json:"name,omitempty"`
	// FederatedIDClaims *federatedIDClaims `json:"federated_claims,omitempty"`
}
