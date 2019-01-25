package discovery

import (
	"encoding/json"
	"net/http"
	jose "gopkg.in/square/go-jose.v2"
)
const (
	// TODO: read baseURL from config.
	baseURL    =  "https://accounts.example.com"
	AuthPath   =  "/auth"
	TokenPath  =  "/token"
	KeysPath   =  "/keys"
	UserPath   =  "/user"
	RevokePath =  "/revoke"
)

type Discovery struct {

	Issuer        string   `json:"issuer"`
	Auth          string   `json:"authorization_endpoint"`
	Token         string   `json:"token_endpoint"`
	Keys          string   `json:"jwks_uri"`
	User          string   `json:"userinfo_endpoint"`
	Revoke        string   `json:"revocation_endpoint"`

	ResponseTypes []string `json:"response_types_supported"`
	Subjects      []string `json:"subject_types_supported"`
	IDTokenAlgs   []string `json:"id_token_signing_alg_values_supported"`
	Scopes        []string `json:"scopes_supported"`
	AuthMethods   []string `json:"token_endpoint_auth_methods_supported"`
	Claims        []string `json:"claims_supported"`
	CodeMethods   []string `json:"code_challenge_methods_supported"`
}

type DiscoveryHandler struct {
}

func NewDiscoveryHandler() *DiscoveryHandler {
	return &DiscoveryHandler{}
}

func (d *DiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	response, _ := json.MarshalIndent(&Discovery{
	Issuer:        baseURL,
	Auth:          baseURL + "/auth",
	Token:         baseURL + "/token",
	Keys:          baseURL + "/keys",
	User:          baseURL + "/user",
	Revoke:        baseURL + "/revoke",
	ResponseTypes: []string{"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token", "none"},
	Subjects:      []string{"public"},
	IDTokenAlgs:   []string{string(jose.RS256)},
	Scopes:        []string{"openid", "email", "groups", "profile", "offline_access"},
	AuthMethods:   []string{"client_secret_post", "client_secret_basic"},
	Claims:        []string{"aud", "email", "email_verified", "exp", "family_name", "given_name", "iat", "iss", "locale", "name", "picture", "sub"},
	CodeMethods:   []string{"plain", "S256"},
	}, "", " ")
	w.Write(response)
}
