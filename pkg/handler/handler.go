package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"

	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"io"
	"strconv"
	"strings"
	"time"
	"github.com/hainesc/roster/pkg/claims"
	"github.com/hainesc/roster/pkg/client"
	"github.com/hainesc/roster/pkg/code"
	"github.com/hainesc/roster/pkg/store"
	jose "gopkg.in/square/go-jose.v2"
)

type OIDCHandler struct {
	store store.Store
}

func NewOIDCHandler(store store.Store) *OIDCHandler {
	return &OIDCHandler{
		store: store,
	}
}

const (
	// TODO: read baseURL from config.
	baseURL    =  "http://accounts.example.com"
	AuthPath   =  "/auth"
	TokenPath  =  "/token"
	KeysPath   =  "/jwts"
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

func (o *OIDCHandler) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	data, _ := json.MarshalIndent(&Discovery{
		Issuer:        baseURL,
		Auth:          baseURL + "/auth",
		Token:         baseURL + "/token",
		Keys:          baseURL + "/jwts",
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

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}

func (o *OIDCHandler) HandleJWTS(w http.ResponseWriter, r *http.Request) {
	// w.Write([]byte("Not implemented"))

	keys, _ := o.store.GetKeys()
	jwks := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, 1),
	}
	jwks.Keys[0] = *keys.SigningKeyPub
	data, _ := json.MarshalIndent(jwks, "", "  ")
	// TODO:
	// w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, must-revalidate", 3600 * 24 * 30))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}

func (o *OIDCHandler) HandleAuth(w http.ResponseWriter, r *http.Request) {
	// w.Write([]byte("Not implemented"))
	_ = r.ParseForm()
	q := r.Form
	redirectURI, _ := url.QueryUnescape(q.Get("redirect_uri"))
	clientID := q.Get("client_id")
	state := q.Get("state")
	nonce := q.Get("nonce")

	scopes := strings.Fields(q.Get("scope"))
	responseTypes := strings.Fields(q.Get("response_type"))

	fmt.Println("Client ID: %s", clientID)
	fmt.Println("State: %s", state)
	fmt.Println("Nonce: %s", nonce)
	fmt.Println("redirect URI: %s", redirectURI)

	fmt.Println("Scope: ")
	for _, scope := range scopes {
		fmt.Print(scope + " ")
	}

	fmt.Println("Response type: ")
	for _, responseType := range responseTypes {
		fmt.Print(responseType + " ")
	}

	http.Redirect(w, r, "http://accounts.example.com/signin/identifier?" + r.URL.RawQuery, http.StatusFound)
	w.Write([]byte("Not implemented"))
}

func (o *OIDCHandler) HandleClient(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		renderTemplate(w, clientTmpl, nil)
	case http.MethodPost:
		clientName := r.FormValue("client_name")
		clientID := r.FormValue("client_id")
		redirectUri := r.FormValue("redirect_uri")
		clientSecret := r.FormValue("client_secret")

		fmt.Println("client name: %s", clientName)
		fmt.Println("client ID: %s", clientID)
		fmt.Println("client Secret: %s", clientSecret)
		fmt.Println("Redirect URI: %s", redirectUri)

		client := client.Client{
			ID: clientID,
			Secret: clientSecret,
			RedirectURI: redirectUri,
			Name: clientName,
		}
		o.store.CreateClient(client)
		w.Write([]byte("Create client success"))
	}
}

var clientTmpl = template.Must(template.New("client.html").Parse(`<html>
  <body>
    <form action="/clients" method="post">
       <p>
         Client Name: <input type="text" name="client_name" placeholder="example-app">
       </p>
       <p>
         Client secret: <input type="text" name="client_secret" placeholder="secret">
       </p>
       <p>
         Client ID: <input type="text" name="client_id" placeholder="id0">
       </p>
       <p>
         Redirect URI: <input type="text" name="redirect_uri" placeholder="http://localhost:5555/callback">
       </p>

       <input type="submit" value="Create Client">
    </form>
  </body>
</html>`))

func renderTemplate(w http.ResponseWriter, tmpl *template.Template, data interface{}) {
	err := tmpl.Execute(w, data)
	if err == nil {
		return
	}

	switch err := err.(type) {
	case *template.Error:
		// An ExecError guarantees that Execute has not written to the underlying reader.
		fmt.Printf("Error rendering template %s: %s", tmpl.Name(), err)

		// TODO(ericchiang): replace with better internal server error.
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	default:
		// An error with the underlying write, such as the connection being
		// dropped. Ignore for now.
	}
}

func (o *OIDCHandler) HandleSignup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		renderTemplate(w, signupTmpl, nil)
	case http.MethodPost:
		userName := r.FormValue("user_name")
		password := r.FormValue("password")
		fmt.Println("User name: %s", userName)
		fmt.Println("Password: %s", password)
		o.store.Signup(userName, password)
		w.Write([]byte("Signup success"))
	}
}

var signupTmpl = template.Must(template.New("signup.html").Parse(`<html>
  <body>
    <form action="/signup" method="post">
       <p>
         User name: <input type="text" name="user_name" placeholder="hainesc">
       </p>
       <p>
         Password: <input type="password" name="password">
       </p>
       <input type="submit" value="Signup">
    </form>
  </body>
</html>`))

var signinTmpl = template.Must(template.New("signin.html").Parse(`<html>
  <body>
    <form action="/signin" method="post">
       <p>
         User name: <input type="text" name="user_name" placeholder="hainesc">
       </p>
       <p>
         Password: <input type="password" name="password">
       </p>
       <input type="submit" value="SignIn">
    </form>
  </body>
</html>`))

var signinIDTmpl = template.Must(template.New("signinid.html").Parse(`<html>
  <body>
    <form action="/signin/identifier?{{ .Query }}" method="post">
       <p>
         User name: <input type="text" name="user_name" placeholder="hainesc">
       </p>
       <p>
         Password: <input type="password" name="password">
       </p>
       <input type="submit" value="SignIn">
    </form>
  </body>
</html>`))

// We use id token and cookie to indicate the user have signed in.
func (o *OIDCHandler) HandleSignin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cookie, err := r.Cookie("AccessToken")
		if err == nil {
			var c claims.Claims
			rawToken := strings.Split(cookie.Value, ".")[1]
			payload, _ := base64.RawURLEncoding.DecodeString(rawToken)
			json.Unmarshal(payload, &c)
			// TODO: security, verify the signature.
			userName := c.Username
			if ok := o.store.Exists(userName); ok {
				// verify the cookied and login the declared user.
				http.Redirect(w, r, "http://accounts.example.com/me", http.StatusFound)
			}
		}
		renderTemplate(w, signinTmpl, nil)
	case http.MethodPost:
		userName := r.FormValue("user_name")
		password := r.FormValue("password")
		fmt.Println("User name: %s", userName)
		fmt.Println("Password: %s", password)

		if err := o.store.Check(userName, password); err != nil {
			w.Write([]byte("User not found or password is wrong."))
			return
		}
		c := &claims.Claims{
			UserID: userName,
			Username: userName,
			Email: userName + "@example.com",
			EmailVerified: true,
			Groups: []string{"example"},
		}

		payload, _ := json.Marshal(c)
		key, _ := o.store.GetKeys()
		signer, _ := jose.NewSigner(jose.SigningKey{Key: key.SigningKey, Algorithm: jose.RS256}, &jose.SignerOptions{})
		signature, _ := signer.Sign(payload)
		jwt, _ := signature.CompactSerialize()
		http.SetCookie(w, &http.Cookie{
			Name:       "AccessToken",
			Value:      jwt,
			Path:       "/",
			RawExpires: "0",
		})

		http.Redirect(w, r, "http://accounts.example.com/me", http.StatusFound)
	}
}

// We use id token and cookie to indicate the user have signed in.
func (o *OIDCHandler) HandleSignID(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	if v["client_id"] == nil {
		w.Write([]byte("The handle is designed to handle oidc flow, you are wrong in here, it is just a prototype now."))
	}
	switch r.Method {
	case http.MethodGet:
		cookie, err := r.Cookie("AccessToken")
		if err == nil {
			var c claims.Claims
			rawToken := strings.Split(cookie.Value, ".")[1]
			payload, _ := base64.RawURLEncoding.DecodeString(rawToken)
			json.Unmarshal(payload, &c)
			// TODO: security, verify the signature.
			userName := c.Username
			v.Set("user", userName)
			if ok := o.store.Exists(userName); ok {
				// verify the cookied and login the declared user.
				http.Redirect(w, r, "http://accounts.example.com/signin/consent?" + v.Encode(), http.StatusFound)
			}
		}
		// TODO: read cookie, if cookie match some user and not expires, then redirect to signed in page or to consent page.
		renderTemplate(w, signinIDTmpl, map[string]interface{}{
			"Query": template.URL(r.URL.RawQuery),
		})
	case http.MethodPost:
		userName := r.FormValue("user_name")
		password := r.FormValue("password")
		fmt.Println("User name: %s", userName)
		fmt.Println("Password: %s", password)

		if err := o.store.Check(userName, password); err != nil {
			w.Write([]byte("User not found or password is wrong."))
			return
		}
		// TODO: requre more field when signup, so we can get the information here.
		// The line below is just an prototype.
		c := &claims.Claims{
			UserID: userName,
			Username: userName,
			Email: userName + "@example.com",
			EmailVerified: true,
			Groups: []string{"example"},
		}

		payload, _ := json.Marshal(c)
		key, _ := o.store.GetKeys()
		signer, _ := jose.NewSigner(jose.SigningKey{Key: key.SigningKey, Algorithm: jose.RS256}, &jose.SignerOptions{})
		signature, _ := signer.Sign(payload)
		jwt, _ := signature.CompactSerialize()
		http.SetCookie(w, &http.Cookie{
			Name:       "AccessToken",
			Value:      jwt,
			Path:       "/",
			RawExpires: "0",
		})
		v.Set("user", userName)
		http.Redirect(w, r, "http://accounts.example.com/signin/consent?" + v.Encode(), http.StatusFound)
	}
}

// We use id token and cookie to indicate the user have signed in.
func (o *OIDCHandler) HandleConsent(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	client_id := v.Get("client_id")
	clientX, _ := o.store.GetClient(client_id)
	switch r.Method {
	case http.MethodGet:
		renderTemplate(w, consentTmpl, map[string]interface{}{
			"Name": clientX.Name,
			"Query": template.URL(r.URL.RawQuery),
		})
	case http.MethodPost:
		// Only code flow implemented here.
		// create and store a code, then redirect to client URI with code query parameter.
		u, _ := url.Parse(clientX.RedirectURI)
		fmt.Println("Redirect URI: %s", clientX.RedirectURI)
		fmt.Println("url to string: %s", u.String())

		codeID := NewID()
		code := code.Code{
			CodeID: codeID,
			ClientID: client_id,
			UserName: v.Get("user"),
			Scope:    strings.Fields(v.Get("scope")),
			Nonce:    v.Get("nonce"),
		}

		o.store.WriteCodeID(codeID, code)
		q := u.Query()
		q.Set("code", codeID)
		q.Set("state", v.Get("state"))
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	}
}

var consentTmpl = template.Must(template.New("consent.html").Parse(`<html>
  <body>
    <form action="/signin/consent?{{ .Query }}" method="post">
       <p> Sign in with Roster </p>
       <p> {{ .Name }} wants to access your roster accounts </p>
       <p> This will allow it access your account some field. </p>
       <p> TODO: no cancel button recently, to cancel, just close the page </p>
       <input type="submit" value="Approval">
    </form>
  </body>
</html>`))

var encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567")
func NewID() string {
	buff := make([]byte, 16) // 128 bit random ID.
	if _, err := io.ReadFull(rand.Reader, buff); err != nil {
		panic(err)
	}
	// Avoid the identifier to begin with number and trim padding
	return string(buff[0]%26+'a') + strings.TrimRight(encoding.EncodeToString(buff[1:]), "=")
}

func (o *OIDCHandler) HandleMe(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("You are signed in, this is your personal page, you can view, modify your personal information, but it is not implemented now."))
}

func (o *OIDCHandler) HandleToken(w http.ResponseWriter, r *http.Request) {
	grantType := r.PostFormValue("grant_type")
	switch grantType {
	case "authorization_code":

		clientID, clientSecret, ok := r.BasicAuth()
		if ok {
			var err error
			if clientID, err = url.QueryUnescape(clientID); err != nil {
				w.Write([]byte("Error get client id in handle token"))
				return
			}
			if clientSecret, err = url.QueryUnescape(clientSecret); err != nil {
				w.Write([]byte("Error get client secret in handle token"))
				return
			}
		} else {
			clientID = r.PostFormValue("client_id")
			clientSecret = r.PostFormValue("client_secret")
		}

		codeID := r.PostFormValue("code")
		// redirectURI := r.PostFormValue("redirect_uri")
		code, _ := o.store.GetCode(codeID)
		fmt.Printf("Code is: %s\n", codeID)
		// The code is one time used.
		defer o.store.DeleteCode(codeID)
		userName := code.UserName
		// TODO: the code should have a expire field and we should check it here.
		accessToken := NewID()
		// TODO: config it.
		issuedAt := time.Now()
		expiry := issuedAt.Add(time.Hour * 24 * 30)

		// atHash, _ := accessTokenHash(signingAlg, accessToken)
		hashAlg := sha256.New
		hash := hashAlg()
		if _, err := io.WriteString(hash, accessToken); err != nil {
			w.Write([]byte("Error atHash"))
			return
		}
		sum := hash.Sum(nil)
		atHash := base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])

		idToken := claims.IDTokenClaims{
			Issuer: "http://accounts.example.com",
			// TODO: A Subject Identifier is a locally unique and never reassigned identifier within the Issuer for the End-User.
			Subject: userName,
			Nonce: code.Nonce,
			Expiry: expiry.Unix(),
			IssuedAt: issuedAt.Unix(),
			AccessTokenHash: atHash,
			// Email: userName + "@example.com",
			// EmailVerified: true,
			// Name: userName,
		}
		idToken.Audience = []string{clientID}
		refresh_token := ""
		verified := true;
		for _, scope := range code.Scope {
			fmt.Printf("Current scope: %s\n", scope)
			switch {
			case scope == "email":
				idToken.Email = userName + "@example.com"
				idToken.EmailVerified = &verified
			case scope == "groups":
				idToken.Groups = []string{"example"}
			case scope == "profile":
				idToken.Name = userName
			case scope == "offline_access":
				// TODO: we need refresh token. but it maybe not the best place for the code.
				refresh_token = NewID()
			}
		}

		payload, _ := json.Marshal(idToken)
		key, _ := o.store.GetKeys()
		signer, _ := jose.NewSigner(jose.SigningKey{Key: key.SigningKey, Algorithm: jose.RS256}, &jose.SignerOptions{})
		signature, _ := signer.Sign(payload)
		jwt, _ := signature.CompactSerialize()

		// TODO: There is no information in access_token, so it should written in db as it will be used to access more information.
		o.writeAccessToken(w, jwt, accessToken, refresh_token, expiry)

	case "refresh_token":
		w.Write([]byte("Not implemented"))
	}
}

func (o *OIDCHandler) writeAccessToken(w http.ResponseWriter, idToken, accessToken, refreshToken string, expiry time.Time) {
	// TODO(ericchiang): figure out an access token story and support the user info
	// endpoint. For now use a random value so no one depends on the access_token
	// holding a specific structure.
	resp := struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token,omitempty"`
		IDToken      string `json:"id_token"`
	}{
		accessToken,
		"bearer",
		int(expiry.Sub(time.Now()).Seconds()),
		refreshToken,
		idToken,
	}
	data, _ := json.Marshal(resp)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}
