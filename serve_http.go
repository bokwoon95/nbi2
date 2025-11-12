package nbi2

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path"
	"strings"

	"github.com/bokwoon95/nbi2/sq"
	"golang.org/x/crypto/blake2b"
)

func (nbrew *Notebrew) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	scheme := "https://"
	if r.TLS == nil {
		scheme = "http://"
	}
	// Redirect the www subdomain to the bare domain.
	if r.Host == "www."+nbrew.CMSDomain {
		http.Redirect(w, r, scheme+nbrew.CMSDomain+r.URL.RequestURI(), http.StatusMovedPermanently)
		return
	}
	// Redirect unclean paths to the clean path equivalent.
	if r.Method == "GET" || r.Method == "HEAD" {
		cleanPath := path.Clean(r.URL.Path)
		if cleanPath != r.URL.Path {
			cleanURL := *r.URL
			cleanURL.Path = cleanPath
			http.Redirect(w, r, cleanURL.String(), http.StatusMovedPermanently)
			return
		}
	}
	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
	w.Header().Add("X-Frame-Options", "DENY")
	w.Header().Add("X-Content-Type-Options", "nosniff")
	w.Header().Add("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Add("Permissions-Policy", "camera=(), microphone=()")
	w.Header().Add("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Add("Cross-Origin-Embedder-Policy", "credentialless")
	w.Header().Add("Cross-Origin-Resource-Policy", "cross-origin")
	if nbrew.CMSDomainHTTPS {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	}
	r = r.WithContext(context.WithValue(r.Context(), LoggerKey, nbrew.Logger.With(
		slog.String("method", r.Method),
		slog.String("url", scheme+r.Host+r.URL.RequestURI()),
	)))
	err := r.ParseForm()
	if err != nil {
		nbrew.BadRequest(w, r, err)
		return
	}
	// TODO: /cms/users/*
	// TODO: /cms/notes/*
	// TODO: /cms/photos/*
}

func (nbrew *Notebrew) RedirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "Use HTTPS", http.StatusBadRequest)
		return
	}
	// Redirect HTTP to HTTPS only if it isn't an API call.
	// https://jviide.iki.fi/http-redirects
	r.ParseForm()
	if r.Host != nbrew.CMSDomain || !r.Form.Has("api") {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		} else {
			host = net.JoinHostPort(host, "443")
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusFound)
		return
	}
	// If someone does make an api call via HTTP, revoke their
	// session token.
	var sessionTokenHashes [][]byte
	header := r.Header.Get("Authorization")
	if header != "" {
		sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", strings.TrimPrefix(header, "Bearer ")))
		if err == nil && len(sessionToken) == 24 {
			var sessionTokenHash [8 + blake2b.Size256]byte
			checksum := blake2b.Sum256(sessionToken[8:])
			copy(sessionTokenHash[:8], sessionToken[:8])
			copy(sessionTokenHash[8:], checksum[:])
			sessionTokenHashes = append(sessionTokenHashes, sessionTokenHash[:])
		}
	}
	cookie, _ := r.Cookie("session")
	if cookie != nil && cookie.Value != "" {
		sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
		if err == nil && len(sessionToken) == 24 {
			var sessionTokenHash [8 + blake2b.Size256]byte
			checksum := blake2b.Sum256(sessionToken[8:])
			copy(sessionTokenHash[:8], sessionToken[:8])
			copy(sessionTokenHash[8:], checksum[:])
			sessionTokenHashes = append(sessionTokenHashes, sessionTokenHash[:])
		}
	}
	if len(sessionTokenHashes) > 0 {
		_, _ = sq.Exec(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "DELETE FROM session WHERE session_token_hash IN ({sessionTokenHashes})",
			Values: []any{
				sq.Param("sessionTokenHashes", sessionTokenHashes),
			},
		})
	}
	http.Error(w, "Use HTTPS", http.StatusBadRequest)
}
