package nbi2

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/bokwoon95/nbi2/sq"
	"github.com/bokwoon95/nbi2/stacktrace"
	"github.com/caddyserver/certmagic"
	"github.com/klauspost/cpuid/v2"
	"golang.org/x/crypto/blake2b"
)

var urlFileExts = map[string]struct{}{
	".html": {}, ".css": {}, ".js": {}, ".txt": {}, ".json": {}, ".xml": {},
	".jpeg": {}, ".jpg": {}, ".png": {}, ".webp": {}, ".gif": {}, ".svg": {},
	".mp4": {}, ".mov": {}, ".webm": {},
	".tgz": {},
}

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
	urlPath := path.Clean(r.URL.Path)
	if urlPath != "/" {
		if _, ok := urlFileExts[path.Ext(urlPath)]; !ok {
			urlPath += "/"
		}
	}
	if urlPath != r.URL.Path {
		if r.Method == "GET" || r.Method == "HEAD" {
			uri := *r.URL
			uri.Path = urlPath
			http.Redirect(w, r, uri.String(), http.StatusMovedPermanently)
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
	if strings.HasPrefix(urlPath, "/cms/") {
		pathHead, pathTail, _ := strings.Cut(strings.Trim(strings.TrimPrefix(urlPath, "/cms/"), "/"), "/")
		r.Pattern = pathTail
		requestContext := RequestContext{
			URLPath:    urlPath,
			CDNDomain:  nbrew.CDNDomain,
			DevMode:    devMode,
			StylesCSS:  template.CSS(stylesCSS),
			NotebrewJS: template.JS(notebrewJS),
		}
		referer := r.Referer()
		if referer != "" {
			uri := *r.URL
			uri.Scheme = scheme
			uri.Host = r.Host
			uri.Fragment = ""
			uri.User = nil
			if referer != uri.String() {
				requestContext.Referer = referer
			}
		}
		var sessionToken string
		header := r.Header.Get("Authorization")
		if header != "" {
			sessionToken = strings.TrimPrefix(header, "Bearer")
		} else {
			cookie, _ := r.Cookie("session")
			if cookie != nil {
				sessionToken = cookie.Value
			}
		}
		var user User
		if sessionToken != "" {
			sessionTokenBytes, err := hex.DecodeString(fmt.Sprintf("%048s", sessionToken))
			if err == nil && len(sessionTokenBytes) == 24 {
				var sessionTokenHash [8 + blake2b.Size256]byte
				checksum := blake2b.Sum256(sessionTokenBytes[8:])
				copy(sessionTokenHash[:8], sessionTokenBytes[:8])
				copy(sessionTokenHash[8:], checksum[:])
				user, err = sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format: "SELECT {*}" +
						" FROM session" +
						" JOIN users ON users.user_id = session.user_id" +
						" WHERE session.session_token_hash = {sessionTokenHash}",
					Values: []any{
						sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
					},
				}, func(row *sq.Row) User {
					user := User{
						UserID:                row.UUID("users.user_id"),
						Username:              row.String("users.username"),
						Email:                 row.String("users.email"),
						TimezoneOffsetSeconds: row.Int("users.timezone_offset_seconds"),
						DisableReason:         row.String("users.disable_reason"),
						SiteLimit:             row.Int64("coalesce(users.site_limit, -1)"),
						StorageLimit:          row.Int64("coalesce(users.storage_limit, -1)"),
					}
					b := row.Bytes(nil, "users.user_flags")
					if len(b) > 0 {
						err := json.Unmarshal(b, &user.UserFlags)
						if err != nil {
							panic(stacktrace.New(err))
						}
					}
					return user
				})
				if err != nil {
					if !errors.Is(err, sql.ErrNoRows) {
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
				}
				requestContext.UserID = user.UserID
				requestContext.Username = user.Username
				requestContext.DisableReason = user.DisableReason
			}
		}
		switch pathHead {
		case "static":
			if pathTail == "" {
				nbrew.NotFound(w, r)
				return
			}
			http.ServeFileFS(w, r, runtimeFS, pathTail)
			return
		case "login":
			nbrew.login(w, r, pathTail, requestContext)
			return
		case "logout":
			if pathTail != "" {
				nbrew.NotFound(w, r)
				return
			}
			// nbrew.logout(w, r, responseContext) // TODO
			return
		case "resetpassword":
			if pathTail != "" {
				nbrew.NotFound(w, r)
				return
			}
			// nbrew.resetpassword(w, r, responseContext) // TODO
			return
		case "invite":
			if pathTail != "" {
				nbrew.NotFound(w, r)
				return
			}
			// nbrew.invite(w, r, responseContext) // TODO
			return
		}
		if requestContext.UserID.IsZero() {
			nbrew.NotAuthenticated(w, r)
			return
		}
		switch pathHead {
		case "":
			http.Redirect(w, r, "/cms/notes/", http.StatusFound)
			return
		case "notes":
			nbrew.notes(w, r, pathTail, requestContext)
			return
		case "photos":
			// nbrew.photos(w, r, responseContext) // TODO
			return
		default:
			nbrew.NotFound(w, r)
			return
		}
	}
	nbrew.NotFound(w, r)
}

func (nbrew *Notebrew) NewServer() (*http.Server, error) {
	server := &http.Server{
		ErrorLog: log.New(&LogFilter{Stderr: os.Stderr}, "", log.LstdFlags),
		Handler:  nbrew,
	}
	var onEvent func(ctx context.Context, event string, data map[string]any) error
	if nbrew.MonitoringConfig.Email != "" && nbrew.Mailer != nil {
		onEvent = func(ctx context.Context, event string, data map[string]any) error {
			if event == "tls_get_certificate" {
				return nil
			}
			data["certmagic.event"] = event
			b, err := json.Marshal(data)
			if err != nil {
				fmt.Println(err)
				return nil
			}
			fmt.Println(string(b))
			if event != "cert_failed" {
				return nil
			}
			renewal := fmt.Sprint(data["renewal"])
			identifier := fmt.Sprint(data["identifier"])
			remaining := fmt.Sprint(data["remaining"])
			issuers := fmt.Sprint(data["issuers"])
			errmsg := fmt.Sprint(data["error"])
			nbrew.BackgroundWaitGroup.Add(1)
			go func() {
				defer func() {
					if v := recover(); v != nil {
						fmt.Println(stacktrace.New(fmt.Errorf("panic: %v", v)))
					}
				}()
				defer nbrew.BackgroundWaitGroup.Done()
				mail := Mail{
					MailFrom: nbrew.MailFrom,
					RcptTo:   nbrew.MonitoringConfig.Email,
					Headers: []string{
						"Subject", "notebrew: certificate renewal for " + identifier + " failed: " + errmsg,
						"Content-Type", "text/plain; charset=utf-8",
					},
					Body: strings.NewReader("Certificate renewal failed." +
						"\r\nRenewal: " + renewal +
						"\r\nThe name on the certificate: " + identifier +
						"\r\nThe issuer(s) tried: " + issuers +
						"\r\nTime left on the certificate: " + remaining +
						"\r\nError: " + errmsg,
					),
				}
				select {
				case <-ctx.Done():
				case <-nbrew.BackgroundContext.Done():
				case nbrew.Mailer.C <- mail:
				}
			}()
			return nil
		}
	}
	switch nbrew.Port {
	case 443:
		server.Addr = ":443"
		server.ReadHeaderTimeout = 5 * time.Minute
		server.WriteTimeout = 60 * time.Minute
		server.IdleTimeout = 5 * time.Minute
		// staticCertConfig is the certmagic config responsible for managing
		// statically-known domains in the nbrew.ManagingDomains slice.
		var staticCertConfig *certmagic.Config
		staticCertCache := certmagic.NewCache(certmagic.CacheOptions{
			GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
				return staticCertConfig, nil
			},
			Logger: nbrew.CertLogger,
		})
		staticCertConfig = certmagic.New(staticCertCache, certmagic.Config{})
		staticCertConfig.OnEvent = onEvent
		staticCertConfig.Storage = nbrew.CertStorage
		staticCertConfig.Logger = nbrew.CertLogger
		if nbrew.DNSProvider != nil {
			staticCertConfig.Issuers = []certmagic.Issuer{
				certmagic.NewACMEIssuer(staticCertConfig, certmagic.ACMEIssuer{
					CA:        certmagic.DefaultACME.CA,
					TestCA:    certmagic.DefaultACME.TestCA,
					Logger:    nbrew.CertLogger,
					HTTPProxy: certmagic.DefaultACME.HTTPProxy,
					DNS01Solver: &certmagic.DNS01Solver{
						DNSManager: certmagic.DNSManager{
							DNSProvider: nbrew.DNSProvider,
							Logger:      nbrew.CertLogger,
						},
					},
				}),
			}
		} else {
			staticCertConfig.Issuers = []certmagic.Issuer{
				certmagic.NewACMEIssuer(staticCertConfig, certmagic.ACMEIssuer{
					CA:        certmagic.DefaultACME.CA,
					TestCA:    certmagic.DefaultACME.TestCA,
					Logger:    nbrew.CertLogger,
					HTTPProxy: certmagic.DefaultACME.HTTPProxy,
				}),
			}
		}
		if len(nbrew.ManagingDomains) == 0 {
			fmt.Printf("WARNING: notebrew is listening on port 443 but no domains are pointing at this current machine's IP address (%s/%s). It means no traffic can reach this current machine. Please configure your DNS correctly.\n", nbrew.IP4.String(), nbrew.IP6.String())
		}
		err := staticCertConfig.ManageSync(context.Background(), nbrew.ManagingDomains)
		if err != nil {
			return nil, err
		}
		// dynamicCertConfig is the certmagic config responsible for managing
		// dynamically-determined domains present in the site table.
		var dynamicCertConfig *certmagic.Config
		dynamicCertCache := certmagic.NewCache(certmagic.CacheOptions{
			GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
				return dynamicCertConfig, nil
			},
			Logger: nbrew.CertLogger,
		})
		dynamicCertConfig = certmagic.New(dynamicCertCache, certmagic.Config{})
		dynamicCertConfig.OnEvent = onEvent
		dynamicCertConfig.Storage = nbrew.CertStorage
		dynamicCertConfig.Logger = nbrew.CertLogger
		dynamicCertConfig.OnDemand = &certmagic.OnDemandConfig{
			DecisionFunc: func(ctx context.Context, name string) error {
				var siteName string
				if certmagic.MatchWildcard(name, "*."+nbrew.ContentDomain) {
					siteName = strings.TrimSuffix(name, "."+nbrew.ContentDomain)
				} else {
					siteName = name
				}
				exists, err := sq.FetchExists(ctx, nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format:  "SELECT 1 FROM site WHERE site_name = {}",
					Values:  []any{siteName},
				})
				if err != nil {
					return err
				}
				if !exists {
					return fmt.Errorf("site does not exist")
				}
				return nil
			},
		}
		// TLSConfig logic copied from (*certmagic.Config).TLSConfig(). The
		// only modification is that in GetCertificate we obtain the
		// certificate from either staticCertConfig or dynamicCertConfig based
		// on clientHello.
		server.TLSConfig = &tls.Config{
			NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
			GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if clientHello.ServerName == "" {
					return nil, fmt.Errorf("server name required")
				}
				for _, domain := range nbrew.ManagingDomains {
					if certmagic.MatchWildcard(clientHello.ServerName, domain) {
						certificate, err := staticCertConfig.GetCertificate(clientHello)
						if err != nil {
							return nil, err
						}
						return certificate, nil
					}
				}
				certificate, err := dynamicCertConfig.GetCertificate(clientHello)
				if err != nil {
					return nil, err
				}
				return certificate, nil
			},
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			PreferServerCipherSuites: true,
		}
		if cpuid.CPU.Supports(cpuid.AESNI) {
			server.TLSConfig.CipherSuites = []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			}
		}
	case 80:
		server.Addr = ":80"
	default:
		if len(nbrew.ProxyConfig.RealIPHeaders) == 0 && len(nbrew.ProxyConfig.ProxyIPs) == 0 {
			server.Addr = "localhost:" + strconv.Itoa(nbrew.Port)
		} else {
			server.Addr = ":" + strconv.Itoa(nbrew.Port)
		}
	}
	return server, nil
}

type LogFilter struct {
	Stderr io.Writer
}

func (logFilter *LogFilter) Write(p []byte) (n int, err error) {
	if bytes.Contains(p, []byte("http: TLS handshake error from ")) ||
		bytes.Contains(p, []byte("http2: RECEIVED GOAWAY")) ||
		bytes.Contains(p, []byte("http2: server: error reading preface from client")) {
		return 0, nil
	}
	return logFilter.Stderr.Write(p)
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
