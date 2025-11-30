package nbi2

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bokwoon95/nbi2/godaddy"
	"github.com/bokwoon95/nbi2/namecheap"
	"github.com/bokwoon95/nbi2/sq"
	"github.com/bokwoon95/nbi2/stacktrace"
	"github.com/bokwoon95/sqddl/ddl"
	"github.com/caddyserver/certmagic"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgconn"
	"github.com/libdns/cloudflare"
	"github.com/libdns/libdns"
	"github.com/libdns/porkbun"
	"github.com/oschwald/maxminddb-golang"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sync/errgroup"
)

// If a buffer's capacity exceeds this value, don't put it back in the pool
// because it's too expensive to keep it around in memory.
//
// From https://victoriametrics.com/blog/tsdb-performance-techniques-sync-pool/
//
// "The maximum capacity of a cached pool is limited to 2^18 bytes as we’ve
// found that the RAM cost of storing buffers larger than this limit is not
// worth the savings of not recreating those buffers."
const maxPoolableBufferCapacity = 1 << 18

var bufPool = sync.Pool{
	New: func() any { return &bytes.Buffer{} },
}

var gzipReaderPool = sync.Pool{}

var gzipWriterPool = sync.Pool{
	New: func() any {
		// Use compression level 4 for best balance between space and
		// performance.
		// https://blog.klauspost.com/gzip-performance-for-go-webservers/
		gzipWriter, _ := gzip.NewWriterLevel(nil, 4)
		return gzipWriter
	},
}

// Notebrew represents a notebrew instance.
type Notebrew struct {
	// DB is the DB associated with the notebrew instance.
	DB *sql.DB

	// Dialect is Dialect of the database. Only sqlite, postgres and mysql
	// databases are supported.
	Dialect string

	// ErrorCode translates a database error into an dialect-specific error
	// code. If the error is not a database error or if no underlying
	// implementation is provided, ErrorCode should return an empty string.
	ErrorCode func(error) string

	// ObjectStorage is used for storage of binary objects.
	ObjectStorage ObjectStorage

	// CMSDomain is the domain that the notebrew is using to serve the CMS.
	// Examples: localhost:6444, notebrew.com
	CMSDomain string

	// CMSDomainHTTPS indicates whether the CMS domain is currently being
	// served over HTTPS.
	CMSDomainHTTPS bool

	// ContentDomain is the domain that the notebrew instance is using to serve
	// the static generated content. Examples: localhost:6444, nbrew.net.
	ContentDomain string

	// ContentDomainHTTPS indicates whether the content domain is currently
	// being served over HTTPS.
	ContentDomainHTTPS bool

	// CDNDomain is the domain of the CDN that notebrew is using to host its
	// images. Examples: cdn.nbrew.net, nbrewcdn.net.
	CDNDomain string

	// LossyImgCmd is the command (must reside in $PATH) used to preprocess
	// images in a lossy way for the web before they are saved to the FS.
	// Images in the notes folder are never preprocessed and are uploaded
	// as-is. This serves as an a escape hatch for users who wish to upload
	// their images without any lossy image preprocessing, as they can upload
	// images to the notes folder first before moving it elsewhere.
	//
	// LossyImgCmd should take in arguments in the form of `<LossyImgCmd>
	// $INPUT_PATH $OUTPUT_PATH`, where $INPUT_PATH is the input path to the
	// raw image and $OUTPUT_PATH is output path where LossyImgCmd should save
	// the preprocessed image.
	LossyImgCmd string

	// VideoCmd is the command (must reside in $PATH) used to preprocess videos
	// in a lossless way for the web before they are saved to the FS.
	//
	// VideoCmd should take in arguments in the form of `<VideoCmd> $INPUT_PATH
	// $OUTPUT_PATH`, where $INPUT_PATH is the input path to the raw video and
	// $OUTPUT_PATH is output path where VideoCmd should save the preprocessed
	// video.
	VideoCmd string

	// (Required) Port is port that notebrew is listening on.
	Port int

	// IP4 is the IPv4 address of the current machine, if notebrew is currently
	// serving either port 80 (HTTP) or 443 (HTTPS).
	IP4 netip.Addr

	// IP6 is the IPv6 address of the current machine, if notebrew is currently
	// serving either port 80 (HTTP) or 443 (HTTPS).
	IP6 netip.Addr

	// Domains is the list of domains that need to point at notebrew for it to
	// work. Does not include user-created domains.
	Domains []string

	// ManagingDomains is the list of domains that the current instance of
	// notebrew is managing SSL certificates for.
	ManagingDomains []string

	// Captcha configuration.
	CaptchaConfig struct {
		// Captcha widget's script src. e.g. https://js.hcaptcha.com/1/api.js,
		// https://challenges.cloudflare.com/turnstile/v0/api.js
		WidgetScriptSrc template.URL

		// Captcha widget's container div class. e.g. h-captcha, cf-turnstile
		WidgetClass string

		// Captcha verification URL to make POST requests to. e.g.
		// https://api.hcaptcha.com/siteverify,
		// https://challenges.cloudflare.com/turnstile/v0/siteverify
		VerificationURL string

		// Captcha response token name. e.g. h-captcha-response,
		// cf-turnstile-response
		ResponseTokenName string

		// Captcha site key.
		SiteKey string

		// Captcha secret key.
		SecretKey string

		// CSP contains the Content-Security-Policy directive names and values
		// required for the captcha widget to work.
		CSP map[string]string
	}

	// Mailer is used to send out transactional emails e.g. password reset
	// emails.
	Mailer *Mailer

	// The default value for the SMTP MAIL FROM instruction.
	MailFrom string

	// The default value for the SMTP Reply-To header.
	ReplyTo string

	// Proxy configuration.
	ProxyConfig struct {
		// RealIPHeaders contains trusted IP addresses to HTTP headers that
		// they are known to populate the real client IP with. e.g. X-Real-IP,
		// True-Client-IP.
		RealIPHeaders map[netip.Addr]string

		// Contains the set of trusted proxy IP addresses. This is used when
		// resolving the real client IP from the X-Forwarded-For HTTP header
		// chain from right (most trusted) to left (most accurate).
		ProxyIPs map[netip.Addr]struct{}
	}

	// DNS provider (required for using wildcard certificates with
	// LetsEncrypt).
	DNSProvider interface {
		libdns.RecordAppender
		libdns.RecordDeleter
		libdns.RecordGetter
		libdns.RecordSetter
	}

	// CertStorage is the magic (certmagic) that automatically provisions SSL
	// certificates for notebrew.
	CertStorage certmagic.Storage

	// CertLogger is the logger used for a certmagic.Config.
	CertLogger *zap.Logger

	// ContentSecurityPolicy is the Content-Security-Policy HTTP header set for
	// every HTML response served on the CMS domain.
	ContentSecurityPolicy string

	// Logger is used for reporting errors that cannot be handled and are
	// thrown away.
	Logger *slog.Logger

	// MaxMindDBReader is the maxmind database reader used to reolve IP
	// addresses to their countries using a maxmind GeoIP database.
	MaxMindDBReader *maxminddb.Reader

	// Monitoring configuration.
	MonitoringConfig struct {
		// Email address to notify for errors.
		Email string
	}

	// BackgroundContext is the background context of the notebrew instance.
	BackgroundContext context.Context

	// backgroundCancel cancels the background context.
	backgroundCancel func()

	// BackgroundWaitGroup tracks the number of background jobs spawned by the
	// notebrew instance. Each background job should take in the background
	// context, and should should initiate shutdown when the background context
	// is canceled.
	BackgroundWaitGroup sync.WaitGroup
}

// New returns a new instance of Notebrew. Each field within it still needs to
// be manually configured.
func New(configDir, dataDir string, csp map[string]string) (*Notebrew, error) {
	backgroundContext, backgroundCancel := context.WithCancel(context.Background())
	nbrew := &Notebrew{
		BackgroundContext: backgroundContext,
		backgroundCancel:  backgroundCancel,
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			AddSource: true,
		})),
	}

	// CMS domain.
	b, err := os.ReadFile(filepath.Join(configDir, "cmsdomain.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "cmsdomain.txt"), err)
	}
	nbrew.CMSDomain = string(bytes.TrimSpace(b))

	// Content domain.
	b, err = os.ReadFile(filepath.Join(configDir, "contentdomain.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "contentdomain.txt"), err)
	}
	nbrew.ContentDomain = string(bytes.TrimSpace(b))

	// CDN domain.
	b, err = os.ReadFile(filepath.Join(configDir, "cdndomain.txt"))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "cdndomain.txt"), err)
		}
	} else {
		nbrew.CDNDomain = string(bytes.TrimSpace(b))
	}

	// MaxMind DB reader.
	b, err = os.ReadFile(filepath.Join(configDir, "maxminddb.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "maxminddb.txt"), err)
	}
	maxMindDBFilePath := string(bytes.TrimSpace(b))
	if maxMindDBFilePath != "" {
		_, err = os.Stat(maxMindDBFilePath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("%s: %s does not exist", filepath.Join(configDir, "maxminddb.txt"), maxMindDBFilePath)
			}
			return nil, fmt.Errorf("%s: %s: %w", filepath.Join(configDir, "maxminddb.txt"), maxMindDBFilePath, err)
		}
		maxmindDBReader, err := maxminddb.Open(maxMindDBFilePath)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", filepath.Join(configDir, "maxminddb.txt"), maxMindDBFilePath, err)
		}
		nbrew.MaxMindDBReader = maxmindDBReader
	}

	// Port.
	b, err = os.ReadFile(filepath.Join(configDir, "port.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "port.txt"), err)
	}
	port := string(bytes.TrimSpace(b))

	// Fill in the port and CMS domain if missing.
	if port != "" {
		nbrew.Port, err = strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a valid integer", filepath.Join(configDir, "port.txt"), port)
		}
		if nbrew.Port <= 0 {
			return nil, fmt.Errorf("%s: %d is not a valid port", filepath.Join(configDir, "port.txt"), nbrew.Port)
		}
		if nbrew.CMSDomain == "" {
			switch nbrew.Port {
			case 443:
				return nil, fmt.Errorf("%s: cannot use port 443 without specifying the cmsdomain", filepath.Join(configDir, "port.txt"))
			case 80:
				break // Use IP address as domain when we find it later.
			default:
				nbrew.CMSDomain = "localhost:" + port
			}
		}
	} else {
		if nbrew.CMSDomain != "" {
			nbrew.Port = 443
		} else {
			nbrew.Port = 6444
			nbrew.CMSDomain = "localhost:6444"
		}
	}

	if nbrew.Port == 443 || nbrew.Port == 80 {
		// IP4 and IP6.
		client := &http.Client{
			Timeout: 10 * time.Second,
		}
		group, groupctx := errgroup.WithContext(context.Background())
		group.Go(func() error {
			request, err := http.NewRequest("GET", "https://ipv4.icanhazip.com", nil)
			if err != nil {
				return fmt.Errorf("ipv4.icanhazip.com: %w", err)
			}
			response, err := client.Do(request.WithContext(groupctx))
			if err != nil {
				return fmt.Errorf("ipv4.icanhazip.com: %w", err)
			}
			defer response.Body.Close()
			var b strings.Builder
			_, err = io.Copy(&b, response.Body)
			if err != nil {
				return fmt.Errorf("ipv4.icanhazip.com: %w", err)
			}
			err = response.Body.Close()
			if err != nil {
				return err
			}
			s := strings.TrimSpace(b.String())
			if s == "" {
				return nil
			}
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return fmt.Errorf("ipv4.icanhazip.com: did not get a valid IP address (%s)", s)
			}
			if ip.Is4() {
				nbrew.IP4 = ip
			}
			return nil
		})
		group.Go(func() error {
			request, err := http.NewRequest("GET", "https://ipv6.icanhazip.com", nil)
			if err != nil {
				return fmt.Errorf("ipv6.icanhazip.com: %w", err)
			}
			response, err := client.Do(request.WithContext(groupctx))
			if err != nil {
				return fmt.Errorf("ipv6.icanhazip.com: %w", err)
			}
			defer response.Body.Close()
			var b strings.Builder
			_, err = io.Copy(&b, response.Body)
			if err != nil {
				return fmt.Errorf("ipv6.icanhazip.com: %w", err)
			}
			err = response.Body.Close()
			if err != nil {
				return err
			}
			s := strings.TrimSpace(b.String())
			if s == "" {
				return nil
			}
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return fmt.Errorf("ipv6.icanhazip.com: did not get a valid IP address (%s)", s)
			}
			if ip.Is6() {
				nbrew.IP6 = ip
			}
			return nil
		})
		err := group.Wait()
		if err != nil {
			return nil, err
		}
		if !nbrew.IP4.IsValid() && !nbrew.IP6.IsValid() {
			return nil, fmt.Errorf("unable to determine the IP address of the current machine")
		}
		if nbrew.CMSDomain == "" {
			if nbrew.IP4.IsValid() {
				nbrew.CMSDomain = nbrew.IP4.String()
			} else {
				nbrew.CMSDomain = "[" + nbrew.IP6.String() + "]"
			}
		}
	}
	if nbrew.ContentDomain == "" {
		nbrew.ContentDomain = nbrew.CMSDomain
	}

	// DNS.
	b, err = os.ReadFile(filepath.Join(configDir, "dns.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "dns.json"), err)
	}
	b = bytes.TrimSpace(b)
	var dnsConfig DNSConfig
	if len(b) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(b))
		err := decoder.Decode(&dnsConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "dns.json"), err)
		}
	}
	switch dnsConfig.Provider {
	case "":
		break
	case "namecheap":
		if dnsConfig.Username == "" {
			return nil, fmt.Errorf("%s: namecheap: missing username field", filepath.Join(configDir, "dns.json"))
		}
		if dnsConfig.APIKey == "" {
			return nil, fmt.Errorf("%s: namecheap: missing apiKey field", filepath.Join(configDir, "dns.json"))
		}
		if !nbrew.IP4.IsValid() && (nbrew.Port == 443 || nbrew.Port == 80) {
			return nil, fmt.Errorf("the current machine's IP address (%s) is not IPv4: an IPv4 address is needed to integrate with namecheap's API", nbrew.IP6.String())
		}
		nbrew.DNSProvider = &namecheap.Provider{
			APIKey:      dnsConfig.APIKey,
			User:        dnsConfig.Username,
			APIEndpoint: "https://api.namecheap.com/xml.response",
			ClientIP:    nbrew.IP4.String(),
		}
	case "cloudflare":
		if dnsConfig.APIToken == "" {
			return nil, fmt.Errorf("%s: cloudflare: missing apiToken field", filepath.Join(configDir, "dns.json"))
		}
		nbrew.DNSProvider = &cloudflare.Provider{
			APIToken: dnsConfig.APIToken,
		}
	case "porkbun":
		if dnsConfig.APIKey == "" {
			return nil, fmt.Errorf("%s: porkbun: missing apiKey field", filepath.Join(configDir, "dns.json"))
		}
		if dnsConfig.SecretKey == "" {
			return nil, fmt.Errorf("%s: porkbun: missing secretKey field", filepath.Join(configDir, "dns.json"))
		}
		nbrew.DNSProvider = &porkbun.Provider{
			APIKey:       dnsConfig.APIKey,
			APISecretKey: dnsConfig.SecretKey,
		}
	case "godaddy":
		if dnsConfig.APIToken == "" {
			return nil, fmt.Errorf("%s: godaddy: missing apiToken field", filepath.Join(configDir, "dns.json"))
		}
		nbrew.DNSProvider = &godaddy.Provider{
			APIToken: dnsConfig.APIToken,
		}
	default:
		return nil, fmt.Errorf("%s: unsupported provider %q (possible values: namecheap, cloudflare, porkbun, godaddy)", filepath.Join(configDir, "dns.json"), dnsConfig.Provider)
	}

	// If CMSDomain is not an IP address, add it to the Domains list.
	_, err = netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(nbrew.CMSDomain, "["), "]"))
	if err != nil {
		nbrew.Domains = append(nbrew.Domains, nbrew.CMSDomain, "www."+nbrew.CMSDomain)
		nbrew.CMSDomainHTTPS = !strings.HasPrefix(nbrew.CMSDomain, "localhost:") && nbrew.Port != 80
	}
	// If ContentDomain is not an IP address, add it to the Domains list.
	_, err = netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(nbrew.ContentDomain, "["), "]"))
	if err != nil {
		if nbrew.ContentDomain == nbrew.CMSDomain {
			nbrew.Domains = append(nbrew.Domains, "cdn."+nbrew.ContentDomain, "storage."+nbrew.ContentDomain)
			nbrew.ContentDomainHTTPS = nbrew.CMSDomainHTTPS
		} else {
			nbrew.Domains = append(nbrew.Domains, nbrew.ContentDomain, "www."+nbrew.ContentDomain, "cdn."+nbrew.ContentDomain, "storage."+nbrew.ContentDomain)
			nbrew.ContentDomainHTTPS = !strings.HasPrefix(nbrew.ContentDomain, "localhost:")
		}
	}

	// Certmagic.
	b, err = os.ReadFile(filepath.Join(configDir, "certmagic.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "certmagic.json"), err)
	}
	b = bytes.TrimSpace(b)
	var certmagicConfig CertmagicConfig
	if len(b) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(b))
		err := decoder.Decode(&certmagicConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "certmagic.json"), err)
		}
	}
	if certmagicConfig.DirectoryPath == "" {
		certmagicConfig.DirectoryPath = filepath.Join(configDir, "certmagic")
	}
	err = os.MkdirAll(certmagicConfig.DirectoryPath, 0755)
	if err != nil {
		return nil, err
	}
	nbrew.CertStorage = &certmagic.FileStorage{
		Path: certmagicConfig.DirectoryPath,
	}
	if certmagicConfig.TerseLogger {
		encoderConfig := zap.NewProductionEncoderConfig()
		encoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
		terseLogger := zap.New(zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			os.Stderr,
			zap.ErrorLevel,
		))
		nbrew.CertLogger = terseLogger
		certmagic.Default.Logger = terseLogger
		certmagic.DefaultACME.Logger = terseLogger
	} else {
		encoderConfig := zap.NewProductionEncoderConfig()
		encoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
		verboseLogger := zap.New(zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			os.Stderr,
			zap.InfoLevel,
		))
		nbrew.CertLogger = verboseLogger
		certmagic.Default.Logger = verboseLogger
		certmagic.DefaultACME.Logger = verboseLogger
	}

	if nbrew.Port == 443 || nbrew.Port == 80 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		group, groupctx := errgroup.WithContext(ctx)
		matched := make([]bool, len(nbrew.Domains))
		for i, domain := range nbrew.Domains {
			group.Go(func() error {
				_, err := netip.ParseAddr(domain)
				if err == nil {
					return nil
				}
				ips, err := net.DefaultResolver.LookupIPAddr(groupctx, domain)
				if err != nil {
					fmt.Println(err)
					return nil
				}
				for _, ip := range ips {
					ip, ok := netip.AddrFromSlice(ip.IP)
					if !ok {
						continue
					}
					if ip.Is4() && ip == nbrew.IP4 || ip.Is6() && ip == nbrew.IP6 {
						matched[i] = true
						break
					}
				}
				return nil
			})
		}
		err = group.Wait()
		if err != nil {
			return nil, err
		}
		switch nbrew.Port {
		case 80:
			for i, domain := range nbrew.Domains {
				if matched[i] {
					nbrew.ManagingDomains = append(nbrew.ManagingDomains, domain)
				}
			}
		case 443:
			cmsDomainWildcard := "*." + nbrew.CMSDomain
			cmsDomainWildcardAdded := false
			contentDomainWildcard := "*." + nbrew.ContentDomain
			contentDomainWildcardAdded := false
			for i, domain := range nbrew.Domains {
				if matched[i] {
					if certmagic.MatchWildcard(domain, cmsDomainWildcard) && nbrew.DNSProvider != nil {
						if !cmsDomainWildcardAdded {
							cmsDomainWildcardAdded = true
							nbrew.ManagingDomains = append(nbrew.ManagingDomains, cmsDomainWildcard)
						}
					} else if certmagic.MatchWildcard(domain, contentDomainWildcard) && nbrew.DNSProvider != nil {
						if !contentDomainWildcardAdded {
							contentDomainWildcardAdded = true
							nbrew.ManagingDomains = append(nbrew.ManagingDomains, contentDomainWildcard)
						}
					} else {
						nbrew.ManagingDomains = append(nbrew.ManagingDomains, domain)
					}
				}
			}
		}
	}

	// Database.
	b, err = os.ReadFile(filepath.Join(configDir, "database.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "database.json"), err)
	}
	b = bytes.TrimSpace(b)
	var databaseConfig DatabaseConfig
	if len(b) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(b))
		err := decoder.Decode(&databaseConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "database.json"), err)
		}
	}
	var dataSourceName string
	switch databaseConfig.Dialect {
	case "", "sqlite":
		if databaseConfig.SQLiteFilePath == "" {
			databaseConfig.SQLiteFilePath = filepath.Join(dataDir, "notebrew-database.db")
		}
		databaseConfig.SQLiteFilePath, err = filepath.Abs(databaseConfig.SQLiteFilePath)
		if err != nil {
			return nil, fmt.Errorf("%s: sqlite: %w", filepath.Join(configDir, "database.json"), err)
		}
		dataSourceName = databaseConfig.SQLiteFilePath + "?" + sqliteQueryString(databaseConfig.Params)
		nbrew.Dialect = "sqlite"
		nbrew.DB, err = sql.Open(sqliteDriverName, dataSourceName)
		if err != nil {
			return nil, fmt.Errorf("%s: sqlite: open %s: %w", filepath.Join(configDir, "database.json"), dataSourceName, err)
		}
		nbrew.ErrorCode = sqliteErrorCode
	case "postgres":
		values := make(url.Values)
		for key, value := range databaseConfig.Params {
			switch key {
			case "sslmode":
				values.Set(key, value)
			}
		}
		if _, ok := databaseConfig.Params["sslmode"]; !ok {
			values.Set("sslmode", "disable")
		}
		if databaseConfig.Port == "" {
			databaseConfig.Port = "5432"
		}
		uri := url.URL{
			Scheme:   "postgres",
			User:     url.UserPassword(databaseConfig.User, databaseConfig.Password),
			Host:     databaseConfig.Host + ":" + databaseConfig.Port,
			Path:     databaseConfig.DBName,
			RawQuery: values.Encode(),
		}
		dataSourceName = uri.String()
		nbrew.Dialect = "postgres"
		nbrew.DB, err = sql.Open("pgx", dataSourceName)
		if err != nil {
			return nil, fmt.Errorf("%s: postgres: open %s: %w", filepath.Join(configDir, "database.json"), dataSourceName, err)
		}
		nbrew.ErrorCode = func(err error) string {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) {
				return pgErr.Code
			}
			return ""
		}
	case "mysql":
		values := make(url.Values)
		for key, value := range databaseConfig.Params {
			switch key {
			case "charset", "collation", "loc", "maxAllowedPacket",
				"readTimeout", "rejectReadOnly", "serverPubKey", "timeout",
				"tls", "writeTimeout", "connectionAttributes":
				values.Set(key, value)
			}
		}
		values.Set("multiStatements", "true")
		values.Set("parseTime", "true")
		if databaseConfig.Port == "" {
			databaseConfig.Port = "3306"
		}
		config, err := mysql.ParseDSN(fmt.Sprintf("tcp(%s:%s)/%s?%s", databaseConfig.Host, databaseConfig.Port, url.PathEscape(databaseConfig.DBName), values.Encode()))
		if err != nil {
			return nil, err
		}
		// Set user and passwd manually to accomodate special characters.
		// https://github.com/go-sql-driver/mysql/issues/1323
		config.User = databaseConfig.User
		config.Passwd = databaseConfig.Password
		driver, err := mysql.NewConnector(config)
		if err != nil {
			return nil, err
		}
		dataSourceName = config.FormatDSN()
		nbrew.Dialect = "mysql"
		nbrew.DB = sql.OpenDB(driver)
		nbrew.ErrorCode = func(err error) string {
			var mysqlErr *mysql.MySQLError
			if errors.As(err, &mysqlErr) {
				return strconv.FormatUint(uint64(mysqlErr.Number), 10)
			}
			return ""
		}
	default:
		return nil, fmt.Errorf("%s: unsupported dialect %q (possible values: sqlite, postgres, mysql)", filepath.Join(configDir, "database.json"), databaseConfig.Dialect)
	}
	err = nbrew.DB.Ping()
	if err != nil {
		return nil, fmt.Errorf("%s: %s: ping %s: %w", filepath.Join(configDir, "database.json"), nbrew.Dialect, dataSourceName, err)
	}
	if databaseConfig.MaxOpenConns > 0 {
		nbrew.DB.SetMaxOpenConns(databaseConfig.MaxOpenConns)
	}
	if databaseConfig.MaxIdleConns > 0 {
		nbrew.DB.SetMaxIdleConns(databaseConfig.MaxIdleConns)
	}
	if databaseConfig.ConnMaxLifetime != "" {
		duration, err := time.ParseDuration(databaseConfig.ConnMaxLifetime)
		if err != nil {
			return nil, fmt.Errorf("%s: connMaxLifetime: %s: %w", filepath.Join(configDir, "database.json"), databaseConfig.ConnMaxLifetime, err)
		}
		nbrew.DB.SetConnMaxLifetime(duration)
	}
	if databaseConfig.ConnMaxIdleTime != "" {
		duration, err := time.ParseDuration(databaseConfig.ConnMaxIdleTime)
		if err != nil {
			return nil, fmt.Errorf("%s: connMaxIdleTime: %s: %w", filepath.Join(configDir, "database.json"), databaseConfig.ConnMaxIdleTime, err)
		}
		nbrew.DB.SetConnMaxIdleTime(duration)
	}
	databaseCatalog := &ddl.Catalog{
		Dialect: nbrew.Dialect,
	}
	err = unmarshalCatalog(databaseSchemaBytes, databaseCatalog)
	if err != nil {
		return nil, err
	}
	automigrateCmd := &ddl.AutomigrateCmd{
		DB:             nbrew.DB,
		Dialect:        nbrew.Dialect,
		DestCatalog:    databaseCatalog,
		AcceptWarnings: true,
		Stderr:         io.Discard,
	}
	err = automigrateCmd.Run()
	if err != nil {
		return nil, err
	}

	// Object Storage.
	b, err = os.ReadFile(filepath.Join(configDir, "objectstorage.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "objectstorage.json"), err)
	}
	b = bytes.TrimSpace(b)
	var objectstorageConfig ObjectstorageConfig
	if len(b) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(b))
		err = decoder.Decode(&objectstorageConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "objectstorage.json"), err)
		}
	}
	switch objectstorageConfig.Provider {
	case "", "directory":
		if objectstorageConfig.DirectoryPath == "" {
			objectstorageConfig.DirectoryPath = filepath.Join(dataDir, "notebrew-objectstorage")
		} else {
			objectstorageConfig.DirectoryPath = filepath.Clean(objectstorageConfig.DirectoryPath)
		}
		err := os.MkdirAll(objectstorageConfig.DirectoryPath, 0755)
		if err != nil {
			return nil, err
		}
		objectStorage, err := NewDirObjectStorage(objectstorageConfig.DirectoryPath, os.TempDir())
		if err != nil {
			return nil, err
		}
		nbrew.ObjectStorage = objectStorage
	case "s3":
		if objectstorageConfig.Endpoint == "" {
			return nil, fmt.Errorf("%s: missing endpoint field", filepath.Join(configDir, "objectstorage.json"))
		}
		if objectstorageConfig.Region == "" {
			return nil, fmt.Errorf("%s: missing region field", filepath.Join(configDir, "objectstorage.json"))
		}
		if objectstorageConfig.Bucket == "" {
			return nil, fmt.Errorf("%s: missing bucket field", filepath.Join(configDir, "objectstorage.json"))
		}
		if objectstorageConfig.AccessKeyID == "" {
			return nil, fmt.Errorf("%s: missing accessKeyID field", filepath.Join(configDir, "objectstorage.json"))
		}
		if objectstorageConfig.SecretAccessKey == "" {
			return nil, fmt.Errorf("%s: missing secretAccessKey field", filepath.Join(configDir, "objectstorage.json"))
		}
		contentTypeMap := map[string]string{
			".jpeg": "image/jpeg",
			".jpg":  "image/jpeg",
			".png":  "image/png",
			".webp": "image/webp",
			".gif":  "image/gif",
			".mp4":  "video/mp4",
			".mov":  "video/mp4",
			".webm": "video/webm",
			".tgz":  "application/octet-stream",
		}
		objectStorage, err := NewS3Storage(context.Background(), S3StorageConfig{
			Endpoint:        objectstorageConfig.Endpoint,
			Region:          objectstorageConfig.Region,
			Bucket:          objectstorageConfig.Bucket,
			AccessKeyID:     objectstorageConfig.AccessKeyID,
			SecretAccessKey: objectstorageConfig.SecretAccessKey,
			ContentTypeMap:  contentTypeMap,
			Logger:          nbrew.Logger,
		})
		if err != nil {
			return nil, err
		}
		nbrew.ObjectStorage = objectStorage
	default:
		return nil, fmt.Errorf("%s: unsupported provider %q (possible values: directory, s3)", filepath.Join(configDir, "objectstorage.json"), objectstorageConfig.Provider)
	}

	// Captcha.
	b, err = os.ReadFile(filepath.Join(configDir, "captcha.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "captcha.json"), err)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 {
		var captchaConfig CaptchaConfig
		decoder := json.NewDecoder(bytes.NewReader(b))
		err := decoder.Decode(&captchaConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "captcha.json"), err)
		}
		nbrew.CaptchaConfig.WidgetScriptSrc = template.URL(captchaConfig.WidgetScriptSrc)
		nbrew.CaptchaConfig.WidgetClass = captchaConfig.WidgetClass
		nbrew.CaptchaConfig.VerificationURL = captchaConfig.VerificationURL
		nbrew.CaptchaConfig.ResponseTokenName = captchaConfig.ResponseTokenName
		nbrew.CaptchaConfig.SiteKey = captchaConfig.SiteKey
		nbrew.CaptchaConfig.SecretKey = captchaConfig.SecretKey
		nbrew.CaptchaConfig.CSP = captchaConfig.CSP
	}

	// SMTP.
	b, err = os.ReadFile(filepath.Join(configDir, "smtp.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "smtp.json"), err)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 {
		var smtpConfig SMTPConfig
		decoder := json.NewDecoder(bytes.NewReader(b))
		err := decoder.Decode(&smtpConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "smtp.json"), err)
		}
		if smtpConfig.Host != "" && smtpConfig.Port != "" && smtpConfig.Username != "" && smtpConfig.Password != "" {
			mailerConfig := MailerConfig{
				Username: smtpConfig.Username,
				Password: smtpConfig.Password,
				Host:     smtpConfig.Host,
				Port:     smtpConfig.Port,
				Logger:   nbrew.Logger,
			}
			nbrew.MailFrom = smtpConfig.MailFrom
			nbrew.ReplyTo = smtpConfig.ReplyTo
			if smtpConfig.LimitInterval == "" {
				mailerConfig.LimitInterval = 3 * time.Minute
			} else {
				limitInterval, err := time.ParseDuration(smtpConfig.LimitInterval)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "smtp.json"), err)
				}
				mailerConfig.LimitInterval = limitInterval
			}
			if smtpConfig.LimitBurst <= 0 {
				mailerConfig.LimitBurst = 20
			} else {
				mailerConfig.LimitBurst = smtpConfig.LimitBurst
			}
			mailer, err := NewMailer(mailerConfig)
			if err != nil {
				return nil, err
			}
			nbrew.Mailer = mailer
		}
	}

	// Proxy.
	b, err = os.ReadFile(filepath.Join(configDir, "proxy.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "proxy.json"), err)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 {
		var proxyConfig ProxyConfig
		decoder := json.NewDecoder(bytes.NewReader(b))
		err := decoder.Decode(&proxyConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "proxy.json"), err)
		}
		nbrew.ProxyConfig.RealIPHeaders = make(map[netip.Addr]string)
		for ip, header := range proxyConfig.RealIPHeaders {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, fmt.Errorf("%s: realIPHeaders: %s: %w", filepath.Join(configDir, "proxy.json"), ip, err)
			}
			nbrew.ProxyConfig.RealIPHeaders[addr] = header
		}
		nbrew.ProxyConfig.ProxyIPs = make(map[netip.Addr]struct{})
		for _, ip := range proxyConfig.ProxyIPs {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, fmt.Errorf("%s: proxyIPs: %s: %w", filepath.Join(configDir, "proxy.json"), ip, err)
			}
			nbrew.ProxyConfig.ProxyIPs[addr] = struct{}{}
		}
	}

	// Monitoring.
	b, err = os.ReadFile(filepath.Join(configDir, "monitoring.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "monitoring.json"), err)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 {
		var monitoringConfig MonitoringConfig
		decoder := json.NewDecoder(bytes.NewReader(b))
		err := decoder.Decode(&monitoringConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "monitoring.json"), err)
		}
		nbrew.MonitoringConfig.Email = monitoringConfig.Email
	}

	// Content Security Policy.
	var buf strings.Builder
	// default-src
	buf.WriteString("default-src 'none';")
	// script-src
	buf.WriteString(" script-src 'self' 'unsafe-hashes' " + notebrewJSHash)
	if value := csp["script-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if value := nbrew.CaptchaConfig.CSP["script-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	// connect-src
	buf.WriteString(" connect-src 'self'")
	if value := csp["connect-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if value := nbrew.CaptchaConfig.CSP["connect-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	// img-src
	buf.WriteString(" img-src 'self' data:")
	if value := csp["img-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if nbrew.CDNDomain != "" {
		buf.WriteString(" " + nbrew.CDNDomain)
	}
	buf.WriteString(";")
	// media-src
	buf.WriteString(" media-src 'self'")
	if value := csp["media-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if nbrew.CDNDomain != "" {
		buf.WriteString(" " + nbrew.CDNDomain)
	}
	buf.WriteString(";")
	// style-src
	buf.WriteString(" style-src 'self' 'unsafe-inline'")
	if value := csp["style-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if value := nbrew.CaptchaConfig.CSP["style-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	// base-uri
	buf.WriteString(" base-uri 'self';")
	// form-action
	buf.WriteString(" form-action 'self'")
	if value := csp["form-action"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	// manifest-src
	buf.WriteString(" manifest-src 'self';")
	// frame-src
	buf.WriteString(" frame-src 'self'")
	if value := csp["frame-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if value := nbrew.CaptchaConfig.CSP["frame-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	// font-src
	buf.WriteString(" font-src 'self';")
	nbrew.ContentSecurityPolicy = buf.String()
	return nbrew, nil
}

// IsKeyViolation returns true if the provided errorCode matches the
// dialect-specific code for representing a primary key/unique constraint
// violation.
func IsKeyViolation(dialect string, errorCode string) bool {
	switch dialect {
	case "sqlite":
		return errorCode == "1555" || errorCode == "2067" // SQLITE_CONSTRAINT_PRIMARYKEY, SQLITE_CONSTRAINT_UNIQUE
	case "postgres":
		return errorCode == "23505" // unique_violation
	case "mysql":
		return errorCode == "1062" // ER_DUP_ENTRY
	case "sqlserver":
		return errorCode == "2627"
	default:
		return false
	}
}

// Close shuts down the notebrew instance as well as any background jobs it may
// have spawned.
func (nbrew *Notebrew) Close() error {
	nbrew.backgroundCancel()
	defer nbrew.BackgroundWaitGroup.Wait()
	var firstErr error
	if nbrew.Dialect == "sqlite" {
		_, err := nbrew.DB.Exec("PRAGMA optimize")
		if err != nil {
			firstErr = err
		}
	}
	if nbrew.Mailer != nil {
		err := nbrew.Mailer.Close()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if nbrew.DB != nil {
		err := nbrew.DB.Close()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if nbrew.MaxMindDBReader != nil {
		err := nbrew.MaxMindDBReader.Close()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// User represents a user in the users table.
type User struct {
	// UserID uniquely identifies a user. It cannot be changed.
	UserID ID `json:"userID"`

	// Username uniquely identifies a user. It can be changed.
	Username string `json:"username"`

	// Email uniquely identifies a user. It can be changed.
	Email string `json:"email"`

	// TimezoneOffsetSeconds represents a user's preferred timezone offset in
	// seconds.
	TimezoneOffsetSeconds int `json:"timezoneOffsetSeconds"`

	// Is not empty, DisableReason is the reason why the user's account is
	// marked as disabled.
	DisableReason string `json:"disableReason"`

	// SiteLimit is the limit on the number of sites the user can create.
	SiteLimit int64 `json:"siteLimit"`

	// StorageLimit is the limit on the amount of storage the user can use.
	StorageLimit int64 `json:"storageLimit"`

	// UserFlags are various properties on a user that may be enabled or
	// disabled e.g. UploadImages.
	UserFlags map[string]bool `json:"userFlags"`
}

type contextKey struct{}

// LoggerKey is the key used by notebrew for setting and getting a logger from
// the request context.
var LoggerKey = &contextKey{}

// GetLogger is a syntactic sugar operation for getting a request-specific
// logger from the context, or else it returns the default logger.
func (nbrew *Notebrew) GetLogger(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(LoggerKey).(*slog.Logger); ok {
		return logger
	}
	return nbrew.Logger
}

// SetFlashSession writes a value into the user's flash session.
func (nbrew *Notebrew) SetFlashSession(w http.ResponseWriter, r *http.Request, flashSetter string, value any) error {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(&value)
	if err != nil {
		return stacktrace.New(err)
	}
	if devMode {
		os.Stderr.WriteString(buf.String())
	}
	var flashTokenBytes [8 + 16]byte
	binary.BigEndian.PutUint64(flashTokenBytes[:8], uint64(time.Now().Unix()))
	_, err = rand.Read(flashTokenBytes[8:])
	if err != nil {
		return stacktrace.New(err)
	}
	var flashTokenHash [8 + blake2b.Size256]byte
	checksum := blake2b.Sum256(flashTokenBytes[8:])
	copy(flashTokenHash[:8], flashTokenBytes[:8])
	copy(flashTokenHash[8:], checksum[:])
	_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
		Dialect: nbrew.Dialect,
		Format:  "INSERT INTO flash (flash_token_hash, flash_setter, data) VALUES ({flashTokenHash}, {flashSetter}, {data})",
		Values: []any{
			sq.BytesParam("flashTokenHash", flashTokenHash[:]),
			sq.StringParam("flashSetter", flashSetter),
			sq.StringParam("data", strings.TrimSpace(buf.String())),
		},
	})
	if err != nil {
		return stacktrace.New(err)
	}
	http.SetCookie(w, &http.Cookie{
		Path:     "/",
		Name:     "flash",
		Value:    strings.TrimLeft(hex.EncodeToString(flashTokenBytes[:]), "0"),
		Secure:   r.TLS != nil,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// GetFlashSession retrieves a value from the user's flash session, unmarshals
// it into the valuePtr and then deletes the session. It returns a boolean
// result indicating if a flash session was retrieved.
func (nbrew *Notebrew) GetFlashSession(w http.ResponseWriter, r *http.Request, flashGetter string, responsePtr any, flashDataPtr *map[string]any) (status int, err error) {
	cookie, _ := r.Cookie("flash")
	if cookie == nil {
		return -1, nil
	}
	http.SetCookie(w, &http.Cookie{
		Path:     "/",
		Name:     "flash",
		Value:    "0",
		MaxAge:   -1,
		Secure:   r.TLS != nil,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	flashToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
	if err != nil {
		return -1, nil
	}
	creationTime := time.Unix(int64(binary.BigEndian.Uint64(flashToken[:8])), 0).UTC()
	if time.Since(creationTime) > 5*time.Minute {
		return -1, nil
	}
	var flashTokenHash [8 + blake2b.Size256]byte
	checksum := blake2b.Sum256(flashToken[8:])
	copy(flashTokenHash[:8], flashToken[:8])
	copy(flashTokenHash[8:], checksum[:])
	var flashSetter string
	var data []byte
	switch nbrew.Dialect {
	case "sqlite", "postgres":
		result, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "DELETE FROM flash WHERE flash_token_hash = {flashTokenHash} RETURNING {*}",
			Values: []any{
				sq.BytesParam("flashTokenHash", flashTokenHash[:]),
			},
		}, func(row *sq.Row) (result struct {
			FlashSetter string
			Data        []byte
		}) {
			result.FlashSetter = row.String("flash_setter")
			result.Data = row.Bytes(nil, "data")
			return result
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return -1, nil
			}
			return -1, stacktrace.New(err)
		}
		flashSetter = result.FlashSetter
		data = result.Data
	default:
		result, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "SELECT {*} FROM flash WHERE flash_token_hash = {flashTokenHash}",
			Values: []any{
				sq.BytesParam("flashTokenHash", flashTokenHash[:]),
			},
		}, func(row *sq.Row) (result struct {
			FlashSetter string
			Data        []byte
		}) {
			result.FlashSetter = row.String("name")
			result.Data = row.Bytes(nil, "data")
			return result
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return -1, nil
			}
			return -1, stacktrace.New(err)
		}
		_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "DELETE FROM flash WHERE flash_token_hash = {flashTokenHash}",
			Values: []any{
				sq.BytesParam("flashTokenHash", flashTokenHash[:]),
			},
		})
		if err != nil {
			return -1, stacktrace.New(err)
		}
		flashSetter = result.FlashSetter
		data = result.Data
	}
	if flashSetter == flashGetter {
		err := json.Unmarshal(data, responsePtr)
		if err != nil {
			return 1, stacktrace.New(err)
		}
		return 1, nil
	}
	err = json.Unmarshal(data, flashDataPtr)
	if err != nil {
		return 0, stacktrace.New(err)
	}
	return 0, nil
}

// urlReplacer escapes special characters in a URL for http.Redirect.
var urlReplacer = strings.NewReplacer("#", "%23", "%", "%25")

// markdownTextOnly takes in a markdown snippet and extracts the text only,
// removing any markup.
func markdownTextOnly(parser parser.Parser, src []byte) string {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	var node ast.Node
	nodes := []ast.Node{
		parser.Parse(text.NewReader(src)),
	}
	for len(nodes) > 0 {
		node, nodes = nodes[len(nodes)-1], nodes[:len(nodes)-1]
		switch node := node.(type) {
		case nil:
			continue
		case *ast.Image, *ast.CodeBlock, *ast.FencedCodeBlock, *ast.HTMLBlock:
			nodes = append(nodes, node.NextSibling())
		case *ast.Text:
			buf.Write(node.Value(src))
			nodes = append(nodes, node.NextSibling(), node.FirstChild())
		default:
			nodes = append(nodes, node.NextSibling(), node.FirstChild())
		}
	}
	// Manually escape backslashes (goldmark may be able to do this,
	// investigate).
	var b strings.Builder
	b.Grow(buf.Len())
	output := buf.Bytes()
	// Jump to the location of each backslash found in the output.
	for i := bytes.IndexByte(output, '\\'); i >= 0; i = bytes.IndexByte(output, '\\') {
		b.Write(output[:i])
		char, width := utf8.DecodeRune(output[i+1:])
		if char != utf8.RuneError {
			b.WriteRune(char)
		}
		output = output[i+1+width:]
	}
	b.Write(output)
	return b.String()
}

// isURLUnsafe is a rune-to-bool mapping indicating if a rune is unsafe for
// URLs.
var isURLUnsafe = [...]bool{
	' ': true, '!': true, '"': true, '#': true, '$': true, '%': true, '&': true, '\'': true,
	'(': true, ')': true, '*': true, '+': true, ',': true, '/': true, ':': true, ';': true,
	'<': true, '>': true, '=': true, '?': true, '[': true, ']': true, '\\': true, '^': true,
	'`': true, '{': true, '}': true, '|': true, '~': true,
}

// urlSafe sanitizes a string to make it url-safe by removing any url-unsafe
// characters.
func urlSafe(s string) string {
	s = strings.TrimSpace(s)
	var count int
	var b strings.Builder
	b.Grow(len(s))
	for _, char := range s {
		if count >= 80 {
			break
		}
		if char == ' ' {
			b.WriteRune('-')
			count++
			continue
		}
		if char == '-' || (char >= '0' && char <= '9') || (char >= 'a' && char <= 'z') {
			b.WriteRune(char)
			count++
			continue
		}
		if char >= 'A' && char <= 'Z' {
			b.WriteRune(unicode.ToLower(char))
			count++
			continue
		}
		n := int(char)
		if n < len(isURLUnsafe) && isURLUnsafe[n] {
			continue
		}
		b.WriteRune(char)
		count++
	}
	return strings.Trim(b.String(), ".")
}

// filenameReplacementChars is a map of filename-unsafe runes to their
// filename-safe replacements. Reference: https://stackoverflow.com/a/31976060.
var filenameReplacementChars = [...]rune{
	'<':  '＜', // U+FF1C, FULLWIDTH LESS-THAN SIGN
	'>':  '＞', // U+FF1E, FULLWIDTH GREATER-THAN SIGN
	':':  '꞉', // U+A789, MODIFIER LETTER COLON
	'"':  '″', // U+2033, DOUBLE PRIME
	'/':  '／', // U+FF0F, FULLWIDTH SOLIDUS
	'\\': '＼', // U+FF3C, FULLWIDTH REVERSE SOLIDUS
	'|':  '│', // U+2502, BOX DRAWINGS LIGHT VERTICAL
	'?':  '？', // U+FF1F, FULLWIDTH QUESTION MARK
	'*':  '∗', // U+2217, ASTERISK OPERATOR
	// NOTE: Hex is technically not filename-unsafe, but is does not get
	// properly escaped in URLs because it gets mistaken as the fragment
	// identifier so we need to replace it too.
	'#': '＃', // U+FF03, FULLWIDTH NUMBER SIGN
}

// filenameSafe makes a string safe for use in filenames by replacing any
// filename-unsafe characters to their filename-safe equivalents.
func filenameSafe(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, char := range s {
		if char >= 0 && char <= 31 {
			continue
		}
		n := int(char)
		if n >= len(filenameReplacementChars) {
			b.WriteRune(char)
			continue
		}
		replacementChar := filenameReplacementChars[n]
		if replacementChar == 0 {
			b.WriteRune(char)
			continue
		}
		b.WriteRune(replacementChar)
	}
	return strings.Trim(b.String(), ".")
}

var hashPool = sync.Pool{
	New: func() any {
		hash, err := blake2b.New256(nil)
		if err != nil {
			panic(err)
		}
		return hash
	},
}

var readerPool = sync.Pool{
	New: func() any {
		return bufio.NewReaderSize(nil, 512)
	},
}

// ExecuteTemplate renders a given template with the given data into the
// ResponseWriter, but it first buffers the HTML output so that it can detect
// if any template errors occurred, and if so return 500 Internal Server Error
// instead. Additionally, it does on-the-fly gzipping of the HTML response as
// well as calculating the ETag so that the HTML may be cached by the client.
func (nbrew *Notebrew) ExecuteTemplate(w http.ResponseWriter, r *http.Request, tmpl *template.Template, data any) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	hasher := hashPool.Get().(hash.Hash)
	defer func() {
		hasher.Reset()
		hashPool.Put(hasher)
	}()
	multiWriter := io.MultiWriter(buf, hasher)
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(multiWriter)
	defer func() {
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
	}()
	err := tmpl.Execute(gzipWriter, data)
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		if devMode {
			fmt.Printf("%#v", data)
		}
		nbrew.InternalServerError(w, r, err)
		return
	}
	err = gzipWriter.Close()
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	var b [blake2b.Size256]byte
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(buf.Bytes()))
}

// ContentBaseURL returns the content site's base URL (starting with http:// or
// https://) for a given site prefix.
func (nbrew *Notebrew) ContentBaseURL(sitePrefix string) string {
	if strings.Contains(sitePrefix, ".") {
		return "https://" + sitePrefix
	}
	if nbrew.CMSDomain == "localhost" || strings.HasPrefix(nbrew.CMSDomain, "localhost:") {
		if sitePrefix != "" {
			return "http://" + strings.TrimPrefix(sitePrefix, "@") + "." + nbrew.CMSDomain
		}
		return "http://" + nbrew.CMSDomain
	}
	if sitePrefix != "" {
		return "https://" + strings.TrimPrefix(sitePrefix, "@") + "." + nbrew.ContentDomain
	}
	return "https://" + nbrew.ContentDomain
}

// GetReferer is like (*http.Request).Referer() except it returns an empty
// string if the referer is the same as the current page's URL so that the user
// doesn't keep pressing back to the same page.
func (nbrew *Notebrew) GetReferer(r *http.Request) string {
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer
	//
	// "The Referer header can contain an origin, path, and querystring, and
	// may not contain URL fragments (i.e. #section) or username:password
	// information."
	referer := r.Referer()
	uri := *r.URL
	if r.TLS == nil {
		uri.Scheme = "http"
	} else {
		uri.Scheme = "https"
	}
	uri.Host = r.Host
	uri.Fragment = ""
	uri.User = nil
	if referer == uri.String() {
		return ""
	}
	return referer
}

type ResponseContext struct {
	CleanPath     string       `json:"cleanPath"`
	CDNDomain     string       `json:"cdnDomain"`
	UserID        ID           `json:"userID"`
	Username      string       `json:"username"`
	DisableReason string       `json:"disableReason"`
	DevMode       bool         `json:"-"`
	StylesCSS     template.CSS `json:"-"`
	NotebrewJS    template.JS  `json:"-"`
	Referer       string       `json:"-"`
}

func (v ResponseContext) GoString() string {
	type ResponseContext2 ResponseContext
	v2 := ResponseContext2(v)
	if v2.StylesCSS != "" {
		v2.StylesCSS = template.CSS(fmt.Sprintf("<redacted len=%d>", len(v2.StylesCSS)))
	}
	if v2.NotebrewJS != "" {
		v2.NotebrewJS = template.JS(fmt.Sprintf("<redacted len=%d>", len(v2.NotebrewJS)))
	}
	return fmt.Sprintf("%#v", v2)
}

var (
	baseTemplatePaths = []string{"embed/icons.html", "embed/base.html"}
	templateMap       = map[string]*template.Template{}
	funcMap           = map[string]any{
		"join":                  path.Join,
		"dir":                   path.Dir,
		"base":                  path.Base,
		"ext":                   path.Ext,
		"hasPrefix":             strings.HasPrefix,
		"hasSuffix":             strings.HasSuffix,
		"trimPrefix":            strings.TrimPrefix,
		"trimSuffix":            strings.TrimSuffix,
		"contains":              strings.Contains,
		"joinStrings":           strings.Join,
		"toLower":               strings.ToLower,
		"toUpper":               strings.ToUpper,
		"humanReadableFileSize": HumanReadableFileSize,
		"safeHTML":              func(s string) template.HTML { return template.HTML(s) },
		"float64ToInt64":        func(n float64) int64 { return int64(n) },
		"incr":                  func(n int) int { return n + 1 },
		"formatTime": func(t time.Time, layout string, offset int) string {
			return t.In(time.FixedZone("", offset)).Format(layout)
		},
		"formatTimezone": func(offset int) string {
			sign := "+"
			seconds := offset
			if offset < 0 {
				sign = "-"
				seconds = -offset
			}
			hours := seconds / 3600
			minutes := (seconds % 3600) / 60
			return fmt.Sprintf("%s%02d:%02d", sign, hours, minutes)
		},
		"head": func(s string) string {
			head, _, _ := strings.Cut(s, "/")
			return head
		},
		"tail": func(s string) string {
			_, tail, _ := strings.Cut(s, "/")
			return tail
		},
		"jsonArray": func(s []string) (string, error) {
			b, err := json.Marshal(s)
			if err != nil {
				return "", err
			}
			return string(b), nil
		},
	}
)

func init() {
	matches, err := fs.Glob(runtimeFS, "embed/*.html")
	if err != nil {
		panic(err)
	}
	for _, match := range matches {
		tmpl := template.New(path.Base(match))
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(runtimeFS, match))
		templateMap[path.Base(match)] = tmpl
	}
}

// HumanReadableFileSize returns a human readable file size of an int64 size in
// bytes.
func HumanReadableFileSize(size int64) string {
	// https://yourbasic.org/golang/formatting-byte-size-to-human-readable-format/
	if size < 0 {
		return ""
	}
	const unit = 1000
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "kMGTPE"[exp])
}

// BadRequest indicates that something was wrong with the request data.
func (nbrew *Notebrew) BadRequest(w http.ResponseWriter, r *http.Request, serverErr error) {
	var message string
	var maxBytesErr *http.MaxBytesError
	if errors.As(serverErr, &maxBytesErr) {
		message = "payload is too big (max " + HumanReadableFileSize(maxBytesErr.Limit) + ")"
	} else {
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if contentType == "application/json" {
			switch serverErr {
			case io.EOF:
				message = "missing JSON body"
			case io.ErrUnexpectedEOF:
				message = "malformed JSON"
			default:
				message = serverErr.Error()
			}
		} else {
			message = serverErr.Error()
		}
	}
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error":   "BadRequest",
			"message": message,
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	tmpl := templateMap["error.html"]
	if devMode {
		tmpl = template.New("error.html")
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(runtimeFS, "embed/error.html"))
	}
	err := tmpl.Execute(buf, map[string]any{
		"ResponseContext": ResponseContext{
			DevMode:    devMode,
			StylesCSS:  template.CSS(stylesCSS),
			NotebrewJS: template.JS(notebrewJS),
			Referer:    r.Referer(),
		},
		"Title":    "400 bad request",
		"Headline": "400 bad request",
		"Byline":   message,
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "BadRequest: "+message, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusBadRequest)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// NotAuthenticated indicates that the user is not logged in.
func (nbrew *Notebrew) NotAuthenticated(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error": "NotAuthenticated",
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	var query string
	if r.Method == "GET" {
		if r.URL.RawQuery != "" {
			query = "?redirect=" + url.QueryEscape(r.URL.Path+"?"+r.URL.RawQuery)
		} else {
			query = "?redirect=" + url.QueryEscape(r.URL.Path)
		}
	}
	tmpl := templateMap["error.html"]
	if devMode {
		tmpl = template.New("error.html")
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(runtimeFS, "embed/error.html"))
	}
	err := tmpl.Execute(buf, map[string]any{
		"ResponseContext": ResponseContext{
			DevMode:    devMode,
			StylesCSS:  template.CSS(stylesCSS),
			NotebrewJS: template.JS(notebrewJS),
			Referer:    r.Referer(),
		},
		"Title":    "401 unauthorized",
		"Headline": "401 unauthorized",
		"Byline":   fmt.Sprintf("You are not authenticated, please <a href='/cms/login/%s' class='link'>log in</a>.", query),
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "NotAuthenticated", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusUnauthorized)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// NotAuthorized indicates that the user is logged in, but is not authorized to
// view the current page or perform the current action.
func (nbrew *Notebrew) NotAuthorized(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error": "NotAuthorized",
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	var byline string
	if r.Method == "GET" || r.Method == "HEAD" {
		byline = "You do not have permission to view this page (try logging in to a different account)."
	} else {
		byline = "You do not have permission to perform that action (try logging in to a different account)."
	}
	tmpl := templateMap["error.html"]
	if devMode {
		tmpl = template.New("error.html")
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(runtimeFS, "embed/error.html"))
	}
	err := tmpl.Execute(buf, map[string]any{
		"ResponseContext": ResponseContext{
			DevMode:    devMode,
			StylesCSS:  template.CSS(stylesCSS),
			NotebrewJS: template.JS(notebrewJS),
			Referer:    r.Referer(),
		},
		"Referer":  nbrew.GetReferer(r),
		"Title":    "403 forbidden",
		"Headline": "403 forbidden",
		"Byline":   byline,
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "NotAuthorized", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusForbidden)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// NotFound indicates that a URL does not exist.
func (nbrew *Notebrew) NotFound(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error": "NotFound",
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	tmpl := templateMap["error.html"]
	if devMode {
		tmpl = template.New("error.html")
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(runtimeFS, "embed/error.html"))
	}
	err := tmpl.Execute(buf, map[string]any{
		"ResponseContext": ResponseContext{
			DevMode:    devMode,
			StylesCSS:  template.CSS(stylesCSS),
			NotebrewJS: template.JS(notebrewJS),
			Referer:    r.Referer(),
		},
		"Referer":  nbrew.GetReferer(r),
		"Title":    "404 not found",
		"Headline": "404 not found",
		"Byline":   "The page you are looking for does not exist.",
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "NotFound", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusNotFound)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// MethodNotAllowed indicates that the request method is not allowed.
func (nbrew *Notebrew) MethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error":  "MethodNotAllowed",
			"method": r.Method,
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	tmpl := templateMap["error.html"]
	if devMode {
		tmpl = template.New("error.html")
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(runtimeFS, "embed/error.html"))
	}
	err := tmpl.Execute(buf, map[string]any{
		"ResponseContext": ResponseContext{
			DevMode:    devMode,
			StylesCSS:  template.CSS(stylesCSS),
			NotebrewJS: template.JS(notebrewJS),
			Referer:    r.Referer(),
		},
		"Referer":  nbrew.GetReferer(r),
		"Title":    "405 method not allowed",
		"Headline": "405 method not allowed: " + r.Method,
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "NotFound", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusMethodNotAllowed)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// UnsupportedContentType indicates that the request did not send a supported
// Content-Type.
func (nbrew *Notebrew) UnsupportedContentType(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")
	var message string
	if contentType == "" {
		message = "missing Content-Type"
	} else {
		message = "unsupported Content-Type: " + contentType
	}
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnsupportedMediaType)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"ResponseContext": ResponseContext{
				DevMode:    devMode,
				StylesCSS:  template.CSS(stylesCSS),
				NotebrewJS: template.JS(notebrewJS),
				Referer:    r.Referer(),
			},
			"error":   "UnsupportedMediaType",
			"message": message,
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	tmpl := templateMap["error.html"]
	if devMode {
		tmpl = template.New("error.html")
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(runtimeFS, "embed/error.html"))
	}
	err := tmpl.Execute(buf, map[string]any{
		"ResponseContext": ResponseContext{
			DevMode:    devMode,
			StylesCSS:  template.CSS(stylesCSS),
			NotebrewJS: template.JS(notebrewJS),
			Referer:    r.Referer(),
		},
		"Referer":  nbrew.GetReferer(r),
		"Title":    "415 unsupported media type",
		"Headline": message,
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "UnsupportedMediaType "+message, http.StatusUnsupportedMediaType)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusUnsupportedMediaType)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// InternalServerError is a catch-all handler for catching server errors and
// displaying it to the user.
//
// This includes the error message as well as the stack trace and notebrew
// version, in hopes that a user will be able to give developers the detailed
// error and trace in order to diagnose the problem faster.
func (nbrew *Notebrew) InternalServerError(w http.ResponseWriter, r *http.Request, serverErr error) {
	if serverErr == nil {
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	var errmsg string
	var callers []string
	var stackTraceErr *stacktrace.Error
	if errors.As(serverErr, &stackTraceErr) {
		errmsg = stackTraceErr.Err.Error()
		callers = stackTraceErr.Callers
	} else {
		errmsg = serverErr.Error()
		var pc [30]uintptr
		n := runtime.Callers(2, pc[:]) // skip runtime.Callers + InternalServerError
		callers = make([]string, 0, n)
		frames := runtime.CallersFrames(pc[:n])
		for frame, more := frames.Next(); more; frame, more = frames.Next() {
			callers = append(callers, frame.File+":"+strconv.Itoa(frame.Line))
		}
	}
	isDeadlineExceeded := errors.Is(serverErr, context.DeadlineExceeded)
	isCanceled := errors.Is(serverErr, context.Canceled)
	if nbrew.MonitoringConfig.Email != "" && nbrew.Mailer != nil && !isDeadlineExceeded && !isCanceled {
		nbrew.BackgroundWaitGroup.Add(1)
		go func() {
			defer func() {
				if v := recover(); v != nil {
					fmt.Println(stacktrace.New(fmt.Errorf("panic: %v", v)))
				}
			}()
			defer nbrew.BackgroundWaitGroup.Done()
			var b strings.Builder
			b.WriteString(nbrew.CMSDomain + ": internal server error")
			b.WriteString("\r\n")
			b.WriteString("\r\n" + errmsg)
			b.WriteString("\r\n")
			b.WriteString("\r\nstack trace:")
			for _, caller := range callers {
				b.WriteString("\r\n" + caller)
			}
			b.WriteString("\r\n")
			mail := Mail{
				MailFrom: nbrew.MailFrom,
				RcptTo:   nbrew.MonitoringConfig.Email,
				Headers: []string{
					"Subject", "notebrew: " + nbrew.CMSDomain + ": internal server error: " + errmsg,
					"Content-Type", "text/plain; charset=utf-8",
				},
				Body: strings.NewReader(b.String()),
			}
			select {
			case <-nbrew.BackgroundContext.Done():
			case nbrew.Mailer.C <- mail:
			}
		}()
	}
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error":   "InternalServerError",
			"message": errmsg,
			"callers": callers,
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	var data map[string]any
	responseContext := ResponseContext{
		DevMode:    devMode,
		StylesCSS:  template.CSS(stylesCSS),
		NotebrewJS: template.JS(notebrewJS),
		Referer:    r.Referer(),
	}
	if isDeadlineExceeded {
		data = map[string]any{
			"ResponseContext": responseContext,
			"Referer":         nbrew.GetReferer(r),
			"Title":           "deadline exceeded",
			"Headline":        "The server took too long to process your request.",
			"Details":         errmsg,
			"Callers":         callers,
		}
	} else {
		data = map[string]any{
			"ResponseContext": responseContext,
			"Referer":         nbrew.GetReferer(r),
			"Title":           "500 internal server error",
			"Headline":        "500 internal server error",
			"Byline":          "There's a bug with notebrew.",
			"Details":         errmsg,
			"Callers":         callers,
		}
	}
	tmpl := templateMap["error.html"]
	if devMode {
		tmpl = template.New("error.html")
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(runtimeFS, "embed/error.html"))
	}
	err := tmpl.Execute(buf, data)
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "ServerError", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusInternalServerError)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// ErrStorageLimitExceeded is the error returned by an operation if a user
// exceeded their storage limit during the operation.
var ErrStorageLimitExceeded = fmt.Errorf("storage limit exceeded")

// StorageLimitExceeded indicates that the user exceeded their storage limit.
func (nbrew *Notebrew) StorageLimitExceeded(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInsufficientStorage)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error": "StorageLimitExceeded",
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	tmpl := templateMap["error.html"]
	if devMode {
		tmpl = template.New("error.html")
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(runtimeFS, "embed/error.html"))
	}
	err := tmpl.Execute(buf, map[string]any{
		"ResponseContext": ResponseContext{
			DevMode:    devMode,
			StylesCSS:  template.CSS(stylesCSS),
			NotebrewJS: template.JS(notebrewJS),
			Referer:    r.Referer(),
		},
		"Referer":  r.Referer(),
		"Title":    "507 insufficient storage",
		"Headline": "507 insufficient storage",
		"Byline":   "You have exceeded your storage limit.",
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "StorageLimitExceeded", http.StatusInsufficientStorage)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusInsufficientStorage)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// AccountDisabled indicates that a user's account is disabled.
func (nbrew *Notebrew) AccountDisabled(w http.ResponseWriter, r *http.Request, disableReason string) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error":         "AccountDisabled",
			"disableReason": disableReason,
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	tmpl := templateMap["error.html"]
	if devMode {
		tmpl = template.New("error.html")
		tmpl.Funcs(funcMap)
		template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
		template.Must(tmpl.ParseFS(runtimeFS, "embed/error.html"))
	}
	err := tmpl.Execute(buf, map[string]any{
		"ResponseContext": ResponseContext{
			DevMode:    devMode,
			StylesCSS:  template.CSS(stylesCSS),
			NotebrewJS: template.JS(notebrewJS),
			Referer:    r.Referer(),
		},
		"Referer":  r.Referer(),
		"Title":    "403 Forbidden",
		"Headline": "403 Forbidden",
		"Byline":   "Your account has been disabled.",
		"Details":  "disable reason: " + disableReason,
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "AccountDisabled", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusForbidden)
	buf.WriteTo(w)
}

// LimitedWriter is the missing counterpart of LimitedReader from the stdlib.
// https://github.com/golang/go/issues/54111#issuecomment-1220793565
type LimitedWriter struct {
	W   io.Writer // underlying writer
	N   int64     // max bytes remaining
	Err error     // error to be returned once limit is reached
}

// Write implements io.Writer.
func (lw *LimitedWriter) Write(p []byte) (int, error) {
	if lw.N < 1 {
		return 0, lw.Err
	}
	if lw.N < int64(len(p)) {
		p = p[:lw.N]
	}
	n, err := lw.W.Write(p)
	lw.N -= int64(n)
	return n, err
}

// RealClientIP returns the real client IP of the request.
func RealClientIP(r *http.Request, realIPHeaders map[netip.Addr]string, proxyIPs map[netip.Addr]struct{}) netip.Addr {
	// Reference: https://adam-p.ca/blog/2022/03/x-forwarded-for/
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	remoteAddr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return netip.Addr{}
	}
	// If we don't have any proxy servers configured (i.e. we are directly
	// connected to the internet), treat remoteAddr as the real client IP.
	if len(realIPHeaders) == 0 && len(proxyIPs) == 0 {
		return remoteAddr
	}
	// If remoteAddr is trusted to populate a known header with the real client
	// IP, look in that header.
	if header, ok := realIPHeaders[remoteAddr]; ok {
		addr, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get(header)))
		if err != nil {
			return netip.Addr{}
		}
		return addr
	}
	// Check X-Forwarded-For header only if remoteAddr is the IP of a proxy
	// server.
	_, ok := proxyIPs[remoteAddr]
	if !ok {
		return remoteAddr
	}
	// Loop over all IP addresses in X-Forwarded-For headers from right to
	// left. We want to rightmost IP address that isn't a proxy server's IP
	// address.
	values := r.Header.Values("X-Forwarded-For")
	for i := len(values) - 1; i >= 0; i-- {
		ips := strings.Split(values[i], ",")
		for j := len(ips) - 1; j >= 0; j-- {
			ip := ips[j]
			addr, err := netip.ParseAddr(strings.TrimSpace(ip))
			if err != nil {
				continue
			}
			_, ok := proxyIPs[addr]
			if ok {
				continue
			}
			return addr
		}
	}
	return netip.Addr{}
}

// MaxMindDBRecord is the struct used to retrieve the country for an IP
// address.
type MaxMindDBRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

var (
	//go:embed embed static
	embedFS embed.FS

	// runtimeFS is the FS containing the runtime files needed by notebrew for
	// operation.
	runtimeFS fs.FS = embedFS

	// devMode indicates if the developer mode is enabled for the current
	// binary.
	devMode = false

	// stylesCSS is the contents of the styles.css file in the embed/
	// directory.
	stylesCSS string

	// stylesCSSHash is the sha256 hash of the StylesCSS contents.
	stylesCSSHash string

	// notebrewJSHash is the sha256 hash of the BaselineJS contents.
	notebrewJS string

	// notebrewJSHash is the sha256 hash of the BaselineJS contents.
	notebrewJSHash string

	// commonPasswords is a set of the top 10,000 most common passwords from
	// top_10000_passwords.txt in the embed/ directory.
	commonPasswords = make(map[string]struct{})

	// countryCodes is the ISO code to country mapping from country_codes.json
	// in the embed/ directory.
	countryCodes map[string]string

	// reservedSubdomains is the list of reserved subdomains that users will
	// not be able to use on the content domain.
	reservedSubdomains = []string{"www", "cdn", "storage", "videocdn", "videostorage"}
)

func init() {
	// styles.css
	b, err := fs.ReadFile(embedFS, "static/styles.css")
	if err != nil {
		panic(err)
	}
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	hash := sha256.Sum256(b)
	stylesCSS = string(b)
	stylesCSSHash = "'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'"
	// notebrew.js
	b, err = fs.ReadFile(embedFS, "static/notebrew.js")
	if err != nil {
		panic(err)
	}
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	hash = sha256.Sum256(b)
	notebrewJS = string(b)
	notebrewJSHash = "'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'"
	// common passwords
	file, err := runtimeFS.Open("embed/top_10000_passwords.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	done := false
	for {
		if done {
			break
		}
		line, err := reader.ReadBytes('\n')
		done = err == io.EOF
		if err != nil && !done {
			panic(err)
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		commonPasswords[string(line)] = struct{}{}
	}
	// country codes
	file, err = runtimeFS.Open("embed/country_codes.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	err = json.NewDecoder(file).Decode(&countryCodes)
	if err != nil {
		panic(err)
	}
}

var chromaStyles = map[string]bool{
	"abap": true, "algol": true, "algol_nu": true, "api": true, "arduino": true,
	"autumn": true, "average": true, "base16-snazzy": true, "borland": true, "bw": true,
	"catppuccin-frappe": true, "catppuccin-latte": true, "catppuccin-macchiato": true,
	"catppuccin-mocha": true, "colorful": true, "compat": true, "doom-one": true,
	"doom-one2": true, "dracula": true, "emacs": true, "friendly": true, "fruity": true,
	"github-dark": true, "github": true, "gruvbox-light": true, "gruvbox": true,
	"hr_high_contrast": true, "hrdark": true, "igor": true, "lovelace": true, "manni": true,
	"modus-operandi": true, "modus-vivendi": true, "monokai": true, "monokailight": true,
	"murphy": true, "native": true, "nord": true, "onedark": true, "onesenterprise": true,
	"paraiso-dark": true, "paraiso-light": true, "pastie": true, "perldoc": true,
	"pygments": true, "rainbow_dash": true, "rose-pine-dawn": true, "rose-pine-moon": true,
	"rose-pine": true, "rrt": true, "solarized-dark": true, "solarized-dark256": true,
	"solarized-light": true, "swapoff": true, "tango": true, "trac": true, "vim": true,
	"vs": true, "vulcan": true, "witchhazel": true, "xcode-dark": true, "xcode": true,
}

var timezoneOffsets = map[string]bool{
	"-12:00": true, "-11:00": true, "-10:00": true, "-09:30": true, "-09:00": true,
	"-08:00": true, "-07:00": true, "-06:00": true, "-05:00": true, "-04:00": true,
	"-03:00": true, "-02:00": true, "-01:00": true, "+00:00": true, "+01:00": true,
	"+02:00": true, "+03:00": true, "+03:30": true, "+04:00": true, "+04:30": true,
	"+05:00": true, "+05:30": true, "+05:45": true, "+06:00": true, "+06:30": true,
	"+07:00": true, "+08:00": true, "+08:45": true, "+09:00": true, "+09:30": true,
	"+10:00": true, "+10:30": true, "+11:00": true, "+12:00": true, "+12:45": true,
	"+13:00": true, "+14:00": true,
}

var languageCodes = map[string]bool{
	"aa": true, "ab": true, "af": true, "ak": true, "am": true, "an": true, "ar": true,
	"as": true, "av": true, "ay": true, "az": true, "ba": true, "be": true, "bg": true,
	"bi": true, "bm": true, "bn": true, "bo": true, "br": true, "bs": true, "ca": true,
	"ce": true, "ch": true, "co": true, "cr": true, "cs": true, "cv": true, "cy": true,
	"da": true, "de": true, "dv": true, "dz": true, "ee": true, "el": true, "en": true,
	"eo": true, "es": true, "et": true, "eu": true, "fa": true, "ff": true, "fi": true,
	"fj": true, "fo": true, "fr": true, "fy": true, "ga": true, "gd": true, "gl": true,
	"gn": true, "gu": true, "gv": true, "ha": true, "he": true, "hi": true, "ho": true,
	"hr": true, "ht": true, "hu": true, "hy": true, "hz": true, "ia": true, "id": true,
	"ie": true, "ig": true, "ii": true, "ik": true, "io": true, "is": true, "it": true,
	"iu": true, "ja": true, "jv": true, "ka": true, "kg": true, "ki": true, "kj": true,
	"kk": true, "kl": true, "km": true, "kn": true, "ko": true, "kr": true, "ks": true,
	"ku": true, "kv": true, "kw": true, "ky": true, "lb": true, "lg": true, "li": true,
	"ln": true, "lo": true, "lt": true, "lu": true, "lv": true, "mg": true, "mh": true,
	"mi": true, "mk": true, "ml": true, "mn": true, "mr": true, "ms": true, "mt": true,
	"my": true, "na": true, "nb": true, "nd": true, "ne": true, "ng": true, "nl": true,
	"nn": true, "no": true, "nr": true, "nv": true, "ny": true, "oc": true, "oj": true,
	"om": true, "or": true, "os": true, "pa": true, "pl": true, "ps": true, "pt": true,
	"qu": true, "rm": true, "rn": true, "ro": true, "ru": true, "rw": true, "sc": true,
	"sd": true, "se": true, "sg": true, "si": true, "sk": true, "sl": true, "sm": true,
	"sn": true, "so": true, "sq": true, "sr": true, "ss": true, "st": true, "su": true,
	"sv": true, "sw": true, "ta": true, "te": true, "tg": true, "th": true, "ti": true,
	"tk": true, "tl": true, "tn": true, "to": true, "tr": true, "ts": true, "tt": true,
	"tw": true, "ty": true, "ug": true, "uk": true, "ur": true, "uz": true, "ve": true,
	"vi": true, "vo": true, "wa": true, "wo": true, "xh": true, "yi": true, "yo": true,
	"za": true, "zh": true, "zu": true,
}

var languageNames = map[string]string{
	"aa": "Afar", "ab": "Abkhazian", "af": "Afrikaans", "ak": "Akan", "am": "Amharic",
	"an": "Aragonese", "ar": "Arabic", "as": "Assamese", "av": "Avaric", "ay": "Aymara",
	"az": "Azerbaijani", "ba": "Bashkir", "be": "Belarusian", "bg": "Bulgarian",
	"bi": "Bislama", "bm": "Bambara", "bn": "Bengali", "bo": "Tibetan", "br": "Breton",
	"bs": "Bosnian", "ca": "Catalan", "ce": "Chechen", "ch": "Chamorro", "co": "Corsican",
	"cr": "Cree", "cs": "Czech", "cv": "Chuvash", "cy": "Welsh", "da": "Danish",
	"de": "German", "dv": "Divehi", "dz": "Dzongkha", "ee": "Ewe", "el": "Greek",
	"en": "English", "eo": "Esperanto", "es": "Spanish", "et": "Estonian", "eu": "Basque",
	"fa": "Persian", "ff": "Fulah", "fi": "Finnish", "fj": "Fijian", "fo": "Faroese",
	"fr": "French", "fy": "Western Frisian", "ga": "Irish", "gd": "Gaelic", "gl": "Galician",
	"gn": "Guarani", "gu": "Gujarati", "gv": "Manx", "ha": "Hausa", "he": "Hebrew",
	"hi": "Hindi", "ho": "Hiri Motu", "hr": "Croatian", "ht": "Haitian", "hu": "Hungarian",
	"hy": "Armenian", "hz": "Herero", "ia": "Interlingua", "id": "Indonesian",
	"ie": "Interlingue", "ig": "Igbo", "ii": "Sichuan Yi", "ik": "Inupiaq", "io": "Ido",
	"is": "Icelandic", "it": "Italian", "iu": "Inuktitut", "ja": "Japanese", "jv": "Javanese",
	"ka": "Georgian", "kg": "Kongo", "ki": "Kikuyu", "kj": "Kuanyama", "kk": "Kazakh",
	"kl": "Kalaallisut", "km": "Central Khmer", "kn": "Kannada", "ko": "Korean", "kr": "Kanuri",
	"ks": "Kashmiri", "ku": "Kurdish", "kv": "Komi", "kw": "Cornish", "ky": "Kirghiz",
	"lb": "Luxembourgish", "lg": "Ganda", "li": "Limburgan", "ln": "Lingala", "lo": "Lao",
	"lt": "Lithuanian", "lu": "Luba-Katanga", "lv": "Latvian", "mg": "Malagasy", "mh": "Marshallese",
	"mi": "Maori", "mk": "Macedonian", "ml": "Malayalam", "mn": "Mongolian", "mr": "Marathi",
	"ms": "Malay", "mt": "Maltese", "my": "Burmese", "na": "Nauru", "nb": "Norwegian Bokmål",
	"nd": "North Ndebele", "ne": "Nepali", "ng": "Ndonga", "nl": "Dutch; Flemish",
	"nn": "Norwegian Nynorsk", "no": "Norwegian", "nr": "South Ndebele", "nv": "Navajo",
	"ny": "Chichewa", "oc": "Occitan", "oj": "Ojibwa", "om": "Oromo", "or": "Oriya", "os": "Ossetian",
	"pa": "Panjabi", "pl": "Polish", "ps": "Pushto", "pt": "Portuguese", "qu": "Quechua",
	"rm": "Romansh", "rn": "Rundi", "ro": "Romanian", "ru": "Russian", "rw": "Kinyarwanda",
	"sc": "Sardinian", "sd": "Sindhi", "se": "Northern Sami", "sg": "Sango", "si": "Sinhala",
	"sk": "Slovak", "sl": "Slovenian", "sm": "Samoan", "sn": "Shona", "so": "Somali",
	"sq": "Albanian", "sr": "Serbian", "ss": "Swati", "st": "Southern Sotho", "su": "Sundanese",
	"sv": "Swedish", "sw": "Swahili", "ta": "Tamil", "te": "Telugu", "tg": "Tajik", "th": "Thai",
	"ti": "Tigrinya", "tk": "Turkmen", "tl": "Tagalog", "tn": "Tswana", "to": "Tonga", "tr": "Turkish",
	"ts": "Tsonga", "tt": "Tatar", "tw": "Twi", "ty": "Tahitian", "ug": "Uighur", "uk": "Ukrainian",
	"ur": "Urdu", "uz": "Uzbek", "ve": "Venda", "vi": "Vietnamese", "vo": "Volapük", "wa": "Walloon",
	"wo": "Wolof", "xh": "Xhosa", "yi": "Yiddish", "yo": "Yoruba", "za": "Zhuang",
	"zh": "Chinese", "zu": "Zulu",
}
