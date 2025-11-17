package nbi2

import (
	"database/sql"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/bokwoon95/nbi2/sq"
)

func (nbrew *Notebrew) login(w http.ResponseWriter, r *http.Request, responseContext ResponseContext) {
	type Request struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		CaptchaResponse string `json:"captchaResponse"`
	}
	type Response struct {
		ResponseContext        ResponseContext `json:"responseContext"`
		HasMailer              bool            `json:"hasMailer"`
		Username               string          `json:"username"`
		RequireCaptcha         bool            `json:"requireCaptcha"`
		CaptchaWidgetScriptSrc template.URL    `json:"captchaWidgetScriptSrc"`
		CaptchaWidgetClass     string          `json:"captchaWidgetClass"`
		CaptchaSiteKey         string          `json:"captchaSiteKey"`
		CaptchaResponseName    string          `json:"captchaResponseName"`
		Error                  string          `json:"error"`
		FormErrors             url.Values      `json:"formErrors"`
		SessionToken           string          `json:"sessionToken"`
		Redirect               string          `json:"redirect"`
		PostRedirectGet        map[string]any  `json:"postRedirectGet"`
	}

	sanitizeRedirect := func(redirect string) string {
		uri, err := url.Parse(path.Clean(redirect))
		if err != nil {
			return ""
		}
		if uri.Host != nbrew.CMSDomain {
			return ""
		}
		head, tail, _ := strings.Cut(strings.Trim(uri.Path, "/"), "/")
		if head != "cms" {
			return ""
		}
		if tail == "" {
			return ""
		}
		uri = &url.URL{
			Path:     strings.Trim(uri.Path, "/"),
			RawQuery: uri.RawQuery,
		}
		if path.Ext(uri.Path) == "" {
			uri.Path = "/" + uri.Path + "/"
		} else {
			uri.Path = "/" + uri.Path
		}
		return uri.String()
	}
	_ = sanitizeRedirect

	switch r.Method {
	case "GET", "HEAD":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			response.CaptchaSiteKey = nbrew.CaptchaConfig.SiteKey
			if nbrew.CaptchaConfig.VerificationURL != "" {
				ip := RealClientIP(r, nbrew.ProxyConfig.RealIPHeaders, nbrew.ProxyConfig.ProxyIPs).As16()
				failedLoginAttempts, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format:  "SELECT {*} FROM ip_login WHERE ip = {ip}",
					Values: []any{
						sq.BytesParam("ip", ip[:]),
					},
				}, func(row *sq.Row) int {
					return row.Int("failed_login_attempts")
				})
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				if failedLoginAttempts >= 3 {
					response.RequireCaptcha = true
				}
			}
			if r.Form.Has("api") {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				if r.Method == "HEAD" {
					w.WriteHeader(http.StatusOK)
					return
				}
				encoder := json.NewEncoder(w)
				encoder.SetIndent("", "  ")
				encoder.SetEscapeHTML(false)
				err := encoder.Encode(&response)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
				}
				return
			}
			tmpl := templates["login.html"]
			if devMode {
				tmpl = template.Must(template.New("login.html").Funcs(funcMap).ParseFS(runtimeFS, "embed/base.html", "embed/login.html"))
			}
			w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
			nbrew.ExecuteTemplate(w, r, tmpl, &response)
		}
		err := r.ParseForm()
		if err != nil {
			nbrew.BadRequest(w, r, err)
			return
		}
		var response Response
		_, err = nbrew.GetFlashSession(w, r, &response)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		response.ResponseContext = responseContext
		response.HasMailer = nbrew.Mailer != nil
		response.CaptchaWidgetScriptSrc = nbrew.CaptchaConfig.WidgetScriptSrc
		response.CaptchaWidgetClass = nbrew.CaptchaConfig.WidgetClass
		response.CaptchaSiteKey = nbrew.CaptchaConfig.SiteKey
		response.CaptchaResponseName = nbrew.CaptchaConfig.ResponseTokenName
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		if r.Form.Has("401") {
			response.Error = "NotAuthenticated"
			writeResponse(w, r, response)
			return
		}
		response.Redirect = sanitizeRedirect(r.Form.Get("redirect"))
		if !responseContext.User.UserID.IsZero() {
			response.Error = "AlreadyAuthenticated"
			writeResponse(w, r, response)
			return
		}
		writeResponse(w, r, response)
	case "POST":
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
