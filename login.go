package nbi2

import (
	"html/template"
	"net/http"
	"net/url"
	"path"
	"strings"
)

func (nbrew *Notebrew) login(w http.ResponseWriter, r *http.Request, responseContext ResponseContext) {
	type Request struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		CaptchaResponse string `json:"captchaResponse"`
	}
	type Response struct {
		ResponseContext        ResponseContext `json:"ResponseContext"`
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
		if r.Host != nbrew.CMSDomain {
			return ""
		}
		uri, err := url.Parse(path.Clean(redirect))
		if err != nil {
			return ""
		}
		head, tail, _ := strings.Cut(strings.Trim(uri.Path, "/"), "/")
		if head != "files" && head != "users" {
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
	case "POST":
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
