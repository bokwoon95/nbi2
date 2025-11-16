package nbi2

import (
	"html/template"
	"net/http"
	"net/url"
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
}
