package nbi2

import (
	"encoding/json"
	"html/template"
	"net/http"
)

func (nbrew *Notebrew) notes(w http.ResponseWriter, r *http.Request, responseContext ResponseContext) {
	type Request struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		CaptchaResponse string `json:"captchaResponse"`
	}
	type Response struct {
		ResponseContext ResponseContext `json:"responseContext"`
		FlashData       map[string]any  `json:"-"`
		TemplateData    map[string]any  `json:"-"`
	}

	switch r.Method {
	case "GET", "HEAD":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
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
			tmpl := templates["notes.html"]
			if devMode {
				tmpl = template.Must(template.New("notes.html").Funcs(funcMap).ParseFS(runtimeFS, "embed/base.html", "embed/notes.html"))
			}
			w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
			nbrew.ExecuteTemplate(w, r, tmpl, &response)
		}
		var response Response
		_, err := nbrew.GetFlashSession(w, r, "notes", &response, &response.FlashData)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		response.ResponseContext = responseContext
		writeResponse(w, r, response)
	case "POST":
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
