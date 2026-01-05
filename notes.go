package nbi2

import (
	"encoding/json"
	"html/template"
	"net/http"
)

func (nbrew *Notebrew) notes(w http.ResponseWriter, r *http.Request, contextData ContextData) {
	type Request struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		CaptchaResponse string `json:"captchaResponse"`
	}
	type Response struct {
		ContextData  ContextData    `json:"contextData"`
		FlashData    map[string]any `json:"-"`
		TemplateData map[string]any `json:"-"`
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
			tmpl := templateMap["notes2.html"]
			if devMode {
				tmpl = template.New("notes2.html")
				tmpl.Funcs(funcMap)
				template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
				template.Must(tmpl.ParseFS(runtimeFS, "embed/notes2.html"))
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
		response.ContextData = contextData
		writeResponse(w, r, response)
	case "POST":
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
