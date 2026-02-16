package nbi2

import (
	"encoding/json"
	"html/template"
	"net/http"
	"time"
)

func (nbrew *Notebrew) notes(w http.ResponseWriter, r *http.Request, contextData ContextData) {
	type Note struct {
		Title       string    `json:"title"`
		Preview     string    `json:"preview"`
		Thumbnail   string    `json:"thumbnail"`
		DateCreated time.Time `json:"dateCreated"`
		DateEdited  time.Time `json:"dateEdited"`
	}
	type Request struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		CaptchaResponse string `json:"captchaResponse"`
	}
	type Response struct {
		ContextData  ContextData    `json:"contextData"`
		Notes        []Note         `json:"notes"`
		FlashData    map[string]any `json:"-"`
		TemplateData map[string]any `json:"-"`
	}
	// {{- if eq (index $.PostRedirectGet "from") "applytheme" }}
	// {{- if eq (index $.FlashData "name") "applytheme" }}

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
			tmpl := templateMap["notes.html"]
			if devMode {
				tmpl = template.New("notes.html")
				tmpl.Funcs(funcMap)
				template.Must(tmpl.ParseFS(runtimeFS, baseTemplatePaths...))
				template.Must(tmpl.ParseFS(runtimeFS, "embed/notes.html"))
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
		response.Notes = []Note{{
			Title:       "Checklist",
			Preview:     "item 1",
			DateCreated: time.Date(1970, time.January, 01, 0, 0, 0, 0, time.UTC),
			DateEdited:  time.Date(1970, time.January, 01, 0, 0, 0, 0, time.UTC),
		}, {
			Title:       "Singapore places to eat",
			Preview:     "Old school delights",
			DateCreated: time.Date(1970, time.January, 01, 0, 0, 0, 0, time.UTC),
			DateEdited:  time.Date(1970, time.January, 01, 0, 0, 0, 0, time.UTC),
		}, {
			Title:       "Japan shopping list",
			Preview:     "tsutenkaku vegan options, try checking the hot and cold vending machines, uniqlo/GU shorts. Muji linen shorts?",
			DateCreated: time.Date(1970, time.January, 01, 0, 0, 0, 0, time.UTC),
			DateEdited:  time.Date(1970, time.January, 01, 0, 0, 0, 0, time.UTC),
		}, {
			Title:       "Paid",
			Preview:     "Credit Card",
			DateCreated: time.Date(1970, time.January, 01, 0, 0, 0, 0, time.UTC),
			DateEdited:  time.Date(1970, time.January, 01, 0, 0, 0, 0, time.UTC),
		}, {
			Title:       "Pending",
			Preview:     "Bank Transfer",
			DateCreated: time.Date(1970, time.January, 01, 0, 0, 0, 0, time.UTC),
			DateEdited:  time.Date(1970, time.January, 01, 0, 0, 0, 0, time.UTC),
		}, {
			Title:       "Unpaid",
			Preview:     "Credit Card",
			DateCreated: time.Date(1970, time.January, 01, 0, 0, 0, 0, time.UTC),
			DateEdited:  time.Date(1970, time.January, 01, 0, 0, 0, 0, time.UTC),
		}}
		writeResponse(w, r, response)
	case "POST":
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
