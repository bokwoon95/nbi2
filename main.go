package main

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

func main() {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		urlPath := path.Clean(strings.Trim(r.URL.Path, "/"))
		var name string
		if urlPath == "." {
			name = "index.html"
		} else if path.Ext(urlPath) == "" {
			name = urlPath + ".html"
		} else {
			name = urlPath
		}
		file, err := os.Open(name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				http.NotFound(w, r)
				return
			}
			slog.Error(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.ServeContent(w, r, path.Base(name), time.Time{}, file)
	})
	serveMux.HandleFunc("/components", func(w http.ResponseWriter, r *http.Request) {
		funcMap := map[string]any{}
		tmpl, err := template.New("").Funcs(funcMap).ParseFS(embedFS, "embed/base.html", "embed/components.html")
		if err != nil {
			slog.Error(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		b := &bytes.Buffer{}
		err = tmpl.ExecuteTemplate(b, "components.html", nil)
		if err != nil {
			slog.Error(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		b.WriteTo(w)
	})
	serveMux.HandleFunc("/skeleton", func(w http.ResponseWriter, r *http.Request) {
		funcMap := map[string]any{}
		tmpl, err := template.New("").Funcs(funcMap).ParseFS(embedFS, "embed/base.html", "embed/skeleton.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		b := &bytes.Buffer{}
		err = tmpl.ExecuteTemplate(w, "base.html", nil)
		if err != nil {
			slog.Error(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		b.WriteTo(w)
	})
	fmt.Println("listening on :8080")
	http.ListenAndServe(":8080", serveMux)
}
