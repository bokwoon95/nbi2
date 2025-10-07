package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
)

var RuntimeFS = os.DirFS(".")

func main() {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		file, err := RuntimeFS.Open("index.html")
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = io.Copy(w, file)
		if err != nil {
			slog.Error(err.Error())
		}
	})
	fmt.Println("listening on :8080")
	http.ListenAndServe(":8080", serveMux)
}
