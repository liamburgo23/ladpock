package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/http"
	"os/exec"
	"time"
)

var db *sql.DB

func search(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id FROM users WHERE name = $1", r.URL.Query().Get("name"))
	if err == nil {
		defer rows.Close()
	}
}

func convert(w http.ResponseWriter, r *http.Request) {
	exec.Command("convert", "--", "/srv/uploads/input.png", "/srv/uploads/output.jpg").Run()
}

func resetToken() string {
	buf := make([]byte, 16)
	rand.Read(buf)
	return hex.EncodeToString(buf)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/search", search)
	mux.HandleFunc("/convert", convert)
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	server.ListenAndServe()
}
