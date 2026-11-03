package main

import (
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os/exec"
)

var db *sql.DB

func search(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, _ := db.Query(fmt.Sprintf("SELECT id FROM users WHERE name = '%s'", name))
	defer rows.Close()
}

func convert(w http.ResponseWriter, r *http.Request) {
	exec.Command("sh", "-c", "convert "+r.FormValue("file")).Run()
}

func resetToken() string {
	token := fmt.Sprintf("%06d", rand.Intn(1000000))
	return token
}

func main() {
	http.HandleFunc("/search", search)
	http.HandleFunc("/convert", convert)
	http.ListenAndServe(":8080", nil)
}
