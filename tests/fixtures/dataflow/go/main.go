package main

import (
	"net/http"
	"os/exec"
	"strconv"
)

func ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	exec.Command("sh", "-c", "ping -c 1 "+host).Run() // EXPECT command-injection direct
}

func download(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	readUpload(name) // EXPECT path-traversal cross-file
}

func page(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.FormValue("n"))
	db.Query("SELECT * FROM posts LIMIT " + strconv.Itoa(n))
}
