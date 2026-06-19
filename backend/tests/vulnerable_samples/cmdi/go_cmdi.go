package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	cmd := "ping -c 1 " + host
	exec.Command("sh", "-c", cmd)
}
