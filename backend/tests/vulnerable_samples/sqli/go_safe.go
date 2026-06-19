package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	raw := r.FormValue("id")
	id, _ := strconv.Atoi(raw)
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %d", id)
	db.Query(query)
}
