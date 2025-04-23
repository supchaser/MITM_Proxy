package api

import (
	"log"
	"net/http"
)

func StartWebAPI() {
	mux := http.NewServeMux()

	mux.HandleFunc("/requests", getAllRequests)
	mux.HandleFunc("/requests/", getRequestByID)
	mux.HandleFunc("/repeat/", repeatRequest)
	mux.HandleFunc("/scan/", scanRequest)
	mux.HandleFunc("/scan-xxe/{id}", scanXXE)

	log.Println("Web API listening on :8000")
	if err := http.ListenAndServe(":8000", mux); err != nil {
		log.Fatal(err)
	}
}
