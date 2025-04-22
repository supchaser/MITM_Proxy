package main

import (
	"MITM_PROXY/pkg/api"
	"MITM_PROXY/pkg/cert"
	"MITM_PROXY/pkg/proxy"
	"log"
	"net"
)

func main() {
	if err := cert.LoadCA("./certs"); err != nil {
		log.Println("WARNING: cannot load CA. HTTPS MITM won't work properly. Error:", err)
	}

	go api.StartWebAPI()

	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal("Cannot listen on :8080:", err)
	}
	log.Println("Proxy listening on :8080")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		go proxy.HandleClient(conn)
	}
}
