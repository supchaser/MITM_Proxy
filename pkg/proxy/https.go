package proxy

import (
	"MITM_PROXY/pkg/cert"
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
)

func handleHTTPS(clientConn net.Conn, parsedUrl *url.URL, versionProtocol string, reader *bufio.Reader) {
	fmt.Fprintf(clientConn, "%s 200 Connection established\r\n\r\n", versionProtocol)

	host := parsedUrl.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	rawServerConn, err := tls.Dial("tcp", host, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Println("Error connecting to real TLS server:", err)
		return
	}

	caCert, caKey := cert.GetCA()
	if caCert == nil || caKey == nil {
		log.Println("CA not loaded, fallback to simple tunnel for https")
		go io.Copy(rawServerConn, reader)
		io.Copy(clientConn, rawServerConn)
		rawServerConn.Close()
		return
	}

	cert, err := cert.BuildCertificate(parsedUrl.Hostname(), caCert, caKey)
	if err != nil {
		log.Println("Cannot build certificate for host:", parsedUrl.Hostname(), err)
		go io.Copy(rawServerConn, reader)
		io.Copy(clientConn, rawServerConn)
		rawServerConn.Close()
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   parsedUrl.Hostname(),
	}
	tlsConn := tls.Server(clientConn, tlsConfig)

	err = tlsConn.Handshake()
	if err != nil {
		log.Println("TLS handshake with client failed:", err)
		rawServerConn.Close()
		return
	}

	go io.Copy(rawServerConn, tlsConn)
	io.Copy(tlsConn, rawServerConn)

	tlsConn.Close()
	rawServerConn.Close()
}
