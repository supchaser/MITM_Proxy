package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type RequestInfo struct {
	ID        int
	Method    string
	URL       string
	Headers   http.Header
	Body      string
	Timestamp time.Time
}

var (
	requests      = make([]*RequestInfo, 0)
	requestsMutex sync.Mutex
)

func addRequest(method, fullURL string, headers http.Header, body string) int {
	requestsMutex.Lock()
	defer requestsMutex.Unlock()

	id := len(requests)
	requests = append(requests, &RequestInfo{
		ID:        id,
		Method:    method,
		URL:       fullURL,
		Headers:   headers.Clone(),
		Body:      body,
		Timestamp: time.Now(),
	})
	return id
}

func getRequestByID(id int) *RequestInfo {
	requestsMutex.Lock()
	defer requestsMutex.Unlock()

	if id < 0 || id >= len(requests) {
		return nil
	}
	return requests[id]
}

func startWebAPI() {
	mux := http.NewServeMux()

	mux.HandleFunc("/requests", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
			return
		}
		requestsMutex.Lock()
		defer requestsMutex.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(requests)
	})

	mux.HandleFunc("/requests/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/requests/"), "/")
		if len(parts) < 1 || parts[0] == "" {
			http.Error(w, "Bad request ID", http.StatusBadRequest)
			return
		}
		idStr := parts[0]

		var id int
		_, err := fmt.Sscanf(idStr, "%d", &id)
		if err != nil {
			http.Error(w, "Bad request ID", http.StatusBadRequest)
			return
		}
		reqInfo := getRequestByID(id)
		if reqInfo == nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(reqInfo)
	})

	mux.HandleFunc("/repeat/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/repeat/"), "/")
		if len(parts) < 1 || parts[0] == "" {
			http.Error(w, "Bad request ID", http.StatusBadRequest)
			return
		}
		idStr := parts[0]
		var id int
		_, err := fmt.Sscanf(idStr, "%d", &id)
		if err != nil {
			http.Error(w, "Bad request ID", http.StatusBadRequest)
			return
		}
		reqInfo := getRequestByID(id)
		if reqInfo == nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		parsed, err := url.Parse(reqInfo.URL)
		if err != nil {
			http.Error(w, "Cannot parse URL", http.StatusBadRequest)
			return
		}

		newReq, err := http.NewRequest(reqInfo.Method, reqInfo.URL, strings.NewReader(reqInfo.Body))
		if err != nil {
			http.Error(w, "Cannot create request", http.StatusInternalServerError)
			return
		}

		for k, vals := range reqInfo.Headers {
			for _, v := range vals {
				newReq.Header.Add(k, v)
			}
		}

		client := &http.Client{}
		resp, err := client.Do(newReq)
		if err != nil {
			http.Error(w, "Error repeating request: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  resp.Status,
			"headers": resp.Header,
			"body":    string(respBody),
			"url":     parsed.String(),
		})
	})

	mux.HandleFunc("/scan/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/scan/"), "/")
		if len(parts) < 1 || parts[0] == "" {
			http.Error(w, "Bad request ID", http.StatusBadRequest)
			return
		}
		idStr := parts[0]
		var id int
		_, err := fmt.Sscanf(idStr, "%d", &id)
		if err != nil {
			http.Error(w, "Bad request ID", http.StatusBadRequest)
			return
		}
		reqInfo := getRequestByID(id)
		if reqInfo == nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		suspicious := []string{"UNION SELECT", "DROP", "alert(", "<script>", "admin' --"}
		found := []string{}
		for _, s := range suspicious {
			if strings.Contains(strings.ToUpper(reqInfo.Body), strings.ToUpper(s)) {
				found = append(found, s)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if len(found) == 0 {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "No obvious injection patterns found",
			})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Potentially dangerous substrings found",
				"found":   found,
			})
		}
	})

	log.Println("Web API listening on :8000")
	if err := http.ListenAndServe(":8000", mux); err != nil {
		log.Fatal(err)
	}
}

var (
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
)

func loadCA() error {
	caKeyBytes, err := os.ReadFile("ca.key")
	if err != nil {
		return fmt.Errorf("cannot read ca.key: %v", err)
	}
	block, _ := pem.Decode(caKeyBytes)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block in ca.key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsedKey, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return fmt.Errorf("cannot parse ca.key: %v", err)
		}
		var ok bool
		key, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("ca.key is not an RSA private key")
		}
	}

	caKey = key
	caCertBytes, err := os.ReadFile("ca.crt")
	if err != nil {
		return fmt.Errorf("cannot read ca.crt: %v", err)
	}
	block, _ = pem.Decode(caCertBytes)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block in ca.crt")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("cannot parse ca.crt: %v", err)
	}
	caCert = cert

	return nil
}

func buildCertificate(host string) (tls.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(0).SetUint64(^uint64(0)>>1))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().AddDate(10, 0, 0),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{host},
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cannot generate key: %w", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cannot create certificate: %w", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes, caCert.Raw},
		PrivateKey:  priv,
	}
	return cert, nil
}

func main() {
	err := loadCA()
	if err != nil {
		log.Println("WARNING: cannot load CA. HTTPS MITM won't work properly. Error:", err)
	}

	go startWebAPI()

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
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	reqLine, err := reader.ReadString('\n')
	if err != nil {
		log.Println("Failed to read first line:", err)
		return
	}

	method, versionProtocol, parsedUrl, err := parseRequestLine(reqLine)
	if err != nil {
		log.Println("Cannot parse request line:", err)
		return
	}

	if strings.ToUpper(method) == "CONNECT" {
		handleHTTPS(conn, parsedUrl, versionProtocol, reader)
	} else {
		handleHTTP(conn, method, versionProtocol, parsedUrl, reqLine, reader)
	}
}

func parseRequestLine(line string) (method string, versionProtocol string, parsedUrl *url.URL, err error) {
	line = strings.TrimSpace(line)
	parts := strings.Split(line, " ")
	if len(parts) < 3 {
		return "", "", nil, fmt.Errorf("invalid request line: %s", line)
	}
	method = parts[0]
	versionProtocol = parts[len(parts)-1]
	fullURL := parts[1]

	if strings.ToUpper(method) == "CONNECT" {

		parsedUrl, err = url.Parse("https://" + fullURL)
		if err != nil {
			return "", "", nil, err
		}
	} else {

		parsedUrl, err = url.Parse(fullURL)
		if err != nil {
			return "", "", nil, err
		}
	}
	return method, versionProtocol, parsedUrl, nil
}

func handleHTTP(clientConn net.Conn, method, versionProtocol string, parsedUrl *url.URL, firstRequestLine string, reader *bufio.Reader) {
	headers := []string{}
	path := parsedUrl.RequestURI()

	if path == "" {
		path = "/"
	}
	newFirstLine := fmt.Sprintf("%s %s %s\r\n", method, path, versionProtocol)
	headers = append(headers, newFirstLine)

	var bodyBuilder strings.Builder
	finalHeaders := make(http.Header)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Println("Error reading headers:", err)
			return
		}
		if line == "\r\n" {

			break
		}
		if strings.HasPrefix(strings.ToLower(line), "proxy-connection:") {

			continue
		}
		headers = append(headers, line)

		headerParts := strings.SplitN(line, ":", 2)
		if len(headerParts) == 2 {
			name := strings.TrimSpace(headerParts[0])
			val := strings.TrimSpace(headerParts[1])
			finalHeaders.Add(name, val)
		}
	}

	var contentLength int64 = 0
	if cl := finalHeaders.Get("Content-Length"); cl != "" {
		fmt.Sscanf(cl, "%d", &contentLength)
	}

	bodyData := []byte{}
	if contentLength > 0 && (strings.ToUpper(method) == "POST" || strings.ToUpper(method) == "PUT") {
		bodyData = make([]byte, contentLength)
		_, err := io.ReadFull(reader, bodyData)
		if err != nil {
			log.Println("Error reading request body:", err)
			return
		}
		bodyBuilder.Write(bodyData)
	}

	fullURL := parsedUrl.String()
	id := addRequest(method, fullURL, finalHeaders, bodyBuilder.String())
	log.Printf("[HTTP] #%d => %s %s", id, method, fullURL)

	host := parsedUrl.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	serverConn, err := net.Dial("tcp", host)
	if err != nil {
		log.Println("Cannot connect to target host:", err)
		return
	}
	defer serverConn.Close()

	for _, h := range headers {
		_, _ = serverConn.Write([]byte(h))
	}

	serverConn.Write([]byte("\r\n"))
	if len(bodyData) > 0 {
		serverConn.Write(bodyData)
	}

	go io.Copy(clientConn, serverConn)
	io.Copy(serverConn, reader)
}

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

	if caCert == nil || caKey == nil {
		log.Println("CA not loaded, fallback to simple tunnel for https")
		go io.Copy(rawServerConn, reader)
		io.Copy(clientConn, rawServerConn)
		rawServerConn.Close()
		return
	}

	cert, err := buildCertificate(parsedUrl.Hostname())
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
