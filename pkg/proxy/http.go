package proxy

import (
	"MITM_PROXY/pkg/storage"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
)

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

	// Read headers
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

	// Read body if present
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

	// Create http.Request object
	req := &http.Request{
		Method: method,
		URL:    parsedUrl,
		Proto:  versionProtocol,
		Header: finalHeaders,
		Body:   io.NopCloser(bytes.NewReader(bodyData)),
		Host:   parsedUrl.Host,
	}

	// Save the request
	id, err := storage.SaveRequest(req, bodyData)
	if err != nil {
		log.Printf("Error saving request: %v", err)
		return
	}
	log.Printf("[HTTP] #%d => %s %s", id, method, parsedUrl.String())

	// Connect to target server
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

	// Write headers to server
	for _, h := range headers {
		_, _ = serverConn.Write([]byte(h))
	}
	serverConn.Write([]byte("\r\n"))

	// Write body if present
	if len(bodyData) > 0 {
		serverConn.Write(bodyData)
	}

	// Proxy the connection
	go io.Copy(clientConn, serverConn)
	io.Copy(serverConn, reader)
}
