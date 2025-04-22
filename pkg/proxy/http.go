package proxy

import (
	"MITM_PROXY/pkg/storage"
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var requestStore = storage.GlobalRequestStore

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
	id := requestStore.AddRequest(method, fullURL, finalHeaders, bodyBuilder.String())
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
