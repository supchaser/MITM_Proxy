package proxy

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
)

func HandleClient(conn net.Conn) {
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
	} else {
		parsedUrl, err = url.Parse(fullURL)
	}
	if err != nil {
		return "", "", nil, err
	}
	return method, versionProtocol, parsedUrl, nil
}
