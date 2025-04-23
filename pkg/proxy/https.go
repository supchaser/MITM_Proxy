package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"MITM_PROXY/pkg/cert"
	"MITM_PROXY/pkg/storage"
)

func handleHTTPS(clientConn net.Conn, parsedUrl *url.URL, versionProtocol string, reader *bufio.Reader) {
	// 1. Считаем и отбросим все заголовки CONNECT‑запроса
	//    (reader уже прочитал только первую строку в parseRequestLine)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Println("Error while discarding CONNECT headers:", err)
			return
		}
		if line == "\r\n" {
			break
		}
	}

	// 2. Отвечаем клиенту, что туннель открывается
	//    (можно использовать HTTP/1.0 или оригинальный versionProtocol)
	fmt.Fprintf(clientConn, "%s 200 Connection established\r\n\r\n", versionProtocol)

	// 3. Открываем TLS‑сессию к реальному серверу
	hostPort := parsedUrl.Host
	if !strings.Contains(hostPort, ":") {
		hostPort += ":443"
	}
	rawServerConn, err := tls.Dial("tcp", hostPort, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Println("Error connecting to real TLS server:", err)
		return
	}
	defer rawServerConn.Close()

	// 4. Если есть CA — включаем MITM, иначе простое туннелирование
	caCert, caKey := cert.GetCA()
	if caCert == nil || caKey == nil {
		log.Println("CA not loaded, fallback to simple tunnel for HTTPS")
		go io.Copy(rawServerConn, reader)  // client→server
		io.Copy(clientConn, rawServerConn) // server→client
		return
	}

	// 5. Генерация MITM‑сертификата
	mitmCert, err := cert.BuildCertificate(parsedUrl.Hostname(), caCert, caKey)
	if err != nil {
		log.Println("Cannot build certificate for host:", parsedUrl.Hostname(), err)
		go io.Copy(rawServerConn, reader)
		io.Copy(clientConn, rawServerConn)
		return
	}

	// 6. Устанавливаем TLS‑сервер поверх clientConn
	tlsClient := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{mitmCert},
		ServerName:   parsedUrl.Hostname(),
	})
	defer tlsClient.Close()

	if err := tlsClient.Handshake(); err != nil {
		log.Println("TLS handshake with client failed:", err)
		return
	}

	// 7. Переключаемся на зашифрованный поток и начинаем читать запросы
	clientReader := bufio.NewReader(tlsClient)
	clientWriter := bufio.NewWriter(tlsClient)

	for {
		// Прочитать следующий HTTP‑запрос поверх TLS
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err != io.EOF {
				log.Println("Error reading HTTPS request:", err)
			}
			break
		}

		// Считать тело (если есть)
		var bodyBytes []byte
		if req.ContentLength > 0 {
			bodyBytes, _ = io.ReadAll(req.Body)
		}
		req.Body.Close()

		// Логируем и сохраняем
		id, err := storage.SaveRequest(req, bodyBytes)
		if err != nil {
			log.Printf("Error saving HTTPS request #%d: %v", id, err)
			go io.Copy(rawServerConn, reader)
			io.Copy(clientConn, rawServerConn)
			return
		}
		log.Printf("[HTTPS] #%d => %s %s", id, req.Method, req.URL.String())

		req.URL.Scheme = "https"
		req.URL.Host = parsedUrl.Host
		req.Host = parsedUrl.Host

		// Восстанавливаем тело
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// Отправляем запрос на реальный сервер
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			log.Println("Error forwarding HTTPS request:", err)
			break
		}

		// Пересылаем ответ клиенту
		resp.Write(clientWriter)
		clientWriter.Flush()
	}
}
