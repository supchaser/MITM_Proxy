package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"MITM_PROXY/pkg/storage"
)

func getAllRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
		return
	}

	requests, err := storage.GetAllRequests()
	if err != nil {
		http.Error(w, "Failed to get requests", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(requests)
}

func getRequestByID(w http.ResponseWriter, r *http.Request) {
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

	reqInfo, err := storage.GetRequestByID(id)
	if err != nil || reqInfo == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reqInfo)
}

func repeatRequest(w http.ResponseWriter, r *http.Request) {
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

	// Get the original request
	req, err := storage.GetRequestByID(id)
	if err != nil || req == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Read the original request body
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes)) // Reset body reader
	}

	// Create a new request
	client := &http.Client{}
	newReq, err := http.NewRequest(req.Method, req.URL.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// Copy headers
	for k, v := range req.Header {
		newReq.Header[k] = v
	}

	// Send the request
	resp, err := client.Do(newReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to send request: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Read the response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response", http.StatusInternalServerError)
		return
	}

	// Return the response
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func scanRequest(w http.ResponseWriter, r *http.Request) {
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

	// Get the original request
	req, err := storage.GetRequestByID(id)
	if err != nil || req == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Perform basic security checks
	issues := make([]string, 0)

	// Check for SQL injection patterns in URL parameters
	for _, values := range req.URL.Query() {
		for _, value := range values {
			if strings.Contains(strings.ToLower(value), "select ") ||
				strings.Contains(strings.ToLower(value), "insert ") ||
				strings.Contains(strings.ToLower(value), "update ") ||
				strings.Contains(strings.ToLower(value), "delete ") {
				issues = append(issues, "Possible SQL injection in URL parameters")
				break
			}
		}
	}

	// Check for XSS patterns
	bodyBytes, err := io.ReadAll(req.Body)
	if err == nil {
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes)) // Reset body reader
		bodyStr := string(bodyBytes)
		if strings.Contains(bodyStr, "<script>") || strings.Contains(bodyStr, "javascript:") {
			issues = append(issues, "Possible XSS in request body")
		}
	}

	// Check for sensitive headers
	if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
		issues = append(issues, "Request contains sensitive headers")
	}

	if len(issues) == 0 {
		issues = append(issues, "No obvious security issues found")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":     id,
		"issues": issues,
	})
}

func scanXXE(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/scan-xxe/"), "/")
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

	req, err := storage.GetRequestByID(id)
	if err != nil || req == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	bodyStr := string(bodyBytes)

	result := map[string]interface{}{
		"id":         id,
		"is_xml":     false,
		"vulnerable": false,
		"details":    "",
	}

	if strings.Contains(bodyStr, "<?xml") {
		result["is_xml"] = true

		xxePayload := `<!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
            <foo>&xxe;</foo>`

		modifiedBody := strings.Replace(bodyStr, "<?xml", xxePayload, 1)

		client := &http.Client{}
		newReq, err := http.NewRequest(req.Method, req.URL.String(), strings.NewReader(modifiedBody))
		if err == nil {
			for k, v := range req.Header {
				newReq.Header[k] = v
			}

			resp, err := client.Do(newReq)
			if err == nil {
				defer resp.Body.Close()
				respBody, _ := io.ReadAll(resp.Body)

				if strings.Contains(string(respBody), "root:") {
					result["vulnerable"] = true
					result["details"] = "System file /etc/passwd was leaked through XXE"
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
