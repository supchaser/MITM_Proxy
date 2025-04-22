package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func getAllRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(requestStore.GetAllRequests())
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
	reqInfo := requestStore.GetRequestByID(id)
	if reqInfo == nil {
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
	reqInfo := requestStore.GetRequestByID(id)
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
	reqInfo := requestStore.GetRequestByID(id)
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
}
