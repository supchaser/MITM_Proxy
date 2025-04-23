package storage

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

type RequestInfo struct {
	ID         int             `json:"id"`
	Method     string          `json:"method"`
	Path       string          `json:"path"`
	Query      json.RawMessage `json:"query_params"`
	Headers    json.RawMessage `json:"headers"`
	Cookies    json.RawMessage `json:"cookies"`
	PostParams json.RawMessage `json:"post_params"`
	Body       string          `json:"body"`
	CreatedAt  string          `json:"created_at"`
}

var pool *pgxpool.Pool

func Init(dsn string) error {
	ctx := context.Background()
	var err error
	pool, err = pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("db: cannot create pool: %w", err)
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return fmt.Errorf("db: cannot ping database: %w", err)
	}
	return nil
}

func SaveRequest(req *http.Request, rawBody []byte) (int, error) {
	ctx := context.Background()

	// Преобразование параметров запроса и других данных в формат JSON
	qp := map[string]interface{}{}
	for k, vs := range req.URL.Query() {
		if len(vs) == 1 {
			qp[k] = vs[0]
		} else {
			qp[k] = vs
		}
	}
	qpJSON, _ := json.Marshal(qp)

	hdrJSON, _ := json.Marshal(req.Header)

	cookies := map[string]string{}
	for _, c := range req.Cookies() {
		cookies[c.Name] = c.Value
	}
	cookiesJSON, _ := json.Marshal(cookies)

	postParams := map[string]interface{}{}
	ct := req.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		vals, _ := url.ParseQuery(string(rawBody))
		for k, vs := range vals {
			if len(vs) == 1 {
				postParams[k] = vs[0]
			} else {
				postParams[k] = vs
			}
		}
	}
	postJSON, _ := json.Marshal(postParams)

	bodyToStore := ""
	if len(postParams) == 0 && len(rawBody) > 0 {
		bodyToStore = string(rawBody)
	}

	const sqlInsert = `
    INSERT INTO requests
      (method, path, query_params, headers, cookies, post_params, body)
    VALUES
      ($1, $2, $3::jsonb, $4::jsonb, $5::jsonb, $6::jsonb, $7)
    RETURNING id
    `
	var id int
	row := pool.QueryRow(ctx, sqlInsert,
		req.Method,
		req.URL.Path,
		string(qpJSON),
		string(hdrJSON),
		string(cookiesJSON),
		string(postJSON),
		bodyToStore,
	)
	if err := row.Scan(&id); err != nil {
		return 0, fmt.Errorf("SaveRequest scan: %w", err)
	}
	return id, nil
}

func SaveResponse(requestID int, resp *http.Response, rawBody []byte) error {
	ctx := context.Background()

	bodyBytes := rawBody
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		if gr, err := gzip.NewReader(bytes.NewReader(rawBody)); err == nil {
			if decoded, err2 := io.ReadAll(gr); err2 == nil {
				bodyBytes = decoded
			}
			gr.Close()
		}
	}

	hdrJSON, _ := json.Marshal(resp.Header)

	const sqlInsert = `
    INSERT INTO responses
      (request_id, status_code, status_message, headers, body)
    VALUES
      ($1, $2, $3, $4::jsonb, $5)
    `
	if _, err := pool.Exec(ctx, sqlInsert,
		requestID,
		resp.StatusCode,
		resp.Status,
		string(hdrJSON),
		string(bodyBytes),
	); err != nil {
		return fmt.Errorf("SaveResponse exec: %w", err)
	}
	return nil
}

func GetAllRequests() ([]RequestInfo, error) {
	ctx := context.Background()

	const sqlQuery = `
    SELECT id, method, path, query_params, headers, cookies, post_params, body, created_at
    FROM requests
    ORDER BY created_at DESC
    `

	rows, err := pool.Query(ctx, sqlQuery)
	if err != nil {
		return nil, fmt.Errorf("GetAllRequests query: %w", err)
	}
	defer rows.Close()

	var requests []RequestInfo
	for rows.Next() {
		var req RequestInfo
		err := rows.Scan(
			&req.ID,
			&req.Method,
			&req.Path,
			&req.Query,
			&req.Headers,
			&req.Cookies,
			&req.PostParams,
			&req.Body,
			&req.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("GetAllRequests scan: %w", err)
		}
		requests = append(requests, req)
	}

	return requests, nil
}

func GetRequestByID(id int) (*http.Request, error) {
	ctx := context.Background()

	const sqlQuery = `
    SELECT method, path, query_params, headers, cookies, post_params, body
    FROM requests WHERE id = $1
    `
	var method, path, queryParams, headers, cookies, postParams, body string
	row := pool.QueryRow(ctx, sqlQuery, id)
	if err := row.Scan(&method, &path, &queryParams, &headers, &cookies, &postParams, &body); err != nil {
		return nil, fmt.Errorf("GetRequestByID scan: %w", err)
	}

	// Create URL and parse path
	u, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("parse URL path: %w", err)
	}

	// Unmarshal query parameters into a map
	var queryValues map[string]interface{}
	if err := json.Unmarshal([]byte(queryParams), &queryValues); err != nil {
		return nil, fmt.Errorf("unmarshal query params: %w", err)
	}

	// Convert the map to url.Values and set them in the URL
	values := url.Values{}
	for k, v := range queryValues {
		switch vv := v.(type) {
		case string:
			values.Add(k, vv)
		case []interface{}:
			for _, item := range vv {
				if s, ok := item.(string); ok {
					values.Add(k, s)
				}
			}
		}
	}
	u.RawQuery = values.Encode()

	// Unmarshal headers
	var headerValues http.Header
	if err := json.Unmarshal([]byte(headers), &headerValues); err != nil {
		return nil, fmt.Errorf("unmarshal headers: %w", err)
	}

	req := &http.Request{
		Method: method,
		URL:    u,
		Header: headerValues,
		Body:   io.NopCloser(strings.NewReader(body)),
	}

	return req, nil
}
