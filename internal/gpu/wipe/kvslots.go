package wipe

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// EraseSlots erases every llama-server slot and returns the ids erased.
// Busy slots are retried with backoff until timeout, then reported as an error (fail-closed).
func EraseSlots(baseURL string, timeout time.Duration) ([]int, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("llama base URL required")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	client := &http.Client{Timeout: timeout}
	ids, err := listSlotIDs(client, baseURL)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		ids = []int{0}
	}

	deadline := time.Now().Add(timeout)
	erased := make([]int, 0, len(ids))
	for _, id := range ids {
		if err := eraseSlotWithRetry(client, baseURL, id, deadline); err != nil {
			return erased, err
		}
		erased = append(erased, id)
	}
	return erased, nil
}

func listSlotIDs(client *http.Client, baseURL string) ([]int, error) {
	resp, err := client.Get(baseURL + "/slots")
	if err != nil {
		return nil, fmt.Errorf("GET /slots: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read /slots: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /slots: status %d: %s", resp.StatusCode, truncate(body))
	}

	slots, err := parseSlots(body)
	if err != nil {
		return nil, err
	}
	ids := make([]int, 0, len(slots))
	for _, s := range slots {
		ids = append(ids, s)
	}
	return ids, nil
}

func parseSlots(body []byte) ([]int, error) {
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse /slots JSON: %w", err)
	}
	var list []any
	switch v := raw.(type) {
	case []any:
		list = v
	case map[string]any:
		if nested, ok := v["slots"].([]any); ok {
			list = nested
		} else {
			return nil, fmt.Errorf("unexpected /slots object shape")
		}
	default:
		return nil, fmt.Errorf("unexpected /slots type %T", raw)
	}

	ids := make([]int, 0, len(list))
	seen := map[int]struct{}{}
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id, ok := intFromAny(m["id"])
		if !ok {
			id, ok = intFromAny(m["id_slot"])
		}
		if !ok {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids, nil
}

func eraseSlotWithRetry(client *http.Client, baseURL string, id int, deadline time.Time) error {
	backoff := 50 * time.Millisecond
	var last error
	for {
		err := eraseSlotOnce(client, baseURL, id)
		if err == nil {
			return nil
		}
		last = err
		if !isBusy(err) || time.Now().After(deadline) {
			return err
		}
		sleep := backoff
		if remaining := time.Until(deadline); remaining < sleep {
			sleep = remaining
		}
		if sleep <= 0 {
			return last
		}
		time.Sleep(sleep)
		if backoff < time.Second {
			backoff *= 2
		}
	}
}

func eraseSlotOnce(client *http.Client, baseURL string, id int) error {
	url := fmt.Sprintf("%s/slots/%d?action=erase", baseURL, id)
	req, err := http.NewRequest(http.MethodPost, url, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Length", "0")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST erase slot %d: %w", id, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = resp.Status
	}
	return fmt.Errorf("erase slot %d: status %d: %s", id, resp.StatusCode, msg)
}

func isBusy(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "busy") || strings.Contains(s, "in use") || strings.Contains(s, "occupied")
}

func intFromAny(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}

func truncate(b []byte) string {
	const max = 200
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
