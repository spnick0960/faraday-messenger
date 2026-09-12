package relay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	Base  string
	HTTP  *http.Client
	Box   string
	Token string
}

func NewClient(base string) *Client {
	return &Client{Base: base, HTTP: &http.Client{Timeout: 15 * time.Second}}
}

func (c *Client) Register(mailbox, tokenHex string) error {
	c.Box, c.Token = mailbox, tokenHex
	body, _ := json.Marshal(mailboxReq{Mailbox: mailbox, Token: tokenHex})
	req, err := http.NewRequest(http.MethodPut, c.Base+"/v1/mailbox", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("register %d: %s", res.StatusCode, b)
	}
	return nil
}

func (c *Client) Drop(to string, blob []byte) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"to":   to,
		"blob": base64.StdEncoding.EncodeToString(blob),
	})
	res, err := c.HTTP.Post(c.Base+"/v1/drop", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		b, _ := io.ReadAll(res.Body)
		return "", fmt.Errorf("drop %d: %s", res.StatusCode, b)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.ID, nil
}

type InboxItem struct {
	ID    string `json:"id"`
	Blob  string `json:"blob"`
	Bytes int    `json:"bytes"`
	At    int64  `json:"at"`
}

func (c *Client) Inbox() ([]InboxItem, error) {
	req, err := http.NewRequest(http.MethodGet, c.Base+"/v1/inbox", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Faraday-Mailbox", c.Box)
	req.Header.Set("Authorization", "Bearer "+c.Token)
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		b, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("inbox %d: %s", res.StatusCode, b)
	}
	var out struct {
		Envelopes []InboxItem `json:"envelopes"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Envelopes, nil
}

func (c *Client) Ack(ids []string) error {
	body, _ := json.Marshal(map[string]any{"ids": ids})
	req, err := http.NewRequest(http.MethodPost, c.Base+"/v1/ack", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Faraday-Mailbox", c.Box)
	req.Header.Set("Authorization", "Bearer "+c.Token)
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("ack %d: %s", res.StatusCode, b)
	}
	return nil
}

func DecodeBlob(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}
