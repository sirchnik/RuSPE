package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/tarm/serial"
)

// --- TTY ---

type tokenResponse struct {
	Type     string `json:"type"`
	Msg      string `json:"error"`
	Token    string `json:"token"`
	TokenLen int    `json:"token_len"`
}

func requestTokenFromTTY(ttyPath string, baudRate int, nonceHex string) (string, error) {
	port, err := serial.OpenPort(&serial.Config{
		Name: ttyPath, Baud: baudRate, ReadTimeout: 5 * time.Second,
	})
	if err != nil {
		return "", err
	}
	defer port.Close()

	buf := make([]byte, 4096)
	var accum string

	for {
		n, err := port.Read(buf)
		if err != nil {
			return "", fmt.Errorf("serial read: %w", err)
		}
		if n == 0 {
			continue
		}
		accum += string(buf[:n])

		for {
			idx := strings.IndexByte(accum, '\n')
			if idx < 0 {
				break
			}
			line := strings.TrimSpace(accum[:idx])
			accum = accum[idx+1:]
			if line == "" {
				continue
			}

			var resp tokenResponse
			if err := json.Unmarshal([]byte(line), &resp); err != nil {
				fmt.Fprintln(os.Stderr, "device (non-JSON):", line)
				continue
			}
			switch resp.Type {
			case "token_response":
				fmt.Println("Received token response")
				tok := strings.TrimSpace(resp.Token)
				for len(tok) >= 2 && strings.HasSuffix(tok, "00") {
					tok = tok[:len(tok)-2]
				}
				return tok, nil
			case "enter_nonce":
				fmt.Println("Device requested nonce, sending...")
				if _, err := io.WriteString(port, nonceHex+"\n"); err != nil {
					return "", fmt.Errorf("serial write: %w", err)
				}
			case "error":
				if resp.Msg == "Nonce-Read Failed" {
					fmt.Fprintln(os.Stderr, "device error: Nonce read failed - check nonce format and length")
					continue
				}
				if resp.Msg == "Nonce-Parse Failed" {
					fmt.Fprintln(os.Stderr, "device error: Nonce parse failed - check nonce format and length")
					continue
				}
				return "", fmt.Errorf("device error: %s", resp.Msg)
			}
		}
	}
}
