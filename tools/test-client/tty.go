// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"go.bug.st/serial"
	"go.bug.st/serial/enumerator"
)

// --- TTY ---

func getCypressPort() (string, error) {
	ports, err := enumerator.GetDetailedPortsList()
	if err == nil {
		for _, port := range ports {
			if strings.Contains(strings.ToLower(port.Product+port.Name), "cypress") || strings.ToUpper(port.VID) == "04B4" {
				return port.Name, nil
			}
		}
	}
	return "", fmt.Errorf("could not find Cypress serial port for non-secure terminal")
}

type tokenResponse struct {
	Type     string `json:"type"`
	Msg      string `json:"error"`
	Token    string `json:"token"`
	TokenLen int    `json:"token_len"`
}

func sendNonceSlowly(port io.Writer, nonceHex string) error {
	time.Sleep(50 * time.Millisecond) // Wait for device to enter read state
	for _, b := range []byte(nonceHex + "\n") {
		if _, err := port.Write([]byte{b}); err != nil {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil
}

func requestTokenFromTTY(ttyPath string, baudRate int, nonceHex string) (string, error) {
	return requestTokenFromTTYContext(context.Background(), ttyPath, baudRate, nonceHex)
}

func requestTokenFromTTYContext(ctx context.Context, ttyPath string, baudRate int, nonceHex string) (string, error) {
	fmt.Printf("Debug: Requesting token with nonce '%s' from %s at %d baud...\n", nonceHex, ttyPath, baudRate)
	port, err := serial.Open(ttyPath, &serial.Mode{BaudRate: baudRate})
	if err != nil {
		return "", err
	}
	if err := port.SetReadTimeout(500 * time.Millisecond); err != nil {
		port.Close()
		return "", fmt.Errorf("failed to set read timeout: %w", err)
	}
	defer port.Close()

	port.Write([]byte("\n"))
	port.Drain()

	buf := make([]byte, 4096)
	var accum string

	fmt.Println("Debug: waiting for newline...")
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		n, err := port.Read(buf)
		if n > 0 {
			fmt.Printf("Debug: Read %d bytes from serial\n", n)
			accum += string(buf[:n])
		}
		if err != nil {
			if err == io.EOF && n == 0 {
				fmt.Println("Debug: Read timeout, sending newline to unblock device...")
				if _, wErr := io.WriteString(port, "\n"); wErr != nil {
					return "", fmt.Errorf("serial write (reset): %w", wErr)
				}
				continue
			}
			if err != io.EOF {
				return "", fmt.Errorf("serial read: %w", err)
			}
		}
		if n == 0 && err == nil {
			continue
		}

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
			fmt.Printf("Debug: Parsed JSON response: %+v\n", resp)
			switch resp.Type {
			case "token_response":
				fmt.Println("Received token response")
				tok := strings.TrimSpace(resp.Token)
				for len(tok) >= 2 && strings.HasSuffix(tok, "00") {
					tok = tok[:len(tok)-2]
				}
				return tok, nil
			case "enter_nonce":
				fmt.Println("Device requested nonce, sending slowly...")
				if err := sendNonceSlowly(port, nonceHex); err != nil {
					return "", fmt.Errorf("serial write: %w", err)
				}
				fmt.Println("Nonce sent")
			case "error":
				fmt.Fprintf(os.Stderr, "device error: %s - retrying via reset...\n", resp.Msg)
				if _, wErr := io.WriteString(port, "\n"); wErr != nil {
					return "", fmt.Errorf("serial write (reset): %w", wErr)
				}
			}
		}
	}
}
