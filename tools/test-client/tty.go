// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

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

func sendNonceSlowly(port io.Writer, nonceHex string) error {
	time.Sleep(50 * time.Millisecond) // Wait for device to enter read state
	for _, b := range []byte(nonceHex + "\n") {
		if _, err := port.Write([]byte{b}); err != nil {
			return err
		}
		time.Sleep(2 * time.Millisecond)
	}
	return nil
}

func requestTokenFromTTY(ttyPath string, baudRate int, nonceHex string) (string, error) {
	fmt.Printf("Debug: Requesting token with nonce '%s' from %s at %d baud...\n", nonceHex, ttyPath, baudRate)
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
		if n > 0 {
			fmt.Printf("Debug: Read %d bytes from serial\n", n)
			accum += string(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				// Read timeout or EOF, continue to retry
				if n == 0 {
					// Timeout occurred. Send a newline to trigger a re-prompt just in case the device is stuck.
					fmt.Println("Debug: Read timeout, sending newline to unblock device...")
					if _, wErr := io.WriteString(port, "\n"); wErr != nil {
						return "", fmt.Errorf("serial write (reset): %w", wErr)
					}
					continue
				}
			} else {
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

			fmt.Printf("Debug: Received line: %s\n", line)

			var resp tokenResponse
			if err := json.Unmarshal([]byte(line), &resp); err != nil {
				if strings.Contains(line, "enter_nonce") {
					fmt.Println("Device requested nonce (fallback match), sending slowly...")
					if err := sendNonceSlowly(port, nonceHex); err != nil {
						return "", fmt.Errorf("serial write: %w", err)
					}
					continue
				}
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
