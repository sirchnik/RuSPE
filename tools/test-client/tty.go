// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	if isTelnetPath(ttyPath) {
		return requestTokenFromTelnetContext(ctx, ttyPath, nonceHex)
	}

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

	if _, err := io.WriteString(port, "\n"); err != nil {
		return "", fmt.Errorf("serial write (reset): %w", err)
	}
	_ = port.Drain()

	return requestTokenLoop(
		ctx,
		port,
		func(buf []byte) (int, error) {
			return port.Read(buf)
		},
		func(err error, n int) bool {
			return n == 0 && errors.Is(err, io.EOF)
		},
		"serial",
		nonceHex,
	)
}

func isTelnetPath(path string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(path)), "telnet://")
}

func requestTokenFromTelnetContext(ctx context.Context, telnetPath string, nonceHex string) (string, error) {
	addr, err := parseTelnetAddress(telnetPath)
	if err != nil {
		return "", err
	}

	fmt.Printf("Debug: Requesting token with nonce '%s' from telnet %s...\n", nonceHex, addr)
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("failed to open telnet connection: %w", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "\n"); err != nil {
		return "", fmt.Errorf("telnet write (reset): %w", err)
	}

	return requestTokenLoop(
		ctx,
		conn,
		func(buf []byte) (int, error) {
			if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
				return 0, err
			}
			return conn.Read(buf)
		},
		func(err error, n int) bool {
			if n != 0 {
				return false
			}
			var netErr net.Error
			return errors.As(err, &netErr) && netErr.Timeout()
		},
		"telnet",
		nonceHex,
	)
}

func parseTelnetAddress(telnetPath string) (string, error) {
	target := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(telnetPath), "telnet://"))
	if target == "" {
		return "", fmt.Errorf("invalid telnet target %q: missing host", telnetPath)
	}

	host, port, err := net.SplitHostPort(target)
	if err == nil {
		if host == "" || port == "" {
			return "", fmt.Errorf("invalid telnet target %q", telnetPath)
		}
		return net.JoinHostPort(host, port), nil
	}

	if strings.Contains(target, ":") {
		return "", fmt.Errorf("invalid telnet target %q: use telnet://host:port", telnetPath)
	}

	return net.JoinHostPort(target, "23"), nil
}

func requestTokenLoop(
	ctx context.Context,
	port io.Writer,
	readChunk func([]byte) (int, error),
	isTimeout func(error, int) bool,
	transport string,
	nonceHex string,
) (string, error) {

	buf := make([]byte, 4096)
	var accum string

	fmt.Println("Debug: waiting for newline...")
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		n, err := readChunk(buf)
		if n > 0 {
			fmt.Printf("Debug: Read %d bytes from %s\n", n, transport)
			accum += string(buf[:n])
		}
		if err != nil {
			if isTimeout(err, n) {
				fmt.Println("Debug: Read timeout, sending newline to unblock device...")
				if _, wErr := io.WriteString(port, "\n"); wErr != nil {
					return "", fmt.Errorf("%s write (reset): %w", transport, wErr)
				}
				continue
			}
			if !(errors.Is(err, io.EOF) && n > 0) {
				return "", fmt.Errorf("%s read: %w", transport, err)
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
					return "", fmt.Errorf("%s write: %w", transport, err)
				}
				fmt.Println("Nonce sent")
			case "error":
				fmt.Fprintf(os.Stderr, "device error: %s - retrying via reset...\n", resp.Msg)
				if _, wErr := io.WriteString(port, "\n"); wErr != nil {
					return "", fmt.Errorf("%s write (reset): %w", transport, wErr)
				}
			}
		}
	}
}
