// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

package main

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"time"
)

//go:embed static/*
var staticFiles embed.FS

type GUIConfig struct {
	TokenSrc string
	TtyPath  string
	BaudRate int
	Nonce    string
	PubKeyX  string
	PubKeyY  string
}

func startGUI(cfg GUIConfig) {
	// Map /static/ directly to the embedded files
	http.Handle("/static/", http.FileServer(http.FS(staticFiles)))

	// Redirect root to /static/index.html
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/static/index.html", http.StatusMovedPermanently)
			return
		}
		http.NotFound(w, r)
	})

	http.HandleFunc("/api/switch-fake", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if cfg.TokenSrc == "tfm" {
			cfg.TokenSrc = "tty"
			fmt.Println("Debug: switching to tty")
		} else {
			cfg.TokenSrc = "tfm"
			fmt.Println("Debug: switching to tfm fake data")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"state": cfg.TokenSrc})
	})

	http.HandleFunc("/api/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		type TokenRequest struct {
			Nonce string `json:"nonce"`
		}
		var req TokenRequest
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&req)
		}

		tokenHex := ""
		switch cfg.TokenSrc {
		case "tty":
			nonce := req.Nonce
			if nonce == "" {
				nonce = cfg.Nonce
			}
			if nonce == "" {
				b := make([]byte, 32)
				_ = randRead(b)
				nonce = hex.EncodeToString(b)
			}
			var err error
			tokenHex, err = requestTokenFromTTY(cfg.TtyPath, cfg.BaudRate, nonce)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(TokenInfo{Error: "TTY Error: " + err.Error()})
				return
			}
		case "tfm":
			tokenHex = tfmToken
		default:
			tokenHex = cfg.TokenSrc
		}

		xCoord := defaultPubKeyX
		yCoord := defaultPubKeyY
		if cfg.TokenSrc == "tfm" {
			xCoord = "Tl4iCZ47zrRbRG0TVf0dw7VFlHtv18HInYhnmMNybo8"
			yCoord = "gNcLhAslaqw0pi7eEEM2TwRAlfADR0uR4Bggkq-xPy4"
		}
		if cfg.PubKeyX != "" {
			xCoord = cfg.PubKeyX
		}
		if cfg.PubKeyY != "" {
			yCoord = cfg.PubKeyY
		}

		fmt.Printf("Debug: GUI API Using Public Key X: %s\n", xCoord)
		fmt.Printf("Debug: GUI API Using Public Key Y: %s\n", yCoord)

		info := verifyTokenForGUI(tokenHex, xCoord, yCoord)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	})

	fmt.Println("Starting GUI on http://localhost:8080")
	go openBrowser("http://localhost:8080/")

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}

func openBrowser(url string) {
	time.Sleep(500 * time.Millisecond)
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		fmt.Printf("Could not open browser automatically, please visit %s\n", url)
	}
}
