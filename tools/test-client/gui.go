// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"embed"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/gorilla/websocket"
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

type WSMessage struct {
	Type         string     `json:"type"`
	Nonce        string     `json:"nonce,omitempty"`
	TokenSrc     string     `json:"tokenSrc,omitempty"`
	Data         *TokenInfo `json:"data,omitempty"`
	ClientCount  int        `json:"clientCount,omitempty"`
	IsProcessing bool       `json:"isProcessing,omitempty"`
	ScrollY      float64    `json:"scrollY,omitempty"`
	ScrollRatio  float64    `json:"scrollRatio,omitempty"`
	IsAtBottom   bool       `json:"isAtBottom,omitempty"`
	IsAtTop      bool       `json:"isAtTop,omitempty"`
	SenderID     string     `json:"senderId,omitempty"`
	MouseX       float64    `json:"mouseX,omitempty"`
	MouseY       float64    `json:"mouseY,omitempty"`
	MouseVisible bool       `json:"mouseVisible,omitempty"`
	IsClick      bool       `json:"isClick,omitempty"`
}

type ClientHub struct {
	clients  map[*websocket.Conn]bool
	mu       sync.Mutex
	upgrader websocket.Upgrader

	stateMu         sync.Mutex
	lastResult      *TokenInfo
	lastNonce       string
	lastScrollY     float64
	lastScrollRatio float64
	lastIsAtBottom  bool
	lastIsAtTop     bool
	isProcessing    bool
	cancelFn        context.CancelFunc
	cfg             *GUIConfig
}

func newHub(cfg *GUIConfig) *ClientHub {
	return &ClientHub{
		clients: make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		cfg: cfg,
	}
}

func (h *ClientHub) broadcast(msg WSMessage) {
	h.broadcastExcept(nil, msg)
}

func (h *ClientHub) broadcastExcept(sender *websocket.Conn, msg WSMessage) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for client := range h.clients {
		if client == sender {
			continue
		}
		if err := client.WriteJSON(msg); err != nil {
			fmt.Printf("WebSocket send error: %v\n", err)
			client.Close()
			delete(h.clients, client)
		}
	}
}

func (h *ClientHub) updateClientCount() {
	h.mu.Lock()
	count := len(h.clients)
	h.mu.Unlock()

	h.broadcast(WSMessage{Type: "client_count", ClientCount: count})
}

func (h *ClientHub) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("WebSocket upgrade failed: %v\n", err)
		return
	}

	h.mu.Lock()
	h.clients[conn] = true
	clientCount := len(h.clients)
	h.mu.Unlock()

	h.stateMu.Lock()
	initMsg := WSMessage{
		Type:         "init",
		TokenSrc:     h.cfg.TokenSrc,
		Nonce:        h.lastNonce,
		Data:         h.lastResult,
		IsProcessing: h.isProcessing,
		ClientCount:  clientCount,
		ScrollY:      h.lastScrollY,
		ScrollRatio:  h.lastScrollRatio,
		IsAtBottom:   h.lastIsAtBottom,
		IsAtTop:      h.lastIsAtTop,
	}
	h.stateMu.Unlock()

	_ = conn.WriteJSON(initMsg)
	h.updateClientCount()

	defer func() {
		h.mu.Lock()
		delete(h.clients, conn)
		h.mu.Unlock()
		conn.Close()
		h.updateClientCount()
	}()

	for {
		var msg WSMessage
		if err := conn.ReadJSON(&msg); err != nil {
			break
		}

		switch msg.Type {
		case "request_token":
			go h.runTokenProcess(msg.Nonce)
		case "update_nonce":
			h.stateMu.Lock()
			h.lastNonce = msg.Nonce
			h.stateMu.Unlock()
			h.broadcastExcept(conn, WSMessage{Type: "nonce_updated", Nonce: msg.Nonce, SenderID: msg.SenderID})
		case "scroll":
			h.stateMu.Lock()
			h.lastScrollY = msg.ScrollY
			h.lastScrollRatio = msg.ScrollRatio
			h.lastIsAtBottom = msg.IsAtBottom
			h.lastIsAtTop = msg.IsAtTop
			h.stateMu.Unlock()
			h.broadcastExcept(conn, msg)
		case "mouse":
			h.broadcastExcept(conn, msg)
		case "switch_fake":
			h.toggleFake()
		}
	}
}

func (h *ClientHub) toggleFake() string {
	h.stateMu.Lock()
	if h.cfg.TokenSrc == "tfm" {
		h.cfg.TokenSrc = "tty"
	} else {
		h.cfg.TokenSrc = "tfm"
	}
	fmt.Println("Debug: switching to", h.cfg.TokenSrc)
	newState := h.cfg.TokenSrc

	if h.cancelFn != nil {
		h.cancelFn()
	}
	h.stateMu.Unlock()

	h.broadcast(WSMessage{Type: "source_switched", TokenSrc: newState})
	return newState
}

func (h *ClientHub) runTokenProcess(reqNonce string) *TokenInfo {
	h.stateMu.Lock()
	if h.isProcessing {
		lastRes := h.lastResult
		h.stateMu.Unlock()
		return lastRes
	}
	h.isProcessing = true

	ctx, cancel := context.WithCancel(context.Background())
	h.cancelFn = cancel

	nonce := reqNonce
	for _, n := range []string{reqNonce, h.lastNonce, h.cfg.Nonce} {
		if n != "" {
			nonce = n
			break
		}
	}
	if nonce == "" {
		nonce = generateNonce()
	}
	h.lastNonce = nonce
	currentSrc := h.cfg.TokenSrc
	h.stateMu.Unlock()

	h.broadcast(WSMessage{
		Type:         "token_started",
		Nonce:        nonce,
		IsProcessing: true,
	})

	tokenHex := ""
	if currentSrc == "tty" {
		var err error
		tokenHex, err = requestTokenFromTTYContext(ctx, h.cfg.TtyPath, h.cfg.BaudRate, nonce)
		if err != nil {
			h.stateMu.Lock()
			switchedToFake := (h.cfg.TokenSrc == "tfm")
			h.stateMu.Unlock()

			if switchedToFake || ctx.Err() != nil {
				fmt.Println("TTY read cancelled or switched to fake data, falling back to TFM token...")
				tokenHex = tfmToken
				currentSrc = "tfm"
			} else {
				info := TokenInfo{Error: "TTY Error: " + err.Error()}
				return h.finishTokenProcess(&info)
			}
		}
	} else if currentSrc == "tfm" {
		tokenHex = tfmToken
	} else {
		tokenHex = currentSrc
	}

	xCoord, yCoord := getPubKey(currentSrc, h.cfg.PubKeyX, h.cfg.PubKeyY)
	fmt.Printf("Debug: GUI API Using Public Key X: %s\n", xCoord)
	fmt.Printf("Debug: GUI API Using Public Key Y: %s\n", yCoord)

	info := verifyTokenForGUI(tokenHex, xCoord, yCoord)
	return h.finishTokenProcess(&info)
}

func (h *ClientHub) finishTokenProcess(info *TokenInfo) *TokenInfo {
	h.stateMu.Lock()
	h.lastResult = info
	h.isProcessing = false
	h.cancelFn = nil
	h.stateMu.Unlock()

	h.broadcast(WSMessage{
		Type:         "token_result",
		Data:         info,
		IsProcessing: false,
	})
	return info
}

func startGUI(cfg GUIConfig) {
	hub := newHub(&cfg)

	http.Handle("/static/", http.FileServer(http.FS(staticFiles)))
	http.HandleFunc("/ws", hub.handleWS)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/static/index.html", http.StatusMovedPermanently)
			return
		}
		http.NotFound(w, r)
	})

	fmt.Println("Starting GUI on http://localhost:8080")
	go openBrowser("http://localhost:8080/")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Error starting server:", err)
	}
}

func openBrowser(url string) {
	time.Sleep(500 * time.Millisecond)
	cmds := map[string][]string{
		"linux":   {"xdg-open", url},
		"windows": {"rundll32", "url.dll,FileProtocolHandler", url},
		"darwin":  {"open", url},
	}
	if args, ok := cmds[runtime.GOOS]; ok {
		if err := exec.Command(args[0], args[1:]...).Start(); err == nil {
			return
		}
	}
	fmt.Printf("Could not open browser automatically, please visit %s\n", url)
}
