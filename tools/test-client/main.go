// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strings"
)

const tfmToken = "d28443a10126a0590100a8190100582101020202020202020202020202020202020202020202020202020202020202020219095c582000000000000000000000000000000000000000000000000000000000000000000a5820010101010101010101010101010101010101010101010101010101010101010119095a1a7fffffff19095b19300019010978217461673a7073616365727469666965642e6f72672c323032333a7073612374666d19010c48000000000000000019095f81a305582004040404040404040404040404040404040404040404040404040404040404040258200303030303030303030303030303030303030303030303030303030303030303016450526f545840786e937a4c42667af3847399319ca95c7e7dbabdc9b50fdb8de3f6bff4ab82ff80c42140e2a488000219e3e10663193da69c75f52b798ea10b2f7041a90e8e5a"

const (
	defaultPubKeyX = "hfymlL5b64lewHwPcn8S--u7Av9MKSy8rUiCnahzd3A"
	defaultPubKeyY = "mGMp76ud1btPVE8SlFEf4-NUXQBPPp0Vxq6rsuw6VNw"
	tfmPubKeyX     = "Tl4iCZ47zrRbRG0TVf0dw7VFlHtv18HInYhnmMNybo8"
	tfmPubKeyY     = "gNcLhAslaqw0pi7eEEM2TwRAlfADR0uR4Bggkq-xPy4"
)

func defaultTTY() string {
	if port, err := getCypressPort(); err == nil && port != "" {
		return port
	}
	if runtime.GOOS == "darwin" {
		fmt.Println("Warning: default TTY path for macOS is untested, may need adjustment")
	}
	if runtime.GOOS == "windows" {
		return "COM10"
	}
	return "/dev/ttyACM0"
}

func getPubKey(tokenSrc, pubKeyX, pubKeyY string) (string, string) {
	x, y := defaultPubKeyX, defaultPubKeyY
	if tokenSrc == "tfm" {
		x, y = tfmPubKeyX, tfmPubKeyY
	}
	if pubKeyX != "" {
		x = pubKeyX
	}
	if pubKeyY != "" {
		y = pubKeyY
	}
	return x, y
}

func generateNonce() string {
	b := make([]byte, 32)
	_ = randRead(b)
	return hex.EncodeToString(b)
}

func main() {
	tokenSrc := flag.String("token-src", "tty", "Token source: 'tty', 'tfm', or a raw hex token")
	ttyPath := flag.String("tty", defaultTTY(), "Serial port or telnet://host[:port] (Default: "+defaultTTY()+")")
	baudRate := flag.Int("baud", 115200, "TTY baud rate")
	nonce := flag.String("nonce", "", "Hex-encoded nonce (random if omitted)")
	pubKeyX := flag.String("pub-key-x", "", "Public key X coordinate (base64url, no padding)")
	pubKeyY := flag.String("pub-key-y", "", "Public key Y coordinate (base64url, no padding)")
	genKey := flag.Bool("gen-key", false, "Generate a new P-256 key pair and exit")
	gui := flag.Bool("gui", false, "Start the fancy GUI")
	defaults := defaultClientTimings()
	tokenTimeout := flag.Duration("token-timeout", defaults.TokenRequestTimeout, "Overall timeout for token requests (0 to disable)")
	serialReadTimeout := flag.Duration("serial-read-timeout", defaults.SerialReadTimeout, "Read timeout for serial/telnet reads")
	flag.Parse()

	timings := ClientTimings{
		TokenRequestTimeout: *tokenTimeout,
		SerialReadTimeout:   *serialReadTimeout,
		TelnetDialTimeout:   defaults.TelnetDialTimeout,
		NonceInitialDelay:   defaults.NonceInitialDelay,
		NonceByteDelay:      defaults.NonceByteDelay,
	}

	if *genKey {
		genPrintKey()
		return
	}
	if *gui {
		startGUI(GUIConfig{
			TokenSrc: *tokenSrc, TtyPath: *ttyPath, BaudRate: *baudRate,
			Nonce: *nonce, PubKeyX: *pubKeyX, PubKeyY: *pubKeyY,
			Timings: timings,
		})
		return
	}

	tokenHex := ""
	switch *tokenSrc {
	case "tty":
		println("Requesting token from TTY...")
		if *nonce == "" {
			*nonce = generateNonce()
		} else if len(*nonce) != 64 {
			fmt.Println("Invalid nonce length")
			os.Exit(1)
		}
		fmt.Println("Nonce:", *nonce)
		var err error
		ctx := context.Background()
		if timings.TokenRequestTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timings.TokenRequestTimeout)
			defer cancel()
		}
		tokenHex, err = requestTokenFromTTYContext(ctx, *ttyPath, *baudRate, *nonce, timings)
		must("request token from tty", err)
		println("Received token hex:", tokenHex)
	case "tfm":
		println("Using built-in TFM token")
		tokenHex = tfmToken
	default:
		println("Using token from command line")
		tokenHex = *tokenSrc
	}

	xCoord, yCoord := getPubKey(*tokenSrc, *pubKeyX, *pubKeyY)
	fmt.Printf("Debug: Using Public Key X: %s\n", xCoord)
	fmt.Printf("Debug: Using Public Key Y: %s\n", yCoord)

	decodeAndVerifyToken(tokenHex, xCoord, yCoord)
}

func cleanHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if idx := strings.IndexByte(s, '='); idx >= 0 {
		s = s[idx+1:]
	}
	s = strings.NewReplacer("0x", "", "0X", "", " ", "", "\n", "", "\r", "").Replace(s)
	return hex.DecodeString(s)
}

func genPrintKey() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must("generate key", err)
	ecdhPub, err := key.PublicKey.ECDH()
	must("convert public key", err)
	pubBytes := ecdhPub.Bytes()
	xBytes, yBytes := pubBytes[1:33], pubBytes[33:65]

	privBytes, err := key.Bytes()
	must("encode private key", err)

	enc := base64.RawURLEncoding.EncodeToString
	fmt.Println("Private key (base64url):")
	fmt.Printf("  D: %s\n", enc(privBytes))
	fmt.Println("Public key (base64url):")
	fmt.Printf("  X: %s\n", enc(xBytes))
	fmt.Printf("  Y: %s\n", enc(yBytes))
	fmt.Println("\nRust byte arrays:")
	fmt.Printf("const PRIVATE_KEY: [u8; %d] = [%s];\n", len(privBytes), rustHex(privBytes))
	fmt.Printf("const PUBLIC_KEY_X: [u8; %d] = [%s];\n", len(xBytes), rustHex(xBytes))
	fmt.Printf("const PUBLIC_KEY_Y: [u8; %d] = [%s];\n", len(yBytes), rustHex(yBytes))
}

func p256KeyFromB64(xB64, yB64 string) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func randRead(b []byte) error { _, err := rand.Read(b); return err }

func must(what string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
		os.Exit(1)
	}
}

func rustHex(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("0x%02x", v)
	}
	return strings.Join(parts, ", ")
}
