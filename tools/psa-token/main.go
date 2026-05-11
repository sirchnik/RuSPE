package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/tarm/serial"
	"github.com/veraison/psatoken"
)

const tfmToken = "d28443a10126a0590100a8190100582101020202020202020202020202020202020202020202020202020202020202020219095c582000000000000000000000000000000000000000000000000000000000000000000a5820010101010101010101010101010101010101010101010101010101010101010119095a1a7fffffff19095b19300019010978217461673a7073616365727469666965642e6f72672c323032333a7073612374666d19010c48000000000000000019095f81a305582004040404040404040404040404040404040404040404040404040404040404040258200303030303030303030303030303030303030303030303030303030303030303016450526f545840786e937a4c42667af3847399319ca95c7e7dbabdc9b50fdb8de3f6bff4ab82ff80c42140e2a488000219e3e10663193da69c75f52b798ea10b2f7041a90e8e5a"

func defaultTTY() string {
	switch runtime.GOOS {
	case "windows":
		return "COM10"
	case "darwin":
		fmt.Println("Warning: default TTY path for macOS is untested, may need adjustment")
		return "/dev/ttyACM0"
	default:
		return "/dev/ttyACM0"
	}
}

func main() {
	tokenSrc := flag.String("token-src", "", "Token source: 'tty', 'tfm', or a raw hex token")
	ttyPath := flag.String("tty", defaultTTY(), "Serial port (e.g. COM3 on Windows, /dev/ttyACM0 on Linux)")
	baudRate := flag.Int("baud", 115200, "TTY baud rate")
	nonce := flag.String("nonce", "", "Hex-encoded nonce (random if omitted)")
	genKey := flag.Bool("gen-key", false, "Generate a new P-256 key pair and exit")
	pubKeyX := flag.String("pub-key-x", "", "Public key X coordinate (base64url, no padding)")
	pubKeyY := flag.String("pub-key-y", "", "Public key Y coordinate (base64url, no padding)")
	privKey := flag.String("priv-key", "", "Private key D value (base64url, no padding)")
	flag.Parse()

	if *genKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must("generate key", err)
		ecdhPub, err := key.PublicKey.ECDH()
		must("convert public key", err)
		pubBytes := ecdhPub.Bytes()
		// Uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes)
		xBytes := pubBytes[1:33]
		yBytes := pubBytes[33:65]
		fmt.Println("Private key (base64url):")
		privBytes, err := key.Bytes()
		must("encode private key", err)
		fmt.Printf("  D: %s\n", base64.RawURLEncoding.EncodeToString(privBytes))
		fmt.Println("Public key (base64url):")
		fmt.Printf("  X: %s\n", base64.RawURLEncoding.EncodeToString(xBytes))
		fmt.Printf("  Y: %s\n", base64.RawURLEncoding.EncodeToString(yBytes))
		fmt.Println("\nRust byte arrays:")
		fmt.Printf("const PRIVATE_KEY: [u8; %d] = [%s];\n", len(privBytes), rustHex(privBytes))
		fmt.Printf("const PUBLIC_KEY_X: [u8; %d] = [%s];\n", len(xBytes), rustHex(xBytes))
		fmt.Printf("const PUBLIC_KEY_Y: [u8; %d] = [%s];\n", len(yBytes), rustHex(yBytes))
		return
	}

	tokenHex := ""
	switch *tokenSrc {
	case "tty":
		println("Requesting token from TTY...")
		if *nonce == "" {
			b := make([]byte, 32)
			must("generate nonce", randRead(b))
			*nonce = hex.EncodeToString(b)
		}
		fmt.Println("Nonce:", *nonce)
		var err error
		tokenHex, err = requestTokenFromTTY(*ttyPath, *baudRate, *nonce)
		println("Received token hex:", tokenHex)
		must("request token from tty", err)
	case "tfm":
		println("Using built-in TFM token")
		tokenHex = tfmToken
	default:
		println("Using token from command line")
		tokenHex = *tokenSrc
	}

	coseBytes, err := cleanHex(tokenHex)
	must("decode token hex", err)

	ev, err := psatoken.DecodeAndValidateEvidenceFromCOSE(coseBytes)
	must("decode evidence", err)

	fmt.Println("--- PSA Token Claims ---")
	printClaims(ev.Claims)

	xCoord := "hfymlL5b64lewHwPcn8S--u7Av9MKSy8rUiCnahzd3A"
	yCoord := "mGMp76ud1btPVE8SlFEf4-NUXQBPPp0Vxq6rsuw6VNw"
	if *tokenSrc == "tfm" {
		xCoord = "Tl4iCZ47zrRbRG0TVf0dw7VFlHtv18HInYhnmMNybo8"
		yCoord = "gNcLhAslaqw0pi7eEEM2TwRAlfADR0uR4Bggkq-xPy4"
	}
	if *pubKeyX != "" {
		xCoord = *pubKeyX
	}
	if *pubKeyY != "" {
		yCoord = *pubKeyY
	}

	pubKey, err := p256KeyFromB64(xCoord, yCoord)
	must("parse public key", err)

	if *privKey != "" {
		dBytes, err := base64.RawURLEncoding.DecodeString(*privKey)
		must("decode private key", err)
		fullKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), dBytes)
		must("parse private key", err)
		_ = fullKey // available for future signing use
	}

	if err := ev.Verify(pubKey); err != nil {
		fmt.Printf("\033[31m✗ Signature verification failed:\033[0m %v\n", err)
	} else {
		fmt.Printf("\033[32m✓ Signature verification: OK\033[0m\n")
	}
}

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
				return "", fmt.Errorf("device error: %s", resp.Msg)
			}
		}
	}
}

// --- Claims ---

func printClaims(c psatoken.IClaims) {
	printStr("Profile", c.GetProfile)
	printHex("InstanceID", c.GetInstID)
	printHex("ImplementationID", c.GetImplID)
	if id, err := c.GetClientID(); err == nil {
		fmt.Println("ClientID:", id)
	}
	if slc, err := c.GetSecurityLifeCycle(); err == nil {
		fmt.Printf("SecurityLifeCycle: 0x%04x\n", slc)
	}
	printHex("BootSeed", c.GetBootSeed)
	printHex("Nonce", c.GetNonce)
	printStr("CertificationReference", c.GetCertificationReference)
	printStr("VSI", c.GetVSI)

	if swComps, err := c.GetSoftwareComponents(); err == nil {
		fmt.Printf("SoftwareComponents: %d component(s)\n", len(swComps))
		for i, comp := range swComps {
			fmt.Printf("  [%d]\n", i)
			printCompStr("    MeasurementType", comp.GetMeasurementType)
			printCompHex("    MeasurementValue", comp.GetMeasurementValue)
			printCompHex("    SignerID", comp.GetSignerID)
			printCompStr("    Version", comp.GetVersion)
			printCompStr("    MeasurementDesc", comp.GetMeasurementDesc)
		}
	}
}

func printStr(label string, fn func() (string, error)) {
	if v, err := fn(); err == nil {
		fmt.Printf("%s: %s\n", label, v)
	}
}

func printHex(label string, fn func() ([]byte, error)) {
	if v, err := fn(); err == nil {
		fmt.Printf("%s: %s\n", label, hex.EncodeToString(v))
	}
}

func printCompStr(prefix string, fn func() (string, error)) {
	if v, err := fn(); err == nil {
		fmt.Printf("%s: %s\n", prefix, v)
	}
}

func printCompHex(prefix string, fn func() ([]byte, error)) {
	if v, err := fn(); err == nil {
		fmt.Printf("%s: %s\n", prefix, hex.EncodeToString(v))
	}
}

// --- Helpers ---

func cleanHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if idx := strings.IndexByte(s, '='); idx >= 0 {
		s = s[idx+1:]
	}
	s = strings.NewReplacer("0x", "", "0X", "", " ", "", "\n", "", "\r", "").Replace(s)
	return hex.DecodeString(s)
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
