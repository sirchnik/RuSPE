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
	"strings"
	"time"

	"github.com/tarm/serial"
	"github.com/veraison/psatoken"
)

var TFM_TOKEN = "TOKEN_TFM=d28443a10126a0590100a8190100582101020202020202020202020202020202020202020202020202020202020202020219095c582000000000000000000000000000000000000000000000000000000000000000000a5820010101010101010101010101010101010101010101010101010101010101010119095a1a7fffffff19095b19300019010978217461673a7073616365727469666965642e6f72672c323032333a7073612374666d19010c48000000000000000019095f81a305582004040404040404040404040404040404040404040404040404040404040404040258200303030303030303030303030303030303030303030303030303030303030303016450526f545840786e937a4c42667af3847399319ca95c7e7dbabdc9b50fdb8de3f6bff4ab82ff80c42140e2a488000219e3e10663193da69c75f52b798ea10b2f7041a90e8e5a"

func main() {
	var tokenSrc = flag.String("token-src", "", "")
	var ttyPath = flag.String("tty", "/dev/ttyACM0", "TTY device used to request a token")
	var baudRate = flag.Int("baud", 115200, "TTY baud rate")
	var nonceHex = flag.String("nonce-hex", "", "Nonce as hex string to send to the device")
	flag.Parse()

	tokenHex := ""

	switch *tokenSrc {
	case "tty":
		if *nonceHex == "" {
			nonceBytes := make([]byte, 32)
			if _, err := rand.Read(nonceBytes); err != nil {
				must("generate nonce", err)
			}
			*nonceHex = hex.EncodeToString(nonceBytes)
		}
		println(nonceHex)
		var err error
		tokenHex, err = requestTokenFromTTY(*ttyPath, *baudRate, *nonceHex)
		must("request token from tty", err)
	case "tfm":
		tokenHex = TFM_TOKEN
	default:
		tokenHex = *tokenSrc
	}

	coseBytes, err := decodeHexString(tokenHex)
	must("decode token hex", err)

	ev, err := psatoken.DecodeAndValidateEvidenceFromCOSE(coseBytes)
	must("decode and validate evidence from COSE", err)

	fmt.Println("--- PSA Token Claims ---")
	inspectClaims(ev.Claims)

	jwkX := "Tl4iCZ47zrRbRG0TVf0dw7VFlHtv18HInYhnmMNybo8"
	jwkY := "gNcLhAslaqw0pi7eEEM2TwRAlfADR0uR4Bggkq-xPy4"

	pubKey, err := ecdsaPublicKeyFromJWK_P256(jwkX, jwkY)
	if err == nil {
		if err := ev.Verify(pubKey); err != nil {
			fmt.Printf("\033[31m✗ Signature verification failed:\033[0m %v\n", err)
		} else {
			fmt.Printf("\033[32m✓ Signature verification: OK\033[0m\n")
		}
	}
}

type tokenResponse struct {
	Type     string `json:"type"`
	Msg      string `json:"error"`
	Token    string `json:"token"`
	TokenLen int    `json:"token_len"`
}

func requestTokenFromTTY(ttyPath string, baudRate int, nonceHex string) (string, error) {
	port, err := serial.OpenPort(&serial.Config{
		Name:        ttyPath,
		Baud:        baudRate,
		ReadTimeout: time.Second * 5,
	})
	if err != nil {
		return "", err
	}
	defer port.Close()

	buf := make([]byte, 2048)
	var response tokenResponse

ReadLoop:
	for {
		_, err := port.Read(buf)
		if err != nil {
			return "", err
		}
		outputs := strings.Split(string(buf), "\n")

	LinesLoop:
		for _, line := range outputs {
			err = json.Unmarshal([]byte(line), &response)
			if err != nil {
				println("Received from device (non-JSON):", line)
				continue
			}
			switch response.Type {
			case "token_response":
				fmt.Println("Received token response from device")
				break ReadLoop
			case "enter_nonce":
				fmt.Println("Device requested nonce, sending...")
				if _, err := io.WriteString(port, strings.TrimSpace(nonceHex)+"\n"); err != nil {
					return "", err
				}
				time.Sleep(3000 * time.Millisecond)
				break LinesLoop
			case "error":
				return "", fmt.Errorf("device error: %s", response.Msg)
			}
		}
	}

	return normalizeTokenHex(response.Token, response.TokenLen), nil
}

func normalizeTokenHex(tokenHex string, tokenLen int) string {
	println("token: ", tokenHex)
	tokenHex = strings.TrimSpace(tokenHex)
	if idx := strings.IndexByte(tokenHex, '='); idx >= 0 {
		tokenHex = tokenHex[idx+1:]
	}
	tokenHex = strings.TrimPrefix(tokenHex, "0x")
	tokenHex = strings.TrimPrefix(tokenHex, "0X")
	tokenHex = strings.ReplaceAll(tokenHex, " ", "")
	tokenHex = strings.ReplaceAll(tokenHex, "\n", "")
	tokenHex = strings.ReplaceAll(tokenHex, "\r", "")

	for len(tokenHex) >= 2 && strings.HasSuffix(tokenHex, "00") {
		tokenHex = tokenHex[:len(tokenHex)-2]
	}
	println("token: ", tokenHex)
	return tokenHex
}

func inspectClaims(c psatoken.IClaims) {
	if profile, err := c.GetProfile(); err == nil {
		fmt.Println("Profile:", profile)
	} else {
		fmt.Println("Profile: <not available>")
	}

	if instID, err := c.GetInstID(); err == nil {
		fmt.Println("InstanceID (hex):", hex.EncodeToString(instID))
	} else {
		fmt.Println("InstanceID: <not available>")
	}

	if implID, err := c.GetImplID(); err == nil {
		fmt.Println("ImplementationID (hex):", hex.EncodeToString(implID))
	} else {
		fmt.Println("ImplementationID: <not available>")
	}

	if clientID, err := c.GetClientID(); err == nil {
		fmt.Println("ClientID:", clientID)
	} else {
		fmt.Println("ClientID: <not available>")
	}

	if slc, err := c.GetSecurityLifeCycle(); err == nil {
		fmt.Printf("SecurityLifeCycle: 0x%04x\n", slc)
	} else {
		fmt.Println("SecurityLifeCycle: <not available>")
	}

	if bootSeed, err := c.GetBootSeed(); err == nil {
		fmt.Println("BootSeed (hex):", hex.EncodeToString(bootSeed))
	} else {
		fmt.Println("BootSeed: <not available>")
	}

	if nonce, err := c.GetNonce(); err == nil {
		fmt.Println("Nonce (hex):", hex.EncodeToString(nonce))
	} else {
		fmt.Println("Nonce: <not available>")
	}

	if certRef, err := c.GetCertificationReference(); err == nil {
		fmt.Println("CertificationReference:", certRef)
	} else {
		fmt.Println("CertificationReference: <not available>")
	}

	if vsi, err := c.GetVSI(); err == nil {
		fmt.Println("VerificationServiceIndicator:", vsi)
	} else {
		fmt.Println("VerificationServiceIndicator: <not available>")
	}

	if swComps, err := c.GetSoftwareComponents(); err == nil {
		fmt.Printf("SoftwareComponents: %d component(s)\n", len(swComps))
		for i, comp := range swComps {
			fmt.Printf("  [%d]\n", i)
			if measType, err := comp.GetMeasurementType(); err == nil {
				fmt.Printf("    MeasurementType: %s\n", measType)
			}
			if measVal, err := comp.GetMeasurementValue(); err == nil {
				fmt.Printf("    MeasurementValue (hex): %s\n", hex.EncodeToString(measVal))
			}
			if signID, err := comp.GetSignerID(); err == nil {
				fmt.Printf("    SignerID (hex): %s\n", hex.EncodeToString(signID))
			}
			if version, err := comp.GetVersion(); err == nil {
				fmt.Printf("    Version: %s\n", version)
			}
			if measDesc, err := comp.GetMeasurementDesc(); err == nil {
				fmt.Printf("    MeasurementDescription: %s\n", measDesc)
			}
		}
	} else {
		fmt.Println("SoftwareComponents: <not available>")
	}
}

func decodeHexString(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if idx := strings.IndexByte(s, '='); idx >= 0 {
		s = s[idx+1:]
	}
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return hex.DecodeString(s)
}

func ecdsaPublicKeyFromJWK_P256(xB64URL, yB64URL string) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(xB64URL)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64URL)
	if err != nil {
		return nil, err
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func must(what string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
		os.Exit(1)
	}
}
