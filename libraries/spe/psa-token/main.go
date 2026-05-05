package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/veraison/psatoken"
)

func main() {
	var tokenHex = flag.String("token-hex", "", "PSA token as full hex string (COSE_Sign1 bytes)")
	flag.Parse()

	// Load optional local constants from ./constants.local
	locals := loadLocals("constants.local")
	constants := loadLocals("constants")

	if *tokenHex == "" {
		println("Using hardcoded token hex from RuSPE (override with -token-hex or constants.local):")
		if v, ok := locals["TOKEN_RUSPE"]; ok && v != "" {
			*tokenHex = v
		} else {
			fmt.Fprintln(os.Stderr, "Error: TOKEN_RUSPE not found in constants.local")
			os.Exit(1)
		}
	}

	if *tokenHex == "tfm" {
		// temporary hardcoded the token (TFM P2 test vector)
		println("Using tfm token:")
		if v, ok := constants["TOKEN_TFM"]; ok && v != "" {
			*tokenHex = v
		} else {
			fmt.Fprintln(os.Stderr, "Error: TOKEN_TFM not found in constants.local")
			os.Exit(1)
		}
	}

	// 1. Decode the hex string into raw bytes
	coseBytes, err := decodeHexString(*tokenHex)
	must("decode token hex", err)

	// 2. Decode and validate the COSE_Sign1 message using psatoken library
	ev, err := psatoken.DecodeAndValidateEvidenceFromCOSE(coseBytes)
	must("decode and validate evidence from COSE", err)

	// 3. Extract and display claims
	fmt.Println("--- PSA Token Claims ---")
	inspectClaims(ev.Claims)

	// 4. (Optional) Verify signature if you have the public key
	// Defaults for JWK values; may be overridden by constants.local
	var jwkX = "Tl4iCZ47zrRbRG0TVf0dw7VFlHtv18HInYhnmMNybo8"
	var jwkY = "gNcLhAslaqw0pi7eEEM2TwRAlfADR0uR4Bggkq-xPy4"

	if v, ok := locals["JWK_X"]; ok && v != "" {
		jwkX = v
	}
	if v, ok := locals["JWK_Y"]; ok && v != "" {
		jwkY = v
	}

	pubKey, err := ecdsaPublicKeyFromJWK_P256(jwkX, jwkY)
	if err == nil {
		if err := ev.Verify(pubKey); err != nil {
			fmt.Printf("Signature verification failed: %v\n", err)
		} else {
			fmt.Println("Signature verification: OK")
		}
	}
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

// ... (Rest of your helper functions: decodeHexString, ecdsaPublicKeyFromJWK_P256, must)

func decodeHexString(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")
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

// loadLocals reads a simple key=value file and returns a map of values.
func loadLocals(path string) map[string]string {
	m := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, "`")
		m[key] = val
	}
	return m
}
