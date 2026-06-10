// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/hex"
	"fmt"

	"github.com/veraison/psatoken"
)

func decodeAndVerifyToken(tokenHex string, xCoord string, yCoord string) {
	coseBytes, err := cleanHex(tokenHex)
	must("decode token hex", err)

	ev, err := psatoken.DecodeAndValidateEvidenceFromCOSE(coseBytes)
	must("decode evidence", err)

	fmt.Println("--- PSA Token Claims ---")
	printClaims(ev.Claims)

	pubKey, err := p256KeyFromB64(xCoord, yCoord)
	must("parse public key", err)

	if err := ev.Verify(pubKey); err != nil {
		fmt.Printf("\033[31m✗ Signature verification failed:\033[0m %v\n", err)
	} else {
		fmt.Printf("\033[32m✓ Signature verification: OK\033[0m\n")
	}
}

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

// --- GUI Helpers ---

type TokenInfo struct {
	Profile                string              `json:"profile,omitempty"`
	InstanceID             string              `json:"instance_id,omitempty"`
	ImplementationID       string              `json:"implementation_id,omitempty"`
	ClientID               int32               `json:"client_id,omitempty"`
	SecurityLifeCycle      uint16              `json:"security_lifecycle,omitempty"`
	BootSeed               string              `json:"boot_seed,omitempty"`
	Nonce                  string              `json:"nonce,omitempty"`
	CertificationReference string              `json:"certification_reference,omitempty"`
	VSI                    string              `json:"vsi,omitempty"`
	SoftwareComponents     []SoftwareComponent `json:"software_components,omitempty"`
	VerificationStatus     bool                `json:"verification_status"`
	VerificationError      string              `json:"verification_error,omitempty"`
	Error                  string              `json:"error,omitempty"`
}

type SoftwareComponent struct {
	MeasurementType  string `json:"measurement_type,omitempty"`
	MeasurementValue string `json:"measurement_value,omitempty"`
	SignerID         string `json:"signer_id,omitempty"`
	Version          string `json:"version,omitempty"`
	MeasurementDesc  string `json:"measurement_desc,omitempty"`
}

func verifyTokenForGUI(tokenHex string, xCoord string, yCoord string) TokenInfo {
	info := TokenInfo{}
	coseBytes, err := cleanHex(tokenHex)
	if err != nil {
		info.Error = "Decode hex error: " + err.Error()
		return info
	}

	ev, err := psatoken.DecodeAndValidateEvidenceFromCOSE(coseBytes)
	if err != nil {
		info.Error = "Decode evidence error: " + err.Error()
		return info
	}

	c := ev.Claims
	if v, err := c.GetProfile(); err == nil {
		info.Profile = v
	}
	if v, err := c.GetInstID(); err == nil {
		info.InstanceID = hex.EncodeToString(v)
	}
	if v, err := c.GetImplID(); err == nil {
		info.ImplementationID = hex.EncodeToString(v)
	}
	if v, err := c.GetClientID(); err == nil {
		info.ClientID = v
	}
	if v, err := c.GetSecurityLifeCycle(); err == nil {
		info.SecurityLifeCycle = v
	}
	if v, err := c.GetBootSeed(); err == nil {
		info.BootSeed = hex.EncodeToString(v)
	}
	if v, err := c.GetNonce(); err == nil {
		info.Nonce = hex.EncodeToString(v)
	}
	if v, err := c.GetCertificationReference(); err == nil {
		info.CertificationReference = v
	}
	if v, err := c.GetVSI(); err == nil {
		info.VSI = v
	}

	if swComps, err := c.GetSoftwareComponents(); err == nil {
		for _, comp := range swComps {
			sc := SoftwareComponent{}
			if v, err := comp.GetMeasurementType(); err == nil {
				sc.MeasurementType = v
			}
			if v, err := comp.GetMeasurementValue(); err == nil {
				sc.MeasurementValue = hex.EncodeToString(v)
			}
			if v, err := comp.GetSignerID(); err == nil {
				sc.SignerID = hex.EncodeToString(v)
			}
			if v, err := comp.GetVersion(); err == nil {
				sc.Version = v
			}
			if v, err := comp.GetMeasurementDesc(); err == nil {
				sc.MeasurementDesc = v
			}
			info.SoftwareComponents = append(info.SoftwareComponents, sc)
		}
	}

	pubKey, err := p256KeyFromB64(xCoord, yCoord)
	if err != nil {
		info.Error = "Parse public key error: " + err.Error()
		return info
	}

	if err := ev.Verify(pubKey); err != nil {
		info.VerificationStatus = false
		info.VerificationError = err.Error()
	} else {
		info.VerificationStatus = true
	}

	return info
}
