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
