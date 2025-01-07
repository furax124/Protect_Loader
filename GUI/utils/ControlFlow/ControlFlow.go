package ControlFlow

import (
	"fmt"
	"fyne.io/fyne/v2/widget"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const excludeDir = "GUI"

func EnableControlflow(logLabel *widget.Label) error {
	var logMessages strings.Builder

	parentDir, err := filepath.Abs("..")
	if err != nil {
		logMessages.WriteString(fmt.Sprintf("[-] failed to get parent directory: %v\n", err))
		logLabel.SetText(logMessages.String())
		return err
	}
	logMessages.WriteString(fmt.Sprintf("[+] Parent directory: %s\n", parentDir))

	err = filepath.Walk(parentDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relativePath, err := filepath.Rel(parentDir, path)
		if err != nil {
			return err
		}

		if info.IsDir() && strings.HasPrefix(relativePath, excludeDir) {
			logMessages.WriteString(fmt.Sprintf("[+] Skipping directory: %s\n", path))
			return filepath.SkipDir
		}

		if !info.IsDir() {
			content, err := ioutil.ReadFile(path)
			if err != nil {
				return fmt.Errorf("[-] failed to read file %s: %v", path, err)
			}

			modifiedContent := strings.ReplaceAll(string(content), "//.garble:controlflow", "//garble:controlflow")

			if modifiedContent != string(content) {
				err = ioutil.WriteFile(path, []byte(modifiedContent), info.Mode())
				if err != nil {
					return fmt.Errorf("[-] failed to write file %s: %v", path, err)
				}
				logMessages.WriteString(fmt.Sprintf("[+] Modified file: %s\n", path))
			}
		}
		return nil
	})

	if err != nil {
		logMessages.WriteString(fmt.Sprintf("[-] error walking the path %s: %v\n", parentDir, err))
		logLabel.SetText(logMessages.String())
		return err
	}

	logMessages.WriteString("[+] ControlFlow obfuscation enabled successfully\n")
	logLabel.SetText(logMessages.String())
	return nil
}

func DisableControlflow(logLabel *widget.Label) error {
	var logMessages strings.Builder
	parentDir, err := filepath.Abs("..")
	if err != nil {
		logMessages.WriteString(fmt.Sprintf("[-] failed to get parent directory: %v\n", err))
		logLabel.SetText(logMessages.String())
		return err
	}
	logMessages.WriteString(fmt.Sprintf("[+] Parent directory: %s\n", parentDir))

	err = filepath.Walk(parentDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relativePath, err := filepath.Rel(parentDir, path)
		if err != nil {
			return err
		}

		if info.IsDir() && strings.HasPrefix(relativePath, excludeDir) {
			logMessages.WriteString(fmt.Sprintf("[+] Skipping directory: %s\n", path))
			return filepath.SkipDir
		}

		if !info.IsDir() {
			content, err := ioutil.ReadFile(path)
			if err != nil {
				return fmt.Errorf("[-] failed to read file %s: %v", path, err)
			}

			modifiedContent := strings.ReplaceAll(string(content), "//garble:controlflow", "//.garble:controlflow")

			if modifiedContent != string(content) {
				err = ioutil.WriteFile(path, []byte(modifiedContent), info.Mode())
				if err != nil {
					return fmt.Errorf("[-] failed to write file %s: %v", path, err)
				}
				logMessages.WriteString(fmt.Sprintf("[+] Modified file: %s\n", path))
			}
		}
		return nil
	})

	if err != nil {
		logMessages.WriteString(fmt.Sprintf("[-] error walking the path %s: %v\n", parentDir, err))
		logLabel.SetText(logMessages.String())
		return err
	}

	logMessages.WriteString("[+] ControlFlow obfuscation disabled successfully\n")
	logLabel.SetText(logMessages.String())
	return nil
}
