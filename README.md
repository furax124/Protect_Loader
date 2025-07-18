
![Logo](https://github.com/furax124/Protect_Loader/blob/main/GUI/Assets/LOGO.png)

# Protect Loader

## Description
Protect Loader is a shellcode loader written in pure golang designed to provide various security and evasion techniques for Go applications. It includes features such as shellcode loading, obfuscation, the use of indirect syscalls, and much more.

## Features
- **Shellcode Loading**: Loading shellcode using Early bird apc.
- **GUI**: User interface created with Fyne.
- **Obfuscation**: Code obfuscation with [garble](https://github.com/burrowers/garble) with optionnaly his controlflow (need to set the environment variable `GARBLE_EXPERIMENTAL_CONTROLFLOW=1`).
- **Indirect Syscalls**: Use of indirect syscalls by [acheron](https://github.com/f1zm0/acheron) for evasion.
- **Api ashing**: [Acheron](https://github.com/f1zm0/acheron) package have a integrated api hashing for evasion
- **Bypass AMSI and EDR**: Techniques to bypass AMSI and EDR.
- **Admin Privileges Check**: Check if admin privileges are enabled.
- **Random Sleep**: Adding random delays.
- **Block Non-Microsoft DLLs**: Blocking the injection of non-Microsoft DLLs.
- **Phantom Technique**: Suspension of event logs.
- **PE file To Shellcode**: The PE file is automatically transformed into a .bin using [Donut](https://github.com/TheWover/donut) and encoded using [Shikata ga nai](https://github.com/EgeBalci/sgn) and encrypted using two layer of encryption (aes-cfb and xor)
- **Key Encryption**: The key generated is encrypted using XOR to prevent his extraction

## Roadmap
- 🚧 = Priority Features

- [X] Create a GUI with Fyne
- [X] Enhance the shellcode injection (can always do better but waste of time)
- [ ] Rework it to be more user-friendly (need to add option and bunch of things)
- [X] Make the code obfuscation with garble
- [X] Use indirect syscalls
- [X] Implement techniques to bypass AMSI and EDR
- [X] Check if admin privileges are enabled
- [X] Add random delays
- [X] Block the injection of non-Microsoft DLLs
- [X] Phantom technique to suspend event logs
- [X] Remove unhooking method (too monitored by EDR/AV,indirect syscalls is better)
- [ ] Call Stack spoofing
- [ ] Polymorphic code
- [ ] Remote shellcode to avoid detection
- [X] Encrypt XOR and AES-CFB keys in `main.go`
- [ ] Sign shellcode and loader with a certificate 🚧
- [X] Enchance the sleep duration (AV accelerate time in a [sandbox](https://www.scriptchildie.com/evasion/av-bypass/3.-delay-execution))
- [X] Adding control flow obfuscation with [garble](https://github.com/burrowers/garble/blob/master/docs/CONTROLFLOW.md)
- [X] Support of shellcode file (.bin)
- [ ] Anti debug/Anti vm
- [ ] Spamming of admin prompt
- [ ] Wiki
- [ ] Add .ico support for the generated PE file

## Requirements:
- Golang 1.24.4+
- CGO enable (you can use [this](https://github.com/ehsan18t/easy-mingw-installer/tree/main?tab=readme-ov-file) to facilate the installation)
- Git

## How to use it

- Run the GUI.bat 
- Select your PE file
- The GUI will compile it automatically (may take some time)
## Notes:
- In the GUI and subfolder there is a lot of PE file (exe) if you don't trust them,feel free to download them from their official repo.
- In complementary you can use [this](https://github.com/furax124/UPX_Compress_And_Patcher) to obfuscate the IAT table with UPX and auto patch
- If you want to debug make sure to remove the elevation code from main.go
- ⚠️ IF you want to use Control flow obfuscation you will need set the environment variable GARBLE_EXPERIMENTAL_CONTROLFLOW=1
## Credit

 - [Hooka Shellcode loader](https://github.com/D3Ext/Hooka) - for the code i use 
 - [scriptchildie](https://www.scriptchildie.com/) - Provide a amazing guide which help me a lot
 - [Taxmachine](https://github.com/TaxMachine) - Help me a lot for debugging or suggestions check out his github !


## Screenshots of the GUI

![App Screenshot](https://github.com/furax124/Protect_Loader/blob/main/GUI/Assets/Preview.png)

## AV detection (may increase) as of 25/06/2025 with Controlflow
- [VirusTotal](https://www.virustotal.com/gui/file/f3978b792133221cdd5582a00548494212f0559242ce37a721aae8598eb7a6a9?nocache=1) The detection is done without anti debug/vm there will be NO update against detection rate,this is done with a reverse shell.
![image](https://raw.githubusercontent.com/furax124/Protect_Loader/refs/heads/main/GUI/Assets/DETECTION.png)

- Avast one Runtime:
![image](https://github.com/user-attachments/assets/22fccf5e-7a47-40fa-bcfa-86853e73b930)


## Authors

- [@furax124](https://github.com/furax124)

## Disclaimer !

- This tool is entended to be used for educational purpose,I don't take any responsability about what you do with this software (and should be not used since its unstable)

## License

This Project is licensed under [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/)
