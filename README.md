
![Logo](https://github.com/furax124/Protect_Loader/blob/main/GUI/Assets/LOGO.png)

# Protect Loader

## Description
Protect Loader is a shellcode loader written in pure golang designed to provide various security and evasion techniques for Go applications. It includes features such as shellcode loading, obfuscation, the use of indirect syscalls, and much more.

## Features
- **Shellcode Loading**: Secure shellcode loading using apc method.
- **GUI**: User interface created with Fyne.
- **Obfuscation**: Code obfuscation with garble.
- **Indirect Syscalls**: Use of indirect syscalls by [acheron](https://github.com/f1zm0/acheron) for evasion.
- **Api ashing**: [Acheron](https://github.com/f1zm0/acheron) package have a integrated api hashing for evasion
- **Bypass AMSI and EDR**: Techniques to bypass AMSI and EDR.
- **Admin Privileges Check**: Check if admin privileges are enabled.
- **Random Sleep**: Adding random delays.
- **Block Non-Microsoft DLLs**: Blocking the injection of non-Microsoft DLLs.
- **Phantom Technique**: Suspension of event logs.
- **Unhooking**: Removal of hooks for av evasion.
- **PE file To Shellcode**: The PE file is automatically transformed into a .bin using [Donut](https://github.com/TheWover/donut) and encoded using [Shikata ga nai](https://github.com/EgeBalci/sgn) and encrypted using two layer of encryption (aes and xor)

## Roadmap
- [X] Create a GUI with Fyne
- [ ] Rework it to be more user-friendly (need to add option and bunch of things)
- [X] Make the code obfuscation with garble
- [X] Use indirect syscalls
- [X] Implement techniques to bypass AMSI and EDR
- [X] Check if admin privileges are enabled
- [X] Add random delays
- [X] Block the injection of non-Microsoft DLLs
- [X] Phantom technique to suspend event logs
- [X] Unhooking
- [ ] Call Stack spoofing
- [ ] Obfuscate IAT table imports you can use [this](https://github.com/furax124/UPX_Compress_And_Patcher)
- [ ] Polymorphic code
- [ ] Remote shellcode to avoid detection
- [X] Encrypt XOR and AES keys in `main.go`
- [ ] Sign shellcode and loader with a certificate


## How to use it

- Run the GUI.bat 
- Select your PE file
- and compile it with this command 
```sh
Garble -literals -seed=random -tiny build -ldflags="-w -s -H=windowsgui -buildid=" -trimpath
```

## Notes:

- Protect Loader actually bypass runtime Avast and Windows Defender detection as 29/12/2024.
- In the GUI and subfolder there is a lot of PE file (exe) if you don't trust them,feel free to download them from their official repo.
- In complementary you can use [this](https://github.com/furax124/UPX_Compress_And_Patcher) to obfuscate the IAT table with UPX and auto patch

## Credit

 - [Hooka Shellcode loader](https://github.com/D3Ext/Hooka) - for the code i use 
 - [scriptchildie](https://www.scriptchildie.com/) - Provide a amazing guide which help me a lot
 - [Taxmachine](https://github.com/TaxMachine) - Help me a lot for debugging or suggestions check out his github !


## Screenshots of the GUI

![App Screenshot](https://github.com/furax124/Protect_Loader/blob/main/GUI/Assets/Preview.png)

## Authors

- [@furax124](https://github.com/furax124)


## License

This Project is licensed under [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/)
