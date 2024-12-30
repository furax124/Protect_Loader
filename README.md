
![Logo](https://github.com/furax124/Protect_Loader/blob/main/GUI/Assets/LOGO.png)

# Protect Loader

## Description
Protect Loader is a shellcode loader written in pure golang designed to provide various security and evasion techniques for Go applications. It includes features such as shellcode loading, obfuscation, the use of indirect syscalls, and much more.

## Features
- **Shellcode Loading**: Secure shellcode loading using apc method.
- **GUI**: User interface created with Fyne.
- **Obfuscation**: Code obfuscation with garble.
- **Indirect Syscalls**: Use of indirect syscalls for evasion.
- **Bypass AMSI and EDR**: Techniques to bypass AMSI and EDR.
- **Admin Privileges Check**: Check if admin privileges are enabled.
- **Random Sleep**: Adding random delays.
- **Block Non-Microsoft DLLs**: Blocking the injection of non-Microsoft DLLs.
- **Phantom Technique**: Suspension of event logs.
- **Unhooking**: Removal of hooks for av evasion.
- **PE file To Shellcode**: The PE file is automatically transformed into a .bin using [Donut](https://github.com/TheWover/donut) and encoded using [Shikata ga nai](https://github.com/EgeBalci/sgn) and encrypted using two layer of encryption (aes and xor)

## Roadmap
- [X] Create a GUI with Fyne
- [ ] Rework it to be more user-friendly
- [X] Make the code obfuscation with garble
- [X] Use indirect syscalls
- [X] Implement techniques to bypass AMSI and EDR
- [X] Check if admin privileges are enabled
- [X] Add random delays
- [X] Block the injection of non-Microsoft DLLs
- [X] Phantom technique to suspend event logs
- [X] Unhooking
- [ ] Obfuscate IAT table imports
- [ ] Polymorphic code
- [ ] Remote shellcode to avoid detection
- [ ] Encrypt XOR and AES keys in `main.go`
- [ ] ACG protection Need to be fixed
- [ ] Sign shellcode and loader with a certificate


## How to use it

- Run the GUI.bat 
- Select your PE file
- and compile it with this command 
```sh
Garble -literals -seed=random -tiny build -ldflags="-w -s -H=windowsgui -buildid=" -trimpath
```

## Notes:

- Protect Loader actually bypass runtime avast detection as 29/12/2024

## Credit

 - [Hooka Shellcode loader](https://github.com/D3Ext/Hooka) - for the code i use 
 - [scriptchildie](https://www.scriptchildie.com/) - Provide a amazing guide which help me a lot
 - [Taxmachine](https://github.com/TaxMachine) - Help me a lot for debugging or suggestions check out his github !


## Screenshots of the GUI

![App Screenshot](https://github.com/furax124/Protect_Loader/blob/main/GUI/Preview.png)

## Authors

- [@furax124](https://github.com/furax124)


## License

This Project is licensed under [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/)
