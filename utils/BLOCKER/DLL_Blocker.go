package DLLBlocker

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

/*

typedef struct _PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY {
  union {
    DWORD Flags;
    struct {
      DWORD MicrosoftSignedOnly : 1;
      DWORD StoreSignedOnly : 1;
      DWORD MitigationOptIn : 1;
      DWORD AuditMicrosoftSignedOnly : 1;
      DWORD AuditStoreSignedOnly : 1;
      DWORD ReservedFlags : 27;
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME;
} PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, *PPROCESS_MITIGATION_BINARY_SIGNATURE_POLICY;

*/

type PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY struct {
	Flags uint32
}

// block non Microsoft-signed DLLs to inject in current process
//garble:controlflow flatten_passes=1 flatten_hardening=xor,delegate_table
func BlockDLLs() error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	SetProcessMitigationPolicy := kernel32.NewProc("SetProcessMitigationPolicy")

	var ProcessSignaturePolicy uint32 = 8
	var sp PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY

	// set MicrosoftSignedOnly
	sp.Flags = 0x1

	ret, _, err := SetProcessMitigationPolicy.Call(
		uintptr(ProcessSignaturePolicy),
		uintptr(unsafe.Pointer(&sp)),
		unsafe.Sizeof(sp),
	)

	if ret == 0 {
		return errors.New(fmt.Sprintf("error: %s\nSetProcessMitigationPolicy returned %x", err, ret))
	}

	return nil
}

//This code is from https://github.com/D3Ext/Hooka
