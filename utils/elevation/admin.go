package elevation

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

func IsAdmin() bool {
	var sid *windows.SID
	// Create a SID for the BUILTIN\Administrators group.
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}

	// Check if the token has the admin SID.
	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}

	return member
}

func Elevate() error {
	if IsAdmin() {
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("[-] failed to get executable path: %v", err)
	}
	verb := "runas"
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	argPtr, _ := syscall.UTF16PtrFromString(" " + syscall.EscapeArg(args))

	var showCmd int32 = 1 // SW_SHOWNORMAL

	err = windows.ShellExecute(0, verbPtr, exePtr, argPtr, nil, showCmd)
	if err != nil {
		return fmt.Errorf("[-] failed to start elevated process: %v", err)
	}

	os.Exit(0)
	return nil
}
