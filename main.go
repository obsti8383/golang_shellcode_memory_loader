// Golang shellcode into memory loader demo using go:embed to include the
// binary code directly in the go executeable
// Note: shellcode and loaded must be the same architecture (386 or amd64)
//
// Demo needs the PE to shellcode converter from the following url to extract the
// pure shellcode binary (.bin) from the PE-file (.exe):
// https://github.com/hasherezade/pe_to_shellcode/releases/download/v0.9/pe2shc.exe
//
// ATTENTION: triggers antivir alerts! Whitelist this file!
//
// prepare, build with:
//  go generate
//  go build
//
// start with:
//  .\golang_shellcode_memory_loader.exe
//
// GPL-3.0 License
//
// partly taken over from https://raw.githubusercontent.com/Ne0nd0g/go-shellcode/master/cmd/CreateThread/main.go (GPL-3.0 License)
//

//go:build windows

package main

import (
	_ "embed"
	"errors"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:generate go build -o .\hello\hello.exe .\hello\.
//go:generate powershell.exe -c Invoke-WebRequest -OutFile pe2shc.exe https://github.com/hasherezade/pe_to_shellcode/releases/download/v0.9/pe2shc.exe
//go:generate .\pe2shc.exe .\hello\hello.exe hello.bin

//go:embed hello.bin
var shellcode []byte

var (
	ntdll         = windows.NewLazySystemDLL("ntdll.dll")
	RtlCopyMemory = ntdll.NewProc("RtlCopyMemory")
	kernel32      = windows.NewLazySystemDLL("kernel32.dll")
	CreateThread  = kernel32.NewProc("CreateThread")
)

func main() {
	// reserve memory
	fmt.Println("Reserving memory using VirtualAlloc")
	addr, errVirtualAlloc := windows.VirtualAlloc(uintptr(0), uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if errVirtualAlloc != nil {
		log.Fatal(fmt.Sprintf("ERROR calling VirtualAlloc: %s", errVirtualAlloc.Error()))
	}
	if addr == 0 {
		log.Fatal("ERROR calling VirtualAlloc: failed and returned 0")
	}
	fmt.Println("Successfully allocated", len(shellcode), "bytes")

	// copy code to reserved memory
	fmt.Println("Copying shellcode to reserved memory using RtlCopyMemory")
	_, _, errRtlCopyMemory := RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	if errRtlCopyMemory != syscall.Errno(0) {
		log.Fatal(fmt.Sprintf("ERROR calling RtlCopyMemory: %s", errRtlCopyMemory.Error()))
	}
	fmt.Println("Shellcode copied to reserved memory successfully")

	// make memory containing code executable
	fmt.Println("Calling VirtualProtect to change memory region to PAGE_EXECUTE_READWRITE")
	var oldProtect uint32
	errVirtualProtect := windows.VirtualProtect(addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if errVirtualProtect != nil {
		log.Fatal(fmt.Sprintf("ERROR calling VirtualProtect:\r\n%s", errVirtualProtect.Error()))
	}
	fmt.Println("Shellcode memory region changed to PAGE_EXECUTE_READWRITE")

	// start thread
	fmt.Println("Calling CreateThread to start shellcode")
	thread, _, errCreateThread := CreateThread.Call(0, 0, addr, uintptr(0), 0, 0)
	if errCreateThread != syscall.Errno(0) {
		log.Fatal(fmt.Sprintf("ERROR calling CreateThread:\r\n%s", errCreateThread.Error()))
	}
	fmt.Println("Shellcode started", thread)

	// wait for thread to terminate
	fmt.Println("Calling WaitForSingleObject to wait for shellcode before terminating")
	waitError := Wait(windows.Handle(thread))
	if waitError != nil {
		log.Fatal(fmt.Sprintf("ERROR calling WaitForSingleObject: %s", waitError.Error()))
	}

	fmt.Println("... finished") // does not get called when using demo shellcode
	// because it terminates the process before.
}

func Wait(h windows.Handle) error {
	s, err := windows.WaitForSingleObject(h, windows.INFINITE)
	fmt.Println("WaitForSingleObject returned with", s)

	switch s {
	case windows.WAIT_OBJECT_0:
		break
	case windows.WAIT_FAILED:
		return err
	default:
		return errors.New("unexpected result from WaitForSingleObject")
	}
	return nil
}
