# Golang shellcode memory loader

Golang shellcode into memory loader demo using go:embed to include the
binary code directly in the go executeable

Note: shellcode and loaded must be the same architecture (386 or amd64)

Demo needs the PE to shellcode converter from the following url to extract the
pure shellcode binary (.bin) from the PE-file (.exe): <https:github.com/hasherezade/pe_to_shellcode/releases/download/v0.9/pe2shc.exe>

ATTENTION: triggers antivir alerts! Whitelist this file!

prepare, build with:

    go generate
    go build

start with:
    
    .\golang_shellcode_memory_loader.exe

GPL-3.0 License

partly taken over from https:raw.githubusercontent.com/Ne0nd0g/go-shellcode/master/cmd/CreateThread/main.go (GPL-3.0 License)
