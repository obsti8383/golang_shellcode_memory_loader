package main

import (
	"fmt"
	//"os"
	"time"
)

func main() {
	//d1 := []byte("hello from embedded exe")
	//os.WriteFile("C:\\tmp\\hello.txt", d1, 0644)
	fmt.Println("--- Hello from embedded bin ---")
	time.Sleep(10 * time.Second)
	fmt.Println("--- fin embedded ---")
}
