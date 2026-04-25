package main

import (
	"fmt"
	"os"
)

func main() {
	f, err := os.Open("/etc/hostname")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer f.Close()
	buf := make([]byte, 256)
	n, _ := f.Read(buf)
	fmt.Println(string(buf[:n]))
}
