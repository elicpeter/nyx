package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	base := "/var/log"
	name := "app.log"
	path := filepath.Join(base, name)
	f, err := os.Open(path)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer f.Close()
	fmt.Println("reading:", path)
}
