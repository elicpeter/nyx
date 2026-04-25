package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	dir := os.Getenv("DATA_DIR")
	if dir == "" {
		dir = "/tmp"
	}
	safe := filepath.Clean(dir)
	f, err := os.Open(safe)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer f.Close()
	fmt.Println("opened:", safe)
}
