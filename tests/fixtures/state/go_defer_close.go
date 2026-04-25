package main

import "os"

func safeRead(path string) {
	f, _ := os.Open(path)
	defer f.Close()
	buf := make([]byte, 1024)
	f.Read(buf)
}
