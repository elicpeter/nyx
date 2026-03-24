package main

import "os"

func leakyRead(path string) {
	f, _ := os.Open(path)
	buf := make([]byte, 1024)
	f.Read(buf)
}
