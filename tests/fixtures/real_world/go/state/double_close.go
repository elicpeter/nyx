package main

import "os"

func doubleClose(path string) {
	f, _ := os.Open(path)
	f.Close()
	f.Close()
}

func useAfterClose(path string) {
	f, _ := os.Open(path)
	f.Close()
	buf := make([]byte, 1024)
	f.Read(buf)
}
