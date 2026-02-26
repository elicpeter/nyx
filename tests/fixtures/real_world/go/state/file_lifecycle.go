package main

import "os"

func readLeak(path string) {
	f, _ := os.Open(path)
	buf := make([]byte, 1024)
	f.Read(buf)
	// f not closed
}

func readClose(path string) {
	f, _ := os.Open(path)
	buf := make([]byte, 1024)
	f.Read(buf)
	f.Close()
}

func readDefer(path string) {
	f, _ := os.Open(path)
	defer f.Close()
	buf := make([]byte, 1024)
	f.Read(buf)
}
