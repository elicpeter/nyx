package main

import "os"

func manualClose(path string) {
	f, _ := os.Open(path)
	buf := make([]byte, 1024)
	f.Read(buf)
	f.Close()
}
