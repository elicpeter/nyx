package main

import "os"

func branchLeak(path string, flag bool) {
	f, _ := os.Open(path)
	if flag {
		buf := make([]byte, 1024)
		f.Read(buf)
		f.Close()
	}
	// f leaked if !flag
}
