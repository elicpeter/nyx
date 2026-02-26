package main

import (
	"fmt"
	"os"
)

func riskyOperation() {
	f, err := os.Open("/tmp/test")
	if err != nil {
		panic(err)
	}
	// f leaked on panic path
	buf := make([]byte, 1024)
	f.Read(buf)
	f.Close()
}

func safeOperation() {
	f, err := os.Open("/tmp/test")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	buf := make([]byte, 1024)
	f.Read(buf)
}

func recoverWrapper() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered:", r)
		}
	}()
	riskyOperation()
}
