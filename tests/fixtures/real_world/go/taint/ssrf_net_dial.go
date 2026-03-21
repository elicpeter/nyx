package main

import (
	"net"
	"os"
)

func main() {
	host := os.Getenv("TARGET_HOST")
	net.Dial("tcp", host+":80")
}
