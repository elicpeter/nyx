package main

import (
	"crypto/des"
	"crypto/md5"
	"net/http"
)

func handleHash(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("data")
	md5.Sum([]byte(data))
}

func handleCipher(w http.ResponseWriter, r *http.Request) {
	key := r.FormValue("key")
	des.NewCipher([]byte(key))
}
