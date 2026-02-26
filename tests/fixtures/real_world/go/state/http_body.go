package main

import (
	"io/ioutil"
	"net/http"
)

func fetchLeak(url string) string {
	resp, _ := http.Get(url)
	body, _ := ioutil.ReadAll(resp.Body)
	// resp.Body not closed
	return string(body)
}

func fetchSafe(url string) string {
	resp, _ := http.Get(url)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body)
}
