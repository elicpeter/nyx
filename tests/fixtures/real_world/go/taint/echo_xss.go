package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func handler(c echo.Context) error {
	name := c.QueryParam("name")
	return c.String(http.StatusOK, "<h1>Hello "+name+"</h1>")
}
