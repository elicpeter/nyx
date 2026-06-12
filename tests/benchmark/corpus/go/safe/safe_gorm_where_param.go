// Synthetic safe counterpart to sqli_gorm_order.go.
// Same GORM builder family, but the tainted value is passed as a bind
// parameter to `db.Where("col = ?", val)` — GORM sends arg 1+ through the
// driver's parameterised path, so the payload-arg-0 gate keeps it silent.
// Pins the precision side of the GORM builder sink fix (CVE-2024-37896): a
// parameterised query must NOT fire even though `db.Where` is a sink.
package main

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var GVA_DB *gorm.DB

func safeFilterHandler(c *gin.Context) {
	name := c.Query("name")
	db := GVA_DB
	db = db.Where("name = ?", name)
	_ = db
}
