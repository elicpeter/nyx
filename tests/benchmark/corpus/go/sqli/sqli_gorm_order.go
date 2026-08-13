// Synthetic regression fixture for the GORM query-builder SQL sink fix.
// Pins: a tainted value passed to a terminal/assigned `db.Order(x)` (GORM
// ORDER BY clause builder) fires SQL_QUERY.  The structural invariant is the
// GORM builder sink set in `src/labels/go.rs` (`db.Order` / `db.Where` /
// `db.Group` / ...).  Original gap surfaced via CVE-2024-37896 (gin-vue-admin).
package main

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var GVA_DB *gorm.DB

func sortHandler(c *gin.Context) {
	order := c.Query("order")
	db := GVA_DB
	db = db.Order(order)
	_ = db
}
