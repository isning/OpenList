package middlewares

import (
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/gin-gonic/gin"
)

// OIDCAccountReadOnly blocks alternate credentials and identity changes for a
// managed session. Ordinary local sessions retain their existing account APIs.
func OIDCAccountReadOnly(c *gin.Context) {
	if _, managed := c.Get(common.OIDCSessionContextKey); managed {
		common.ErrorStrResp(c, "OIDC-managed sessions cannot change authentication information", 403)
		c.Abort()
		return
	}
	c.Next()
}
