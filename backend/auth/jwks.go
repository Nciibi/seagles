package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// JWKSHandler publishes the active verification key so third parties can
// validate access tokens without sharing the private key. The response is
// public by design; Rotate-key deployments should publish both old and new
// keys during the overlap window.
func JWKSHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		jwk, err := GetPublicJWK()
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"data": nil, "error": "signing key unavailable"})
			return
		}
		c.Header("Cache-Control", "public, max-age=300")
		c.JSON(http.StatusOK, gin.H{"keys": []JWK{jwk}})
	}
}

// PublicKeyPEMHandler keeps the PEM form available for clients that do not
// implement JWK parsing.
func PublicKeyPEMHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		pemKey, err := GetPublicKeyPEM()
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"data": nil, "error": "signing key unavailable"})
			return
		}
		c.Header("Content-Type", "application/x-pem-file")
		c.String(http.StatusOK, pemKey)
	}
}
