package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// JWKSHandler publishes every currently accepted verification key so third
// parties can validate access tokens without sharing a private key. The
// response is public by design; during rotation both the new and the retired
// key are published so consumers can switch by "kid" without an outage.
func JWKSHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		keys, err := GetPublicJWKs()
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"data": nil, "error": "signing key unavailable"})
			return
		}
		c.Header("Cache-Control", "public, max-age=300")
		c.JSON(http.StatusOK, gin.H{"keys": keys})
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
