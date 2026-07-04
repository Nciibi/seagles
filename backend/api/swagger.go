package api

import (
	"embed"
	"net/http"

	"github.com/gin-gonic/gin"
)

//go:embed swagger.json
var swaggerFS embed.FS

func SwaggerJSONHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := swaggerFS.ReadFile("swagger.json")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Swagger spec not found"})
			return
		}
		c.Data(http.StatusOK, "application/json", data)
	}
}

func SwaggerUIHandler() gin.HandlerFunc {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>IronMesh API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js" crossorigin></script>
  <script>
    SwaggerUIBundle({
      url: "/api/v1/swagger.json",
      dom_id: "#swagger-ui",
    });
  </script>
</body>
</html>`
	return func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
	}
}
