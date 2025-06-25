# ADC SSO Service SDK

Go SDK for integrating with the ADC SSO Service.

## Installation

```bash
go get github.com/verawat1234/adc-sso-service/sdk
```

## Usage

### Initialize Client

```go
import "github.com/verawat1234/adc-sso-service/sdk"

client := sdk.NewSSOClient("http://localhost:9000")
```

### Get SSO Login URL

```go
loginResp, err := client.GetSSOLoginURL()
if err != nil {
    log.Fatal(err)
}

// Redirect user to loginResp.RedirectURL
fmt.Printf("Redirect to: %s\n", loginResp.RedirectURL)
```

### Handle SSO Callback

```go
// After user returns from Keycloak
code := "authorization_code_from_callback"
state := "state_from_callback"

callbackResp, err := client.HandleSSOCallback(code, state)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("User authenticated: %s (%s)\n", 
    callbackResp.Username, callbackResp.Email)
fmt.Printf("Access Token: %s\n", callbackResp.AccessToken)
```

### Validate Token

```go
validationResp, err := client.ValidateToken(accessToken)
if err != nil {
    log.Printf("Token validation failed: %v", err)
    return
}

if validationResp.Valid {
    fmt.Printf("Token valid for user: %s\n", validationResp.Username)
} else {
    fmt.Println("Token is invalid")
}
```

### Refresh Token

```go
refreshResp, err := client.RefreshToken(refreshToken)
if err != nil {
    log.Printf("Token refresh failed: %v", err)
    return
}

fmt.Printf("New access token: %s\n", refreshResp.AccessToken)
```

### Health Check

```go
if err := client.CheckHealth(); err != nil {
    log.Printf("SSO service is unhealthy: %v", err)
} else {
    log.Println("SSO service is healthy")
}
```

## Integration Example

```go
package main

import (
    "log"
    
    "github.com/verawat1234/adc-sso-service/sdk"
    "github.com/gin-gonic/gin"
)

func main() {
    ssoClient := sdk.NewSSOClient("http://localhost:9000")
    
    router := gin.Default()
    
    // Initiate SSO login
    router.GET("/auth/sso/login", func(c *gin.Context) {
        loginResp, err := ssoClient.GetSSOLoginURL()
        if err != nil {
            c.JSON(500, gin.H{"error": err.Error()})
            return
        }
        
        c.Redirect(302, loginResp.RedirectURL)
    })
    
    // Handle SSO callback
    router.GET("/auth/sso/callback", func(c *gin.Context) {
        code := c.Query("code")
        state := c.Query("state")
        
        callbackResp, err := ssoClient.HandleSSOCallback(code, state)
        if err != nil {
            c.JSON(500, gin.H{"error": err.Error()})
            return
        }
        
        // Store tokens in session/database
        // Redirect to application dashboard
        c.JSON(200, callbackResp)
    })
    
    // Protected middleware using token validation
    router.Use(func(c *gin.Context) {
        token := c.GetHeader("Authorization")
        if token == "" {
            c.JSON(401, gin.H{"error": "Missing authorization header"})
            c.Abort()
            return
        }
        
        // Remove "Bearer " prefix
        if len(token) > 7 && token[:7] == "Bearer " {
            token = token[7:]
        }
        
        validationResp, err := ssoClient.ValidateToken(token)
        if err != nil || !validationResp.Valid {
            c.JSON(401, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }
        
        // Add user info to context
        c.Set("user_id", validationResp.UserID)
        c.Set("username", validationResp.Username)
        c.Set("email", validationResp.Email)
        c.Next()
    })
    
    router.Run(":8080")
}
```

## Configuration

The SDK automatically handles:
- HTTP timeouts (30 seconds)
- JSON marshaling/unmarshaling
- Error handling and propagation
- Response validation

## Error Handling

All methods return descriptive errors that include:
- Network errors
- HTTP status errors
- JSON parsing errors
- SSO service errors

Always check for errors and handle them appropriately in your application.