package types

type TokenValidationRequest struct {
	AccessToken string `json:"access_token" binding:"required"`
}

type TokenRefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}