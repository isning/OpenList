package common

import (
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/oidcauth"
	"github.com/OpenListTeam/go-cache"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
)

var SecretKey []byte

type UserClaims struct {
	Username      string `json:"username"`
	OIDCSessionID string `json:"oidc_session_id,omitempty"`
	PwdTS         int64  `json:"pwd_ts"`
	jwt.RegisteredClaims
}

var validTokenCache = cache.NewMemCache[bool]()

func GenerateToken(user *model.User) (string, error) {
	if RequiresOIDC(user) {
		return "", oidcauth.ErrUnauthorized
	}
	return generateToken(user, "")
}

func generateToken(user *model.User, sessionID string) (tokenString string, err error) {
	claim := UserClaims{
		Username:      user.Username,
		OIDCSessionID: sessionID,
		PwdTS:         user.PwdTS,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(conf.Conf.TokenExpiresIn) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		}}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	tokenString, err = token.SignedString(SecretKey)
	if err != nil {
		return "", err
	}
	validTokenCache.Set(tokenString, true, cache.WithEx[bool](time.Duration(conf.Conf.TokenExpiresIn)*time.Hour))
	return tokenString, err
}

func ParseToken(tokenString string) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("invalid login token algorithm")
		}
		return SecretKey, nil
	})
	if IsTokenInvalidated(tokenString) {
		return nil, errors.New("token is invalidated")
	}
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, errors.New("that's not even a token")
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, errors.New("token is expired")
			} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				return nil, errors.New("token not active yet")
			} else {
				return nil, errors.New("couldn't handle this token")
			}
		}
	}
	if token == nil {
		return nil, errors.New("couldn't handle this token")
	}
	if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("couldn't handle this token")
}

func InvalidateToken(tokenString string) error {
	if tokenString == "" {
		return nil // don't invalidate empty guest token
	}
	if claims, err := ParseToken(tokenString); err == nil && claims.OIDCSessionID != "" {
		closeOIDCSession(claims.OIDCSessionID)
	}
	validTokenCache.Del(tokenString)
	return nil
}

func IsTokenInvalidated(tokenString string) bool {
	_, ok := validTokenCache.Get(tokenString)
	return !ok
}
