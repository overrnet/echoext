package echoext

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

func BasicErrorHandler() echo.HTTPErrorHandler {
	return func(c echo.Context, err error) {
		if err, ok := err.(*echo.HTTPError); ok {
			c.String(err.Code, fmt.Sprint(err.Message))
			return
		}
		c.NoContent(http.StatusInternalServerError)
	}
}

func JsonErrorHandler() echo.HTTPErrorHandler {
	return func(c echo.Context, err error) {
		if err, ok := err.(*echo.HTTPError); ok {
			c.JSON(err.Code, echo.Map{"status": err.Message, "code": err.Code})
			return
		}
		c.NoContent(http.StatusInternalServerError)
	}
}

func CorsAny() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Response().Header().Set(echo.HeaderAccessControlAllowOrigin, "*")
			return next(c)
		}
	}
}

type UserPass map[string]string

func BasicAuth(kv UserPass) echo.MiddlewareFunc {
	return middleware.BasicAuth(func(_ echo.Context, username, password string) (bool, error) {
		passwordCheck, ok := kv[username]
		if !ok {
			return false, nil
		}

		if subtle.ConstantTimeCompare([]byte(password), []byte(passwordCheck)) == 1 {
			return true, nil
		}
		return false, nil
	})
}

type DisallowList []string

func DisallowInPath(list DisallowList, code int) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			for _, txt := range list {
				if strings.Contains(c.Request().URL.Path, txt) {
					return echo.NewHTTPError(code, http.StatusText(code))
				}
			}
			return next(c)
		}
	}
}

func EnvPortOr(port string) (string, bool) {
	envPort, envExists := os.LookupEnv("PORT")
	if !envExists {
		return ":" + port, false
	}
	return ":" + envPort, true
}

// 5 is a good level
//
// file extentions to compress ".js", ".css"
func GzipMiddleware(level int, types ...string) echo.MiddlewareFunc {
	return middleware.GzipWithConfig(middleware.GzipConfig{
		Level: level,
		Skipper: func(c echo.Context) bool {
			var found = false
			for _, ext := range types {
				if strings.HasSuffix(c.Request().URL.Path, ext) {
					found = true
				}
			}
			return !found
		},
	})
}
