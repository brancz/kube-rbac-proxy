package filters

import (
	"net/http"
	"path"
)

func WithAllowPaths(allowPaths []string, handler http.HandlerFunc) http.HandlerFunc {
	if len(allowPaths) == 0 {
		return handler
	}

	return func(w http.ResponseWriter, req *http.Request) {
		for _, pathAllowed := range allowPaths {
			found, err := path.Match(pathAllowed, req.URL.Path)
			if err != nil {
				http.Error(
					w,
					http.StatusText(http.StatusInternalServerError),
					http.StatusInternalServerError,
				)
				return
			}

			if found {
				handler.ServeHTTP(w, req)
				return
			}
		}

		http.NotFound(w, req)
	}
}
