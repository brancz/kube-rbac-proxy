package filters

import (
	"net/http"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/klog/v2"
)

func WithAuthentication(authReq authenticator.Request, audiences []string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		if len(audiences) > 0 {
			ctx = authenticator.WithAudiences(ctx, audiences)
			req = req.WithContext(ctx)
		}

		res, ok, err := authReq.AuthenticateRequest(req)
		if err != nil {
			klog.Errorf("Unable to authenticate the request due to an error: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		req = req.WithContext(request.WithUser(req.Context(), res.User))
		handler.ServeHTTP(w, req)
	}
}
