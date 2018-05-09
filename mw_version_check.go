package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/request"
)

// VersionCheck will check whether the version of the requested API the request is accessing has any restrictions on URL endpoints
type VersionCheck struct {
	BaseMiddleware
	sh SuccessHandler
}

func (v *VersionCheck) Init() {
	v.sh = SuccessHandler{v.BaseMiddleware}
}

func (v *VersionCheck) Name() string {
	return "VersionCheck"
}

func (v *VersionCheck) DoMockReply(w http.ResponseWriter, meta interface{}) {
	// Reply with some alternate data
	emeta := meta.(*apidef.EndpointMethodMeta)
	responseMessage := []byte(emeta.Data)
	for header, value := range emeta.Headers {
		w.Header().Add(header, value)
	}

	w.WriteHeader(emeta.Code)
	w.Write(responseMessage)
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (v *VersionCheck) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	// Check versioning, blacklist, whitelist and ignored status
	result := v.Spec.RequestValid2(r)
	// requestValid, stat, meta := v.Spec.RequestValid2(r)
	if !result.valid {
		// Fire a versioning failure event
		v.FireEvent(EventVersionFailure, EventVersionFailureMeta{
			EventMetaDefault: EventMetaDefault{Message: "Attempted access to disallowed version / path.", OriginatingRequest: EncodeRequestToEvent(r)},
			Path:             r.URL.Path,
			Origin:           request.RealIP(r),
			Reason:           string(result.status),
		})
		return errors.New(string(result.status)), 403
	}

	// We handle redirects before ignores in case we aren't using a whitelist
	if result.status == StatusRedirectFlowByReply {
		v.DoMockReply(w, result.meta)
		return nil, mwStatusRespond
	}

	if expTime, _ := result.meta.(*time.Time); expTime != nil {
		w.Header().Set("x-tyk-api-expires", expTime.Format(time.RFC1123))
	}

	if result.status == StatusOkAndIgnore {
		v.sh.ServeHTTP(w, r)
		return nil, mwStatusRespond
	}

	return nil, 200
}
