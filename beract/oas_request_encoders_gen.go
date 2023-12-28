// Code generated by ogen, DO NOT EDIT.

package beract

import (
	"bytes"
	"net/http"

	"github.com/go-faster/errors"
	"github.com/go-faster/jx"

	ht "github.com/ogen-go/ogen/http"
)

func encodeActivitiesCreateRequest(
	req ActivitiesCreateReq,
	r *http.Request,
) error {
	const contentType = "application/json"
	e := new(jx.Encoder)
	{
		req.Encode(e)
	}
	encoded := e.Bytes()
	ht.SetBody(r, bytes.NewReader(encoded), contentType)
	return nil
}

func encodeArtefactsCreateRequest(
	req *ArtefactsCreateReqWithContentType,
	r *http.Request,
) error {
	contentType := req.ContentType
	if contentType != "" && !ht.MatchContentType("application/*", contentType) {
		return errors.Errorf("%q does not match mask %q", contentType, "application/*")
	}
	{
		req := req.Content
		body := req
		ht.SetBody(r, body, contentType)
		return nil
	}
}