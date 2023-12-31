// Code generated by ogen, DO NOT EDIT.

package beridp

import (
	"github.com/go-faster/errors"

	"github.com/ogen-go/ogen/validate"
)

func (s ApplicationsListIsPublic) Validate() error {
	switch s {
	case "true":
		return nil
	case "false":
		return nil
	case "all":
		return nil
	default:
		return errors.Errorf("invalid value: %v", s)
	}
}

func (s *ApplicationsListOKHeaders) Validate() error {
	var failures []validate.FieldError
	if err := func() error {
		if s.Response == nil {
			return errors.New("nil is invalid value")
		}
		return nil
	}(); err != nil {
		failures = append(failures, validate.FieldError{
			Name:  "Response",
			Error: err,
		})
	}
	if len(failures) > 0 {
		return &validate.Error{Fields: failures}
	}
	return nil
}

func (s ApplicationsListOrderBy) Validate() error {
	switch s {
	case "created_at_asc":
		return nil
	case "created_at_desc":
		return nil
	case "updated_at_asc":
		return nil
	case "updated_at_desc":
		return nil
	default:
		return errors.Errorf("invalid value: %v", s)
	}
}
