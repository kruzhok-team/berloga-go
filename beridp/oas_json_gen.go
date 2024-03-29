// Code generated by ogen, DO NOT EDIT.

package beridp

import (
	"math/bits"
	"strconv"

	"github.com/go-faster/errors"
	"github.com/go-faster/jx"
	"github.com/google/uuid"

	"github.com/ogen-go/ogen/json"
	"github.com/ogen-go/ogen/validate"
)

// Encode implements json.Marshaler.
func (s *Application) Encode(e *jx.Encoder) {
	e.ObjStart()
	s.encodeFields(e)
	e.ObjEnd()
}

// encodeFields encodes fields.
func (s *Application) encodeFields(e *jx.Encoder) {
	{
		e.FieldStart("id")
		s.ID.Encode(e)
	}
	{
		e.FieldStart("created_at")
		json.EncodeDateTime(e, s.CreatedAt)
	}
	{
		e.FieldStart("updated_at")
		json.EncodeDateTime(e, s.UpdatedAt)
	}
	{
		e.FieldStart("is_public")
		e.Bool(s.IsPublic)
	}
	{
		e.FieldStart("name")
		e.Str(s.Name)
	}
	{
		e.FieldStart("icon_url")
		e.Str(s.IconURL)
	}
	{
		e.FieldStart("package_name")
		e.Str(s.PackageName)
	}
	{
		e.FieldStart("store_url")
		e.Str(s.StoreURL)
	}
	{
		e.FieldStart("launch_url")
		e.Str(s.LaunchURL)
	}
	{
		e.FieldStart("intro")
		e.Str(s.Intro)
	}
}

var jsonFieldsNameOfApplication = [10]string{
	0: "id",
	1: "created_at",
	2: "updated_at",
	3: "is_public",
	4: "name",
	5: "icon_url",
	6: "package_name",
	7: "store_url",
	8: "launch_url",
	9: "intro",
}

// Decode decodes Application from json.
func (s *Application) Decode(d *jx.Decoder) error {
	if s == nil {
		return errors.New("invalid: unable to decode Application to nil")
	}
	var requiredBitSet [2]uint8

	if err := d.ObjBytes(func(d *jx.Decoder, k []byte) error {
		switch string(k) {
		case "id":
			requiredBitSet[0] |= 1 << 0
			if err := func() error {
				if err := s.ID.Decode(d); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"id\"")
			}
		case "created_at":
			requiredBitSet[0] |= 1 << 1
			if err := func() error {
				v, err := json.DecodeDateTime(d)
				s.CreatedAt = v
				if err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"created_at\"")
			}
		case "updated_at":
			requiredBitSet[0] |= 1 << 2
			if err := func() error {
				v, err := json.DecodeDateTime(d)
				s.UpdatedAt = v
				if err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"updated_at\"")
			}
		case "is_public":
			requiredBitSet[0] |= 1 << 3
			if err := func() error {
				v, err := d.Bool()
				s.IsPublic = bool(v)
				if err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"is_public\"")
			}
		case "name":
			requiredBitSet[0] |= 1 << 4
			if err := func() error {
				v, err := d.Str()
				s.Name = string(v)
				if err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"name\"")
			}
		case "icon_url":
			requiredBitSet[0] |= 1 << 5
			if err := func() error {
				v, err := d.Str()
				s.IconURL = string(v)
				if err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"icon_url\"")
			}
		case "package_name":
			requiredBitSet[0] |= 1 << 6
			if err := func() error {
				v, err := d.Str()
				s.PackageName = string(v)
				if err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"package_name\"")
			}
		case "store_url":
			requiredBitSet[0] |= 1 << 7
			if err := func() error {
				v, err := d.Str()
				s.StoreURL = string(v)
				if err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"store_url\"")
			}
		case "launch_url":
			requiredBitSet[1] |= 1 << 0
			if err := func() error {
				v, err := d.Str()
				s.LaunchURL = string(v)
				if err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"launch_url\"")
			}
		case "intro":
			requiredBitSet[1] |= 1 << 1
			if err := func() error {
				v, err := d.Str()
				s.Intro = string(v)
				if err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"intro\"")
			}
		default:
			return d.Skip()
		}
		return nil
	}); err != nil {
		return errors.Wrap(err, "decode Application")
	}
	// Validate required fields.
	var failures []validate.FieldError
	for i, mask := range [2]uint8{
		0b11111111,
		0b00000011,
	} {
		if result := (requiredBitSet[i] & mask) ^ mask; result != 0 {
			// Mask only required fields and check equality to mask using XOR.
			//
			// If XOR result is not zero, result is not equal to expected, so some fields are missed.
			// Bits of fields which would be set are actually bits of missed fields.
			missed := bits.OnesCount8(result)
			for bitN := 0; bitN < missed; bitN++ {
				bitIdx := bits.TrailingZeros8(result)
				fieldIdx := i*8 + bitIdx
				var name string
				if fieldIdx < len(jsonFieldsNameOfApplication) {
					name = jsonFieldsNameOfApplication[fieldIdx]
				} else {
					name = strconv.Itoa(fieldIdx)
				}
				failures = append(failures, validate.FieldError{
					Name:  name,
					Error: validate.ErrFieldRequired,
				})
				// Reset bit.
				result &^= 1 << bitIdx
			}
		}
	}
	if len(failures) > 0 {
		return &validate.Error{Fields: failures}
	}

	return nil
}

// MarshalJSON implements stdjson.Marshaler.
func (s *Application) MarshalJSON() ([]byte, error) {
	e := jx.Encoder{}
	s.Encode(&e)
	return e.Bytes(), nil
}

// UnmarshalJSON implements stdjson.Unmarshaler.
func (s *Application) UnmarshalJSON(data []byte) error {
	d := jx.DecodeBytes(data)
	return s.Decode(d)
}

// Encode encodes ApplicationID as json.
func (s ApplicationID) Encode(e *jx.Encoder) {
	unwrapped := uuid.UUID(s)

	json.EncodeUUID(e, unwrapped)
}

// Decode decodes ApplicationID from json.
func (s *ApplicationID) Decode(d *jx.Decoder) error {
	if s == nil {
		return errors.New("invalid: unable to decode ApplicationID to nil")
	}
	var unwrapped uuid.UUID
	if err := func() error {
		v, err := json.DecodeUUID(d)
		unwrapped = v
		if err != nil {
			return err
		}
		return nil
	}(); err != nil {
		return errors.Wrap(err, "alias")
	}
	*s = ApplicationID(unwrapped)
	return nil
}

// MarshalJSON implements stdjson.Marshaler.
func (s ApplicationID) MarshalJSON() ([]byte, error) {
	e := jx.Encoder{}
	s.Encode(&e)
	return e.Bytes(), nil
}

// UnmarshalJSON implements stdjson.Unmarshaler.
func (s *ApplicationID) UnmarshalJSON(data []byte) error {
	d := jx.DecodeBytes(data)
	return s.Decode(d)
}

// Encode implements json.Marshaler.
func (s *Error) Encode(e *jx.Encoder) {
	e.ObjStart()
	s.encodeFields(e)
	e.ObjEnd()
}

// encodeFields encodes fields.
func (s *Error) encodeFields(e *jx.Encoder) {
	{
		e.FieldStart("error_message")
		e.Str(s.ErrorMessage)
	}
	{
		if s.VerboseMessage.Set {
			e.FieldStart("verbose_message")
			s.VerboseMessage.Encode(e)
		}
	}
}

var jsonFieldsNameOfError = [2]string{
	0: "error_message",
	1: "verbose_message",
}

// Decode decodes Error from json.
func (s *Error) Decode(d *jx.Decoder) error {
	if s == nil {
		return errors.New("invalid: unable to decode Error to nil")
	}
	var requiredBitSet [1]uint8

	if err := d.ObjBytes(func(d *jx.Decoder, k []byte) error {
		switch string(k) {
		case "error_message":
			requiredBitSet[0] |= 1 << 0
			if err := func() error {
				v, err := d.Str()
				s.ErrorMessage = string(v)
				if err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"error_message\"")
			}
		case "verbose_message":
			if err := func() error {
				s.VerboseMessage.Reset()
				if err := s.VerboseMessage.Decode(d); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"verbose_message\"")
			}
		default:
			return d.Skip()
		}
		return nil
	}); err != nil {
		return errors.Wrap(err, "decode Error")
	}
	// Validate required fields.
	var failures []validate.FieldError
	for i, mask := range [1]uint8{
		0b00000001,
	} {
		if result := (requiredBitSet[i] & mask) ^ mask; result != 0 {
			// Mask only required fields and check equality to mask using XOR.
			//
			// If XOR result is not zero, result is not equal to expected, so some fields are missed.
			// Bits of fields which would be set are actually bits of missed fields.
			missed := bits.OnesCount8(result)
			for bitN := 0; bitN < missed; bitN++ {
				bitIdx := bits.TrailingZeros8(result)
				fieldIdx := i*8 + bitIdx
				var name string
				if fieldIdx < len(jsonFieldsNameOfError) {
					name = jsonFieldsNameOfError[fieldIdx]
				} else {
					name = strconv.Itoa(fieldIdx)
				}
				failures = append(failures, validate.FieldError{
					Name:  name,
					Error: validate.ErrFieldRequired,
				})
				// Reset bit.
				result &^= 1 << bitIdx
			}
		}
	}
	if len(failures) > 0 {
		return &validate.Error{Fields: failures}
	}

	return nil
}

// MarshalJSON implements stdjson.Marshaler.
func (s *Error) MarshalJSON() ([]byte, error) {
	e := jx.Encoder{}
	s.Encode(&e)
	return e.Bytes(), nil
}

// UnmarshalJSON implements stdjson.Unmarshaler.
func (s *Error) UnmarshalJSON(data []byte) error {
	d := jx.DecodeBytes(data)
	return s.Decode(d)
}

// Encode implements json.Marshaler.
func (s *IssueTokenCreated) Encode(e *jx.Encoder) {
	e.ObjStart()
	s.encodeFields(e)
	e.ObjEnd()
}

// encodeFields encodes fields.
func (s *IssueTokenCreated) encodeFields(e *jx.Encoder) {
	{
		e.FieldStart("token")
		e.Str(s.Token)
	}
	{
		e.FieldStart("expires_in")
		e.Int32(s.ExpiresIn)
	}
}

var jsonFieldsNameOfIssueTokenCreated = [2]string{
	0: "token",
	1: "expires_in",
}

// Decode decodes IssueTokenCreated from json.
func (s *IssueTokenCreated) Decode(d *jx.Decoder) error {
	if s == nil {
		return errors.New("invalid: unable to decode IssueTokenCreated to nil")
	}
	var requiredBitSet [1]uint8

	if err := d.ObjBytes(func(d *jx.Decoder, k []byte) error {
		switch string(k) {
		case "token":
			requiredBitSet[0] |= 1 << 0
			if err := func() error {
				v, err := d.Str()
				s.Token = string(v)
				if err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"token\"")
			}
		case "expires_in":
			requiredBitSet[0] |= 1 << 1
			if err := func() error {
				v, err := d.Int32()
				s.ExpiresIn = int32(v)
				if err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"expires_in\"")
			}
		default:
			return d.Skip()
		}
		return nil
	}); err != nil {
		return errors.Wrap(err, "decode IssueTokenCreated")
	}
	// Validate required fields.
	var failures []validate.FieldError
	for i, mask := range [1]uint8{
		0b00000011,
	} {
		if result := (requiredBitSet[i] & mask) ^ mask; result != 0 {
			// Mask only required fields and check equality to mask using XOR.
			//
			// If XOR result is not zero, result is not equal to expected, so some fields are missed.
			// Bits of fields which would be set are actually bits of missed fields.
			missed := bits.OnesCount8(result)
			for bitN := 0; bitN < missed; bitN++ {
				bitIdx := bits.TrailingZeros8(result)
				fieldIdx := i*8 + bitIdx
				var name string
				if fieldIdx < len(jsonFieldsNameOfIssueTokenCreated) {
					name = jsonFieldsNameOfIssueTokenCreated[fieldIdx]
				} else {
					name = strconv.Itoa(fieldIdx)
				}
				failures = append(failures, validate.FieldError{
					Name:  name,
					Error: validate.ErrFieldRequired,
				})
				// Reset bit.
				result &^= 1 << bitIdx
			}
		}
	}
	if len(failures) > 0 {
		return &validate.Error{Fields: failures}
	}

	return nil
}

// MarshalJSON implements stdjson.Marshaler.
func (s *IssueTokenCreated) MarshalJSON() ([]byte, error) {
	e := jx.Encoder{}
	s.Encode(&e)
	return e.Bytes(), nil
}

// UnmarshalJSON implements stdjson.Unmarshaler.
func (s *IssueTokenCreated) UnmarshalJSON(data []byte) error {
	d := jx.DecodeBytes(data)
	return s.Decode(d)
}

// Encode implements json.Marshaler.
func (s *IssueTokenReq) Encode(e *jx.Encoder) {
	e.ObjStart()
	s.encodeFields(e)
	e.ObjEnd()
}

// encodeFields encodes fields.
func (s *IssueTokenReq) encodeFields(e *jx.Encoder) {
	{
		e.FieldStart("application_id")
		s.ApplicationID.Encode(e)
	}
	{
		e.FieldStart("player_id")
		s.PlayerID.Encode(e)
	}
	{
		e.FieldStart("player_secret")
		s.PlayerSecret.Encode(e)
	}
}

var jsonFieldsNameOfIssueTokenReq = [3]string{
	0: "application_id",
	1: "player_id",
	2: "player_secret",
}

// Decode decodes IssueTokenReq from json.
func (s *IssueTokenReq) Decode(d *jx.Decoder) error {
	if s == nil {
		return errors.New("invalid: unable to decode IssueTokenReq to nil")
	}
	var requiredBitSet [1]uint8

	if err := d.ObjBytes(func(d *jx.Decoder, k []byte) error {
		switch string(k) {
		case "application_id":
			requiredBitSet[0] |= 1 << 0
			if err := func() error {
				if err := s.ApplicationID.Decode(d); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"application_id\"")
			}
		case "player_id":
			requiredBitSet[0] |= 1 << 1
			if err := func() error {
				if err := s.PlayerID.Decode(d); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"player_id\"")
			}
		case "player_secret":
			requiredBitSet[0] |= 1 << 2
			if err := func() error {
				if err := s.PlayerSecret.Decode(d); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"player_secret\"")
			}
		default:
			return d.Skip()
		}
		return nil
	}); err != nil {
		return errors.Wrap(err, "decode IssueTokenReq")
	}
	// Validate required fields.
	var failures []validate.FieldError
	for i, mask := range [1]uint8{
		0b00000111,
	} {
		if result := (requiredBitSet[i] & mask) ^ mask; result != 0 {
			// Mask only required fields and check equality to mask using XOR.
			//
			// If XOR result is not zero, result is not equal to expected, so some fields are missed.
			// Bits of fields which would be set are actually bits of missed fields.
			missed := bits.OnesCount8(result)
			for bitN := 0; bitN < missed; bitN++ {
				bitIdx := bits.TrailingZeros8(result)
				fieldIdx := i*8 + bitIdx
				var name string
				if fieldIdx < len(jsonFieldsNameOfIssueTokenReq) {
					name = jsonFieldsNameOfIssueTokenReq[fieldIdx]
				} else {
					name = strconv.Itoa(fieldIdx)
				}
				failures = append(failures, validate.FieldError{
					Name:  name,
					Error: validate.ErrFieldRequired,
				})
				// Reset bit.
				result &^= 1 << bitIdx
			}
		}
	}
	if len(failures) > 0 {
		return &validate.Error{Fields: failures}
	}

	return nil
}

// MarshalJSON implements stdjson.Marshaler.
func (s *IssueTokenReq) MarshalJSON() ([]byte, error) {
	e := jx.Encoder{}
	s.Encode(&e)
	return e.Bytes(), nil
}

// UnmarshalJSON implements stdjson.Unmarshaler.
func (s *IssueTokenReq) UnmarshalJSON(data []byte) error {
	d := jx.DecodeBytes(data)
	return s.Decode(d)
}

// Encode encodes int32 as json.
func (o OptNilInt32) Encode(e *jx.Encoder) {
	if !o.Set {
		return
	}
	if o.Null {
		e.Null()
		return
	}
	e.Int32(int32(o.Value))
}

// Decode decodes int32 from json.
func (o *OptNilInt32) Decode(d *jx.Decoder) error {
	if o == nil {
		return errors.New("invalid: unable to decode OptNilInt32 to nil")
	}
	if d.Next() == jx.Null {
		if err := d.Null(); err != nil {
			return err
		}

		var v int32
		o.Value = v
		o.Set = true
		o.Null = true
		return nil
	}
	o.Set = true
	o.Null = false
	v, err := d.Int32()
	if err != nil {
		return err
	}
	o.Value = int32(v)
	return nil
}

// MarshalJSON implements stdjson.Marshaler.
func (s OptNilInt32) MarshalJSON() ([]byte, error) {
	e := jx.Encoder{}
	s.Encode(&e)
	return e.Bytes(), nil
}

// UnmarshalJSON implements stdjson.Unmarshaler.
func (s *OptNilInt32) UnmarshalJSON(data []byte) error {
	d := jx.DecodeBytes(data)
	return s.Decode(d)
}

// Encode encodes string as json.
func (o OptString) Encode(e *jx.Encoder) {
	if !o.Set {
		return
	}
	e.Str(string(o.Value))
}

// Decode decodes string from json.
func (o *OptString) Decode(d *jx.Decoder) error {
	if o == nil {
		return errors.New("invalid: unable to decode OptString to nil")
	}
	o.Set = true
	v, err := d.Str()
	if err != nil {
		return err
	}
	o.Value = string(v)
	return nil
}

// MarshalJSON implements stdjson.Marshaler.
func (s OptString) MarshalJSON() ([]byte, error) {
	e := jx.Encoder{}
	s.Encode(&e)
	return e.Bytes(), nil
}

// UnmarshalJSON implements stdjson.Unmarshaler.
func (s *OptString) UnmarshalJSON(data []byte) error {
	d := jx.DecodeBytes(data)
	return s.Decode(d)
}

// Encode implements json.Marshaler.
func (s *PlayerGetOK) Encode(e *jx.Encoder) {
	e.ObjStart()
	s.encodeFields(e)
	e.ObjEnd()
}

// encodeFields encodes fields.
func (s *PlayerGetOK) encodeFields(e *jx.Encoder) {
	{
		if s.TalentID.Set {
			e.FieldStart("talent_id")
			s.TalentID.Encode(e)
		}
	}
	{
		if s.PlayerIds != nil {
			e.FieldStart("player_ids")
			e.ArrStart()
			for _, elem := range s.PlayerIds {
				elem.Encode(e)
			}
			e.ArrEnd()
		}
	}
}

var jsonFieldsNameOfPlayerGetOK = [2]string{
	0: "talent_id",
	1: "player_ids",
}

// Decode decodes PlayerGetOK from json.
func (s *PlayerGetOK) Decode(d *jx.Decoder) error {
	if s == nil {
		return errors.New("invalid: unable to decode PlayerGetOK to nil")
	}

	if err := d.ObjBytes(func(d *jx.Decoder, k []byte) error {
		switch string(k) {
		case "talent_id":
			if err := func() error {
				s.TalentID.Reset()
				if err := s.TalentID.Decode(d); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"talent_id\"")
			}
		case "player_ids":
			if err := func() error {
				s.PlayerIds = make([]PlayerID, 0)
				if err := d.Arr(func(d *jx.Decoder) error {
					var elem PlayerID
					if err := elem.Decode(d); err != nil {
						return err
					}
					s.PlayerIds = append(s.PlayerIds, elem)
					return nil
				}); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"player_ids\"")
			}
		default:
			return d.Skip()
		}
		return nil
	}); err != nil {
		return errors.Wrap(err, "decode PlayerGetOK")
	}

	return nil
}

// MarshalJSON implements stdjson.Marshaler.
func (s *PlayerGetOK) MarshalJSON() ([]byte, error) {
	e := jx.Encoder{}
	s.Encode(&e)
	return e.Bytes(), nil
}

// UnmarshalJSON implements stdjson.Unmarshaler.
func (s *PlayerGetOK) UnmarshalJSON(data []byte) error {
	d := jx.DecodeBytes(data)
	return s.Decode(d)
}

// Encode encodes PlayerID as json.
func (s PlayerID) Encode(e *jx.Encoder) {
	unwrapped := uuid.UUID(s)

	json.EncodeUUID(e, unwrapped)
}

// Decode decodes PlayerID from json.
func (s *PlayerID) Decode(d *jx.Decoder) error {
	if s == nil {
		return errors.New("invalid: unable to decode PlayerID to nil")
	}
	var unwrapped uuid.UUID
	if err := func() error {
		v, err := json.DecodeUUID(d)
		unwrapped = v
		if err != nil {
			return err
		}
		return nil
	}(); err != nil {
		return errors.Wrap(err, "alias")
	}
	*s = PlayerID(unwrapped)
	return nil
}

// MarshalJSON implements stdjson.Marshaler.
func (s PlayerID) MarshalJSON() ([]byte, error) {
	e := jx.Encoder{}
	s.Encode(&e)
	return e.Bytes(), nil
}

// UnmarshalJSON implements stdjson.Unmarshaler.
func (s *PlayerID) UnmarshalJSON(data []byte) error {
	d := jx.DecodeBytes(data)
	return s.Decode(d)
}

// Encode encodes PlayerSecret as json.
func (s PlayerSecret) Encode(e *jx.Encoder) {
	unwrapped := string(s)

	e.Str(unwrapped)
}

// Decode decodes PlayerSecret from json.
func (s *PlayerSecret) Decode(d *jx.Decoder) error {
	if s == nil {
		return errors.New("invalid: unable to decode PlayerSecret to nil")
	}
	var unwrapped string
	if err := func() error {
		v, err := d.Str()
		unwrapped = string(v)
		if err != nil {
			return err
		}
		return nil
	}(); err != nil {
		return errors.Wrap(err, "alias")
	}
	*s = PlayerSecret(unwrapped)
	return nil
}

// MarshalJSON implements stdjson.Marshaler.
func (s PlayerSecret) MarshalJSON() ([]byte, error) {
	e := jx.Encoder{}
	s.Encode(&e)
	return e.Bytes(), nil
}

// UnmarshalJSON implements stdjson.Unmarshaler.
func (s *PlayerSecret) UnmarshalJSON(data []byte) error {
	d := jx.DecodeBytes(data)
	return s.Decode(d)
}

// Encode implements json.Marshaler.
func (s *PlayersCreateCreated) Encode(e *jx.Encoder) {
	e.ObjStart()
	s.encodeFields(e)
	e.ObjEnd()
}

// encodeFields encodes fields.
func (s *PlayersCreateCreated) encodeFields(e *jx.Encoder) {
	{
		e.FieldStart("player_id")
		s.PlayerID.Encode(e)
	}
	{
		e.FieldStart("player_secret")
		s.PlayerSecret.Encode(e)
	}
}

var jsonFieldsNameOfPlayersCreateCreated = [2]string{
	0: "player_id",
	1: "player_secret",
}

// Decode decodes PlayersCreateCreated from json.
func (s *PlayersCreateCreated) Decode(d *jx.Decoder) error {
	if s == nil {
		return errors.New("invalid: unable to decode PlayersCreateCreated to nil")
	}
	var requiredBitSet [1]uint8

	if err := d.ObjBytes(func(d *jx.Decoder, k []byte) error {
		switch string(k) {
		case "player_id":
			requiredBitSet[0] |= 1 << 0
			if err := func() error {
				if err := s.PlayerID.Decode(d); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"player_id\"")
			}
		case "player_secret":
			requiredBitSet[0] |= 1 << 1
			if err := func() error {
				if err := s.PlayerSecret.Decode(d); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"player_secret\"")
			}
		default:
			return d.Skip()
		}
		return nil
	}); err != nil {
		return errors.Wrap(err, "decode PlayersCreateCreated")
	}
	// Validate required fields.
	var failures []validate.FieldError
	for i, mask := range [1]uint8{
		0b00000011,
	} {
		if result := (requiredBitSet[i] & mask) ^ mask; result != 0 {
			// Mask only required fields and check equality to mask using XOR.
			//
			// If XOR result is not zero, result is not equal to expected, so some fields are missed.
			// Bits of fields which would be set are actually bits of missed fields.
			missed := bits.OnesCount8(result)
			for bitN := 0; bitN < missed; bitN++ {
				bitIdx := bits.TrailingZeros8(result)
				fieldIdx := i*8 + bitIdx
				var name string
				if fieldIdx < len(jsonFieldsNameOfPlayersCreateCreated) {
					name = jsonFieldsNameOfPlayersCreateCreated[fieldIdx]
				} else {
					name = strconv.Itoa(fieldIdx)
				}
				failures = append(failures, validate.FieldError{
					Name:  name,
					Error: validate.ErrFieldRequired,
				})
				// Reset bit.
				result &^= 1 << bitIdx
			}
		}
	}
	if len(failures) > 0 {
		return &validate.Error{Fields: failures}
	}

	return nil
}

// MarshalJSON implements stdjson.Marshaler.
func (s *PlayersCreateCreated) MarshalJSON() ([]byte, error) {
	e := jx.Encoder{}
	s.Encode(&e)
	return e.Bytes(), nil
}

// UnmarshalJSON implements stdjson.Unmarshaler.
func (s *PlayersCreateCreated) UnmarshalJSON(data []byte) error {
	d := jx.DecodeBytes(data)
	return s.Decode(d)
}

// Encode implements json.Marshaler.
func (s *PlayersCreateReq) Encode(e *jx.Encoder) {
	e.ObjStart()
	s.encodeFields(e)
	e.ObjEnd()
}

// encodeFields encodes fields.
func (s *PlayersCreateReq) encodeFields(e *jx.Encoder) {
	{
		e.FieldStart("application_id")
		s.ApplicationID.Encode(e)
	}
	{
		e.FieldStart("device_id")
		e.Str(s.DeviceID)
	}
}

var jsonFieldsNameOfPlayersCreateReq = [2]string{
	0: "application_id",
	1: "device_id",
}

// Decode decodes PlayersCreateReq from json.
func (s *PlayersCreateReq) Decode(d *jx.Decoder) error {
	if s == nil {
		return errors.New("invalid: unable to decode PlayersCreateReq to nil")
	}
	var requiredBitSet [1]uint8

	if err := d.ObjBytes(func(d *jx.Decoder, k []byte) error {
		switch string(k) {
		case "application_id":
			requiredBitSet[0] |= 1 << 0
			if err := func() error {
				if err := s.ApplicationID.Decode(d); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"application_id\"")
			}
		case "device_id":
			requiredBitSet[0] |= 1 << 1
			if err := func() error {
				v, err := d.Str()
				s.DeviceID = string(v)
				if err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"device_id\"")
			}
		default:
			return d.Skip()
		}
		return nil
	}); err != nil {
		return errors.Wrap(err, "decode PlayersCreateReq")
	}
	// Validate required fields.
	var failures []validate.FieldError
	for i, mask := range [1]uint8{
		0b00000011,
	} {
		if result := (requiredBitSet[i] & mask) ^ mask; result != 0 {
			// Mask only required fields and check equality to mask using XOR.
			//
			// If XOR result is not zero, result is not equal to expected, so some fields are missed.
			// Bits of fields which would be set are actually bits of missed fields.
			missed := bits.OnesCount8(result)
			for bitN := 0; bitN < missed; bitN++ {
				bitIdx := bits.TrailingZeros8(result)
				fieldIdx := i*8 + bitIdx
				var name string
				if fieldIdx < len(jsonFieldsNameOfPlayersCreateReq) {
					name = jsonFieldsNameOfPlayersCreateReq[fieldIdx]
				} else {
					name = strconv.Itoa(fieldIdx)
				}
				failures = append(failures, validate.FieldError{
					Name:  name,
					Error: validate.ErrFieldRequired,
				})
				// Reset bit.
				result &^= 1 << bitIdx
			}
		}
	}
	if len(failures) > 0 {
		return &validate.Error{Fields: failures}
	}

	return nil
}

// MarshalJSON implements stdjson.Marshaler.
func (s *PlayersCreateReq) MarshalJSON() ([]byte, error) {
	e := jx.Encoder{}
	s.Encode(&e)
	return e.Bytes(), nil
}

// UnmarshalJSON implements stdjson.Unmarshaler.
func (s *PlayersCreateReq) UnmarshalJSON(data []byte) error {
	d := jx.DecodeBytes(data)
	return s.Decode(d)
}

// Encode implements json.Marshaler.
func (s *PlayersMigrateOK) Encode(e *jx.Encoder) {
	e.ObjStart()
	s.encodeFields(e)
	e.ObjEnd()
}

// encodeFields encodes fields.
func (s *PlayersMigrateOK) encodeFields(e *jx.Encoder) {
	{
		e.FieldStart("player_secret")
		s.PlayerSecret.Encode(e)
	}
}

var jsonFieldsNameOfPlayersMigrateOK = [1]string{
	0: "player_secret",
}

// Decode decodes PlayersMigrateOK from json.
func (s *PlayersMigrateOK) Decode(d *jx.Decoder) error {
	if s == nil {
		return errors.New("invalid: unable to decode PlayersMigrateOK to nil")
	}
	var requiredBitSet [1]uint8

	if err := d.ObjBytes(func(d *jx.Decoder, k []byte) error {
		switch string(k) {
		case "player_secret":
			requiredBitSet[0] |= 1 << 0
			if err := func() error {
				if err := s.PlayerSecret.Decode(d); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"player_secret\"")
			}
		default:
			return d.Skip()
		}
		return nil
	}); err != nil {
		return errors.Wrap(err, "decode PlayersMigrateOK")
	}
	// Validate required fields.
	var failures []validate.FieldError
	for i, mask := range [1]uint8{
		0b00000001,
	} {
		if result := (requiredBitSet[i] & mask) ^ mask; result != 0 {
			// Mask only required fields and check equality to mask using XOR.
			//
			// If XOR result is not zero, result is not equal to expected, so some fields are missed.
			// Bits of fields which would be set are actually bits of missed fields.
			missed := bits.OnesCount8(result)
			for bitN := 0; bitN < missed; bitN++ {
				bitIdx := bits.TrailingZeros8(result)
				fieldIdx := i*8 + bitIdx
				var name string
				if fieldIdx < len(jsonFieldsNameOfPlayersMigrateOK) {
					name = jsonFieldsNameOfPlayersMigrateOK[fieldIdx]
				} else {
					name = strconv.Itoa(fieldIdx)
				}
				failures = append(failures, validate.FieldError{
					Name:  name,
					Error: validate.ErrFieldRequired,
				})
				// Reset bit.
				result &^= 1 << bitIdx
			}
		}
	}
	if len(failures) > 0 {
		return &validate.Error{Fields: failures}
	}

	return nil
}

// MarshalJSON implements stdjson.Marshaler.
func (s *PlayersMigrateOK) MarshalJSON() ([]byte, error) {
	e := jx.Encoder{}
	s.Encode(&e)
	return e.Bytes(), nil
}

// UnmarshalJSON implements stdjson.Unmarshaler.
func (s *PlayersMigrateOK) UnmarshalJSON(data []byte) error {
	d := jx.DecodeBytes(data)
	return s.Decode(d)
}

// Encode implements json.Marshaler.
func (s *PlayersMigrateReq) Encode(e *jx.Encoder) {
	e.ObjStart()
	s.encodeFields(e)
	e.ObjEnd()
}

// encodeFields encodes fields.
func (s *PlayersMigrateReq) encodeFields(e *jx.Encoder) {
	{
		e.FieldStart("application_id")
		s.ApplicationID.Encode(e)
	}
	{
		e.FieldStart("player_id")
		s.PlayerID.Encode(e)
	}
}

var jsonFieldsNameOfPlayersMigrateReq = [2]string{
	0: "application_id",
	1: "player_id",
}

// Decode decodes PlayersMigrateReq from json.
func (s *PlayersMigrateReq) Decode(d *jx.Decoder) error {
	if s == nil {
		return errors.New("invalid: unable to decode PlayersMigrateReq to nil")
	}
	var requiredBitSet [1]uint8

	if err := d.ObjBytes(func(d *jx.Decoder, k []byte) error {
		switch string(k) {
		case "application_id":
			requiredBitSet[0] |= 1 << 0
			if err := func() error {
				if err := s.ApplicationID.Decode(d); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"application_id\"")
			}
		case "player_id":
			requiredBitSet[0] |= 1 << 1
			if err := func() error {
				if err := s.PlayerID.Decode(d); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"player_id\"")
			}
		default:
			return d.Skip()
		}
		return nil
	}); err != nil {
		return errors.Wrap(err, "decode PlayersMigrateReq")
	}
	// Validate required fields.
	var failures []validate.FieldError
	for i, mask := range [1]uint8{
		0b00000011,
	} {
		if result := (requiredBitSet[i] & mask) ^ mask; result != 0 {
			// Mask only required fields and check equality to mask using XOR.
			//
			// If XOR result is not zero, result is not equal to expected, so some fields are missed.
			// Bits of fields which would be set are actually bits of missed fields.
			missed := bits.OnesCount8(result)
			for bitN := 0; bitN < missed; bitN++ {
				bitIdx := bits.TrailingZeros8(result)
				fieldIdx := i*8 + bitIdx
				var name string
				if fieldIdx < len(jsonFieldsNameOfPlayersMigrateReq) {
					name = jsonFieldsNameOfPlayersMigrateReq[fieldIdx]
				} else {
					name = strconv.Itoa(fieldIdx)
				}
				failures = append(failures, validate.FieldError{
					Name:  name,
					Error: validate.ErrFieldRequired,
				})
				// Reset bit.
				result &^= 1 << bitIdx
			}
		}
	}
	if len(failures) > 0 {
		return &validate.Error{Fields: failures}
	}

	return nil
}

// MarshalJSON implements stdjson.Marshaler.
func (s *PlayersMigrateReq) MarshalJSON() ([]byte, error) {
	e := jx.Encoder{}
	s.Encode(&e)
	return e.Bytes(), nil
}

// UnmarshalJSON implements stdjson.Unmarshaler.
func (s *PlayersMigrateReq) UnmarshalJSON(data []byte) error {
	d := jx.DecodeBytes(data)
	return s.Decode(d)
}
