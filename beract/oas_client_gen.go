// Code generated by ogen, DO NOT EDIT.

package beract

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/go-faster/errors"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/ogen-go/ogen/conv"
	ht "github.com/ogen-go/ogen/http"
	"github.com/ogen-go/ogen/ogenerrors"
	"github.com/ogen-go/ogen/otelogen"
	"github.com/ogen-go/ogen/uri"
)

// Invoker invokes operations described by OpenAPI v3 specification.
type Invoker interface {
	// ActivitiesCreate invokes ActivitiesCreate operation.
	//
	// Каждая из активностей опционально может иметь
	// метриики и артефакт.
	// Запись активностей доступа в коротком и расширенном
	// форматах.
	// #### Короткий формат
	// Передается только массив активностей. Если они
	// ссылаются на артефакты, эти артефакты должны быть
	// предварительно [загружены](#operation/ArtefactsCreate). Ответ на
	// такой запрос тоже включает в себя только массив с
	// активностями.
	// #### Расширенный формат
	// В этом формате передается объект, который должен
	// содержать активности в массиве, аналогичном
	// короткому формату, и опционально может включать в
	// себя еще артефакты для создания. В ответе на такой
	// запрос, аналогично, возвращается объект, содержащий
	// те же ключи. В возвращаемом массиве артефактов будут
	// ссылки, по которым эти артефакты должны быть
	// загружены.
	// > Ссылки имеют ограниченный срок жизни. Если данные
	// артефакта не были загружены в рамках этого периода,
	// то нужно [запросить новую ссылку](#operation/ArtefactUploadURL).
	// > До тех пор, пока указанные в активности артефакты не
	// будут загружены, эта активность с ее баллами не будет
	// учитываться в прогрессе традиции игрока.
	// После загрузки данных артефакта по полученной ссылке,
	//  нужно [подтвердить что загрузка
	// завершена](#operation/ArtefactSetUploaded).
	//
	// POST /activities
	ActivitiesCreate(ctx context.Context, request ActivitiesCreateReq) (ActivitiesCreateRes, error)
	// ActivitiesList invokes ActivitiesList operation.
	//
	// Если какие-то из указанных активностей не будут
	// найдены, то они просто будут отсутствовать в ответе.
	//
	// GET /activities
	ActivitiesList(ctx context.Context, params ActivitiesListParams) ([]Activity, error)
	// ActivitiesScores invokes ActivitiesScores operation.
	//
	// **Обязательно** указание либо `tradition_id`, либо `context_ids`;
	// эти параметры взаимоисключающие.
	//
	// GET /activities/scores
	ActivitiesScores(ctx context.Context, params ActivitiesScoresParams) (ActivitiesScoresRes, error)
	// ActivitiesScoresByTraditions invokes ActivitiesScoresByTraditions operation.
	//
	// Баллы сгруппированные по традициям.
	//
	// GET /activities/scores/traditions
	ActivitiesScoresByTraditions(ctx context.Context, params ActivitiesScoresByTraditionsParams) (ActivitiesScoresByTraditionsRes, error)
	// ActivityRead invokes ActivityRead operation.
	//
	// Чтение активности.
	//
	// GET /activities/{activity_id}
	ActivityRead(ctx context.Context, params ActivityReadParams) (ActivityReadRes, error)
	// ArtefactSetUploaded invokes ArtefactSetUploaded operation.
	//
	// Подтверждение загрузки артефакта.
	//
	// POST /artefacts/{artefact_id}/set-uploaded
	ArtefactSetUploaded(ctx context.Context, params ArtefactSetUploadedParams) (ArtefactSetUploadedRes, error)
	// ArtefactTypesList invokes ArtefactTypesList operation.
	//
	// Справочник типов артефактов.
	//
	// GET /artefact-types
	ArtefactTypesList(ctx context.Context) ([]ArtefactTypesListOKItem, error)
	// ArtefactUploadURL invokes ArtefactUploadURL operation.
	//
	// Ссылка для загрузки данных артефактом имеет
	// ограниченный срок жизни. После его завершения, если
	// данные артефакта еще не были успешно загружены, нужно
	// запрашивать новую ссылку. Загрузку данных по ссылке
	// нужно выполнять методом PUT.
	//
	// GET /artefacts/{artefact_id}/upload-url
	ArtefactUploadURL(ctx context.Context, params ArtefactUploadURLParams) (ArtefactUploadURLRes, error)
	// ArtefactsCreate invokes ArtefactsCreate operation.
	//
	// Артефакт предварительно загружается для передачи
	// его в активности.
	//
	// POST /artefacts
	ArtefactsCreate(ctx context.Context, request *ArtefactsCreateReqWithContentType, params ArtefactsCreateParams) (ArtefactsCreateRes, error)
	// ContextTraditionID invokes ContextTraditionID operation.
	//
	// Традиция контекста.
	//
	// GET /contexts/{context_id}/tradition-id
	ContextTraditionID(ctx context.Context, params ContextTraditionIDParams) (ContextTraditionIDRes, error)
}

// Client implements OAS client.
type Client struct {
	serverURL *url.URL
	sec       SecuritySource
	baseClient
}

func trimTrailingSlashes(u *url.URL) {
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = strings.TrimRight(u.RawPath, "/")
}

// NewClient initializes new Client defined by OAS.
func NewClient(serverURL string, sec SecuritySource, opts ...ClientOption) (*Client, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, err
	}
	trimTrailingSlashes(u)

	c, err := newClientConfig(opts...).baseClient()
	if err != nil {
		return nil, err
	}
	return &Client{
		serverURL:  u,
		sec:        sec,
		baseClient: c,
	}, nil
}

type serverURLKey struct{}

// WithServerURL sets context key to override server URL.
func WithServerURL(ctx context.Context, u *url.URL) context.Context {
	return context.WithValue(ctx, serverURLKey{}, u)
}

func (c *Client) requestURL(ctx context.Context) *url.URL {
	u, ok := ctx.Value(serverURLKey{}).(*url.URL)
	if !ok {
		return c.serverURL
	}
	return u
}

// ActivitiesCreate invokes ActivitiesCreate operation.
//
// Каждая из активностей опционально может иметь
// метриики и артефакт.
// Запись активностей доступа в коротком и расширенном
// форматах.
// #### Короткий формат
// Передается только массив активностей. Если они
// ссылаются на артефакты, эти артефакты должны быть
// предварительно [загружены](#operation/ArtefactsCreate). Ответ на
// такой запрос тоже включает в себя только массив с
// активностями.
// #### Расширенный формат
// В этом формате передается объект, который должен
// содержать активности в массиве, аналогичном
// короткому формату, и опционально может включать в
// себя еще артефакты для создания. В ответе на такой
// запрос, аналогично, возвращается объект, содержащий
// те же ключи. В возвращаемом массиве артефактов будут
// ссылки, по которым эти артефакты должны быть
// загружены.
// > Ссылки имеют ограниченный срок жизни. Если данные
// артефакта не были загружены в рамках этого периода,
// то нужно [запросить новую ссылку](#operation/ArtefactUploadURL).
// > До тех пор, пока указанные в активности артефакты не
// будут загружены, эта активность с ее баллами не будет
// учитываться в прогрессе традиции игрока.
// После загрузки данных артефакта по полученной ссылке,
//
//	нужно [подтвердить что загрузка
//
// завершена](#operation/ArtefactSetUploaded).
//
// POST /activities
func (c *Client) ActivitiesCreate(ctx context.Context, request ActivitiesCreateReq) (ActivitiesCreateRes, error) {
	res, err := c.sendActivitiesCreate(ctx, request)
	return res, err
}

func (c *Client) sendActivitiesCreate(ctx context.Context, request ActivitiesCreateReq) (res ActivitiesCreateRes, err error) {
	otelAttrs := []attribute.KeyValue{
		otelogen.OperationID("ActivitiesCreate"),
		semconv.HTTPMethodKey.String("POST"),
		semconv.HTTPRouteKey.String("/activities"),
	}

	// Run stopwatch.
	startTime := time.Now()
	defer func() {
		// Use floating point division here for higher precision (instead of Millisecond method).
		elapsedDuration := time.Since(startTime)
		c.duration.Record(ctx, float64(float64(elapsedDuration)/float64(time.Millisecond)), metric.WithAttributes(otelAttrs...))
	}()

	// Increment request counter.
	c.requests.Add(ctx, 1, metric.WithAttributes(otelAttrs...))

	// Start a span for this request.
	ctx, span := c.cfg.Tracer.Start(ctx, "ActivitiesCreate",
		trace.WithAttributes(otelAttrs...),
		clientSpanKind,
	)
	// Track stage for error reporting.
	var stage string
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, stage)
			c.errors.Add(ctx, 1, metric.WithAttributes(otelAttrs...))
		}
		span.End()
	}()

	stage = "BuildURL"
	u := uri.Clone(c.requestURL(ctx))
	var pathParts [1]string
	pathParts[0] = "/activities"
	uri.AddPathParts(u, pathParts[:]...)

	stage = "EncodeRequest"
	r, err := ht.NewRequest(ctx, "POST", u)
	if err != nil {
		return res, errors.Wrap(err, "create request")
	}
	if err := encodeActivitiesCreateRequest(request, r); err != nil {
		return res, errors.Wrap(err, "encode request")
	}

	{
		type bitset = [1]uint8
		var satisfied bitset
		{
			stage = "Security:BerlogaJWT"
			switch err := c.securityBerlogaJWT(ctx, "ActivitiesCreate", r); {
			case err == nil: // if NO error
				satisfied[0] |= 1 << 0
			case errors.Is(err, ogenerrors.ErrSkipClientSecurity):
				// Skip this security.
			default:
				return res, errors.Wrap(err, "security \"BerlogaJWT\"")
			}
		}

		if ok := func() bool {
		nextRequirement:
			for _, requirement := range []bitset{
				{0b00000001},
			} {
				for i, mask := range requirement {
					if satisfied[i]&mask != mask {
						continue nextRequirement
					}
				}
				return true
			}
			return false
		}(); !ok {
			return res, ogenerrors.ErrSecurityRequirementIsNotSatisfied
		}
	}

	stage = "SendRequest"
	resp, err := c.cfg.Client.Do(r)
	if err != nil {
		return res, errors.Wrap(err, "do request")
	}
	defer resp.Body.Close()

	stage = "DecodeResponse"
	result, err := decodeActivitiesCreateResponse(resp)
	if err != nil {
		return res, errors.Wrap(err, "decode response")
	}

	return result, nil
}

// ActivitiesList invokes ActivitiesList operation.
//
// Если какие-то из указанных активностей не будут
// найдены, то они просто будут отсутствовать в ответе.
//
// GET /activities
func (c *Client) ActivitiesList(ctx context.Context, params ActivitiesListParams) ([]Activity, error) {
	res, err := c.sendActivitiesList(ctx, params)
	return res, err
}

func (c *Client) sendActivitiesList(ctx context.Context, params ActivitiesListParams) (res []Activity, err error) {
	otelAttrs := []attribute.KeyValue{
		otelogen.OperationID("ActivitiesList"),
		semconv.HTTPMethodKey.String("GET"),
		semconv.HTTPRouteKey.String("/activities"),
	}

	// Run stopwatch.
	startTime := time.Now()
	defer func() {
		// Use floating point division here for higher precision (instead of Millisecond method).
		elapsedDuration := time.Since(startTime)
		c.duration.Record(ctx, float64(float64(elapsedDuration)/float64(time.Millisecond)), metric.WithAttributes(otelAttrs...))
	}()

	// Increment request counter.
	c.requests.Add(ctx, 1, metric.WithAttributes(otelAttrs...))

	// Start a span for this request.
	ctx, span := c.cfg.Tracer.Start(ctx, "ActivitiesList",
		trace.WithAttributes(otelAttrs...),
		clientSpanKind,
	)
	// Track stage for error reporting.
	var stage string
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, stage)
			c.errors.Add(ctx, 1, metric.WithAttributes(otelAttrs...))
		}
		span.End()
	}()

	stage = "BuildURL"
	u := uri.Clone(c.requestURL(ctx))
	var pathParts [1]string
	pathParts[0] = "/activities"
	uri.AddPathParts(u, pathParts[:]...)

	stage = "EncodeQueryParams"
	q := uri.NewQueryEncoder()
	{
		// Encode "ids" parameter.
		cfg := uri.QueryParameterEncodingConfig{
			Name:    "ids",
			Style:   uri.QueryStyleForm,
			Explode: true,
		}

		if err := q.EncodeParam(cfg, func(e uri.Encoder) error {
			return e.EncodeArray(func(e uri.Encoder) error {
				for i, item := range params.Ids {
					if err := func() error {
						return e.EncodeValue(conv.UUIDToString(item))
					}(); err != nil {
						return errors.Wrapf(err, "[%d]", i)
					}
				}
				return nil
			})
		}); err != nil {
			return res, errors.Wrap(err, "encode query")
		}
	}
	u.RawQuery = q.Values().Encode()

	stage = "EncodeRequest"
	r, err := ht.NewRequest(ctx, "GET", u)
	if err != nil {
		return res, errors.Wrap(err, "create request")
	}

	{
		type bitset = [1]uint8
		var satisfied bitset
		{
			stage = "Security:BerlogaJWT"
			switch err := c.securityBerlogaJWT(ctx, "ActivitiesList", r); {
			case err == nil: // if NO error
				satisfied[0] |= 1 << 0
			case errors.Is(err, ogenerrors.ErrSkipClientSecurity):
				// Skip this security.
			default:
				return res, errors.Wrap(err, "security \"BerlogaJWT\"")
			}
		}

		if ok := func() bool {
		nextRequirement:
			for _, requirement := range []bitset{
				{0b00000001},
			} {
				for i, mask := range requirement {
					if satisfied[i]&mask != mask {
						continue nextRequirement
					}
				}
				return true
			}
			return false
		}(); !ok {
			return res, ogenerrors.ErrSecurityRequirementIsNotSatisfied
		}
	}

	stage = "SendRequest"
	resp, err := c.cfg.Client.Do(r)
	if err != nil {
		return res, errors.Wrap(err, "do request")
	}
	defer resp.Body.Close()

	stage = "DecodeResponse"
	result, err := decodeActivitiesListResponse(resp)
	if err != nil {
		return res, errors.Wrap(err, "decode response")
	}

	return result, nil
}

// ActivitiesScores invokes ActivitiesScores operation.
//
// **Обязательно** указание либо `tradition_id`, либо `context_ids`;
// эти параметры взаимоисключающие.
//
// GET /activities/scores
func (c *Client) ActivitiesScores(ctx context.Context, params ActivitiesScoresParams) (ActivitiesScoresRes, error) {
	res, err := c.sendActivitiesScores(ctx, params)
	return res, err
}

func (c *Client) sendActivitiesScores(ctx context.Context, params ActivitiesScoresParams) (res ActivitiesScoresRes, err error) {
	otelAttrs := []attribute.KeyValue{
		otelogen.OperationID("ActivitiesScores"),
		semconv.HTTPMethodKey.String("GET"),
		semconv.HTTPRouteKey.String("/activities/scores"),
	}

	// Run stopwatch.
	startTime := time.Now()
	defer func() {
		// Use floating point division here for higher precision (instead of Millisecond method).
		elapsedDuration := time.Since(startTime)
		c.duration.Record(ctx, float64(float64(elapsedDuration)/float64(time.Millisecond)), metric.WithAttributes(otelAttrs...))
	}()

	// Increment request counter.
	c.requests.Add(ctx, 1, metric.WithAttributes(otelAttrs...))

	// Start a span for this request.
	ctx, span := c.cfg.Tracer.Start(ctx, "ActivitiesScores",
		trace.WithAttributes(otelAttrs...),
		clientSpanKind,
	)
	// Track stage for error reporting.
	var stage string
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, stage)
			c.errors.Add(ctx, 1, metric.WithAttributes(otelAttrs...))
		}
		span.End()
	}()

	stage = "BuildURL"
	u := uri.Clone(c.requestURL(ctx))
	var pathParts [1]string
	pathParts[0] = "/activities/scores"
	uri.AddPathParts(u, pathParts[:]...)

	stage = "EncodeQueryParams"
	q := uri.NewQueryEncoder()
	{
		// Encode "tradition_id" parameter.
		cfg := uri.QueryParameterEncodingConfig{
			Name:    "tradition_id",
			Style:   uri.QueryStyleForm,
			Explode: true,
		}

		if err := q.EncodeParam(cfg, func(e uri.Encoder) error {
			if val, ok := params.TraditionID.Get(); ok {
				return e.EncodeValue(conv.Int32ToString(val))
			}
			return nil
		}); err != nil {
			return res, errors.Wrap(err, "encode query")
		}
	}
	{
		// Encode "context_ids" parameter.
		cfg := uri.QueryParameterEncodingConfig{
			Name:    "context_ids",
			Style:   uri.QueryStyleForm,
			Explode: true,
		}

		if err := q.EncodeParam(cfg, func(e uri.Encoder) error {
			return e.EncodeArray(func(e uri.Encoder) error {
				for i, item := range params.ContextIds {
					if err := func() error {
						if unwrapped := uuid.UUID(item); true {
							return e.EncodeValue(conv.UUIDToString(unwrapped))
						}
						return nil
					}(); err != nil {
						return errors.Wrapf(err, "[%d]", i)
					}
				}
				return nil
			})
		}); err != nil {
			return res, errors.Wrap(err, "encode query")
		}
	}
	{
		// Encode "player_ids" parameter.
		cfg := uri.QueryParameterEncodingConfig{
			Name:    "player_ids",
			Style:   uri.QueryStyleForm,
			Explode: true,
		}

		if err := q.EncodeParam(cfg, func(e uri.Encoder) error {
			return e.EncodeArray(func(e uri.Encoder) error {
				for i, item := range params.PlayerIds {
					if err := func() error {
						if unwrapped := uuid.UUID(item); true {
							return e.EncodeValue(conv.UUIDToString(unwrapped))
						}
						return nil
					}(); err != nil {
						return errors.Wrapf(err, "[%d]", i)
					}
				}
				return nil
			})
		}); err != nil {
			return res, errors.Wrap(err, "encode query")
		}
	}
	u.RawQuery = q.Values().Encode()

	stage = "EncodeRequest"
	r, err := ht.NewRequest(ctx, "GET", u)
	if err != nil {
		return res, errors.Wrap(err, "create request")
	}

	{
		type bitset = [1]uint8
		var satisfied bitset
		{
			stage = "Security:BerlogaJWT"
			switch err := c.securityBerlogaJWT(ctx, "ActivitiesScores", r); {
			case err == nil: // if NO error
				satisfied[0] |= 1 << 0
			case errors.Is(err, ogenerrors.ErrSkipClientSecurity):
				// Skip this security.
			default:
				return res, errors.Wrap(err, "security \"BerlogaJWT\"")
			}
		}
		{
			stage = "Security:ServiceKey"
			switch err := c.securityServiceKey(ctx, "ActivitiesScores", r); {
			case err == nil: // if NO error
				satisfied[0] |= 1 << 1
			case errors.Is(err, ogenerrors.ErrSkipClientSecurity):
				// Skip this security.
			default:
				return res, errors.Wrap(err, "security \"ServiceKey\"")
			}
		}

		if ok := func() bool {
		nextRequirement:
			for _, requirement := range []bitset{
				{0b00000001},
				{0b00000010},
			} {
				for i, mask := range requirement {
					if satisfied[i]&mask != mask {
						continue nextRequirement
					}
				}
				return true
			}
			return false
		}(); !ok {
			return res, ogenerrors.ErrSecurityRequirementIsNotSatisfied
		}
	}

	stage = "SendRequest"
	resp, err := c.cfg.Client.Do(r)
	if err != nil {
		return res, errors.Wrap(err, "do request")
	}
	defer resp.Body.Close()

	stage = "DecodeResponse"
	result, err := decodeActivitiesScoresResponse(resp)
	if err != nil {
		return res, errors.Wrap(err, "decode response")
	}

	return result, nil
}

// ActivitiesScoresByTraditions invokes ActivitiesScoresByTraditions operation.
//
// Баллы сгруппированные по традициям.
//
// GET /activities/scores/traditions
func (c *Client) ActivitiesScoresByTraditions(ctx context.Context, params ActivitiesScoresByTraditionsParams) (ActivitiesScoresByTraditionsRes, error) {
	res, err := c.sendActivitiesScoresByTraditions(ctx, params)
	return res, err
}

func (c *Client) sendActivitiesScoresByTraditions(ctx context.Context, params ActivitiesScoresByTraditionsParams) (res ActivitiesScoresByTraditionsRes, err error) {
	otelAttrs := []attribute.KeyValue{
		otelogen.OperationID("ActivitiesScoresByTraditions"),
		semconv.HTTPMethodKey.String("GET"),
		semconv.HTTPRouteKey.String("/activities/scores/traditions"),
	}

	// Run stopwatch.
	startTime := time.Now()
	defer func() {
		// Use floating point division here for higher precision (instead of Millisecond method).
		elapsedDuration := time.Since(startTime)
		c.duration.Record(ctx, float64(float64(elapsedDuration)/float64(time.Millisecond)), metric.WithAttributes(otelAttrs...))
	}()

	// Increment request counter.
	c.requests.Add(ctx, 1, metric.WithAttributes(otelAttrs...))

	// Start a span for this request.
	ctx, span := c.cfg.Tracer.Start(ctx, "ActivitiesScoresByTraditions",
		trace.WithAttributes(otelAttrs...),
		clientSpanKind,
	)
	// Track stage for error reporting.
	var stage string
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, stage)
			c.errors.Add(ctx, 1, metric.WithAttributes(otelAttrs...))
		}
		span.End()
	}()

	stage = "BuildURL"
	u := uri.Clone(c.requestURL(ctx))
	var pathParts [1]string
	pathParts[0] = "/activities/scores/traditions"
	uri.AddPathParts(u, pathParts[:]...)

	stage = "EncodeQueryParams"
	q := uri.NewQueryEncoder()
	{
		// Encode "talent_id" parameter.
		cfg := uri.QueryParameterEncodingConfig{
			Name:    "talent_id",
			Style:   uri.QueryStyleForm,
			Explode: true,
		}

		if err := q.EncodeParam(cfg, func(e uri.Encoder) error {
			return e.EncodeValue(conv.Int32ToString(params.TalentID))
		}); err != nil {
			return res, errors.Wrap(err, "encode query")
		}
	}
	u.RawQuery = q.Values().Encode()

	stage = "EncodeRequest"
	r, err := ht.NewRequest(ctx, "GET", u)
	if err != nil {
		return res, errors.Wrap(err, "create request")
	}

	{
		type bitset = [1]uint8
		var satisfied bitset
		{
			stage = "Security:ServiceKey"
			switch err := c.securityServiceKey(ctx, "ActivitiesScoresByTraditions", r); {
			case err == nil: // if NO error
				satisfied[0] |= 1 << 0
			case errors.Is(err, ogenerrors.ErrSkipClientSecurity):
				// Skip this security.
			default:
				return res, errors.Wrap(err, "security \"ServiceKey\"")
			}
		}

		if ok := func() bool {
		nextRequirement:
			for _, requirement := range []bitset{
				{0b00000001},
			} {
				for i, mask := range requirement {
					if satisfied[i]&mask != mask {
						continue nextRequirement
					}
				}
				return true
			}
			return false
		}(); !ok {
			return res, ogenerrors.ErrSecurityRequirementIsNotSatisfied
		}
	}

	stage = "SendRequest"
	resp, err := c.cfg.Client.Do(r)
	if err != nil {
		return res, errors.Wrap(err, "do request")
	}
	defer resp.Body.Close()

	stage = "DecodeResponse"
	result, err := decodeActivitiesScoresByTraditionsResponse(resp)
	if err != nil {
		return res, errors.Wrap(err, "decode response")
	}

	return result, nil
}

// ActivityRead invokes ActivityRead operation.
//
// Чтение активности.
//
// GET /activities/{activity_id}
func (c *Client) ActivityRead(ctx context.Context, params ActivityReadParams) (ActivityReadRes, error) {
	res, err := c.sendActivityRead(ctx, params)
	return res, err
}

func (c *Client) sendActivityRead(ctx context.Context, params ActivityReadParams) (res ActivityReadRes, err error) {
	otelAttrs := []attribute.KeyValue{
		otelogen.OperationID("ActivityRead"),
		semconv.HTTPMethodKey.String("GET"),
		semconv.HTTPRouteKey.String("/activities/{activity_id}"),
	}

	// Run stopwatch.
	startTime := time.Now()
	defer func() {
		// Use floating point division here for higher precision (instead of Millisecond method).
		elapsedDuration := time.Since(startTime)
		c.duration.Record(ctx, float64(float64(elapsedDuration)/float64(time.Millisecond)), metric.WithAttributes(otelAttrs...))
	}()

	// Increment request counter.
	c.requests.Add(ctx, 1, metric.WithAttributes(otelAttrs...))

	// Start a span for this request.
	ctx, span := c.cfg.Tracer.Start(ctx, "ActivityRead",
		trace.WithAttributes(otelAttrs...),
		clientSpanKind,
	)
	// Track stage for error reporting.
	var stage string
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, stage)
			c.errors.Add(ctx, 1, metric.WithAttributes(otelAttrs...))
		}
		span.End()
	}()

	stage = "BuildURL"
	u := uri.Clone(c.requestURL(ctx))
	var pathParts [2]string
	pathParts[0] = "/activities/"
	{
		// Encode "activity_id" parameter.
		e := uri.NewPathEncoder(uri.PathEncoderConfig{
			Param:   "activity_id",
			Style:   uri.PathStyleSimple,
			Explode: false,
		})
		if err := func() error {
			if unwrapped := uuid.UUID(params.ActivityID); true {
				return e.EncodeValue(conv.UUIDToString(unwrapped))
			}
			return nil
		}(); err != nil {
			return res, errors.Wrap(err, "encode path")
		}
		encoded, err := e.Result()
		if err != nil {
			return res, errors.Wrap(err, "encode path")
		}
		pathParts[1] = encoded
	}
	uri.AddPathParts(u, pathParts[:]...)

	stage = "EncodeRequest"
	r, err := ht.NewRequest(ctx, "GET", u)
	if err != nil {
		return res, errors.Wrap(err, "create request")
	}

	stage = "SendRequest"
	resp, err := c.cfg.Client.Do(r)
	if err != nil {
		return res, errors.Wrap(err, "do request")
	}
	defer resp.Body.Close()

	stage = "DecodeResponse"
	result, err := decodeActivityReadResponse(resp)
	if err != nil {
		return res, errors.Wrap(err, "decode response")
	}

	return result, nil
}

// ArtefactSetUploaded invokes ArtefactSetUploaded operation.
//
// Подтверждение загрузки артефакта.
//
// POST /artefacts/{artefact_id}/set-uploaded
func (c *Client) ArtefactSetUploaded(ctx context.Context, params ArtefactSetUploadedParams) (ArtefactSetUploadedRes, error) {
	res, err := c.sendArtefactSetUploaded(ctx, params)
	return res, err
}

func (c *Client) sendArtefactSetUploaded(ctx context.Context, params ArtefactSetUploadedParams) (res ArtefactSetUploadedRes, err error) {
	otelAttrs := []attribute.KeyValue{
		otelogen.OperationID("ArtefactSetUploaded"),
		semconv.HTTPMethodKey.String("POST"),
		semconv.HTTPRouteKey.String("/artefacts/{artefact_id}/set-uploaded"),
	}

	// Run stopwatch.
	startTime := time.Now()
	defer func() {
		// Use floating point division here for higher precision (instead of Millisecond method).
		elapsedDuration := time.Since(startTime)
		c.duration.Record(ctx, float64(float64(elapsedDuration)/float64(time.Millisecond)), metric.WithAttributes(otelAttrs...))
	}()

	// Increment request counter.
	c.requests.Add(ctx, 1, metric.WithAttributes(otelAttrs...))

	// Start a span for this request.
	ctx, span := c.cfg.Tracer.Start(ctx, "ArtefactSetUploaded",
		trace.WithAttributes(otelAttrs...),
		clientSpanKind,
	)
	// Track stage for error reporting.
	var stage string
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, stage)
			c.errors.Add(ctx, 1, metric.WithAttributes(otelAttrs...))
		}
		span.End()
	}()

	stage = "BuildURL"
	u := uri.Clone(c.requestURL(ctx))
	var pathParts [3]string
	pathParts[0] = "/artefacts/"
	{
		// Encode "artefact_id" parameter.
		e := uri.NewPathEncoder(uri.PathEncoderConfig{
			Param:   "artefact_id",
			Style:   uri.PathStyleSimple,
			Explode: false,
		})
		if err := func() error {
			if unwrapped := uuid.UUID(params.ArtefactID); true {
				return e.EncodeValue(conv.UUIDToString(unwrapped))
			}
			return nil
		}(); err != nil {
			return res, errors.Wrap(err, "encode path")
		}
		encoded, err := e.Result()
		if err != nil {
			return res, errors.Wrap(err, "encode path")
		}
		pathParts[1] = encoded
	}
	pathParts[2] = "/set-uploaded"
	uri.AddPathParts(u, pathParts[:]...)

	stage = "EncodeRequest"
	r, err := ht.NewRequest(ctx, "POST", u)
	if err != nil {
		return res, errors.Wrap(err, "create request")
	}

	{
		type bitset = [1]uint8
		var satisfied bitset
		{
			stage = "Security:BerlogaJWT"
			switch err := c.securityBerlogaJWT(ctx, "ArtefactSetUploaded", r); {
			case err == nil: // if NO error
				satisfied[0] |= 1 << 0
			case errors.Is(err, ogenerrors.ErrSkipClientSecurity):
				// Skip this security.
			default:
				return res, errors.Wrap(err, "security \"BerlogaJWT\"")
			}
		}

		if ok := func() bool {
		nextRequirement:
			for _, requirement := range []bitset{
				{0b00000001},
			} {
				for i, mask := range requirement {
					if satisfied[i]&mask != mask {
						continue nextRequirement
					}
				}
				return true
			}
			return false
		}(); !ok {
			return res, ogenerrors.ErrSecurityRequirementIsNotSatisfied
		}
	}

	stage = "SendRequest"
	resp, err := c.cfg.Client.Do(r)
	if err != nil {
		return res, errors.Wrap(err, "do request")
	}
	defer resp.Body.Close()

	stage = "DecodeResponse"
	result, err := decodeArtefactSetUploadedResponse(resp)
	if err != nil {
		return res, errors.Wrap(err, "decode response")
	}

	return result, nil
}

// ArtefactTypesList invokes ArtefactTypesList operation.
//
// Справочник типов артефактов.
//
// GET /artefact-types
func (c *Client) ArtefactTypesList(ctx context.Context) ([]ArtefactTypesListOKItem, error) {
	res, err := c.sendArtefactTypesList(ctx)
	return res, err
}

func (c *Client) sendArtefactTypesList(ctx context.Context) (res []ArtefactTypesListOKItem, err error) {
	otelAttrs := []attribute.KeyValue{
		otelogen.OperationID("ArtefactTypesList"),
		semconv.HTTPMethodKey.String("GET"),
		semconv.HTTPRouteKey.String("/artefact-types"),
	}

	// Run stopwatch.
	startTime := time.Now()
	defer func() {
		// Use floating point division here for higher precision (instead of Millisecond method).
		elapsedDuration := time.Since(startTime)
		c.duration.Record(ctx, float64(float64(elapsedDuration)/float64(time.Millisecond)), metric.WithAttributes(otelAttrs...))
	}()

	// Increment request counter.
	c.requests.Add(ctx, 1, metric.WithAttributes(otelAttrs...))

	// Start a span for this request.
	ctx, span := c.cfg.Tracer.Start(ctx, "ArtefactTypesList",
		trace.WithAttributes(otelAttrs...),
		clientSpanKind,
	)
	// Track stage for error reporting.
	var stage string
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, stage)
			c.errors.Add(ctx, 1, metric.WithAttributes(otelAttrs...))
		}
		span.End()
	}()

	stage = "BuildURL"
	u := uri.Clone(c.requestURL(ctx))
	var pathParts [1]string
	pathParts[0] = "/artefact-types"
	uri.AddPathParts(u, pathParts[:]...)

	stage = "EncodeRequest"
	r, err := ht.NewRequest(ctx, "GET", u)
	if err != nil {
		return res, errors.Wrap(err, "create request")
	}

	stage = "SendRequest"
	resp, err := c.cfg.Client.Do(r)
	if err != nil {
		return res, errors.Wrap(err, "do request")
	}
	defer resp.Body.Close()

	stage = "DecodeResponse"
	result, err := decodeArtefactTypesListResponse(resp)
	if err != nil {
		return res, errors.Wrap(err, "decode response")
	}

	return result, nil
}

// ArtefactUploadURL invokes ArtefactUploadURL operation.
//
// Ссылка для загрузки данных артефактом имеет
// ограниченный срок жизни. После его завершения, если
// данные артефакта еще не были успешно загружены, нужно
// запрашивать новую ссылку. Загрузку данных по ссылке
// нужно выполнять методом PUT.
//
// GET /artefacts/{artefact_id}/upload-url
func (c *Client) ArtefactUploadURL(ctx context.Context, params ArtefactUploadURLParams) (ArtefactUploadURLRes, error) {
	res, err := c.sendArtefactUploadURL(ctx, params)
	return res, err
}

func (c *Client) sendArtefactUploadURL(ctx context.Context, params ArtefactUploadURLParams) (res ArtefactUploadURLRes, err error) {
	otelAttrs := []attribute.KeyValue{
		otelogen.OperationID("ArtefactUploadURL"),
		semconv.HTTPMethodKey.String("GET"),
		semconv.HTTPRouteKey.String("/artefacts/{artefact_id}/upload-url"),
	}

	// Run stopwatch.
	startTime := time.Now()
	defer func() {
		// Use floating point division here for higher precision (instead of Millisecond method).
		elapsedDuration := time.Since(startTime)
		c.duration.Record(ctx, float64(float64(elapsedDuration)/float64(time.Millisecond)), metric.WithAttributes(otelAttrs...))
	}()

	// Increment request counter.
	c.requests.Add(ctx, 1, metric.WithAttributes(otelAttrs...))

	// Start a span for this request.
	ctx, span := c.cfg.Tracer.Start(ctx, "ArtefactUploadURL",
		trace.WithAttributes(otelAttrs...),
		clientSpanKind,
	)
	// Track stage for error reporting.
	var stage string
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, stage)
			c.errors.Add(ctx, 1, metric.WithAttributes(otelAttrs...))
		}
		span.End()
	}()

	stage = "BuildURL"
	u := uri.Clone(c.requestURL(ctx))
	var pathParts [3]string
	pathParts[0] = "/artefacts/"
	{
		// Encode "artefact_id" parameter.
		e := uri.NewPathEncoder(uri.PathEncoderConfig{
			Param:   "artefact_id",
			Style:   uri.PathStyleSimple,
			Explode: false,
		})
		if err := func() error {
			if unwrapped := uuid.UUID(params.ArtefactID); true {
				return e.EncodeValue(conv.UUIDToString(unwrapped))
			}
			return nil
		}(); err != nil {
			return res, errors.Wrap(err, "encode path")
		}
		encoded, err := e.Result()
		if err != nil {
			return res, errors.Wrap(err, "encode path")
		}
		pathParts[1] = encoded
	}
	pathParts[2] = "/upload-url"
	uri.AddPathParts(u, pathParts[:]...)

	stage = "EncodeRequest"
	r, err := ht.NewRequest(ctx, "GET", u)
	if err != nil {
		return res, errors.Wrap(err, "create request")
	}

	{
		type bitset = [1]uint8
		var satisfied bitset
		{
			stage = "Security:BerlogaJWT"
			switch err := c.securityBerlogaJWT(ctx, "ArtefactUploadURL", r); {
			case err == nil: // if NO error
				satisfied[0] |= 1 << 0
			case errors.Is(err, ogenerrors.ErrSkipClientSecurity):
				// Skip this security.
			default:
				return res, errors.Wrap(err, "security \"BerlogaJWT\"")
			}
		}

		if ok := func() bool {
		nextRequirement:
			for _, requirement := range []bitset{
				{0b00000001},
			} {
				for i, mask := range requirement {
					if satisfied[i]&mask != mask {
						continue nextRequirement
					}
				}
				return true
			}
			return false
		}(); !ok {
			return res, ogenerrors.ErrSecurityRequirementIsNotSatisfied
		}
	}

	stage = "SendRequest"
	resp, err := c.cfg.Client.Do(r)
	if err != nil {
		return res, errors.Wrap(err, "do request")
	}
	defer resp.Body.Close()

	stage = "DecodeResponse"
	result, err := decodeArtefactUploadURLResponse(resp)
	if err != nil {
		return res, errors.Wrap(err, "decode response")
	}

	return result, nil
}

// ArtefactsCreate invokes ArtefactsCreate operation.
//
// Артефакт предварительно загружается для передачи
// его в активности.
//
// POST /artefacts
func (c *Client) ArtefactsCreate(ctx context.Context, request *ArtefactsCreateReqWithContentType, params ArtefactsCreateParams) (ArtefactsCreateRes, error) {
	res, err := c.sendArtefactsCreate(ctx, request, params)
	return res, err
}

func (c *Client) sendArtefactsCreate(ctx context.Context, request *ArtefactsCreateReqWithContentType, params ArtefactsCreateParams) (res ArtefactsCreateRes, err error) {
	otelAttrs := []attribute.KeyValue{
		otelogen.OperationID("ArtefactsCreate"),
		semconv.HTTPMethodKey.String("POST"),
		semconv.HTTPRouteKey.String("/artefacts"),
	}

	// Run stopwatch.
	startTime := time.Now()
	defer func() {
		// Use floating point division here for higher precision (instead of Millisecond method).
		elapsedDuration := time.Since(startTime)
		c.duration.Record(ctx, float64(float64(elapsedDuration)/float64(time.Millisecond)), metric.WithAttributes(otelAttrs...))
	}()

	// Increment request counter.
	c.requests.Add(ctx, 1, metric.WithAttributes(otelAttrs...))

	// Start a span for this request.
	ctx, span := c.cfg.Tracer.Start(ctx, "ArtefactsCreate",
		trace.WithAttributes(otelAttrs...),
		clientSpanKind,
	)
	// Track stage for error reporting.
	var stage string
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, stage)
			c.errors.Add(ctx, 1, metric.WithAttributes(otelAttrs...))
		}
		span.End()
	}()

	stage = "BuildURL"
	u := uri.Clone(c.requestURL(ctx))
	var pathParts [1]string
	pathParts[0] = "/artefacts"
	uri.AddPathParts(u, pathParts[:]...)

	stage = "EncodeRequest"
	r, err := ht.NewRequest(ctx, "POST", u)
	if err != nil {
		return res, errors.Wrap(err, "create request")
	}
	if err := encodeArtefactsCreateRequest(request, r); err != nil {
		return res, errors.Wrap(err, "encode request")
	}

	stage = "EncodeHeaderParams"
	h := uri.NewHeaderEncoder(r.Header)
	{
		cfg := uri.HeaderParameterEncodingConfig{
			Name:    "X-Artefact-Type",
			Explode: false,
		}
		if err := h.EncodeParam(cfg, func(e uri.Encoder) error {
			return e.EncodeValue(conv.Int32ToString(params.XArtefactType))
		}); err != nil {
			return res, errors.Wrap(err, "encode header")
		}
	}
	{
		cfg := uri.HeaderParameterEncodingConfig{
			Name:    "X-Checksum",
			Explode: false,
		}
		if err := h.EncodeParam(cfg, func(e uri.Encoder) error {
			return e.EncodeValue(conv.StringToString(params.XChecksum))
		}); err != nil {
			return res, errors.Wrap(err, "encode header")
		}
	}

	{
		type bitset = [1]uint8
		var satisfied bitset
		{
			stage = "Security:BerlogaJWT"
			switch err := c.securityBerlogaJWT(ctx, "ArtefactsCreate", r); {
			case err == nil: // if NO error
				satisfied[0] |= 1 << 0
			case errors.Is(err, ogenerrors.ErrSkipClientSecurity):
				// Skip this security.
			default:
				return res, errors.Wrap(err, "security \"BerlogaJWT\"")
			}
		}

		if ok := func() bool {
		nextRequirement:
			for _, requirement := range []bitset{
				{0b00000001},
			} {
				for i, mask := range requirement {
					if satisfied[i]&mask != mask {
						continue nextRequirement
					}
				}
				return true
			}
			return false
		}(); !ok {
			return res, ogenerrors.ErrSecurityRequirementIsNotSatisfied
		}
	}

	stage = "SendRequest"
	resp, err := c.cfg.Client.Do(r)
	if err != nil {
		return res, errors.Wrap(err, "do request")
	}
	defer resp.Body.Close()

	stage = "DecodeResponse"
	result, err := decodeArtefactsCreateResponse(resp)
	if err != nil {
		return res, errors.Wrap(err, "decode response")
	}

	return result, nil
}

// ContextTraditionID invokes ContextTraditionID operation.
//
// Традиция контекста.
//
// GET /contexts/{context_id}/tradition-id
func (c *Client) ContextTraditionID(ctx context.Context, params ContextTraditionIDParams) (ContextTraditionIDRes, error) {
	res, err := c.sendContextTraditionID(ctx, params)
	return res, err
}

func (c *Client) sendContextTraditionID(ctx context.Context, params ContextTraditionIDParams) (res ContextTraditionIDRes, err error) {
	otelAttrs := []attribute.KeyValue{
		otelogen.OperationID("ContextTraditionID"),
		semconv.HTTPMethodKey.String("GET"),
		semconv.HTTPRouteKey.String("/contexts/{context_id}/tradition-id"),
	}

	// Run stopwatch.
	startTime := time.Now()
	defer func() {
		// Use floating point division here for higher precision (instead of Millisecond method).
		elapsedDuration := time.Since(startTime)
		c.duration.Record(ctx, float64(float64(elapsedDuration)/float64(time.Millisecond)), metric.WithAttributes(otelAttrs...))
	}()

	// Increment request counter.
	c.requests.Add(ctx, 1, metric.WithAttributes(otelAttrs...))

	// Start a span for this request.
	ctx, span := c.cfg.Tracer.Start(ctx, "ContextTraditionID",
		trace.WithAttributes(otelAttrs...),
		clientSpanKind,
	)
	// Track stage for error reporting.
	var stage string
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, stage)
			c.errors.Add(ctx, 1, metric.WithAttributes(otelAttrs...))
		}
		span.End()
	}()

	stage = "BuildURL"
	u := uri.Clone(c.requestURL(ctx))
	var pathParts [3]string
	pathParts[0] = "/contexts/"
	{
		// Encode "context_id" parameter.
		e := uri.NewPathEncoder(uri.PathEncoderConfig{
			Param:   "context_id",
			Style:   uri.PathStyleSimple,
			Explode: false,
		})
		if err := func() error {
			if unwrapped := uuid.UUID(params.ContextID); true {
				return e.EncodeValue(conv.UUIDToString(unwrapped))
			}
			return nil
		}(); err != nil {
			return res, errors.Wrap(err, "encode path")
		}
		encoded, err := e.Result()
		if err != nil {
			return res, errors.Wrap(err, "encode path")
		}
		pathParts[1] = encoded
	}
	pathParts[2] = "/tradition-id"
	uri.AddPathParts(u, pathParts[:]...)

	stage = "EncodeRequest"
	r, err := ht.NewRequest(ctx, "GET", u)
	if err != nil {
		return res, errors.Wrap(err, "create request")
	}

	stage = "SendRequest"
	resp, err := c.cfg.Client.Do(r)
	if err != nil {
		return res, errors.Wrap(err, "do request")
	}
	defer resp.Body.Close()

	stage = "DecodeResponse"
	result, err := decodeContextTraditionIDResponse(resp)
	if err != nil {
		return res, errors.Wrap(err, "decode response")
	}

	return result, nil
}
