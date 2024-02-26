// Code generated by ogen, DO NOT EDIT.

package beract

import (
	"github.com/google/uuid"
)

// ActivitiesListParams is parameters of ActivitiesList operation.
type ActivitiesListParams struct {
	// Идентификаторы активностей.
	Ids []uuid.UUID
}

// ActivitiesScoresParams is parameters of ActivitiesScores operation.
type ActivitiesScoresParams struct {
	// Идентификатор традиции.
	TraditionID OptInt32
	// Список идентификаторов контекстов.
	ContextIds []ContextID
	// Список игроков, активности которых попадут в выборку.
	// Параметр доступен только при использовании
	// авторизации `ServiceKey`.
	PlayerIds []PlayerID
}

// ActivitiesScoresByTraditionsParams is parameters of ActivitiesScoresByTraditions operation.
type ActivitiesScoresByTraditionsParams struct {
	// Получение баллов по всем PlayerID пользователя.
	TalentID int32
}

// ActivityReadParams is parameters of ActivityRead operation.
type ActivityReadParams struct {
	ActivityID ActivityID
}

// ArtefactSetUploadedParams is parameters of ArtefactSetUploaded operation.
type ArtefactSetUploadedParams struct {
	ArtefactID ArtefactID
}

// ArtefactUploadURLParams is parameters of ArtefactUploadURL operation.
type ArtefactUploadURLParams struct {
	ArtefactID ArtefactID
}

// ArtefactsCreateParams is parameters of ArtefactsCreate operation.
type ArtefactsCreateParams struct {
	// ID типа артефакта из [справочника](#operation/ArtefactTypesList).
	XArtefactType int32
	// SHA-1 контрольная сумма.
	XChecksum string
}

// ContextTraditionIDParams is parameters of ContextTraditionID operation.
type ContextTraditionIDParams struct {
	ContextID ContextID
}
