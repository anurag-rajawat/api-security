package model

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// TODO: Unify json tags to camelCase across entire pipeline

type ApiEvent struct {
	BSONID primitive.ObjectID `bson:"_id,omitempty" json:"-"` // Hide from GraphQL
	GQLID  string             `bson:"-" json:"id"`            // GraphQL ID, populated from BSONID

	// Metadata providing context and details about the API event.
	Metadata *APIEventMetadata `bson:"metadata" json:"metadata"`

	// Network-related information, detailing the source and destination of the API call.
	Network *Network `bson:"network" json:"network"`

	// HTTP request and response details, if applicable.
	HTTP *HTTP `bson:"http" json:"http"`

	// JSON Web Token (JWT) information, if authentication was performed using JWT.
	User *JwtInfo `bson:"user" json:"user,omitempty"`

	// The number of times this API endpoint has been accessed.
	Count int32 `bson:"count" json:"count"`

	// A concise summary of the API event.
	Summary string `bson:"summary" json:"summary"`

	OverallRiskScore int32    `bson:"overall_risk_score,omitempty" json:"overallRiskScore,omitempty"`
	OverallSeverity  Severity `bson:"overall_severity,omitempty" json:"overallSeverity,omitempty"`

	// Details about any sensitive data detected within the API event.
	SensitiveData []*SensitiveData `bson:"sensitive_data" json:"sensitiveData,omitempty"`
}
