package graph

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-viper/mapstructure/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/anurag-rajawat/api-security/graph/model"
	"github.com/anurag-rajawat/api-security/pkg/util"
)

var (
	severityName = map[int32]model.Severity{
		1: model.SeverityLow,
		2: model.SeverityMedium,
		3: model.SeverityHigh,
		4: model.SeverityCritical,
	}
	severityValue = map[model.Severity]int32{
		model.SeverityLow:      1,
		model.SeverityMedium:   2,
		model.SeverityHigh:     3,
		model.SeverityCritical: 4,
	}
)

// pageInfoInput holds intermediate data for building the connection.
type pageInfoInput struct {
	totalCount      int64
	hasNextPage     bool
	hasPreviousPage bool
}

const defaultPageSize = 20
const maxPageSize = 100

const cursorPrefix = "cursor:"

func encodeCursor(id primitive.ObjectID) string {
	return cursorPrefix + base64.StdEncoding.EncodeToString([]byte(id.Hex()))
}

func decodeCursor(encodedCursor *string) (primitive.ObjectID, error) {
	if encodedCursor == nil || *encodedCursor == "" {
		return primitive.NilObjectID, fmt.Errorf("cursor is nil or empty")
	}

	// Remove prefix if it exists
	trimmedCursor := strings.TrimPrefix(*encodedCursor, cursorPrefix)

	bytes, err := base64.StdEncoding.DecodeString(trimmedCursor)
	if err != nil {
		return primitive.NilObjectID, fmt.Errorf("invalid cursor format (base64 decode failed): %w", err)
	}

	hexID := string(bytes)
	if _, err := primitive.ObjectIDFromHex(hexID); err != nil {
		return primitive.NilObjectID, fmt.Errorf("invalid cursor format (not a valid ObjectID hex): %s", hexID)
	}

	objID, err := primitive.ObjectIDFromHex(hexID)
	if err != nil {
		// Should not happen if IsValidObjectID passed, but check anyway
		return primitive.NilObjectID, fmt.Errorf("invalid cursor format (ObjectID conversion failed): %w", err)
	}

	return objID, nil
}

func ginContextFromContext(ctx context.Context) (*gin.Context, error) {
	ginContext := ctx.Value("GinContextKey")
	if ginContext == nil {
		return nil, fmt.Errorf("could not retrieve gin.Context")
	}

	gc, ok := ginContext.(*gin.Context)
	if !ok {
		return nil, fmt.Errorf("gin.Context has wrong type")
	}
	return gc, nil
}

func extractTenantId(ctx context.Context) (string, bool) {
	ginCtx, err := ginContextFromContext(ctx)
	if err != nil {
		return "", false
	}
	tenantId := ginCtx.Request.Header.Get("x-tenant-id")
	if tenantId == "" {
		return "", false
	}
	return tenantId, true
}

func marshalIntoApiEvent(doc bson.M) (*model.ApiEvent, error) {
	// Todo: Unify Data Types
	var apiEvent model.ApiEvent

	bsonId, ok := doc["_id"].(primitive.ObjectID)
	if !ok {
		return nil, fmt.Errorf("bson id not found")
	}
	// IMPORTANT: POPULATE BSONID
	apiEvent.BSONID = bsonId
	apiEvent.GQLID = bsonId.Hex()

	event, ok := doc["api_event"]
	if !ok {
		return nil, fmt.Errorf("api_event not found")
	}

	if err := mapstructure.Decode(event, &apiEvent); err != nil {
		return nil, err
	}

	return populateApiEvent(doc, &apiEvent)
}

func populateApiEvent(doc bson.M, apiEvent *model.ApiEvent) (*model.ApiEvent, error) {
	if err := populateMetadata(doc, apiEvent); err != nil {
		return nil, err
	}

	statusCode, ok := doc["api_event"].(bson.M)["http"].(bson.M)["response"].(bson.M)["status_code"].(int64)
	if !ok {
		return nil, fmt.Errorf("response status code not found")
	}
	apiEvent.HTTP.Response.StatusCode = int32(statusCode)

	if err := populateJwtInfo(doc, apiEvent); err != nil {
		return nil, err
	}

	if err := populateSensitiveData(doc, apiEvent); err != nil {
		return nil, err
	}

	if overallRiskScore, ok := doc["api_event"].(bson.M)["overall_risk_score"].(int64); ok {
		apiEvent.OverallRiskScore = int32(int(overallRiskScore))
	}
	if overallSeverity, ok := doc["api_event"].(bson.M)["overall_severity"].(int32); ok {
		apiEvent.OverallSeverity = severityName[overallSeverity]
	}

	return apiEvent, nil
}

func populateSensitiveData(doc bson.M, apiEvent *model.ApiEvent) error {
	data, ok := doc["api_event"].(bson.M)["sensitive_data"].(bson.A)
	if !ok {
		return nil
	}

	for _, element := range data {
		valueMap, ok := element.(bson.M)
		if !ok {
			continue
		}
		var datum model.SensitiveData

		bytes, err := json.Marshal(valueMap)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(bytes, &datum); err != nil {
			return err
		}

		if riskScore, ok := valueMap["risk_score"].(int64); ok {
			riskScoreInt32 := int32(riskScore)
			datum.RiskScore = &riskScoreInt32
		}
		if startIndex, ok := valueMap["location"].(bson.M)["start_index"].(int32); ok {
			datum.Location.StartIndex = &startIndex
		}
		if endIndex, ok := valueMap["location"].(bson.M)["end_index"].(int32); ok {
			datum.Location.EndIndex = &endIndex
		}
		apiEvent.SensitiveData = append(apiEvent.SensitiveData, &datum)
	}
	return nil
}

func populateJwtInfo(doc bson.M, apiEvent *model.ApiEvent) error {
	info, ok := doc["api_event"].(bson.M)["user"].(bson.M)
	if !ok {
		return fmt.Errorf("key `api_event.user` not found")
	}

	if apiEvent.User == nil {
		apiEvent.User = &model.JwtInfo{}
	}

	if userName, ok := info["username"].(string); ok {
		apiEvent.User.Username = &userName
	}
	if email, ok := info["email"].(string); ok {
		apiEvent.User.Email = &email
	}
	if issuer, ok := info["issuer"].(string); ok {
		apiEvent.User.Issuer = &issuer
	}
	if subject, ok := info["subject"].(string); ok {
		apiEvent.User.Subject = &subject
	}
	if audience, ok := info["audience"].(string); ok {
		apiEvent.User.Audience = &audience
	}
	if expirationTime, ok := info["expiration_time"].(string); ok {
		apiEvent.User.ExpirationTime = &expirationTime
	}
	if notBefore, ok := info["not_before"].(string); ok {
		apiEvent.User.NotBefore = &notBefore
	}
	if issuedAt, ok := info["issued_at"].(string); ok {
		apiEvent.User.IssuedAt = &issuedAt
	}
	if jti, ok := info["jti"].(string); ok {
		apiEvent.User.Jti = &jti
	}
	if algorithm, ok := info["algorithm"].(string); ok {
		apiEvent.User.Algorithm = &algorithm
	}

	return nil
}

func populateMetadata(doc bson.M, apiEvent *model.ApiEvent) error {
	if apiEvent.Metadata == nil {
		apiEvent.Metadata = &model.APIEventMetadata{}
	}

	// Todo: What if the key in mid way not found?

	if apiEvent.Metadata.Timestamp == 0 {
		firstseen, ok := doc["api_event"].(bson.M)["metadata"].(bson.M)["timestamp"].(int64)
		if !ok {
			return fmt.Errorf("api_event missing `timestamp` metadata")
		}
		apiEvent.Metadata.Timestamp = firstseen
	}
	if apiEvent.Metadata.UpdatedTime == 0 {
		lastSeen, ok := doc["api_event"].(bson.M)["metadata"].(bson.M)["updated_time"].(int64)
		if !ok {
			return fmt.Errorf("api_event missing `updated_time` metadata")
		}
		apiEvent.Metadata.UpdatedTime = lastSeen
	}

	if apiEvent.Metadata.APIType == nil {
		apiType, ok := doc["api_event"].(bson.M)["metadata"].(bson.M)["api_type"].(string)
		if !ok {
			return fmt.Errorf("api_event missing `api_type`")
		}
		apiTypeRef := model.APIType(apiType)
		apiEvent.Metadata.APIType = &apiTypeRef
	}

	if apiEvent.Metadata.IsAuthenticated == nil {
		isAuthenticatd, ok := doc["api_event"].(bson.M)["metadata"].(bson.M)["is_authenticated"].(bool)
		if !ok {
			return fmt.Errorf("api_event missing `is_authenticated` metadata")
		}
		apiEvent.Metadata.IsAuthenticated = &isAuthenticatd
	}

	if apiEvent.Metadata.ClusterName == "" {
		clusterName, ok := doc["cluster_name"].(string)
		if !ok {
			return fmt.Errorf("api_event missing `cluster_name` metadata")
		}
		apiEvent.Metadata.ClusterName = clusterName
	}
	if apiEvent.Metadata.ClusterID == 0 {
		clusterID, ok := doc["cluster_id"].(int32)
		if !ok {
			return fmt.Errorf("api_event missing `cluster_id` metadata")
		}
		apiEvent.Metadata.ClusterID = clusterID
	}

	if apiEvent.Metadata.Hostname == "" {
		hostName, ok := doc["api_event"].(bson.M)["http"].(bson.M)["request"].(bson.M)["headers"].(bson.M)[":authority"].(string)
		if !ok {
			return fmt.Errorf("api_event missing `hostname` metadata")
		}
		apiEvent.Metadata.Hostname = hostName
	}

	if apiEvent.Metadata.Scheme == nil {
		scheme, ok := doc["api_event"].(bson.M)["http"].(bson.M)["request"].(bson.M)["headers"].(bson.M)[":scheme"].(string)
		if !ok {
			return fmt.Errorf("api_event missing `scheme` metadata")
		}
		if scheme == "http" {
			httpScheme := model.SchemeHTTP
			apiEvent.Metadata.Scheme = &httpScheme
		} else if scheme == "https" {
			httpScheme := model.SchemeHTTPS
			apiEvent.Metadata.Scheme = &httpScheme
		}
	}

	return nil
}

func applyStringFilter(filters *bson.D, bsonField string, input *model.StringFilterInput) error {
	if isNil(input) {
		return nil
	}
	conditions := bson.D{}
	opCount := 0
	if input.Eq != nil {
		conditions = append(conditions, bson.E{Key: "$eq", Value: *input.Eq})
		opCount++
	}
	if input.Ne != nil {
		conditions = append(conditions, bson.E{Key: "$ne", Value: *input.Ne})
		opCount++
	}
	if len(input.In) > 0 {
		conditions = append(conditions, bson.E{Key: "$in", Value: input.In})
		opCount++
	}
	if len(input.Nin) > 0 {
		conditions = append(conditions, bson.E{Key: "$nin", Value: input.Nin})
		opCount++
	}
	if input.Regex != nil {
		conditions = append(conditions, bson.E{Key: "$regex", Value: primitive.Regex{Pattern: *input.Regex, Options: ""}})
		opCount++
	}
	if input.Iregex != nil {
		conditions = append(conditions, bson.E{Key: "$regex", Value: primitive.Regex{Pattern: *input.Iregex, Options: "i"}})
		opCount++
	}

	if len(conditions) == 1 && conditions[0].Key == "$eq" {
		*filters = append(*filters, bson.E{Key: bsonField, Value: conditions[0].Value})
	} else if len(conditions) > 0 {
		*filters = append(*filters, bson.E{Key: bsonField, Value: conditions})
	}
	return nil
}

func applyIntFilter(filters *bson.D, bsonField string, input *model.IntFilterInput) error {
	if isNil(input) {
		return nil
	}
	conditions, err := buildIntFilterConditions(input)
	if err != nil {
		return fmt.Errorf("failed to build int filter for %s: %w", bsonField, err)
	}
	if len(conditions) == 1 && conditions[0].Key == "$eq" {
		*filters = append(*filters, bson.E{Key: bsonField, Value: conditions[0].Value})
	} else if len(conditions) > 0 {
		*filters = append(*filters, bson.E{Key: bsonField, Value: conditions})
	}
	return nil
}

func applyEnumFilter(filters *bson.D, bsonField string, input interface{}) error {
	if isNil(input) {
		return nil
	}

	conditions := bson.D{}
	processed := false
	if typedInput, ok := input.(*model.APITypeFilterInput); ok && typedInput != nil {
		processed = true
		if typedInput.Eq != nil {
			conditions = append(conditions, bson.E{Key: "$eq", Value: typedInput.Eq.String()})
		}
		if typedInput.Ne != nil {
			conditions = append(conditions, bson.E{Key: "$ne", Value: typedInput.Ne.String()})
		}
		if len(typedInput.In) > 0 {
			inVals := make([]string, len(typedInput.In))
			for i, v := range typedInput.In {
				inVals[i] = v.String()
			}
			conditions = append(conditions, bson.E{Key: "$in", Value: inVals})
		}
		if len(typedInput.Nin) > 0 {
			ninVals := make([]string, len(typedInput.Nin))
			for i, v := range typedInput.Nin {
				ninVals[i] = v.String()
			}
			conditions = append(conditions, bson.E{Key: "$nin", Value: ninVals})
		}
	} else if typedInput, ok := input.(*model.SeverityFilterInput); ok && typedInput != nil {
		processed = true
		if typedInput.Eq != nil {
			conditions = append(conditions, bson.E{Key: "$eq", Value: severityValue[*typedInput.Eq]})
		}
		if typedInput.Ne != nil {
			conditions = append(conditions, bson.E{Key: "$ne", Value: severityValue[*typedInput.Ne]})
		}
		if len(typedInput.In) > 0 {
			inVals := make([]int32, len(typedInput.In))
			for i, v := range typedInput.In {
				inVals[i] = severityValue[v]
			}
			conditions = append(conditions, bson.E{Key: "$in", Value: inVals})
		}
		if len(typedInput.Nin) > 0 {
			ninVals := make([]int32, len(typedInput.Nin))
			for i, v := range typedInput.Nin {
				ninVals[i] = severityValue[v]
			}
			conditions = append(conditions, bson.E{Key: "$nin", Value: ninVals})
		}
	}

	if !processed {
		return fmt.Errorf("unsupported enum filter type provided for field %s (%T)", bsonField, input)
	}

	if len(conditions) == 1 && conditions[0].Key == "$eq" {
		*filters = append(*filters, bson.E{Key: bsonField, Value: conditions[0].Value})
	} else if len(conditions) > 0 {
		*filters = append(*filters, bson.E{Key: bsonField, Value: conditions})
	}

	return nil
}

func applyBooleanFilter(filters *bson.D, bsonField string, input *model.BooleanFilterInput) error {
	if isNil(input) {
		return nil
	}
	conditions := bson.D{}
	if input.Eq != nil {
		conditions = append(conditions, bson.E{Key: "$eq", Value: *input.Eq})
	}
	if input.Ne != nil {
		conditions = append(conditions, bson.E{Key: "$ne", Value: *input.Ne})
	}
	if len(conditions) == 1 && conditions[0].Key == "$eq" {
		*filters = append(*filters, bson.E{Key: bsonField, Value: conditions[0].Value})
	} else if len(conditions) > 0 {
		*filters = append(*filters, bson.E{Key: bsonField, Value: conditions})
	}
	return nil
}

func applyStatusCodeFilter(filters *bson.D, bsonIntField string, input *model.StringFilterInput) error {
	if isNil(input) {
		return nil
	}
	intConditions := bson.D{}
	var errs []string
	parseCode := func(codeStr string) (op string, value interface{}, err error) {
		codeStr = strings.ToLower(strings.TrimSpace(codeStr))
		if strings.HasSuffix(codeStr, "xx") && len(codeStr) == 3 {
			family := codeStr[0:1]
			startCode, err := strconv.Atoi(family)
			if err != nil || startCode < 1 || startCode > 5 {
				return "", nil, fmt.Errorf("invalid status family prefix: %s", family)
			}
			lowerBound := int32(startCode * 100)
			upperBound := lowerBound + 100
			// Return the condition for the range directly
			return "$range", bson.D{bson.E{Key: "$gte", Value: lowerBound}, bson.E{Key: "$lt", Value: upperBound}}, nil
		} else {
			specificCode, err := strconv.Atoi(codeStr)
			if err != nil || specificCode < 100 || specificCode > 599 {
				return "", nil, fmt.Errorf("invalid specific status code: %s", codeStr)
			}
			// Return the specific code for equality check
			return "$eq", int32(specificCode), nil
		}
	}

	if input.Eq != nil {
		op, val, err := parseCode(*input.Eq)
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			if op == "$range" {
				intConditions = append(intConditions, val.(bson.D)...)
			} else {
				intConditions = append(intConditions, bson.E{Key: "$eq", Value: val})
			}
		}
	}
	if input.Ne != nil {
		op, val, err := parseCode(*input.Ne)
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			if op == "$range" { // Not in range means $not applied to the range condition
				intConditions = append(intConditions, bson.E{Key: "$not", Value: val.(bson.D)})
			} else { // op == "$eq" -> $ne
				intConditions = append(intConditions, bson.E{Key: "$ne", Value: val})
			}
		}
	}

	if len(input.In) > 0 {
		// Collect specific codes for $in and range conditions for $or
		inValues := bson.A{}
		orConditions := bson.A{}
		for _, codeStr := range input.In {
			op, val, err := parseCode(codeStr)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			if op == "$range" {
				orConditions = append(orConditions, val.(bson.D)) // Add range { $gte: ..., $lt: ... } to $or list
			} else { // op == "$eq"
				inValues = append(inValues, val) // Add specific int32 code to $in list
			}
		}
		// Build the final condition for "In"
		if len(inValues) > 0 && len(orConditions) == 0 {
			// Only specific codes: use $in
			intConditions = append(intConditions, bson.E{Key: "$in", Value: inValues})
		} else if len(inValues) == 0 && len(orConditions) > 0 {
			// Only ranges: use $or
			if len(orConditions) == 1 { // Simplify if only one range
				intConditions = append(intConditions, orConditions[0].(bson.D)...)
			} else {
				intConditions = append(intConditions, bson.E{Key: "$or", Value: orConditions})
			}
		} else if len(inValues) > 0 && len(orConditions) > 0 {
			// Mixed codes and ranges: combine with $or
			// Add the $in condition for specific codes as one part of the $or
			if len(inValues) == 1 {
				orConditions = append(orConditions, bson.D{{"$eq", inValues[0]}}) // Use $eq if only one specific value
			} else {
				orConditions = append(orConditions, bson.D{{Key: "$in", Value: inValues}})
			}
			intConditions = append(intConditions, bson.E{Key: "$or", Value: orConditions})
		}
	}

	// Handle Nin (not in list of codes or families)
	if len(input.Nin) > 0 {
		// Similar logic to "In", but combining conditions using $nor or negating simple $in
		ninValues := bson.A{}
		norConditions := bson.A{}
		for _, codeStr := range input.Nin {
			op, val, err := parseCode(codeStr)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			if op == "$range" {
				norConditions = append(norConditions, val.(bson.D))
			} else { // op == "$eq"
				ninValues = append(ninValues, val)
			}
		}
		// Build the final condition for "Nin"
		if len(ninValues) > 0 && len(norConditions) == 0 {
			// Only specific codes: use $nin
			intConditions = append(intConditions, bson.E{Key: "$nin", Value: ninValues})
		} else if len(ninValues) == 0 && len(norConditions) > 0 {
			// Only ranges: use $nor
			intConditions = append(intConditions, bson.E{Key: "$nor", Value: norConditions})
		} else if len(ninValues) > 0 && len(norConditions) > 0 {
			// Mixed codes and ranges: combine with $nor
			if len(ninValues) == 1 {
				norConditions = append(norConditions, bson.D{{"$eq", ninValues[0]}}) // Use $eq for single value inside $nor
			} else {
				norConditions = append(norConditions, bson.D{{Key: "$nin", Value: ninValues}}) // Use $nin inside $nor
			}
			intConditions = append(intConditions, bson.E{Key: "$nor", Value: norConditions})
		}
	}

	// Regex ops don't apply to integer field
	if input.Regex != nil || input.Iregex != nil {
		errs = append(errs, "regex/iregex not supported for integer status code filtering")
	}

	// Check for accumulated errors
	if len(errs) > 0 {
		return fmt.Errorf("errors parsing status code filter: %s", strings.Join(errs, "; "))
	}

	// Append the final conditions doc for the bsonIntField
	if len(intConditions) == 1 && intConditions[0].Key == "$eq" {
		// Simplify {$eq: val} to just val for the field
		*filters = append(*filters, bson.E{Key: bsonIntField, Value: intConditions[0].Value})
	} else if len(intConditions) > 0 {
		// Apply the combined conditions document {$ne: ..., $or: [...], etc.}
		*filters = append(*filters, bson.E{Key: bsonIntField, Value: intConditions})
	}
	return nil
}

func getPrimarySort(sortDoc bson.D) (string, int) {
	if len(sortDoc) > 0 {
		primary := sortDoc[0]
		switch dirVal := primary.Value.(type) {
		case int:
			return primary.Key, dirVal
		case int32:
			return primary.Key, int(dirVal)
		case int64:
			return primary.Key, int(dirVal)
		}
	}
	return "_id", 1 // Default
}

func buildIntFilterConditions(input *model.IntFilterInput) (bson.D, error) {
	conditions := bson.D{}
	if isNil(input) {
		return conditions, nil
	}
	if input.Eq != nil {
		conditions = append(conditions, bson.E{Key: "$eq", Value: *input.Eq})
	}
	if input.Ne != nil {
		conditions = append(conditions, bson.E{Key: "$ne", Value: *input.Ne})
	}
	if len(input.In) > 0 {
		in32 := make([]int32, len(input.In))
		for i, v := range input.In {
			in32[i] = v
		}
		conditions = append(conditions, bson.E{Key: "$in", Value: in32})
	}
	if len(input.Nin) > 0 {
		nin32 := make([]int32, len(input.Nin))
		for i, v := range input.Nin {
			nin32[i] = v
		}
		conditions = append(conditions, bson.E{Key: "$nin", Value: nin32})
	}
	if input.Lt != nil {
		conditions = append(conditions, bson.E{Key: "$lt", Value: *input.Lt})
	}
	if input.Lte != nil {
		conditions = append(conditions, bson.E{Key: "$lte", Value: *input.Lte})
	}
	if input.Gt != nil {
		conditions = append(conditions, bson.E{Key: "$gt", Value: *input.Gt})
	}
	if input.Gte != nil {
		conditions = append(conditions, bson.E{Key: "$gte", Value: *input.Gte})
	}
	return conditions, nil
}

func isNil(a any) bool {
	return a == nil || (reflect.ValueOf(a).Kind() == reflect.Ptr && reflect.ValueOf(a).IsNil())
}

func (r *queryResolver) buildContentFilters(filters *model.Filters) (bson.D, error) {
	contentFilters := bson.D{bson.E{Key: "operation", Value: "Api"}}
	var err error

	if len(filters.ClusterIds) > 0 {
		contentFilters = append(contentFilters, bson.E{Key: "cluster_id", Value: bson.D{bson.E{Key: "$in", Value: filters.ClusterIds}}})
	} else {
		return nil, fmt.Errorf("clusterIds filter is required")
	}

	// Time Range Filter
	timeFilter := bson.D{}
	if filters.FromTimestamp != nil {
		timeFilter = append(timeFilter, bson.E{Key: "$gte", Value: *filters.FromTimestamp})
	}
	if filters.ToTimestamp != nil {
		timeFilter = append(timeFilter, bson.E{Key: "$lte", Value: *filters.ToTimestamp})
	}
	if len(timeFilter) > 0 {
		// Todo: Double check bson key path?
		// Why or why not `api_event.metadata.timestamp/updated_time?
		contentFilters = append(contentFilters, bson.E{Key: "updated_time", Value: timeFilter})
	}

	if err = applyEnumFilter(&contentFilters, "api_event.metadata.api_type", filters.APIType); err != nil {
		return nil, err
	}
	if err = applyBooleanFilter(&contentFilters, "api_event.metadata.is_authenticated", filters.IsAuthenticated); err != nil {
		return nil, err
	}
	if err = applyStringFilter(&contentFilters, "api_event.http.request.headers.:authority", filters.Hostname); err != nil {
		return nil, err
	}

	if err = applyStatusCodeFilter(&contentFilters, "api_event.http.response.status_code", filters.ResponseStatusCode); err != nil {
		return nil, err
	}
	if err = applyStringFilter(&contentFilters, "api_event.http.request.path", filters.RequestPath); err != nil {
		return nil, err
	}
	if err = applyStringFilter(&contentFilters, "api_event.http.request.method", filters.RequestMethod); err != nil {
		return nil, err
	}

	if err = applyStringFilter(&contentFilters, "api_event.network.destination.ip", filters.DestinationIP); err != nil {
		return nil, err
	}
	if err = applyStringFilter(&contentFilters, "api_event.network.destination.metadata.name", filters.DestinationName); err != nil {
		return nil, err
	}
	if err = applyStringFilter(&contentFilters, "api_event.network.destination.type", filters.DestinationType); err != nil {
		return nil, err
	}

	if err = applyIntFilter(&contentFilters, "api_event.overall_risk_score", filters.SensitiveDataRiskScore); err != nil {
		return nil, err
	}
	if err = applyEnumFilter(&contentFilters, "api_event.overall_severity", filters.SensitiveDataSeverity); err != nil {
		return nil, err
	}

	return contentFilters, nil
}

func (r *queryResolver) buildSortDocument(sortBy *model.APIEventSortInput, isBackwardPagination bool) bson.D {
	sortDoc := bson.D{}

	// Determine default sort direction based on pagination intention
	defaultSortDir := 1 // ASC for forward / no pagination args
	if isBackwardPagination {
		defaultSortDir = -1 // DESC for backward pagination
	}

	primarySortField := "_id" // Default primary sort field
	primarySortDir := defaultSortDir

	if sortBy != nil {
		sortFieldBSON := ""
		switch sortBy.Field {
		case model.APIEventSortableFieldTimestamp:
			// Todo: Double check bson key path?
			// Why or why not `api_event.metadata.timestamp/updated_time?
			sortFieldBSON = "updated_time"
		case model.APIEventSortableFieldUpdatedTime:
			// Todo: Double check bson key path?
			// Why or why not `api_event.metadata.timestamp/updated_time?
			sortFieldBSON = "updated_time"
		case model.APIEventSortableFieldRequestPath:
			sortFieldBSON = "api_event.http.request.path"
		case model.APIEventSortableFieldStatusCode:
			sortFieldBSON = "api_event.http.response.status_code"
		case model.APIEventSortableFieldCount:
			sortFieldBSON = "api_event.count"
		case model.APIEventSortableFieldRiskScore:
			sortFieldBSON = "api_event.overall_risk_score"
		case model.APIEventSortableFieldSeverity:
			sortFieldBSON = "api_event.overall_severity"
		default:
			r.Logger.Warnf("unsupported sort field %s, falling back to default %s sort", primarySortField, sortBy.Field)
		}

		// Only override defaults if a valid field was found
		if sortFieldBSON != "" {
			primarySortField = sortFieldBSON
			primarySortDir = 1 // ASC default
			if sortBy.Direction == model.SortDirectionDesc {
				primarySortDir = -1 // User specified DESC
			}
		}
	}

	// Add the primary sort key determined above
	sortDoc = append(sortDoc, bson.E{Key: primarySortField, Value: primarySortDir})

	// Add `_id` as the secondary sort key ONLY if the primary wasn't `_id`
	// This ensures stable order for pagination when sorting by potentially non-unique fields.
	if primarySortField != "_id" {
		// Use the same direction as the primary sort for the secondary _id key
		sortDoc = append(sortDoc, bson.E{Key: "_id", Value: primarySortDir})
	}

	return sortDoc
}

func (r *queryResolver) calculatePaginationLimits(first *int32, last *int32) (limit int, fetchLimit int) {
	limit = defaultPageSize

	isBackwardPagination := last != nil
	if isBackwardPagination {
		requestedLimit := int(*last)
		if requestedLimit < 0 {
			requestedLimit = 0
		}
		if requestedLimit == 0 {
			limit = 0
		} else if requestedLimit > maxPageSize {
			limit = maxPageSize
		} else {
			limit = requestedLimit
		}
	} else { // Forward pagination or default
		if first != nil {
			requestedLimit := int(*first)
			if requestedLimit < 0 {
				requestedLimit = 0
			}
			if requestedLimit == 0 {
				limit = 0
			} else if requestedLimit > maxPageSize {
				limit = maxPageSize
			} else {
				limit = requestedLimit
			}
		}
	}

	fetchLimit = limit + 1
	if limit == 0 {
		fetchLimit = 0
	}
	return limit, fetchLimit
}

type cursorPayload struct {
	Value any    `json:"v"`
	IDHex string `json:"id"`
}

func (r *queryResolver) buildCursorFilter(sortDoc bson.D, after *string, before *string) (bson.D, error) {
	cursorFilter := bson.D{}
	primarySortField, _ := getPrimarySort(sortDoc)

	// Only apply simple _id filter if primary sort IS _id
	// More complex logic needed for other sort fields.
	if primarySortField == "_id" {
		if after != nil {
			cursorObjID, err := decodeCursor(after)
			if err != nil {
				r.Logger.Warnw("Invalid 'after' cursor", "cursor", *after, "error", err)
				return nil, fmt.Errorf("invalid `after` cursor: %w", err)
			}
			// Only apply if sort matches expected default _id ASC
			expectedSort := bson.D{{"_id", 1}}
			if reflect.DeepEqual(sortDoc, expectedSort) {
				cursorFilter = append(cursorFilter, bson.E{Key: "_id", Value: bson.D{{"$gt", cursorObjID}}})
			} else {
				r.Logger.Warn("Cursor pagination (`after`) ignored: applied only when sorting by _id ASC.")
			}
		} else if before != nil {
			cursorObjID, err := decodeCursor(before)
			if err != nil {
				r.Logger.Warnw("Invalid 'before' cursor", "cursor", *before, "error", err)
				return nil, fmt.Errorf("invalid `before` cursor: %w", err)
			}
			// Only apply if sort matches expected default _id DESC
			expectedSort := bson.D{{"_id", -1}}
			if reflect.DeepEqual(sortDoc, expectedSort) {
				cursorFilter = append(cursorFilter, bson.E{Key: "_id", Value: bson.D{{"$lt", cursorObjID}}})
			} else {
				r.Logger.Warn("Cursor pagination (`before`) ignored: applied only when sorting by _id DESC.")
			}
		}
	} else if after != nil || before != nil {
		// Primary sort is NOT _id, but cursor args were provided
		r.Logger.Warn("Cursor pagination (`after`/`before`) ignored: not supported when sorting by fields other than _id in this simplified implementation.")
	}
	return cursorFilter, nil
}

func (r *queryResolver) fetchAPIEvents(ctx context.Context, collection *mongo.Collection,
	query bson.D, sort bson.D, limit int64, totalCount int64) ([]*model.ApiEvent, error) {

	var fetchedEvents []*model.ApiEvent
	if limit > 0 && totalCount > 0 {
		findOptions := options.Find()
		findOptions.SetSort(sort)
		findOptions.SetLimit(limit)

		//projection := buildProjection(ctx)
		//if projection != nil {
		//	findOptions.SetProjection(projection)
		//	r.Logger.Debugw("Applying projection", "projection", projection)
		//} else {
		//	r.Logger.Debug("projection is nil")
		//}

		r.Logger.Debugw("Executing Find query", "query", query, "sort", sort, "limit", limit)
		cursor, err := collection.Find(ctx, query, findOptions)
		if err != nil {
			r.Logger.Errorw("Failed to execute find query", "query", query, "sort", sort, "limit", limit, "error", err)
			return nil, fmt.Errorf("failed to execute find query: %w", err)
		}
		defer func() {
			if cerr := cursor.Close(ctx); cerr != nil {
				r.Logger.Errorw("Failed to close cursor", "error", cerr)
			}
		}()

		for cursor.Next(ctx) {
			doc := bson.M{}
			if err := cursor.Decode(&doc); err != nil {
				r.Logger.Errorw("Failed to decode document", "error", err)
				continue
			}
			event, err := marshalIntoApiEvent(doc)
			if err != nil {
				r.Logger.Errorw("Failed to marshal event", "error", err)
				continue
			}
			if event != nil {
				event.GQLID = event.BSONID.Hex() // Populate GQL ID
				fetchedEvents = append(fetchedEvents, event)
			}
		}
		if err := cursor.Err(); err != nil {
			r.Logger.Errorw("Cursor iteration error", "error", err)
			return nil, fmt.Errorf("error during cursor iteration: %w", err)
		}
	} else {
		r.Logger.Debugw("Skipping Find query", "fetchLimit", limit, "totalCount", totalCount)
	}
	return fetchedEvents, nil
}

func buildProjection(ctx context.Context) bson.D {
	// Get requested fields using gqlgen context function
	logger := util.GetLogger()
	fields := preloads(ctx)
	logger.Debugw("fields", "fields", fields)

	// Simple mapping (GraphQL field name -> BSON path).
	// **CRITICAL**: Update these paths to match your BSON structure! Use paths from filters/sorts.
	projectionMap := map[string]string{
		//"edges.node.id":            "_id", // Need _id to generate GQLID and cursor
		"edges.node.metadata":      "api_event.metadata",
		"edges.node.count":         "api_event.count",
		"edges.node.network":       "api_event.network",
		"edges.node.http":          "api_event.http",
		"edges.node.user":          "api_event.user",
		"edges.node.summary":       "api_event.summary",
		"edges.node.sensitiveData": "api_event.sensitive_data",
	}

	projection := bson.D{bson.E{Key: "_id", Value: 1}} // Always include _id
	hasProjection := false

	// Crude check: if specific sub-fields are requested, include the parent BSON field
	for _, field := range fields {
		// Check top-level fields
		if bsonPath, ok := projectionMap[field]; ok {
			projection = append(projection, bson.E{Key: bsonPath, Value: 1})
			hasProjection = true
		}
		// Add more sophisticated checks for nested fields if needed
		// e.g., if field is "metadata.timestamp", ensure "metadata" is included.
		// gqlgen's CollectFields function can provide more detailed info.
		// This simple version fetches entire sub-documents if *any* part is requested.
	}

	// If only 'id' or other implicitly included fields were requested,
	// projection might just be {'_id': 1}. In this case, no specific projection needed
	// unless you want to *exclude* fields (value: 0), but that's less common here.
	if hasProjection && len(projection) > 1 { // Only apply if specific fields were added beyond _id
		return projection
	}

	// Return nil to fetch all fields if no specific projection was built
	// (or only default _id was included)
	return nil
}

func (r *queryResolver) buildAPIEventConnection(resultsToReturn []*model.ApiEvent, pageInfoIn pageInfoInput) *model.APIEventConnection {
	apiEventEdges := make([]*model.APIEventEdge, 0, len(resultsToReturn))
	for _, event := range resultsToReturn {
		if event == nil {
			continue
		}
		apiEventEdges = append(apiEventEdges, &model.APIEventEdge{
			Cursor: encodeCursor(event.BSONID), // Using _id based cursor
			Node:   event,
		})
	}

	pageInfo := &model.PageInfo{
		HasNextPage:     pageInfoIn.hasNextPage,
		HasPreviousPage: pageInfoIn.hasPreviousPage,
	}
	if len(apiEventEdges) > 0 {
		startCursor := apiEventEdges[0].Cursor
		endCursor := apiEventEdges[len(apiEventEdges)-1].Cursor
		pageInfo.StartCursor = &startCursor
		pageInfo.EndCursor = &endCursor
	}

	return &model.APIEventConnection{
		TotalCount: pageInfoIn.totalCount,
		Edges:      apiEventEdges,
		PageInfo:   pageInfo,
	}
}

func (r *queryResolver) processPaginationResults(fetchedEvents []*model.ApiEvent, limit int, isBackwardPagination bool, after, before *string) (
	resultsToReturn []*model.ApiEvent, hasNextPage bool, hasPreviousPage bool) {

	resultsToReturn = fetchedEvents
	fetchLimit := limit + 1
	if limit == 0 {
		fetchLimit = 0
	}

	if isBackwardPagination {
		if len(fetchedEvents) >= fetchLimit && limit > 0 {
			hasPreviousPage = true
			resultsToReturn = fetchedEvents[:limit]
		} else {
			hasPreviousPage = false
		}
		hasNextPage = before != nil

		for i, j := 0, len(resultsToReturn)-1; i < j; i, j = i+1, j-1 {
			resultsToReturn[i], resultsToReturn[j] = resultsToReturn[j], resultsToReturn[i]
		}
	} else { // Forward pagination or default
		if len(fetchedEvents) >= fetchLimit && limit > 0 {
			hasNextPage = true
			resultsToReturn = fetchedEvents[:limit]
		} else {
			hasNextPage = false
		}
		hasPreviousPage = after != nil
	}

	if limit == 0 {
		resultsToReturn = []*model.ApiEvent{}
	}
	return resultsToReturn, hasNextPage, hasPreviousPage
}
