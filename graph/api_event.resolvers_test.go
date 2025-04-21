package graph

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap/zaptest"

	"github.com/anurag-rajawat/api-security/graph/model"
)

func TestCalculatePaginationLimits(t *testing.T) {
	r := &queryResolver{
		&Resolver{
			Logger: zaptest.NewLogger(t).Sugar(),
		},
	}
	first := func(v int32) *int32 { return &v }
	last := func(v int32) *int32 { return &v }

	tests := []struct {
		name               string
		first              *int32
		last               *int32
		expectedLimit      int
		expectedFetchLimit int
	}{
		{
			"first and last are nil should use default page size limit",
			nil,
			nil,
			defaultPageSize,
			defaultPageSize + 1,
		},
		{
			"first only should use first page size limit",
			first(10),
			nil,
			10,
			11,
		},
		{
			"last only should use last page size limit",
			nil,
			last(5),
			5,
			6,
		},
		{
			"first is 0 limit should be 0",
			first(0),
			nil,
			0,
			0,
		},
		{
			"last is 0 limit should be 0",
			nil,
			last(0),
			0,
			0,
		},
		{
			"first is greater than max should use max page size limit",
			first(int32(maxPageSize + 50)),
			nil,
			maxPageSize,
			maxPageSize + 1,
		},
		{
			"last is greater than max should use max page size limit",
			nil,
			last(int32(maxPageSize + 50)),
			maxPageSize,
			maxPageSize + 1,
		},
		{
			"first and last both are specified last should take precedence",
			first(10),
			last(5),
			5,
			6,
		},
		{
			"first is negative page size limit should be zero",
			first(-10),
			nil,
			0,
			0,
		},
		{
			"last is negative page size limit should be zero",
			nil,
			last(-5),
			0,
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limit, fetchLimit := r.calculatePaginationLimits(tt.first, tt.last)
			if tt.expectedLimit != limit {
				t.Errorf("calculatePaginationLimits() expectedLimit, got = %v, want %v", limit, tt.expectedLimit)
			}
			if tt.expectedFetchLimit != fetchLimit {
				t.Errorf("calculatePaginationLimits() expectedFetchLimit, got = %v, want %v", fetchLimit, tt.expectedFetchLimit)
			}
		})
	}
}

func TestBuildSortDocument(t *testing.T) {
	r := &queryResolver{
		&Resolver{
			Logger: zaptest.NewLogger(t).Sugar(),
		},
	}
	asc := model.SortDirectionAsc
	desc := model.SortDirectionDesc
	tsField := model.APIEventSortableFieldTimestamp
	countField := model.APIEventSortableFieldCount

	tests := []struct {
		name                 string
		sortBy               *model.APIEventSortInput
		isBackwardPagination bool
		expectedSortDoc      bson.D
	}{
		{
			"sortBy is nil and not backward pagination should use default forward",
			nil,
			false,
			bson.D{{"_id", 1}},
		},
		{
			"sortBy is nil and backward pagination is true should use default backward",
			nil,
			true,
			bson.D{{"_id", -1}},
		},
		{
			"timestamp asc",
			&model.APIEventSortInput{
				Field:     tsField,
				Direction: asc,
			},
			false,
			bson.D{{"updated_time", 1}, {"_id", 1}},
		},
		{"timestamp desc",
			&model.APIEventSortInput{
				Field:     tsField,
				Direction: desc,
			},
			false,
			bson.D{{"updated_time", -1}, {"_id", -1}},
		},
		{
			"count desc backward",
			&model.APIEventSortInput{
				Field:     countField,
				Direction: desc,
			},
			true,
			bson.D{{"api_event.count", -1}, {"_id", -1}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sortDoc := r.buildSortDocument(tt.sortBy, tt.isBackwardPagination)
			if len(sortDoc) != len(tt.expectedSortDoc) {
				t.Errorf("buildSortDocument() sort document length mismatch, got = %v, want %v", sortDoc, tt.expectedSortDoc)
			}
			for i := range tt.expectedSortDoc {
				if tt.expectedSortDoc[i].Key != sortDoc[i].Key {
					t.Errorf("buildSortDocument() sort key mismatch, got = %v, want %v", tt.expectedSortDoc[i].Key, sortDoc[i].Key)
				}
				if tt.expectedSortDoc[i].Value != sortDoc[i].Value {
					t.Errorf("buildSortDocument() sort value mismatch, got = %v, want %v", tt.expectedSortDoc[i].Value, sortDoc[i].Value)
				}
			}
		})
	}
}

//--- Unit Tests for processPaginationResults ---

func TestProcessPaginationResults(t *testing.T) {
	r := &queryResolver{
		&Resolver{
			Logger: zaptest.NewLogger(t).Sugar(),
		},
	}
	// Helper to create dummy events with specific IDs for checking order/reversal
	makeEvent := func(idHex string) *model.ApiEvent {
		oid, _ := primitive.ObjectIDFromHex(idHex)
		return &model.ApiEvent{BSONID: oid, GQLID: idHex /* other fields */}
	}

	// Test data (ensure enough for limit+1 scenarios)
	// Use simple sequential ObjectIDs for predictable ordering
	oid1 := primitive.NewObjectIDFromTimestamp(time.Now().Add(-5 * time.Second))
	oid2 := primitive.NewObjectIDFromTimestamp(time.Now().Add(-4 * time.Second))
	oid3 := primitive.NewObjectIDFromTimestamp(time.Now().Add(-3 * time.Second))
	oid4 := primitive.NewObjectIDFromTimestamp(time.Now().Add(-2 * time.Second))
	oid5 := primitive.NewObjectIDFromTimestamp(time.Now().Add(-1 * time.Second))
	event1, event2, event3, event4, event5 := makeEvent(oid1.Hex()), makeEvent(oid2.Hex()), makeEvent(oid3.Hex()), makeEvent(oid4.Hex()), makeEvent(oid5.Hex())

	strPtr := func(s string) *string { return &s }

	tests := []struct {
		name          string
		fetchedEvents []*model.ApiEvent
		limit         int
		isBackward    bool
		after         *string
		before        *string
		// Expected results
		expectedResults     []*model.ApiEvent
		expectedHasNext     bool
		expectedHasPrevious bool
	}{
		// Forward Pagination
		{"forward basic", []*model.ApiEvent{event1, event2, event3}, 2, false, nil, nil, []*model.ApiEvent{event1, event2}, true, false},
		{"forward exact limit", []*model.ApiEvent{event1, event2}, 2, false, nil, nil, []*model.ApiEvent{event1, event2}, false, false},
		{"forward less than limit", []*model.ApiEvent{event1}, 2, false, nil, nil, []*model.ApiEvent{event1}, false, false},
		{"forward empty fetch", []*model.ApiEvent{}, 2, false, nil, nil, []*model.ApiEvent{}, false, false},
		{"forward with 'after'", []*model.ApiEvent{event3, event4, event5}, 2, false, strPtr("cursor2"), nil, []*model.ApiEvent{event3, event4}, true, true},
		{"forward with 'after' exact", []*model.ApiEvent{event3, event4}, 2, false, strPtr("cursor2"), nil, []*model.ApiEvent{event3, event4}, false, true},
		{"forward limit 0", []*model.ApiEvent{event1, event2}, 0, false, nil, nil, []*model.ApiEvent{}, true, false}, // hasNext is true because fetched > limit

		// Backward Pagination
		{"backward basic", []*model.ApiEvent{event5, event4, event3}, 2, true, nil, nil, []*model.ApiEvent{event4, event5}, false, true},                      // Fetched [5,4,3], limit=2 -> hasPrev=T, keep [5,4], reverse -> [4,5], hasNext=F
		{"backward exact limit", []*model.ApiEvent{event5, event4}, 2, true, nil, nil, []*model.ApiEvent{event4, event5}, false, false},                       // Fetched [5,4], limit=2 -> hasPrev=F, keep [5,4], reverse -> [4,5], hasNext=F
		{"backward less than limit", []*model.ApiEvent{event5}, 2, true, nil, nil, []*model.ApiEvent{event5}, false, false},                                   // Fetched [5], limit=2 -> hasPrev=F, keep [5], reverse -> [5], hasNext=F
		{"backward empty fetch", []*model.ApiEvent{}, 2, true, nil, nil, []*model.ApiEvent{}, false, false},                                                   // Fetched [], limit=2 -> hasPrev=F, keep [], reverse -> [], hasNext=F
		{"backward with 'before'", []*model.ApiEvent{event3, event2, event1}, 2, true, nil, strPtr("cursor4"), []*model.ApiEvent{event2, event3}, true, true}, // Fetched [3,2,1], limit=2 -> hasPrev=T, keep [3,2], reverse -> [2,3], hasNext=T (before!=nil)
		{"backward with 'before' exact", []*model.ApiEvent{event3, event2}, 2, true, nil, strPtr("cursor4"), []*model.ApiEvent{event2, event3}, true, false},  // Fetched [3,2], limit=2 -> hasPrev=F, keep [3,2], reverse -> [2,3], hasNext=T (before!=nil)
		{"backward limit 0", []*model.ApiEvent{event5, event4}, 0, true, nil, nil, []*model.ApiEvent{}, false, true},                                          // hasPrev is true because fetched > limit
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, hasNext, hasPrev := r.processPaginationResults(tt.fetchedEvents, tt.limit, tt.isBackward, tt.after, tt.before)

			// Check slice content equality (order matters)
			require.Equal(t, len(tt.expectedResults), len(results), "results length mismatch")
			for i := range tt.expectedResults {
				// Assuming BSONID comparison is sufficient for identity check
				assert.Equal(t, tt.expectedResults[i].BSONID, results[i].BSONID, "result mismatch at index %d", i)
			}
			assert.Equal(t, tt.expectedHasNext, hasNext, "hasNextPage mismatch")
			assert.Equal(t, tt.expectedHasPrevious, hasPrev, "hasPreviousPage mismatch")
		})
	}
}

//--- Unit Tests for buildContentFilters ---
//NOTE: This requires testing the underlying apply*Filter functions first or mocking them.
//Assuming apply*Filter functions work correctly for this example.

func TestBuildContentFilters(t *testing.T) {
	r := &queryResolver{
		&Resolver{
			Logger: zaptest.NewLogger(t).Sugar(),
		},
	}
	clusters := []int32{1, 2}
	strPtr := func(s string) *string { return &s }
	int32Ptr := func(i int32) *int32 { return &i }
	int64Ptr := func(i int64) *int64 { return &i }
	//boolPtr := func(b bool) *bool { return &b }
	//restType := model.APITypeRest
	highSeverity := model.SeverityHigh

	tests := []struct {
		name          string
		filters       *model.Filters
		expectedQuery bson.D
		expectedError bool
	}{
		{
			name:    "only mandatory clusters",
			filters: &model.Filters{ClusterIds: clusters},
			// **VERIFY BSON PATHS**
			expectedQuery: bson.D{
				{"cluster_id", bson.D{{"$in", clusters}}},
			},
			expectedError: false,
		},
		{
			name:          "missing mandatory clusters",
			filters:       &model.Filters{ClusterIds: []int32{}}, // Empty slice
			expectedQuery: nil,
			expectedError: true, // Expect error because clusterIds is required
		},
		{
			name: "with timestamp",
			filters: &model.Filters{
				ClusterIds:    clusters,
				FromTimestamp: int64Ptr(1712655600), // Example timestamp
				ToTimestamp:   int64Ptr(1712659200),
			},
			// **VERIFY BSON PATHS**
			expectedQuery: bson.D{
				{"cluster_id", bson.D{{"$in", clusters}}},
				{"metadata.timestamp", bson.D{{"$gte", int64(1712655600)}, {"$lte", int64(1712659200)}}},
			},
			expectedError: false,
		},
		{
			name: "with string eq filter",
			filters: &model.Filters{
				ClusterIds: clusters,
				Hostname:   &model.StringFilterInput{Eq: strPtr("example.com")},
			},
			// **VERIFY BSON PATHS**
			expectedQuery: bson.D{
				{"cluster_id", bson.D{{"$in", clusters}}},
				{"metadata.hostname", "example.com"}, // Simplified from {$eq: ...}
			},
			expectedError: false,
		},
		{
			name: "with string ne filter",
			filters: &model.Filters{
				ClusterIds: clusters,
				Hostname:   &model.StringFilterInput{Ne: strPtr("example.com")},
			},
			// **VERIFY BSON PATHS**
			expectedQuery: bson.D{
				{"cluster_id", bson.D{{"$in", clusters}}},
				{"metadata.hostname", bson.D{{"$ne", "example.com"}}},
			},
			expectedError: false,
		},
		{
			name: "with string regex filter",
			filters: &model.Filters{
				ClusterIds:  clusters,
				RequestPath: &model.StringFilterInput{Regex: strPtr("^/api/v1/")},
			},
			// **VERIFY BSON PATHS**
			expectedQuery: bson.D{
				{"cluster_id", bson.D{{"$in", clusters}}},
				{"http.request.path", bson.D{{"$regex", primitive.Regex{Pattern: "^/api/v1/", Options: ""}}}},
			},
			expectedError: false,
		},
		{
			name: "with sensitive data elemMatch",
			filters: &model.Filters{
				ClusterIds:             clusters,
				SensitiveDataRiskScore: &model.IntFilterInput{Gte: int32Ptr(50)},
				SensitiveDataSeverity:  &model.SeverityFilterInput{Eq: &highSeverity},
			},
			// **VERIFY BSON PATHS**
			expectedQuery: bson.D{
				{"cluster_id", bson.D{{"$in", clusters}}},
				{"api_event.sensitive_data", bson.D{
					{"$elemMatch", bson.D{
						{"riskScore", bson.D{{"$gte", int32(50)}}}, // Inner structure from helpers
						{"severity", "HIGH"},
					}},
				}},
			},
			expectedError: false,
		},
		{
			name: "with sensitive data single",
			filters: &model.Filters{
				ClusterIds:            clusters,
				SensitiveDataSeverity: &model.SeverityFilterInput{Eq: &highSeverity},
			},
			// **VERIFY BSON PATHS**
			expectedQuery: bson.D{
				{"cluster_id", bson.D{{"$in", clusters}}},
				{"api_event.sensitive_data.severity", "HIGH"}, // Simplified from {$eq: ...}
			},
			expectedError: false,
		},
		// Add more test cases for other filter types, combinations, invalid inputs, etc.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// You might need to mock underlying filter helpers if they are complex,
			// or test them separately and trust them here.
			query, err := r.buildContentFilters(tt.filters)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				// Comparing bson.D can be tricky due to order sometimes. DeepEqual might work,
				// or convert to map/string for comparison if needed, or compare element by element.
				assert.Equal(t, tt.expectedQuery, query)
				// require.Equal... might be better for BSON comparison if using testify extensively
			}
		})
	}
}

// --- Add Unit Tests for apply*Filter helpers ---
// Example for applyStringFilter
func TestApplyStringFilter(t *testing.T) {
	strPtr := func(s string) *string { return &s }
	targetField := "test.field"
	tests := []struct {
		name        string
		input       *model.StringFilterInput
		expected    bson.E // Expected element added to filters
		expectAdded bool   // Whether we expect the element to be added
	}{
		{"nil input", nil, bson.E{}, false},
		{"empty input", &model.StringFilterInput{}, bson.E{}, false},
		{"eq only", &model.StringFilterInput{Eq: strPtr("value")}, bson.E{Key: targetField, Value: "value"}, true},
		{"ne only", &model.StringFilterInput{Ne: strPtr("value")}, bson.E{Key: targetField, Value: bson.D{{"$ne", "value"}}}, true},
		{"regex only", &model.StringFilterInput{Regex: strPtr("pattern")}, bson.E{Key: targetField, Value: bson.D{{"$regex", primitive.Regex{Pattern: "pattern", Options: ""}}}}, true},
		{"iregex only", &model.StringFilterInput{Iregex: strPtr("ipattern")}, bson.E{Key: targetField, Value: bson.D{{"$regex", primitive.Regex{Pattern: "ipattern", Options: "i"}}}}, true},
		{"in only", &model.StringFilterInput{In: []string{"a", "b"}}, bson.E{Key: targetField, Value: bson.D{{"$in", []string{"a", "b"}}}}, true},
		{"nin only", &model.StringFilterInput{Nin: []string{"c", "d"}}, bson.E{Key: targetField, Value: bson.D{{"$nin", []string{"c", "d"}}}}, true},
		{"eq and ne", &model.StringFilterInput{Eq: strPtr("v1"), Ne: strPtr("v2")}, bson.E{Key: targetField, Value: bson.D{{"$eq", "v1"}, {"$ne", "v2"}}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filters := bson.D{}
			err := applyStringFilter(&filters, targetField, tt.input)
			assert.NoError(t, err)
			if tt.expectAdded {
				require.Len(t, filters, 1, "Expected one filter element to be added")
				assert.Equal(t, tt.expected, filters[0])
			} else {
				assert.Empty(t, filters, "Expected no filter elements to be added")
			}
		})
	}
}

//Add similar detailed unit tests for applyIntFilter, applyEnumFilter, applyBooleanFilter, applyStatusCodeFilter, etc.
