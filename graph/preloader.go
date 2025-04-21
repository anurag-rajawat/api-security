package graph

import (
	"context"

	"github.com/99designs/gqlgen/graphql"
)

func preloads(ctx context.Context) []string {
	return nestedPreloads(
		graphql.GetOperationContext(ctx),
		graphql.CollectFieldsCtx(ctx, nil),
		"",
	)
}
func nestedPreloads(ctx *graphql.OperationContext, fields []graphql.CollectedField, prefix string) (preloads []string) {
	for _, column := range fields {
		prefixColumn := preloadString(prefix, column.Name)
		preloads = append(preloads, prefixColumn)
		preloads = append(preloads, nestedPreloads(ctx, graphql.CollectFields(ctx, column.Selections, nil), prefixColumn)...)
	}
	return
}
func preloadString(prefix, name string) string {
	if len(prefix) > 0 {
		return prefix + "." + name
	}
	return name
}
