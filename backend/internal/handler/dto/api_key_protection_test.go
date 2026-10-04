package dto

import (
	"encoding/json"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAPIKeyDTOCannotExposeBearerInUserOrUsageLists(t *testing.T) {
	raw := "synthetic-downstream-key-for-dto-protection"
	key := &service.APIKey{ID: 123, Key: raw, Name: "test"}
	data, err := json.Marshal(APIKeyFromService(key))
	require.NoError(t, err)
	require.NotContains(t, string(data), raw)
	require.Contains(t, string(data), "********")
	require.Equal(t, raw, key.Key)
}
