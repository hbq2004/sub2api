package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestRedeemGenerationShowsCodeOnceAndListMasksIt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	stub := newStubAdminService()
	stub.redeems = []service.RedeemCode{{ID: 42, Code: "ABCD1234EFGH5678", Type: service.RedeemTypeBalance, Value: 10, Status: service.StatusUnused}}
	handler := NewRedeemHandler(stub, nil)
	router := gin.New()
	router.POST("/api/v1/admin/redeem-codes/generate", handler.Generate)
	router.GET("/api/v1/admin/redeem-codes", handler.List)

	generated := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/redeem-codes/generate", strings.NewReader(`{"count":1,"type":"balance","value":10}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(generated, request)
	require.Equal(t, http.StatusOK, generated.Code)
	require.Equal(t, "private, no-store", generated.Header().Get("Cache-Control"))
	require.Contains(t, generated.Body.String(), "ABCD1234EFGH5678")

	listed := httptest.NewRecorder()
	router.ServeHTTP(listed, httptest.NewRequest(http.MethodGet, "/api/v1/admin/redeem-codes", nil))
	require.Equal(t, http.StatusOK, listed.Code)
	require.Contains(t, listed.Body.String(), "ABCD...5678")
	require.NotContains(t, listed.Body.String(), "ABCD1234EFGH5678")
}
