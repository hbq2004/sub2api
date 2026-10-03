package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type stepUpReadRepo struct {
	SettingRepository
	value string
	err error
}

func (r *stepUpReadRepo) GetValue(context.Context, string) (string, error) {
	return r.value, r.err
}

func TestStepUpSettingReadFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		value string
		err error
		enabled bool
		wantError bool
	}{
		{"enabled", "true", nil, true, false},
		{"explicitly-disabled", "false", nil, false, false},
		{"missing", "", ErrSettingNotFound, false, true},
		{"storage-failure", "", errors.New("synthetic storage failure"), false, true},
		{"empty", "", nil, false, true},
		{"invalid", "off", nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &SettingService{settingRepo: &stepUpReadRepo{value:tc.value,err:tc.err}}
			enabled, err := svc.IsStepUpEnabledStrict(context.Background())
			require.Equal(t, tc.enabled, enabled)
			require.Equal(t, tc.wantError, err != nil)
		})
	}
}
