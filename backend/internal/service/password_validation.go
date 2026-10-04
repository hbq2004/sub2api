package service

import infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"

var ErrPasswordTooLong = infraerrors.BadRequest("PASSWORD_TOO_LONG", "password must not exceed 72 UTF-8 bytes")

func validatePasswordLength(password string) error {
	if len(password) > 72 {
		return ErrPasswordTooLong
	}
	return nil
}
