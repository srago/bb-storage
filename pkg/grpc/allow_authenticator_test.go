package authenticator_test

import (
	"context"
	"testing"

	"github.com/buildbarn/bb-storage/pkg/authenticator"
	"github.com/stretchr/testify/require"
)

func TestAllowAuthenticator(t *testing.T) {
	newCtx, err := authenticator.AllowAuthenticator.Authenticate(context.Background())
	require.NoError(t, err)
	require.Equal(t, context.Background(), newCtx)
}
