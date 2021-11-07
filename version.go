package filecoin

import (
	"context"
	"github.com/cyvadra/filecoin-client/types"
)

// Version Get Lotus Node version
func (c *Client) Version(ctx context.Context) (*types.Version, error) {
	var version *types.Version
	return version, c.Request(ctx, c.FilecoinMethod("Version"), &version)
}
