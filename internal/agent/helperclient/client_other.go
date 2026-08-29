//go:build !linux

package helperclient

import (
	"context"
	"fmt"

	"github.com/NurRobin/NurProxy/internal/shared/helperprotocol"
)

type Client struct{}

func New(string, string, Pin) (*Client, error) {
	return nil, fmt.Errorf("root helper client is supported only on Linux")
}

func (c *Client) Hello(context.Context) (helperprotocol.HelperHello, error) {
	return helperprotocol.HelperHello{}, fmt.Errorf("root helper client is supported only on Linux")
}

func (c *Client) Plan(context.Context, helperprotocol.Action, helperprotocol.LogicalTarget, string) (helperprotocol.Signed[helperprotocol.HelperPlan], error) {
	return helperprotocol.Signed[helperprotocol.HelperPlan]{}, fmt.Errorf("root helper client is supported only on Linux")
}
