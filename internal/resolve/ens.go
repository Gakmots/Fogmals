package resolve

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"dwebproxy/internal/content"
	"dwebproxy/internal/records"
	ens "github.com/ensdomains/go-ens/v4"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

type ENS struct {
	client *ethclient.Client
	ccip   *http.Client
}

func NewENS(endpoint string, client, ccip *http.Client, order []records.Type) (*ENS, error) {
	definitions, err := records.ForENS(order)
	if err != nil {
		return nil, err
	}
	if endpoint == "" || len(definitions) == 0 {
		return nil, nil
	}
	rpcClient, err := rpc.DialOptions(context.Background(), endpoint, rpc.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	return &ENS{ethclient.NewClient(rpcClient), ccip}, nil
}

func (r *ENS) Close() {
	if r != nil {
		r.client.Close()
	}
}

func (r *ENS) Resolve(ctx context.Context, name string) (content.Target, error) {
	if r == nil {
		return content.Target{}, ErrUnavailable
	}
	u, err := ens.NewUniversalResolver(ctx, r.client, ens.WithHTTPClient(r.ccip), ens.WithMaxHops(4))
	if err != nil {
		return content.Target{}, fmt.Errorf("ENS Universal Resolver: %w", err)
	}
	raw, err := u.Contenthash(ctx, name)
	if errors.Is(err, ens.ErrUnregistered) {
		return content.Target{}, ErrNotFound
	}
	if err != nil {
		return content.Target{}, fmt.Errorf("ENS contenthash: %w", err)
	}
	if len(raw) == 0 {
		return content.Target{}, ErrNotFound
	}
	return content.DecodeHash(raw)
}
