package opclient

import (
	"context"
	"errors"
	"fmt"

	op "github.com/1password/onepassword-sdk-go"
)

type API interface {
	CreateVault(ctx context.Context, p op.VaultCreateParams) (op.Vault, error)
	GetVault(ctx context.Context, id string, accessors bool) (op.Vault, error)
	ListVaults(ctx context.Context) ([]op.VaultOverview, error)
	UpdateVault(ctx context.Context, id string, p op.VaultUpdateParams) (op.Vault, error)
	DeleteVault(ctx context.Context, id string) error
	GrantGroup(ctx context.Context, vaultID, groupID string, bits uint32) error
	UpdateGroup(ctx context.Context, vaultID, groupID string, bits uint32) error
	RevokeGroup(ctx context.Context, vaultID, groupID string) error
	GetGroup(ctx context.Context, id string) (op.Group, error)
}

type SDK struct {
	c *op.Client
}

func New(ctx context.Context, token, version string) (*SDK, error) {
	c, err := op.NewClient(ctx,
		op.WithServiceAccountToken(token),
		op.WithIntegrationInfo("opadmin", version),
	)
	if err != nil {
		return nil, err
	}
	return &SDK{c: c}, nil
}

func (s *SDK) CreateVault(ctx context.Context, p op.VaultCreateParams) (op.Vault, error) {
	return s.c.Vaults().Create(ctx, p)
}

func (s *SDK) GetVault(ctx context.Context, id string, accessors bool) (op.Vault, error) {
	return s.c.Vaults().Get(ctx, id, op.VaultGetParams{Accessors: &accessors})
}

func (s *SDK) ListVaults(ctx context.Context) ([]op.VaultOverview, error) {
	decrypt := true
	return s.c.Vaults().List(ctx, op.VaultListParams{DecryptDetails: &decrypt})
}

func (s *SDK) UpdateVault(ctx context.Context, id string, p op.VaultUpdateParams) (op.Vault, error) {
	return s.c.Vaults().Update(ctx, id, p)
}

func (s *SDK) DeleteVault(ctx context.Context, id string) error {
	return s.c.Vaults().Delete(ctx, id)
}

func (s *SDK) GrantGroup(ctx context.Context, vaultID, groupID string, bits uint32) error {
	return s.c.Vaults().GrantGroupPermissions(ctx, vaultID, []op.GroupAccess{{GroupID: groupID, Permissions: bits}})
}

func (s *SDK) UpdateGroup(ctx context.Context, vaultID, groupID string, bits uint32) error {
	return s.c.Vaults().UpdateGroupPermissions(ctx, []op.GroupVaultAccess{{VaultID: vaultID, GroupID: groupID, Permissions: bits}})
}

func (s *SDK) RevokeGroup(ctx context.Context, vaultID, groupID string) error {
	return s.c.Vaults().RevokeGroupPermissions(ctx, vaultID, groupID)
}

func (s *SDK) GetGroup(ctx context.Context, id string) (op.Group, error) {
	withVaults := true
	return s.c.Groups().Get(ctx, id, op.GroupGetParams{VaultPermissions: &withVaults})
}

type Presence int

const (
	Present Presence = iota
	Absent
	Unknown
)

func VaultPresence(ctx context.Context, api API, id string) (Presence, error) {
	vaults, err := api.ListVaults(ctx)
	if err != nil {
		return Unknown, err
	}
	for _, v := range vaults {
		if v.ID == id {
			return Present, nil
		}
	}
	return Absent, nil
}

func Explain(op string, err error) string {
	var rl *opRateLimit
	if errors.As(err, &rl) {
		return fmt.Sprintf("%s: the account's daily service-account quota is spent; nothing was observed and nothing changed: %v", op, err)
	}
	return fmt.Sprintf("%s: %v", op, err)
}

type opRateLimit = op.RateLimitExceededError
