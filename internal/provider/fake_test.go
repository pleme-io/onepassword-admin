package provider

import (
	"context"
	"errors"
	"sync"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"

	"github.com/pleme-io/terraform-provider-opadmin/internal/opclient"
)

type fake struct {
	mu        sync.Mutex
	next      int
	vaults    map[string]*op.Vault
	foreign   map[string]bool
	groups    map[string]op.Group
	getFails  bool
	listFails bool
	calls     []string
}

func newFake() *fake {
	return &fake{vaults: map[string]*op.Vault{}, foreign: map[string]bool{}, groups: map[string]op.Group{}}
}

var errUnreachable = errors.New("dial tcp: connection refused")

func (f *fake) record(c string) {
	f.calls = append(f.calls, c)
}

func (f *fake) CreateVault(_ context.Context, p op.VaultCreateParams) (op.Vault, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("create")
	f.next++
	id := "v" + string(rune('0'+f.next))
	desc := ""
	if p.Description != nil {
		desc = *p.Description
	}
	v := &op.Vault{ID: id, Title: p.Title, Description: desc, VaultType: op.VaultTypeUserCreated}
	f.vaults[id] = v
	return *v, nil
}

func (f *fake) GetVault(_ context.Context, id string, _ bool) (op.Vault, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("get")
	if f.getFails {
		return op.Vault{}, errUnreachable
	}
	v, ok := f.vaults[id]
	if !ok || f.foreign[id] {
		return op.Vault{}, errors.New("vault not found")
	}
	return *v, nil
}

func (f *fake) ListVaults(_ context.Context) ([]op.VaultOverview, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("list")
	if f.listFails {
		return nil, errUnreachable
	}
	var out []op.VaultOverview
	for _, v := range f.vaults {
		if f.foreign[v.ID] {
			continue
		}
		out = append(out, op.VaultOverview{ID: v.ID, Title: v.Title, Description: v.Description, VaultType: v.VaultType, ActiveItemCount: v.ActiveItemCount})
	}
	return out, nil
}

func (f *fake) UpdateVault(_ context.Context, id string, p op.VaultUpdateParams) (op.Vault, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("update")
	v, ok := f.vaults[id]
	if !ok {
		return op.Vault{}, errors.New("vault not found")
	}
	if p.Title != nil {
		v.Title = *p.Title
	}
	if p.Description != nil {
		v.Description = *p.Description
	}
	return *v, nil
}

func (f *fake) DeleteVault(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("delete")
	delete(f.vaults, id)
	return nil
}

func (f *fake) setAccess(vaultID, groupID string, bits uint32, keep bool) error {
	v, ok := f.vaults[vaultID]
	if !ok {
		return errors.New("vault not found")
	}
	var access []op.VaultAccess
	for _, a := range v.Access {
		if a.AccessorUuid != groupID {
			access = append(access, a)
		}
	}
	if keep {
		access = append(access, op.VaultAccess{VaultUuid: vaultID, AccessorType: op.VaultAccessorTypeGroup, AccessorUuid: groupID, Permissions: bits})
	}
	v.Access = access
	return nil
}

func (f *fake) GrantGroup(_ context.Context, vaultID, groupID string, bits uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("grant")
	return f.setAccess(vaultID, groupID, bits, true)
}

func (f *fake) UpdateGroup(_ context.Context, vaultID, groupID string, bits uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("update-group")
	return f.setAccess(vaultID, groupID, bits, true)
}

func (f *fake) RevokeGroup(_ context.Context, vaultID, groupID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("revoke")
	return f.setAccess(vaultID, groupID, 0, false)
}

func (f *fake) GetGroup(_ context.Context, id string) (op.Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g, ok := f.groups[id]
	if !ok {
		return op.Group{}, errors.New("group not found")
	}
	return g, nil
}

func (f *fake) factories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"opadmin": providerserver.NewProtocol6WithError(&Provider{
			Version: "test",
			Connect: func(context.Context, string, string) (opclient.API, error) { return f, nil },
		}),
	}
}
