package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pleme-io/terraform-provider-opadmin/internal/opclient"
	"github.com/pleme-io/terraform-provider-opadmin/internal/permissions"
)

type vaultsDataSource struct {
	api opclient.API
}

type vaultSummary struct {
	ID              types.String `tfsdk:"id"`
	Title           types.String `tfsdk:"title"`
	Description     types.String `tfsdk:"description"`
	VaultType       types.String `tfsdk:"vault_type"`
	ActiveItemCount types.Int64  `tfsdk:"active_item_count"`
}

type vaultsModel struct {
	Vaults []vaultSummary `tfsdk:"vaults"`
}

func (d *vaultsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_vaults"
}

func (d *vaultsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Every vault the service account can see.",
		Attributes: map[string]schema.Attribute{
			"vaults": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":                schema.StringAttribute{Computed: true},
						"title":             schema.StringAttribute{Computed: true},
						"description":       schema.StringAttribute{Computed: true},
						"vault_type":        schema.StringAttribute{Computed: true},
						"active_item_count": schema.Int64Attribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *vaultsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	api, ok := apiFrom(req.ProviderData)
	if !ok {
		resp.Diagnostics.AddError("provider data", fmt.Sprintf("unexpected %T", req.ProviderData))
		return
	}
	d.api = api
}

func (d *vaultsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	vaults, err := d.api.ListVaults(ctx)
	if err != nil {
		resp.Diagnostics.AddError("list vaults", opclient.Explain("list vaults", err))
		return
	}
	m := vaultsModel{Vaults: make([]vaultSummary, 0, len(vaults))}
	for _, v := range vaults {
		m.Vaults = append(m.Vaults, vaultSummary{
			ID:              types.StringValue(v.ID),
			Title:           types.StringValue(v.Title),
			Description:     types.StringValue(v.Description),
			VaultType:       types.StringValue(string(v.VaultType)),
			ActiveItemCount: types.Int64Value(int64(v.ActiveItemCount)),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

type groupDataSource struct {
	api opclient.API
}

type groupVaultAccess struct {
	VaultID     types.String `tfsdk:"vault_id"`
	Permissions types.Set    `tfsdk:"permissions"`
}

type groupModel struct {
	ID          types.String       `tfsdk:"id"`
	Title       types.String       `tfsdk:"title"`
	Description types.String       `tfsdk:"description"`
	GroupType   types.String       `tfsdk:"group_type"`
	State       types.String       `tfsdk:"state"`
	VaultAccess []groupVaultAccess `tfsdk:"vault_access"`
}

func (d *groupDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

func (d *groupDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A group and its vault permissions. Groups have no write API a service account can use.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Required: true},
			"title":       schema.StringAttribute{Computed: true},
			"description": schema.StringAttribute{Computed: true},
			"group_type":  schema.StringAttribute{Computed: true},
			"state":       schema.StringAttribute{Computed: true},
			"vault_access": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"vault_id":    schema.StringAttribute{Computed: true},
						"permissions": schema.SetAttribute{Computed: true, ElementType: types.StringType},
					},
				},
			},
		},
	}
}

func (d *groupDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	api, ok := apiFrom(req.ProviderData)
	if !ok {
		resp.Diagnostics.AddError("provider data", fmt.Sprintf("unexpected %T", req.ProviderData))
		return
	}
	d.api = api
}

func (d *groupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m groupModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	g, err := d.api.GetGroup(ctx, m.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("get group", opclient.Explain("get group", err))
		return
	}
	m.Title = types.StringValue(g.Title)
	m.Description = types.StringValue(g.Description)
	m.GroupType = types.StringValue(string(g.GroupType))
	m.State = types.StringValue(string(g.State))
	m.VaultAccess = make([]groupVaultAccess, 0, len(g.VaultAccess))
	for _, a := range g.VaultAccess {
		names, err := permissions.Decode(a.Permissions)
		if err != nil {
			resp.Diagnostics.AddError("get group", err.Error())
			return
		}
		set, diags := types.SetValueFrom(ctx, types.StringType, names)
		resp.Diagnostics.Append(diags...)
		m.VaultAccess = append(m.VaultAccess, groupVaultAccess{VaultID: types.StringValue(a.VaultUuid), Permissions: set})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}
