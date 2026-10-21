package provider

import (
	"context"
	"fmt"
	"strings"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pleme-io/terraform-provider-opadmin/internal/opclient"
	"github.com/pleme-io/terraform-provider-opadmin/internal/permissions"
)

type groupVaultAccessResource struct {
	api opclient.API
}

type grantModel struct {
	ID          types.String `tfsdk:"id"`
	VaultID     types.String `tfsdk:"vault_id"`
	GroupID     types.String `tfsdk:"group_id"`
	Permissions types.Set    `tfsdk:"permissions"`
}

var (
	_ resource.ResourceWithConfigure   = &groupVaultAccessResource{}
	_ resource.ResourceWithImportState = &groupVaultAccessResource{}
)

func (r *groupVaultAccessResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group_vault_access"
}

func (r *groupVaultAccessResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "One group's permissions on one vault the service account created. Authoritative for that pair only. Teams or Business accounts.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"vault_id": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"group_id": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"permissions": schema.SetAttribute{
				ElementType: types.StringType,
				Required:    true,
				Description: "Permission names. Empty grants access with no permissions. The kinko bidama validates dependency closure and the plan tier before render; the vendor refuses an unclosed set.",
			},
		},
	}
}

func (r *groupVaultAccessResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	api, ok := apiFrom(req.ProviderData)
	if !ok {
		resp.Diagnostics.AddError("provider data", fmt.Sprintf("unexpected %T", req.ProviderData))
		return
	}
	r.api = api
}

func (r *groupVaultAccessResource) bits(ctx context.Context, m grantModel) (uint32, bool, string) {
	var names []string
	if d := m.Permissions.ElementsAs(ctx, &names, false); d.HasError() {
		return 0, false, "permissions are not a list of strings"
	}
	bits, err := permissions.Encode(names)
	if err != nil {
		return 0, false, err.Error()
	}
	return bits, true, ""
}

func (r *groupVaultAccessResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan grantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	bits, ok, why := r.bits(ctx, plan)
	if !ok {
		resp.Diagnostics.AddAttributeError(path.Root("permissions"), "permissions", why)
		return
	}
	if err := r.api.GrantGroup(ctx, plan.VaultID.ValueString(), plan.GroupID.ValueString(), bits); err != nil {
		resp.Diagnostics.AddError("grant group", opclient.Explain("grant group", err))
		return
	}
	plan.ID = types.StringValue(plan.VaultID.ValueString() + "/" + plan.GroupID.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func findGroupAccess(v op.Vault, groupID string) (uint32, bool) {
	for _, a := range v.Access {
		if a.AccessorType == op.VaultAccessorTypeGroup && a.AccessorUuid == groupID {
			return a.Permissions, true
		}
	}
	return 0, false
}

func (r *groupVaultAccessResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state grantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	vaultID := state.VaultID.ValueString()
	v, err := r.api.GetVault(ctx, vaultID, true)
	if err != nil {
		presence, perr := opclient.VaultPresence(ctx, r.api, vaultID)
		if presence == opclient.Absent {
			resp.State.RemoveResource(ctx)
			return
		}
		if perr != nil {
			err = fmt.Errorf("%w; the absence probe also failed: %v", err, perr)
		}
		resp.Diagnostics.AddError("read group access", opclient.Explain("read vault access", err))
		return
	}
	bits, found := findGroupAccess(v, state.GroupID.ValueString())
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	names, err := permissions.Decode(bits)
	if err != nil {
		resp.Diagnostics.AddError("read group access", err.Error())
		return
	}
	set, d := types.SetValueFrom(ctx, types.StringType, names)
	resp.Diagnostics.Append(d...)
	state.Permissions = set
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *groupVaultAccessResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state grantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	bits, ok, why := r.bits(ctx, plan)
	if !ok {
		resp.Diagnostics.AddAttributeError(path.Root("permissions"), "permissions", why)
		return
	}
	if err := r.api.UpdateGroup(ctx, plan.VaultID.ValueString(), plan.GroupID.ValueString(), bits); err != nil {
		resp.Diagnostics.AddError("update group access", opclient.Explain("update group access", err))
		return
	}
	plan.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *groupVaultAccessResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state grantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.api.RevokeGroup(ctx, state.VaultID.ValueString(), state.GroupID.ValueString()); err != nil {
		resp.Diagnostics.AddError("revoke group", opclient.Explain("revoke group", err))
	}
}

func (r *groupVaultAccessResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(req.ID, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		resp.Diagnostics.AddError("import group access", fmt.Sprintf("want <vault_id>/<group_id>, got %q", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("vault_id"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("group_id"), parts[1])...)
}
