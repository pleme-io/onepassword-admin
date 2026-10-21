package provider

import (
	"context"
	"fmt"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pleme-io/terraform-provider-opadmin/internal/opclient"
)

type vaultResource struct {
	api opclient.API
}

type vaultModel struct {
	ID                types.String `tfsdk:"id"`
	Title             types.String `tfsdk:"title"`
	Description       types.String `tfsdk:"description"`
	AllowAdminsAccess types.Bool   `tfsdk:"allow_admins_access"`
	ForceDestroy      types.Bool   `tfsdk:"force_destroy"`
}

var (
	_ resource.ResourceWithConfigure   = &vaultResource{}
	_ resource.ResourceWithImportState = &vaultResource{}
	_ resource.ResourceWithModifyPlan  = &vaultResource{}
)

func (r *vaultResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_vault"
}

func (r *vaultResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A vault the service account created. No attribute forces a replace: a replace would destroy the vault's items.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"title": schema.StringAttribute{Required: true},
			"description": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(""),
			},
			"allow_admins_access": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Set at creation only. The SDK cannot read it back or change it, so a change is a plan error.",
			},
			"force_destroy": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Destroy refuses a vault that still holds items unless this is true.",
			},
		},
	}
}

func (r *vaultResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	api, ok := apiFrom(req.ProviderData)
	if !ok {
		resp.Diagnostics.AddError("provider data", fmt.Sprintf("unexpected %T", req.ProviderData))
		return
	}
	r.api = api
}

func (r *vaultResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var state, plan vaultModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.AllowAdminsAccess.IsUnknown() && plan.AllowAdminsAccess.ValueBool() != state.AllowAdminsAccess.ValueBool() {
		resp.Diagnostics.AddAttributeError(path.Root("allow_admins_access"), "immutable",
			"allow_admins_access is fixed at creation; the SDK has no update for it, and a replace would destroy the vault's items")
	}
}

func (r *vaultResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan vaultModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	desc := plan.Description.ValueString()
	admins := plan.AllowAdminsAccess.ValueBool()
	v, err := r.api.CreateVault(ctx, op.VaultCreateParams{
		Title:             plan.Title.ValueString(),
		Description:       &desc,
		AllowAdminsAccess: &admins,
	})
	if err != nil {
		resp.Diagnostics.AddError("create vault", opclient.Explain("create vault", err))
		return
	}
	plan.ID = types.StringValue(v.ID)
	plan.Title = types.StringValue(v.Title)
	plan.Description = types.StringValue(v.Description)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *vaultResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state vaultModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	v, err := r.api.GetVault(ctx, state.ID.ValueString(), false)
	if err != nil {
		presence, perr := opclient.VaultPresence(ctx, r.api, state.ID.ValueString())
		if presence == opclient.Absent {
			resp.State.RemoveResource(ctx)
			return
		}
		if perr != nil {
			err = fmt.Errorf("%w; the absence probe also failed: %v", err, perr)
		}
		resp.Diagnostics.AddError("read vault", opclient.Explain("read vault", err))
		return
	}
	state.Title = types.StringValue(v.Title)
	state.Description = types.StringValue(v.Description)
	if state.AllowAdminsAccess.IsNull() {
		state.AllowAdminsAccess = types.BoolValue(true)
	}
	if state.ForceDestroy.IsNull() {
		state.ForceDestroy = types.BoolValue(false)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *vaultResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state vaultModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	title := plan.Title.ValueString()
	desc := plan.Description.ValueString()
	v, err := r.api.UpdateVault(ctx, state.ID.ValueString(), op.VaultUpdateParams{Title: &title, Description: &desc})
	if err != nil {
		resp.Diagnostics.AddError("update vault", opclient.Explain("update vault", err))
		return
	}
	plan.ID = state.ID
	plan.Title = types.StringValue(v.Title)
	plan.Description = types.StringValue(v.Description)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *vaultResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state vaultModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	if !state.ForceDestroy.ValueBool() {
		v, err := r.api.GetVault(ctx, id, false)
		if err != nil {
			if presence, _ := opclient.VaultPresence(ctx, r.api, id); presence == opclient.Absent {
				return
			}
			resp.Diagnostics.AddError("delete vault", opclient.Explain("checking the vault is empty", err))
			return
		}
		if v.ActiveItemCount > 0 {
			resp.Diagnostics.AddError("delete vault",
				fmt.Sprintf("vault %q holds %d items; set force_destroy = true to destroy them with it", v.Title, v.ActiveItemCount))
			return
		}
	}
	if err := r.api.DeleteVault(ctx, id); err != nil {
		resp.Diagnostics.AddError("delete vault", opclient.Explain("delete vault", err))
	}
}

func (r *vaultResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if _, err := r.api.GetVault(ctx, req.ID, false); err != nil {
		resp.Diagnostics.AddError("import vault",
			fmt.Sprintf("the service account cannot read vault %q. It can manage only vaults it created; import one of those, or read this vault with the opadmin_vaults data source. %s",
				req.ID, opclient.Explain("get vault", err)))
		return
	}
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
