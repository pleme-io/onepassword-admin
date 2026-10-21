package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pleme-io/terraform-provider-opadmin/internal/opclient"
)

const TokenEnv = "OP_SERVICE_ACCOUNT_TOKEN"

type Provider struct {
	Version string
	Connect func(ctx context.Context, token, version string) (opclient.API, error)
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &Provider{
			Version: version,
			Connect: func(ctx context.Context, token, version string) (opclient.API, error) {
				return opclient.New(ctx, token, version)
			},
		}
	}
}

type config struct {
	Token types.String `tfsdk:"service_account_token"`
}

func (p *Provider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "opadmin"
	resp.Version = p.Version
}

func (p *Provider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "1Password vaults and group vault access through the vendor Go SDK. Items stay with the 1Password/onepassword provider.",
		Attributes: map[string]schema.Attribute{
			"service_account_token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Service account token. Defaults to $" + TokenEnv + ". The account manages only vaults it created.",
			},
		},
	}
}

func (p *Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg config
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	token := cfg.Token.ValueString()
	if token == "" {
		token = os.Getenv(TokenEnv)
	}
	if token == "" {
		resp.Diagnostics.AddError("no service account token", "set service_account_token or $"+TokenEnv)
		return
	}
	api, err := p.Connect(ctx, token, p.Version)
	if err != nil {
		resp.Diagnostics.AddError("1Password SDK client", err.Error())
		return
	}
	resp.ResourceData = api
	resp.DataSourceData = api
}

func (p *Provider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		func() resource.Resource { return &vaultResource{} },
		func() resource.Resource { return &groupVaultAccessResource{} },
	}
}

func (p *Provider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		func() datasource.DataSource { return &vaultsDataSource{} },
		func() datasource.DataSource { return &groupDataSource{} },
	}
}

func apiFrom(data any) (opclient.API, bool) {
	if data == nil {
		return nil, true
	}
	api, ok := data.(opclient.API)
	return api, ok
}
