package provider

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"testing"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestMain(m *testing.M) {
	if os.Getenv("TF_ACC_TERRAFORM_PATH") == "" {
		if p, err := exec.LookPath("tofu"); err == nil {
			os.Setenv("TF_ACC_TERRAFORM_PATH", p)
			os.Setenv("TF_ACC_PROVIDER_HOST", "registry.opentofu.org")
			os.Setenv("TF_ACC_PROVIDER_NAMESPACE", "pleme-io")
		}
	}
	os.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "fake")
	os.Exit(m.Run())
}

const vaultCfg = `
resource "opadmin_vault" "a" {
  title       = %q
  description = "d"
}
`

func cfg(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

func TestVaultLifecycle(t *testing.T) {
	f := newFake()
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps: []resource.TestStep{
			{
				Config: cfg(vaultCfg, "one"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("opadmin_vault.a", "title", "one"),
					resource.TestCheckResourceAttr("opadmin_vault.a", "allow_admins_access", "true"),
					resource.TestCheckResourceAttr("opadmin_vault.a", "force_destroy", "false"),
				),
			},
			{
				Config: cfg(vaultCfg, "two"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("opadmin_vault.a", "title", "two"),
					func(*terraform.State) error {
						for _, c := range f.calls {
							if c == "delete" {
								t.Fatalf("a title change deleted the vault: %v", f.calls)
							}
						}
						return nil
					},
				),
			},
			{
				ResourceName:      "opadmin_vault.a",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAllowAdminsAccessChangeIsAPlanError(t *testing.T) {
	f := newFake()
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps: []resource.TestStep{
			{Config: `resource "opadmin_vault" "a" { title = "x" }`},
			{
				Config:      "resource \"opadmin_vault\" \"a\" {\n  title = \"x\"\n  allow_admins_access = false\n}\n",
				ExpectError: regexp.MustCompile(`fixed at creation`),
			},
		},
	})
}

func TestNonEmptyVaultRefusesDestroy(t *testing.T) {
	f := newFake()
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps: []resource.TestStep{
			{
				Config: `resource "opadmin_vault" "a" { title = "x" }`,
				Check: func(*terraform.State) error {
					for _, v := range f.vaults {
						v.ActiveItemCount = 3
					}
					return nil
				},
			},
			{
				Config:      `resource "opadmin_vault" "a" { title = "x" }`,
				Destroy:     true,
				ExpectError: regexp.MustCompile(`holds 3 items`),
			},
			{
				Config: "resource \"opadmin_vault\" \"a\" {\n  title = \"x\"\n  force_destroy = true\n}\n",
			},
		},
	})
}

func TestUnreachableAccountNeverEmptiesState(t *testing.T) {
	f := newFake()
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps: []resource.TestStep{
			{Config: `resource "opadmin_vault" "a" { title = "x" }`},
			{
				PreConfig:   func() { f.getFails, f.listFails = true, true },
				Config:      `resource "opadmin_vault" "a" { title = "x" }`,
				ExpectError: regexp.MustCompile(`absence probe also failed`),
			},
			{
				PreConfig: func() { f.getFails, f.listFails = false, false },
				Config:    `resource "opadmin_vault" "a" { title = "x" }`,
				PlanOnly:  true,
			},
		},
	})
}

func TestVaultGoneOutOfBandIsRecreated(t *testing.T) {
	f := newFake()
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps: []resource.TestStep{
			{
				Config: `resource "opadmin_vault" "a" { title = "x" }`,
				Check: func(*terraform.State) error {
					f.vaults = map[string]*op.Vault{}
					return nil
				},
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

const pinned = `
terraform {
  required_providers {
    opadmin = { source = "registry.opentofu.org/pleme-io/opadmin" }
  }
}
`

func TestImportOfAForeignVaultNamesTheOwnershipRule(t *testing.T) {
	f := newFake()
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps: []resource.TestStep{
			{Config: pinned + `resource "opadmin_vault" "a" { title = "x" }`},
			{
				Config:        pinned + `resource "opadmin_vault" "a" { title = "x" }`,
				ResourceName:  "opadmin_vault.a",
				ImportState:   true,
				ImportStateId: "someone-elses",
				ExpectError:   regexp.MustCompile(`only\s+vaults\s+it\s+created`),
			},
		},
	})
}

const grantCfg = `
resource "opadmin_vault" "a" { title = "x" }
resource "opadmin_group_vault_access" "g" {
  vault_id    = opadmin_vault.a.id
  group_id    = "grp"
  permissions = %s
}
`

func TestGroupVaultAccessLifecycle(t *testing.T) {
	f := newFake()
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps: []resource.TestStep{
			{
				Config: cfg(grantCfg, `["read_items"]`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("opadmin_group_vault_access.g", "permissions.#", "1"),
				),
			},
			{
				Config: cfg(grantCfg, `["read_items", "reveal_item_password", "update_items", "delete_items"]`),
				Check:  resource.TestCheckResourceAttr("opadmin_group_vault_access.g", "permissions.#", "4"),
			},
			{
				ResourceName:      "opadmin_group_vault_access.g",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config:      cfg(grantCfg, `["bogus"]`),
				ExpectError: regexp.MustCompile(`unknown permission "bogus"`),
			},
		},
	})
}
