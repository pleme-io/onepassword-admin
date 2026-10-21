package permissions

import (
	"fmt"
	"sort"
	"strings"

	op "github.com/1password/onepassword-sdk-go"
)

type Permission struct {
	Name     string
	Bit      uint32
	Requires []string
	Settable bool
}

var Table = []Permission{
	{Name: "read_items", Bit: op.ReadItems, Settable: true},
	{Name: "create_items", Bit: op.CreateItems, Requires: []string{"read_items"}, Settable: true},
	{Name: "reveal_item_password", Bit: op.RevealItemPassword, Requires: []string{"read_items"}, Settable: true},
	{Name: "update_items", Bit: op.UpdateItems, Requires: []string{"read_items", "reveal_item_password"}, Settable: true},
	{Name: "archive_items", Bit: op.ArchiveItems, Requires: []string{"read_items", "reveal_item_password", "update_items"}, Settable: true},
	{Name: "delete_items", Bit: op.DeleteItems, Requires: []string{"read_items", "reveal_item_password", "update_items"}, Settable: true},
	{Name: "update_item_history", Bit: op.UpdateItemHistory, Requires: []string{"read_items", "reveal_item_password"}, Settable: true},
	{Name: "import_items", Bit: op.ImportItems, Requires: []string{"read_items", "create_items"}, Settable: true},
	{Name: "export_items", Bit: op.ExportItems, Requires: []string{"read_items", "reveal_item_password", "update_item_history"}, Settable: true},
	{Name: "send_items", Bit: op.SendItems, Requires: []string{"read_items", "reveal_item_password", "update_item_history"}, Settable: true},
	{Name: "print_items", Bit: op.PrintItems, Requires: []string{"read_items", "reveal_item_password", "update_item_history"}, Settable: true},
	{Name: "manage_vault", Bit: op.ManageVault, Settable: true},
	{Name: "recover_vault", Bit: op.RecoverVault},
}

var TeamsBundles = map[string][]string{
	"view":   {"read_items", "reveal_item_password", "update_item_history"},
	"edit":   {"create_items", "update_items", "archive_items", "delete_items", "import_items", "export_items", "send_items", "print_items"},
	"manage": {"manage_vault"},
}

var byName = func() map[string]Permission {
	m := make(map[string]Permission, len(Table))
	for _, p := range Table {
		m[p.Name] = p
	}
	return m
}()

func SettableNames() []string {
	var out []string
	for _, p := range Table {
		if p.Settable {
			out = append(out, p.Name)
		}
	}
	return out
}

func Encode(names []string) (uint32, error) {
	var bits uint32
	for _, n := range names {
		p, ok := byName[n]
		if !ok {
			return 0, fmt.Errorf("unknown permission %q; legal: %s", n, strings.Join(SettableNames(), ", "))
		}
		bits |= p.Bit
	}
	return bits, nil
}

func Decode(bits uint32) ([]string, error) {
	var names []string
	rest := bits
	for _, p := range Table {
		if bits&p.Bit != 0 {
			names = append(names, p.Name)
			rest &^= p.Bit
		}
	}
	if rest != 0 {
		return nil, fmt.Errorf("permission bits %#x are not in the SDK v0.4.1 table; the vendor added a permission this provider does not model", rest)
	}
	sort.Strings(names)
	return names, nil
}

func Validate(names []string) []string {
	have := make(map[string]bool, len(names))
	for _, n := range names {
		have[n] = true
	}
	var problems []string
	for _, n := range sortedKeys(have) {
		p, ok := byName[n]
		if !ok {
			problems = append(problems, fmt.Sprintf("%q is not a permission; legal: %s", n, strings.Join(SettableNames(), ", ")))
			continue
		}
		if !p.Settable {
			problems = append(problems, fmt.Sprintf("%q belongs to the built-in recovery group and cannot be declared", n))
			continue
		}
		var missing []string
		for _, r := range p.Requires {
			if !have[r] {
				missing = append(missing, r)
			}
		}
		if len(missing) > 0 {
			problems = append(problems, fmt.Sprintf("%q requires %s", n, strings.Join(missing, ", ")))
		}
	}
	return problems
}

func ValidateTeams(names []string) []string {
	have := make(map[string]bool, len(names))
	for _, n := range names {
		have[n] = true
	}
	covered := make(map[string]bool)
	var problems []string
	for _, bundle := range []string{"view", "edit", "manage"} {
		members := TeamsBundles[bundle]
		var in, out []string
		for _, m := range members {
			if have[m] {
				in = append(in, m)
			} else {
				out = append(out, m)
			}
			covered[m] = true
		}
		if len(in) > 0 && len(out) > 0 {
			problems = append(problems, fmt.Sprintf("a Teams account grants the %q bundle whole: add %s or remove %s", bundle, strings.Join(out, ", "), strings.Join(in, ", ")))
		}
	}
	for _, n := range sortedKeys(have) {
		if !covered[n] {
			problems = append(problems, fmt.Sprintf("%q is not part of any Teams bundle", n))
		}
	}
	if have[TeamsBundles["edit"][0]] && !have["read_items"] {
		problems = append(problems, `the "edit" bundle requires the "view" bundle`)
	}
	return problems
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
