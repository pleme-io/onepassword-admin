package permissions

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type Permission struct {
	Name     string
	Bit      uint32
	Requires []string
	Settable bool
}

//go:embed permissions.json
var raw []byte

type document struct {
	Permissions []struct {
		Name     string   `json:"name"`
		Bit      uint32   `json:"bit"`
		Requires []string `json:"requires"`
		Settable bool     `json:"settable"`
	} `json:"permissions"`
	TeamsBundles map[string][]string `json:"teams_bundles"`
}

var Table []Permission

var TeamsBundles map[string][]string

func init() {
	var d document
	if err := json.Unmarshal(raw, &d); err != nil {
		panic("permissions.json: " + err.Error())
	}
	for _, p := range d.Permissions {
		Table = append(Table, Permission{Name: p.Name, Bit: p.Bit, Requires: p.Requires, Settable: p.Settable})
	}
	TeamsBundles = d.TeamsBundles
	byName = make(map[string]Permission, len(Table))
	for _, p := range Table {
		byName[p.Name] = p
	}
}

var byName map[string]Permission

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
