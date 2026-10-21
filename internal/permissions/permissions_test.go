package permissions

import (
	"reflect"
	"strings"
	"testing"
)

func TestTableCoversEverySDKBit(t *testing.T) {
	var all uint32
	for _, p := range Table {
		if all&p.Bit != 0 {
			t.Fatalf("%s reuses a bit", p.Name)
		}
		all |= p.Bit
	}
	names, err := Decode(all)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != len(Table) {
		t.Fatalf("decoded %d of %d", len(names), len(Table))
	}
}

func TestRequiresNameRealPermissions(t *testing.T) {
	for _, p := range Table {
		for _, r := range p.Requires {
			if _, ok := byName[r]; !ok {
				t.Fatalf("%s requires unknown %s", p.Name, r)
			}
		}
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := []string{"read_items", "reveal_item_password", "update_items", "delete_items"}
	bits, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(bits)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"delete_items", "read_items", "reveal_item_password", "update_items"}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("got %v want %v", out, want)
	}
}

func TestDecodeRefusesUnknownBits(t *testing.T) {
	if _, err := Decode(1 << 30); err == nil {
		t.Fatal("an unknown bit decoded silently")
	}
}

func TestValidateClosure(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{nil, nil},
		{[]string{"read_items"}, nil},
		{[]string{"manage_vault"}, nil},
		{[]string{"delete_items"}, []string{`"delete_items" requires read_items, reveal_item_password, update_items`}},
		{[]string{"read_items", "reveal_item_password", "update_items", "delete_items"}, nil},
		{[]string{"recover_vault"}, []string{`"recover_vault" belongs to the built-in recovery group`}},
		{[]string{"bogus"}, []string{`"bogus" is not a permission`}},
	}
	for _, c := range cases {
		got := Validate(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("%v: got %v want %v", c.in, got, c.want)
		}
		for i := range got {
			if !strings.HasPrefix(got[i], c.want[i]) {
				t.Fatalf("%v: got %q want prefix %q", c.in, got[i], c.want[i])
			}
		}
	}
}

func TestEverySettableAloneWithItsRequiresIsClosed(t *testing.T) {
	for _, p := range Table {
		if !p.Settable {
			continue
		}
		set := append([]string{p.Name}, p.Requires...)
		if got := Validate(set); len(got) != 0 {
			t.Fatalf("%s with its direct requires is not closed: %v", p.Name, got)
		}
	}
}

func TestValidateTeams(t *testing.T) {
	view := TeamsBundles["view"]
	edit := append(append([]string{}, view...), TeamsBundles["edit"]...)
	if got := ValidateTeams(view); len(got) != 0 {
		t.Fatalf("view bundle refused: %v", got)
	}
	if got := ValidateTeams(edit); len(got) != 0 {
		t.Fatalf("view+edit refused: %v", got)
	}
	if got := ValidateTeams([]string{"read_items"}); len(got) == 0 {
		t.Fatal("partial view bundle accepted")
	}
	if got := ValidateTeams(TeamsBundles["edit"]); len(got) == 0 {
		t.Fatal("edit without view accepted")
	}
	if got := ValidateTeams([]string{"recover_vault"}); len(got) == 0 {
		t.Fatal("recover_vault accepted on Teams")
	}
}

func TestTeamsBundlesSatisfyClosure(t *testing.T) {
	all := append(append(append([]string{}, TeamsBundles["view"]...), TeamsBundles["edit"]...), TeamsBundles["manage"]...)
	if got := Validate(all); len(got) != 0 {
		t.Fatalf("full Teams grant fails closure: %v", got)
	}
	viewEdit := append(append([]string{}, TeamsBundles["view"]...), TeamsBundles["edit"]...)
	if got := Validate(viewEdit); len(got) != 0 {
		t.Fatalf("view+edit fails closure: %v", got)
	}
}
