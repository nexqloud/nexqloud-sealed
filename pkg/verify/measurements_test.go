package verify

import "testing"

func TestParseInitrdRelease(t *testing.T) {
	raw := []byte(`{
	  "schema": "nexqloud-sealed-initrd-release/1",
	  "environment": "staging",
	  "git_sha": "abc",
	  "measurement": "E21564CB0DDFCEAC2F8738251F2D4ED9232A63C396C21E190E5F5D03A965C2CE089173C5522B2462B92D843AE7F645E1"
	}`)
	rel, err := ParseInitrdRelease(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rel.Measurement[0] != 'e' {
		t.Fatalf("expected lowercase hex, got %q", rel.Measurement[:4])
	}
	if len(rel.Measurement) != 96 {
		t.Fatalf("len=%d", len(rel.Measurement))
	}
}

func TestEffectiveMeasurements(t *testing.T) {
	pub := []string{"aa", "bb", "aa"}
	got := EffectiveMeasurements(pub)
	if len(got) != 2 || got[0] != "aa" || got[1] != "bb" {
		t.Fatalf("expected deduped published list, got %#v", got)
	}
	if len(EffectiveMeasurements(nil)) != 0 {
		t.Fatal("empty published should yield empty catalog")
	}
}

func TestInitrdReleaseURL(t *testing.T) {
	u := InitrdReleaseURL(DefaultR2PublicBase, "staging")
	want := DefaultR2PublicBase + "/staging/sealed-initrd/latest/release.json"
	if u != want {
		t.Fatalf("got %s want %s", u, want)
	}
}
