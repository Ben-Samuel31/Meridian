package main

import "testing"

func TestMatchesShape(t *testing.T) {
	data := map[string]any{"user": map[string]any{"id":"u_1","active":true}, "count": float64(3)}
	if !matchesShape(data, map[string]any{"user":map[string]any{"id":"string","active":"boolean"},"count":"number"}) { t.Fatal("expected matching shape") }
	if matchesShape(data, map[string]any{"missing":"string"}) { t.Fatal("missing field must fail") }
}

func TestAssertions(t *testing.T) {
	data := map[string]any{"user":map[string]any{"id":"u_1","score":float64(9)}}
	for _, tc := range []struct{ a Assertion; want bool }{
		{Assertion{"user.id","non_empty",nil},true}, {Assertion{"user.none","exists",nil},false},
		{Assertion{"user.id","equals","u_1"},true}, {Assertion{"user.score","greater_than",5},true},
	} { v,ok:=jsonPath(data,tc.a.Field); if got:=assertionOK(v,ok,tc.a); got!=tc.want { t.Fatalf("%+v: got %v",tc.a,got) } }
}
