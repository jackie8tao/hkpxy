package cfg

import "testing"

func TestParse(t *testing.T) {
	c, err := Parse("config.json")
	if err != nil {
		t.Error(err)
	}
	if c.Password != "foobar" {
		t.Fail()
	}
	t.Logf("%v", c)
}
