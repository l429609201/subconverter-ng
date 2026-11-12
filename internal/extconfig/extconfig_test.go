package extconfig

import "testing"

const sample = `[custom]
; a comment
# another comment
ruleset=🎯 全球直连,[]GEOIP,CN
ruleset=🐟 漏网之鱼,[]FINAL
ruleset=🚀 节点选择,https://example.com/PROXY.list
ruleset=bad-no-comma
custom_proxy_group=🚀 节点选择` + "`select`" + `[]♻️ 自动选择` + "`" + `[]DIRECT
custom_proxy_group=♻️ 自动选择` + "`url-test`" + `.*` + "`" + `http://www.gstatic.com/generate_204` + "`" + `300,5,50
custom_proxy_group=too-few-fields
exclude_remarks=(到期|过期)
exclude_remarks=[invalid(regex
include_remarks=(HK|US)
exclude_protocol=hy2,tuic
exclude_protocols=wireguard
exclude_type=vless
filter_protocol=trojan
filter_type=socks5
enable_rule_generator=true
overwrite_original_rules=true
clash_rule_base=https://example.com/base.yml
rename=美国@US
rename=\[(.+?)\]@\1
unknown_key=ignored
`

func TestParse(t *testing.T) {
	cfg := Parse([]byte(sample))

	if len(cfg.Rulesets) != 3 {
		t.Fatalf("rulesets = %d, want 3 (bad-no-comma dropped)", len(cfg.Rulesets))
	}
	if cfg.Rulesets[0].Inline != "GEOIP,CN" || cfg.Rulesets[0].URL != "" {
		t.Errorf("inline GEOIP parsed wrong: %+v", cfg.Rulesets[0])
	}
	if cfg.Rulesets[1].Inline != "FINAL" {
		t.Errorf("FINAL inline parsed wrong: %+v", cfg.Rulesets[1])
	}
	if cfg.Rulesets[2].URL != "https://example.com/PROXY.list" || cfg.Rulesets[2].Inline != "" {
		t.Errorf("remote ruleset parsed wrong: %+v", cfg.Rulesets[2])
	}

	if len(cfg.ProxyGroups) != 2 {
		t.Fatalf("proxy groups = %d, want 2 (too-few-fields dropped)", len(cfg.ProxyGroups))
	}
	sel := cfg.ProxyGroups[0]
	if sel.Type != "select" || len(sel.Selectors) != 2 {
		t.Errorf("select group wrong: %+v", sel)
	}
	ut := cfg.ProxyGroups[1]
	if ut.Type != "url-test" || ut.TestURL == "" || ut.Interval != 300 || ut.Timeout != 5 || ut.Tolerance != 50 {
		t.Errorf("url-test group interval spec wrong: %+v", ut)
	}
	if len(ut.Selectors) != 1 || ut.Selectors[0] != ".*" {
		t.Errorf("url-test selectors wrong: %+v", ut.Selectors)
	}

	if len(cfg.ExcludeRemarks) != 1 { // invalid regex skipped
		t.Errorf("exclude remarks = %d, want 1 (invalid regex dropped)", len(cfg.ExcludeRemarks))
	}
	if len(cfg.IncludeRemarks) != 1 {
		t.Errorf("include remarks = %d, want 1", len(cfg.IncludeRemarks))
	}
	if !cfg.EnableRuleGenerator || !cfg.OverwriteRules {
		t.Error("bool flags not set")
	}
	if cfg.ClashRuleBase != "https://example.com/base.yml" {
		t.Errorf("clash_rule_base = %q", cfg.ClashRuleBase)
	}
	if len(cfg.RenameRules) != 2 || cfg.RenameRules[0] != "美国@US" || cfg.RenameRules[1] != `\[(.+?)\]@\1` {
		t.Errorf("rename rules parsed wrong: %v", cfg.RenameRules)
	}
	if len(cfg.ExcludeProtocols) != 5 || cfg.ExcludeProtocols[0] != "hy2,tuic" || cfg.ExcludeProtocols[1] != "wireguard" ||
		cfg.ExcludeProtocols[2] != "vless" || cfg.ExcludeProtocols[3] != "trojan" || cfg.ExcludeProtocols[4] != "socks5" {
		t.Errorf("exclude protocols parsed wrong: %v", cfg.ExcludeProtocols)
	}
}

func TestParseDefaultsRuleGeneratorOn(t *testing.T) {
	cfg := Parse([]byte(""))
	if !cfg.EnableRuleGenerator {
		t.Error("EnableRuleGenerator should default to true")
	}
}

func TestLiteral(t *testing.T) {
	if name, ok := Literal("[]DIRECT"); !ok || name != "DIRECT" {
		t.Errorf("Literal([]DIRECT) = %q,%v", name, ok)
	}
	if _, ok := Literal("(港|HK)"); ok {
		t.Error("regex selector should not be a literal")
	}
}

func TestParseIntervalPartial(t *testing.T) {
	i, to, tol := parseInterval("300")
	if i != 300 || to != 0 || tol != 0 {
		t.Errorf("parseInterval(300) = %d,%d,%d", i, to, tol)
	}
	i, to, tol = parseInterval("300,,50")
	if i != 300 || to != 0 || tol != 50 {
		t.Errorf("parseInterval(300,,50) = %d,%d,%d", i, to, tol)
	}
}

// 规则来源格式、刷新间隔与 inline 逗号必须各自保留其语义。
func TestParseRulesetFormatAndInterval(t *testing.T) {
	tests := []struct {
		name, rhs, url, inline, format string
		interval                       int
	}{
		{name: "默认远程", rhs: "https://example.com/a.list", url: "https://example.com/a.list", interval: 86400},
		{name: "Surge", rhs: "surge:https://example.com/a.list,300", url: "https://example.com/a.list", format: "surge", interval: 300},
		{name: "QuanX", rhs: "quanx:https://example.com/a.list", url: "https://example.com/a.list", format: "quanx", interval: 86400},
		{name: "Clash经典", rhs: "clash-classic:https://example.com/a.yaml,600", url: "https://example.com/a.yaml", format: "clash-classic", interval: 600},
		{name: "Clash域名", rhs: "clash-domain:https://example.com/a.yaml,0", url: "https://example.com/a.yaml", format: "clash-domain"},
		{name: "Clash网段", rhs: "clash-ipcidr:https://example.com/a.yaml,123", url: "https://example.com/a.yaml", format: "clash-ipcidr", interval: 123},
		{name: "最后逗号", rhs: "https://example.com/a,b.list, 900 ", url: "https://example.com/a,b.list", interval: 900},
		{name: "非数字间隔", rhs: "https://example.com/a.list,invalid", url: "https://example.com/a.list"},
		{name: "空间隔", rhs: "https://example.com/a.list,", url: "https://example.com/a.list"},
		{name: "溢出间隔", rhs: "https://example.com/a.list,999999999999999999999999999", url: "https://example.com/a.list"},
		{name: "未知格式", rhs: "unknown:https://example.com/a.list,30", url: "unknown:https://example.com/a.list", format: "unknown", interval: 30},
		{name: "仅识别小写", rhs: "SURGE:https://example.com/a.list", url: "SURGE:https://example.com/a.list", format: "SURGE", interval: 86400},
		{name: "HTTP协议", rhs: "http://example.com/a.list", url: "http://example.com/a.list", interval: 86400},
		{name: "inline不拆尾", rhs: "[]GEOIP,CN,no-resolve", inline: "GEOIP,CN,no-resolve"},
		{name: "inline数字参数", rhs: "[]DST-PORT,443", inline: "DST-PORT,443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Parse([]byte("ruleset=目标," + tt.rhs))
			if len(cfg.Rulesets) != 1 {
				t.Fatalf("规则集数量 = %d，期望 1", len(cfg.Rulesets))
			}
			want := Ruleset{Group: "目标", URL: tt.url, Inline: tt.inline, Format: tt.format, Interval: tt.interval}
			if got := cfg.Rulesets[0]; got != want {
				t.Errorf("规则集 = %+v，期望 %+v", got, want)
			}
		})
	}
}

func TestBoolVal(t *testing.T) {
	for _, on := range []string{"true", "1", "yes", "ON"} {
		if !boolVal(on) {
			t.Errorf("boolVal(%q) should be true", on)
		}
	}
	for _, off := range []string{"false", "0", "no", ""} {
		if boolVal(off) {
			t.Errorf("boolVal(%q) should be false", off)
		}
	}
}
