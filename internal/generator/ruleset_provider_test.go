package generator

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
)

// 原生 Clash 三类列表必须交由正确的 YAML provider 解码，不能误标为文本。
func TestRuleProvidersFormats(t *testing.T) {
	for _, tt := range []struct {
		prefix, behavior, format, extension string
	}{
		{"", "classical", "text", ".list"},
		{"surge:", "classical", "text", ".list"},
		{"clash-classic:", "classical", "yaml", ".yaml"},
		{"clash-domain:", "domain", "yaml", ".yaml"},
		{"clash-ipcidr:", "ipcidr", "yaml", ".yaml"},
	} {
		t.Run(tt.prefix, func(t *testing.T) {
			cfg := extconfig.Parse([]byte("ruleset=目标," + tt.prefix + "https://example.com/rules,321"))
			rules, providers, skipped, err := buildRuleProviders(cfg, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if len(skipped) != 0 || !reflect.DeepEqual(rules, []string{"RULE-SET,provider_1,目标"}) {
				t.Fatalf("规则 = %v，跳过 = %v", rules, skipped)
			}
			want := map[string]any{
				"type": "http", "behavior": tt.behavior, "format": tt.format,
				"url": "https://example.com/rules", "interval": 321,
				"path": "./ruleset/provider_1" + tt.extension,
			}
			if !reflect.DeepEqual(providers["provider_1"], want) {
				t.Errorf("provider = %#v，期望 %#v", providers["provider_1"], want)
			}
		})
	}
}

// 同地址不同格式或间隔不能共用缓存文件；相同语义可跨组复用。
func TestRuleProvidersDedupIdentity(t *testing.T) {
	cfg := extconfig.Parse([]byte(`ruleset=A,https://example.com/rules
ruleset=A,surge:https://example.com/rules
ruleset=B,surge:https://example.com/rules
ruleset=A,clash-domain:https://example.com/rules
ruleset=A,clash-domain:https://example.com/rules,0
ruleset=A,clash-domain:https://example.com/rules,invalid
ruleset=A,clash-domain:https://example.com/rules,300
ruleset=A,clash-ipcidr:https://example.com/rules
ruleset=A,clash-classic:https://example.com/rules
ruleset=A,[]FINAL
`))
	rules, providers, skipped, err := buildRuleProviders(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	wantRules := []string{
		"RULE-SET,provider_1,A", "RULE-SET,provider_1,B", "RULE-SET,provider_2,A",
		"RULE-SET,provider_3,A", "RULE-SET,provider_4,A", "RULE-SET,provider_5,A",
		"RULE-SET,provider_6,A", "MATCH,A",
	}
	if len(providers) != 6 || len(skipped) != 0 || !reflect.DeepEqual(rules, wantRules) {
		t.Fatalf("providers = %v，规则 = %v，跳过 = %v", providers, rules, skipped)
	}
	if got := providers["provider_1"].(map[string]any)["interval"]; got != 86400 {
		t.Errorf("默认间隔 = %v，期望 86400", got)
	}
	if got := providers["provider_3"].(map[string]any)["interval"]; got != 0 {
		t.Errorf("显式零间隔 = %v，期望 0", got)
	}
}

// QuanX 与未知前缀不能直接生成 classical text，否则会输出客户端无法使用的规则源。
func TestRuleProvidersUnsupportedFormat(t *testing.T) {
	for _, format := range []string{"quanx", "unknown", "SURGE"} {
		t.Run(format, func(t *testing.T) {
			cfg := extconfig.Parse([]byte("ruleset=A,https://example.com/good.list\nruleset=B," + format + ":https://example.com/bad.list"))
			rules, providers, skipped, err := buildRuleProviders(cfg, Options{})
			if err == nil || !strings.Contains(err.Error(), format) {
				t.Fatalf("期望含格式的明确错误，得到 %v", err)
			}
			if rules != nil || providers != nil || skipped != nil {
				t.Fatalf("失败时不得返回部分配置：%v，%v，%v", rules, providers, skipped)
			}
			res, err := GenerateClash(context.Background(), nil, cfg, nil, Options{UseRuleProviders: true})
			if err == nil || res != nil {
				t.Fatalf("生成器必须传播 provider 错误：结果 %v，错误 %v", res, err)
			}
		})
	}
}

// 禁用规则生成时仍保留独立的 Tailscale 规则，但不生成 provider。
func TestRuleProvidersDisabled(t *testing.T) {
	cfg := extconfig.Parse([]byte("enable_rule_generator=false\nruleset=A,clash-domain:https://example.com/rules"))
	rules, providers, skipped, err := buildRuleProviders(cfg, Options{Tailscale: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || len(providers) != 0 || len(skipped) != 0 {
		t.Fatalf("规则 = %v，providers = %v，跳过 = %v", rules, providers, skipped)
	}
}
