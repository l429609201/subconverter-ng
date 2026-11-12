package convert

import (
	"context"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// 覆盖用户模板的远程 classical + interval 与内联规则混排，避免只剩地理规则。
func TestRunClassicalRulesetTemplate(t *testing.T) {
	f := fakeFetcher{
		"client/subscribe": sampleSubscription(),
		"template.ini":     []byte("[custom]\nruleset=全球直连,[]GEOIP,private,no-resolve\nruleset=特定域名,clash-classic:https://rules.example/classic.yaml,28800\nruleset=非标端口,clash-classic:https://rules.example/ports.yaml,28800\nruleset=漏网之鱼,[]FINAL\n"),
		"classic.yaml":     []byte("payload:\n  - DOMAIN-SUFFIX,example.com\n  - IP-CIDR,192.0.2.0/24,no-resolve\n"),
		"ports.yaml":       []byte("payload: ['DST-PORT,1-79', 'DST-PORT,444-65535']\n"),
	}
	data, _, err := Run(context.Background(), f, Request{Target: "clash", SubURLs: []string{"https://airport.example/client/subscribe"}, ConfigURL: "https://config.example/template.ini"})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	want := []string{"GEOIP,private,全球直连,no-resolve", "DOMAIN-SUFFIX,example.com,特定域名", "IP-CIDR,192.0.2.0/24,特定域名,no-resolve", "DST-PORT,1-79,非标端口", "DST-PORT,444-65535,非标端口", "MATCH,漏网之鱼"}
	if strings.Join(doc.Rules, "\n") != strings.Join(want, "\n") {
		t.Fatalf("rules = %v, want %v", doc.Rules, want)
	}
}

// 远程源失败只略过该部分，保留有效规则、兜底规则并提供诊断。
func TestRunSkipsBrokenRulesets(t *testing.T) {
	for _, target := range []string{"clash", "surge", "loon", "quanx", "singbox"} {
		for _, payload := range []string{"", "payload: not-a-list", "payload: ['NOT-A-RULE,x']", "download-failure"} {
			t.Run(target+"/"+payload, func(t *testing.T) {
				f := fakeFetcher{"client/subscribe": sampleSubscription(), "template.ini": []byte("ruleset=DIRECT,clash-classic:https://rules.example/broken.yaml,28800\nruleset=DIRECT,clash-classic:https://rules.example/good.yaml\nruleset=DIRECT,[]FINAL\n"), "broken.yaml": []byte(payload), "good.yaml": []byte("payload: ['DOMAIN,example.com']")}
				if payload == "download-failure" {
					delete(f, "broken.yaml")
				}
				data, diag, err := Run(context.Background(), f, Request{Target: target, SubURLs: []string{"https://airport.example/client/subscribe"}, ConfigURL: "https://config.example/template.ini"})
				if err != nil || len(data) == 0 {
					t.Fatalf("must preserve remaining configuration: err=%v output=%q", err, data)
				}
				if len(diag.SkippedRules) != 1 || !strings.Contains(diag.SkippedRules[0], "已跳过") {
					t.Fatalf("missing diagnostic: %+v", diag)
				}
				if !strings.Contains(string(data), "example.com") || strings.Contains(string(data), "下载或解析失败") {
					t.Fatalf("valid rule lost or diagnostic leaked: %s", data)
				}
				if target == "clash" {
					var doc struct {
						Rules []string `yaml:"rules"`
					}
					if err := yaml.Unmarshal(data, &doc); err != nil {
						t.Fatal(err)
					}
					if strings.Join(doc.Rules, "\n") != "DOMAIN,example.com,DIRECT\nMATCH,DIRECT" {
						t.Fatalf("unexpected rules: %v", doc.Rules)
					}
				}
			})
		}
	}
}
