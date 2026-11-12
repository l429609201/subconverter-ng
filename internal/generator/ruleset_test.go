package generator

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseRulesetContentFormats(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		content string
		want    []Rule
		skipped []string
	}{
		{
			name:    "默认 Surge 重绑策略",
			content: "# 注释\r\n; 注释\n// 注释\nDOMAIN,example.com,Old\r\nIP-CIDR,192.0.2.0/24,Old,no-resolve\nGEOIP,CN,no-resolve\nFINAL,Old\nUNKNOWN,test\ninvalid\n",
			want: []Rule{
				{Type: "DOMAIN", Value: "example.com", Group: "目标"},
				{Type: "IP-CIDR", Value: "192.0.2.0/24", Group: "目标", Flag: "no-resolve"},
				{Type: "GEOIP", Value: "CN", Group: "目标", Flag: "no-resolve"},
				{Type: "MATCH", Group: "目标"},
			},
			skipped: []string{"UNKNOWN,test", "invalid"},
		},
		{
			name:    "Surge 保留目标中立类型及 URL",
			format:  "surge",
			content: "URL-REGEX,^https?://example.com,Old\nDOMAIN-SUFFIX,example.org\nDOMAIN,x.com,Old,extended-matching\n",
			want: []Rule{
				{Type: "URL-REGEX", Value: "^https?://example.com", Group: "目标"},
				{Type: "DOMAIN-SUFFIX", Value: "example.org", Group: "目标"},
				{Type: "DOMAIN", Value: "x.com", Group: "目标"},
			},
		},
		{
			name:    "兼容旧式 YAML 包装",
			content: "payload:\n- 'DOMAIN,example.com'\n- \"GEOIP,CN,no-resolve\"\n",
			want: []Rule{
				{Type: "DOMAIN", Value: "example.com", Group: "目标"},
				{Type: "GEOIP", Value: "CN", Group: "目标", Flag: "no-resolve"},
			},
		},
		{
			name:    "Classic 正规 YAML 引号注释与 flow",
			format:  "clash-classic",
			content: "# 注释\npayload: ['DOMAIN,example.com', \"IP-CIDR,192.0.2.0/24,no-resolve\", 'UNKNOWN,nope'] # 注释\n",
			want: []Rule{
				{Type: "DOMAIN", Value: "example.com", Group: "目标"},
				{Type: "IP-CIDR", Value: "192.0.2.0/24", Group: "目标", Flag: "no-resolve"},
			},
			skipped: []string{"UNKNOWN,nope"},
		},
		{
			name:    "Classical 别名块序列",
			format:  "clash-classical",
			content: "payload:\n  - DOMAIN-SUFFIX,example.com # 行尾注释\n  - 'DOMAIN-KEYWORD,foo#bar'\n  - 'DOMAIN,example.org,Source,no-resolve'\n",
			want: []Rule{
				{Type: "DOMAIN-SUFFIX", Value: "example.com", Group: "目标"},
				{Type: "DOMAIN-KEYWORD", Value: "foo#bar", Group: "目标"},
				{Type: "DOMAIN", Value: "example.org", Group: "目标", Flag: "no-resolve"},
			},
		},
		{
			name:    "域名三种转换与不可表达通配",
			format:  "clash-domain",
			content: "payload: [example.com, '.example.org', '+.example.net', '+.foo.*', '.foo.*.*', '+.bar.*.*', '*.bad.com', '+.', 'bad domain', 'https://example.com', 'foo..com']\n",
			want: []Rule{
				{Type: "DOMAIN", Value: "example.com", Group: "目标"},
				{Type: "DOMAIN-SUFFIX", Value: "example.org", Group: "目标"},
				{Type: "DOMAIN-SUFFIX", Value: "example.net", Group: "目标"},
				{Type: "DOMAIN-KEYWORD", Value: "foo", Group: "目标"},
				{Type: "DOMAIN-KEYWORD", Value: "foo", Group: "目标"},
				{Type: "DOMAIN-KEYWORD", Value: "bar", Group: "目标"},
			},
			skipped: []string{"*.bad.com", "+.", "bad domain", "https://example.com", "foo..com"},
		},
		{
			name:    "IP 前缀验证地址族",
			format:  "clash-ipcidr",
			content: "payload: ['192.0.2.0/24', '2001:db8::/32', '0.0.0.0/0', '::/0', '192.0.2.0/33', '2001:db8::/129', 'not-ip/24', '192.0.2.1', 'fe80::%eth0/64']",
			want: []Rule{
				{Type: "IP-CIDR", Value: "192.0.2.0/24", Group: "目标"},
				{Type: "IP-CIDR6", Value: "2001:db8::/32", Group: "目标"},
				{Type: "IP-CIDR", Value: "0.0.0.0/0", Group: "目标"},
				{Type: "IP-CIDR6", Value: "::/0", Group: "目标"},
			},
			skipped: []string{"192.0.2.0/33", "2001:db8::/129", "not-ip/24", "192.0.2.1", "fe80::%eth0/64"},
		},
		{
			name:    "QuanX 类型与注释及源策略",
			format:  "quanx",
			content: "# 注释\n; 注释\n// 注释\nhost, example.com, old // 注释\nhost-suffix,example.org,old\nhost-keyword,example,old\nip6-cidr,2001:db8::/32,old,no-resolve // 注释\nip-cidr,192.0.2.0/24,no-resolve\nfinal,old\nunsupported,x,old\n",
			want: []Rule{
				{Type: "DOMAIN", Value: "example.com", Group: "目标"},
				{Type: "DOMAIN-SUFFIX", Value: "example.org", Group: "目标"},
				{Type: "DOMAIN-KEYWORD", Value: "example", Group: "目标"},
				{Type: "IP-CIDR6", Value: "2001:db8::/32", Group: "目标", Flag: "no-resolve"},
				{Type: "IP-CIDR", Value: "192.0.2.0/24", Group: "目标", Flag: "no-resolve"},
				{Type: "MATCH", Group: "目标"},
			},
			skipped: []string{"unsupported,x,old"},
		},
		{
			name:    "不支持规则不得成功计入",
			format:  "surge",
			content: "DOMAIN,valid.example\nUNKNOWN,x\nDOMAIN,\nDOMAIN,x,a,b,c\nFINAL,a,b\nNOT,(DOMAIN,x)\n",
			want:    []Rule{{Type: "DOMAIN", Value: "valid.example", Group: "目标"}},
			skipped: []string{"UNKNOWN,x", "DOMAIN,", "DOMAIN,x,a,b,c", "FINAL,a,b", "NOT,(DOMAIN,x)"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, skipped, err := parseRulesetContent([]byte(tt.content), "目标", tt.format)
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("规则 = %#v，期望 %#v", got, tt.want)
			}
			if !reflect.DeepEqual(skipped, tt.skipped) {
				t.Errorf("跳过 = %#v，期望 %#v", skipped, tt.skipped)
			}
		})
	}
}

func TestParseRulesetContentErrors(t *testing.T) {
	for _, format := range []string{"", "surge", "quanx", "clash-classic", "clash-classical", "clash-domain", "clash-ipcidr"} {
		t.Run("空内容/"+format, func(t *testing.T) {
			if _, _, err := parseRulesetContent(nil, "G", format); err == nil {
				t.Fatal("空内容必须报错")
			}
		})
	}
	if _, _, err := parseRulesetContent([]byte("DOMAIN,x"), "G", "unknown"); err == nil {
		t.Fatal("未知格式必须报错")
	}
	for _, text := range []string{" \n# 注释\n; 注释\n// 注释", "payload:\n"} {
		if _, _, err := parseRulesetContent([]byte(text), "G", ""); err == nil {
			t.Errorf("仅有注释或包装必须报错: %q", text)
		}
	}
	// 所有 YAML 格式共享严格的字符串序列契约，禁止隐式类型转换或半解析。
	bad := []string{
		"payload: [", "{}", "[]", "payload: null", "payload: []", "payload: DOMAIN,x",
		"payload: {a: b}", "payload: [123]", "payload: [true]", "payload: [null]",
		"payload: [1.25]", "payload: [[DOMAIN,x]]", "payload: [{a: b}]",
		"payload: ['']", "payload: ['   ']", "payload: [DOMAIN,x]\npayload: [DOMAIN,y]",
		"payload: ['DOMAIN,x']\n---\npayload: ['DOMAIN,y']",
		"value: &entry 'DOMAIN,x'\npayload: [*entry]",
	}
	for _, format := range []string{"clash-classic", "clash-domain", "clash-ipcidr"} {
		for _, text := range bad {
			t.Run(format+"/"+text, func(t *testing.T) {
				rules, _, err := parseRulesetContent([]byte(text), "G", format)
				if err == nil || len(rules) != 0 {
					t.Fatalf("坏 payload 不应返回成功规则: rules=%v err=%v", rules, err)
				}
			})
		}
	}
}

func TestParseRulesetContentAllSkippedErrors(t *testing.T) {
	for _, tc := range []struct{ format, content string }{
		{"", "UNKNOWN,x\nDOMAIN,"},
		{"surge", "NOT,(DOMAIN,x)"},
		{"quanx", "unsupported,x,old"},
		{"clash-classic", "payload: ['UNKNOWN,x']"},
		{"clash-classical", "payload: ['invalid']"},
		{"clash-domain", "payload: ['*.example.com']"},
		{"clash-ipcidr", "payload: ['not-a-cidr']"},
	} {
		t.Run(tc.format, func(t *testing.T) {
			rules, skipped, err := parseRulesetContent([]byte(tc.content), "G", tc.format)
			if err == nil || len(rules) != 0 || len(skipped) == 0 {
				t.Fatalf("全部跳过必须报错且保留诊断: %v %v %v", rules, skipped, err)
			}
		})
	}
}

func TestParseRulesetContentStrictStrings(t *testing.T) {
	// 引号明确指定字符串后，即使长得像数字或布尔也仍按域名文本处理。
	got, skipped, err := parseRulesetContent([]byte("payload: ['123', 'true', !!str 456]"), "G", "clash-domain")
	if err != nil || len(got) != 3 || len(skipped) != 0 {
		t.Fatalf("显式字符串应保留: %v %v %v", got, skipped, err)
	}
}

func TestParseRulesetContentRetainsRemoteCompatibility(t *testing.T) {
	data := []byte("DOMAIN,x.com\nGEOIP,CN,no-resolve\nFINAL\n")
	want, wantSkipped := parseRemoteRuleset(data, "G")
	for _, format := range []string{"", "surge"} {
		got, skipped, err := parseRulesetContent(data, "G", format)
		if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(skipped, wantSkipped) {
			t.Fatalf("兼容解析发生漂移: %v %v %v", got, skipped, err)
		}
	}
	// 旧兼容函数行为保持原样，新入口独立纠正源策略被当成 Flag 的问题。
	legacy, _ := parseRemoteRuleset([]byte("DOMAIN,x.com,Old"), "G")
	if len(legacy) != 1 || !strings.EqualFold(legacy[0].Flag, "Old") {
		t.Fatalf("旧兼容函数不应被本次修改: %v", legacy)
	}
}
