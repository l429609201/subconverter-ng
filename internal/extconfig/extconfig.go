// Package extconfig parses subconverter's INI-style external config (the file
// referenced by the &config= URL parameter). It supports the subset the MVP
// needs to reproduce a typical ACL4SSR setup:
//
//	ruleset=<group>,<url|[]inline-rule>
//	custom_proxy_group=<name>`<type>`<selector>`...`[<test-url>`<interval-spec>]
//	enable_rule_generator=true
//	overwrite_original_rules=true
//	exclude_remarks=<regex>     (repeatable)
//	include_remarks=<regex>     (repeatable)
//	clash_rule_base=<url>
//	rename=<regex-pattern>@<replacement>   (repeatable)
//
// Selectors inside a custom_proxy_group are either []Literal (a reference to
// another group or builtin such as DIRECT/REJECT) or a regular expression
// matched against node names (".*" meaning all nodes).
package extconfig

import (
	"regexp"
	"strconv"
	"strings"
)

// Ruleset is one ruleset= entry. Exactly one of URL or Inline is set.
type Ruleset struct {
	Group    string
	URL      string // remote ruleset to fetch and expand
	Inline   string // inline rule body with the leading "[]" stripped (e.g. "GEOIP,CN", "FINAL")
	Format   string // 空值默认 Surge；已知格式为 surge/quanx/clash-classic/clash-domain/clash-ipcidr，未知前缀原样保留供解析器报错。
	Interval int    // 远程规则默认 86400 秒；显式非数字间隔按源契约记为 0。
}

// ProxyGroup is one custom_proxy_group= entry.
type ProxyGroup struct {
	Name      string
	Type      string   // select | url-test | fallback | load-balance | relay
	Selectors []string // []Literal references and/or regex/.* node matchers, in order
	TestURL   string
	Interval  int
	Timeout   int
	Tolerance int
}

// Config is the parsed external config.
type Config struct {
	Rulesets            []Ruleset
	ProxyGroups         []ProxyGroup
	ExcludeRemarks      []*regexp.Regexp
	IncludeRemarks      []*regexp.Regexp
	ExcludeProtocols    []string
	EnableRuleGenerator bool
	OverwriteRules      bool
	ClashRuleBase       string

	// RenameRules holds raw "pattern@replacement" lines from rename= entries,
	// in declared order. The pattern is a regex; the replacement may be empty.
	RenameRules []string

	// Emoji settings (subconverter-compatible). EmojiRules holds raw
	// "<regex>,<emoji>" lines. AddEmoji/RemoveOldEmoji are nil when the config
	// does not set them, so URL params / global defaults can take over.
	EmojiRules     []string
	AddEmoji       *bool
	RemoveOldEmoji *bool
}

// Literal reports whether a selector is a []Reference (vs a regex matcher) and
// returns the dereferenced name.
func Literal(selector string) (name string, ok bool) {
	if strings.HasPrefix(selector, "[]") {
		return selector[2:], true
	}
	return "", false
}

// Parse reads an INI external config. Unknown keys are ignored so we stay
// forward-compatible with fuller subconverter configs.
func Parse(data []byte) *Config {
	cfg := &Config{EnableRuleGenerator: true} // subconverter default
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			continue // section header, e.g. [custom]
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		switch key {
		case "ruleset":
			if r, ok := parseRuleset(val); ok {
				cfg.Rulesets = append(cfg.Rulesets, r)
			}
		case "custom_proxy_group":
			if g, ok := parseProxyGroup(val); ok {
				cfg.ProxyGroups = append(cfg.ProxyGroups, g)
			}
		case "exclude_remarks":
			if re, err := regexp.Compile(val); err == nil {
				cfg.ExcludeRemarks = append(cfg.ExcludeRemarks, re)
			}
		case "include_remarks":
			if re, err := regexp.Compile(val); err == nil {
				cfg.IncludeRemarks = append(cfg.IncludeRemarks, re)
			}
		case "exclude_protocol", "exclude_protocols", "exclude_type", "exclude_types",
			"filter_protocol", "filter_protocols", "filter_type", "filter_types":
			if val != "" {
				cfg.ExcludeProtocols = append(cfg.ExcludeProtocols, val)
			}
		case "enable_rule_generator":
			cfg.EnableRuleGenerator = boolVal(val)
		case "overwrite_original_rules":
			cfg.OverwriteRules = boolVal(val)
		case "clash_rule_base":
			cfg.ClashRuleBase = val
		case "rename":
			if val != "" {
				cfg.RenameRules = append(cfg.RenameRules, val)
			}
		case "emoji":
			cfg.EmojiRules = append(cfg.EmojiRules, val)
		case "add_emoji":
			b := boolVal(val)
			cfg.AddEmoji = &b
		case "remove_old_emoji":
			b := boolVal(val)
			cfg.RemoveOldEmoji = &b
		}
	}
	return cfg
}

// parseRuleset splits "group,rhs" on the FIRST comma so inline rules that
// themselves contain commas (e.g. []GEOIP,CN) are preserved.
func parseRuleset(val string) (Ruleset, bool) {
	group, rhs, ok := strings.Cut(val, ",")
	if !ok {
		return Ruleset{}, false
	}
	group = strings.TrimSpace(group)
	rhs = strings.TrimSpace(rhs)
	if group == "" || rhs == "" {
		return Ruleset{}, false
	}
	// inline 中的逗号属于规则参数，不能当作刷新间隔拆分。
	if strings.HasPrefix(rhs, "[]") {
		return Ruleset{Group: group, Inline: rhs[2:]}, true
	}
	r := Ruleset{Group: group, URL: rhs, Interval: 86400}
	if i := strings.LastIndexByte(r.URL, ','); i >= 0 {
		// 源配置取最后一个逗号后的间隔，转换失败（含溢出）统一为 0。
		interval, err := strconv.Atoi(strings.TrimSpace(r.URL[i+1:]))
		if err == nil {
			r.Interval = interval
		} else {
			r.Interval = 0
		}
		r.URL = strings.TrimSpace(r.URL[:i])
	}
	if prefix, rest, ok := strings.Cut(r.URL, ":"); ok {
		switch prefix {
		case "surge", "quanx", "clash-classic", "clash-domain", "clash-ipcidr":
			r.Format = prefix
			r.URL = strings.TrimSpace(rest)
		default:
			// HTTP(S) 是地址协议而非格式；未知格式保留前缀和原地址，避免被当作 Surge 静默接受。
			if prefix != "http" && prefix != "https" {
				r.Format = prefix
			}
		}
	}
	return r, true
}

// parseProxyGroup parses the backtick-delimited custom_proxy_group format,
// teasing apart node selectors from the optional trailing test-URL and
// interval spec (e.g. "300,,50" => interval=300, tolerance=50).
func parseProxyGroup(val string) (ProxyGroup, bool) {
	tokens := strings.Split(val, "`")
	if len(tokens) < 3 {
		return ProxyGroup{}, false
	}
	g := ProxyGroup{Name: strings.TrimSpace(tokens[0]), Type: strings.TrimSpace(tokens[1])}
	for _, tok := range tokens[2:] {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		switch {
		case strings.HasPrefix(tok, "http://") || strings.HasPrefix(tok, "https://"):
			g.TestURL = tok
		case intervalSpec.MatchString(tok):
			g.Interval, g.Timeout, g.Tolerance = parseInterval(tok)
		default:
			g.Selectors = append(g.Selectors, tok)
		}
	}
	if g.Name == "" || g.Type == "" {
		return ProxyGroup{}, false
	}
	return g, true
}

// intervalSpec matches "300", "300,5", "300,,50" — digits separated by commas.
var intervalSpec = regexp.MustCompile(`^\d+(,\d*)*$`)

func parseInterval(s string) (interval, timeout, tolerance int) {
	parts := strings.Split(s, ",")
	get := func(i int) int {
		if i < len(parts) {
			n, _ := strconv.Atoi(parts[i])
			return n
		}
		return 0
	}
	return get(0), get(1), get(2)
}

func boolVal(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}
