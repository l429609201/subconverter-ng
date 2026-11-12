package generator

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// parseRulesetContent 将远程规则转换为中立规则；源策略不参与输出策略或标志。
func parseRulesetContent(data []byte, group, format string) ([]Rule, []string, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	var entries []string
	switch format {
	case "", "surge", "quanx":
		for _, raw := range strings.Split(string(data), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
				continue
			}
			if format == "quanx" {
				if i := strings.Index(line, "//"); i >= 0 {
					line = strings.TrimSpace(line[:i])
				}
			} else {
				// 保留旧解析器对简单 payload 包装的兼容，正式 YAML 格式走下方解码。
				if strings.HasPrefix(line, "payload:") {
					continue
				}
				if strings.HasPrefix(line, "- ") {
					line = strings.Trim(strings.TrimPrefix(line, "- "), "'\"")
				}
			}
			if line != "" {
				entries = append(entries, line)
			}
		}
	case "clash-classic", "clash-classical", "clash-domain", "clash-ipcidr":
		var err error
		entries, err = rulesetYAMLPayload(data)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("不支持的远程规则格式 %q", format)
	}
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("远程规则内容为空")
	}

	var rules []Rule
	var skipped []string
	for _, entry := range entries {
		line := strings.TrimSpace(entry)
		var r Rule
		var ok bool
		switch format {
		case "clash-domain":
			r, ok = rulesetDomainRule(line, group)
		case "clash-ipcidr":
			if prefix, err := netip.ParsePrefix(line); err == nil {
				typ := "IP-CIDR6"
				if prefix.Addr().Is4() {
					typ = "IP-CIDR"
				}
				r, ok = ruleFromFields([]string{typ, line}, group)
			}
		default:
			r, ok = rulesetTextRule(line, group)
		}
		if !ok {
			skipped = append(skipped, entry)
			continue
		}
		rules = append(rules, r)
	}
	if len(rules) == 0 {
		return nil, skipped, fmt.Errorf("远程规则不包含可支持的有效规则")
	}
	return rules, skipped, nil
}

// rulesetYAMLPayload 使用节点标签拒绝数字、布尔、嵌套集合及别名，避免字符串强制转换。
func rulesetYAMLPayload(data []byte) ([]string, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("解析远程规则 YAML: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("远程规则 YAML 只能包含一个文档")
		}
		return nil, fmt.Errorf("解析远程规则 YAML: %w", err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("远程规则 YAML 必须包含 payload 映射")
	}
	root := doc.Content[0]
	var payload *yaml.Node
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == "payload" {
			if payload != nil {
				return nil, fmt.Errorf("远程规则 YAML 包含重复 payload")
			}
			payload = root.Content[i+1]
		}
	}
	if payload == nil || payload.Kind != yaml.SequenceNode || len(payload.Content) == 0 {
		return nil, fmt.Errorf("远程规则 payload 必须是非空字符串序列")
	}
	entries := make([]string, 0, len(payload.Content))
	for _, node := range payload.Content {
		if node.Kind != yaml.ScalarNode || node.Tag != "!!str" || strings.TrimSpace(node.Value) == "" {
			return nil, fmt.Errorf("远程规则 payload 第 %d 行必须是非空字符串", node.Line)
		}
		entries = append(entries, node.Value)
	}
	return entries, nil
}

// rulesetTextRule 只保留 no-resolve，第三字段源策略及其他源选项不泄漏到 Flag。
func rulesetTextRule(line, group string) (Rule, bool) {
	fields := strings.Split(line, ",")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	typ := normalizeRuleType(fields[0])
	// 复合表达式含嵌套逗号，不能按普通字段截断后冒充已支持的规则。
	if typ == "AND" || typ == "OR" || typ == "NOT" || typ == "SUB-RULE" {
		return Rule{}, false
	}
	if typ == "FINAL" || typ == "MATCH" {
		if len(fields) > 2 {
			return Rule{}, false
		}
		return ruleFromFields([]string{"MATCH"}, group)
	}
	_, surgeOK := surgeSupportedRuleTypes[typ]
	if (!isValidRuleType(typ) && !surgeOK) || len(fields) < 2 || len(fields) > 4 || fields[1] == "" {
		return Rule{}, false
	}
	clean := []string{typ, fields[1]}
	for _, field := range fields[2:] {
		if strings.EqualFold(field, "no-resolve") {
			clean = append(clean, "no-resolve")
			break
		}
	}
	return ruleFromFields(clean, group)
}

// rulesetDomainRule 仅转换可无损表达的域名通配形式，其他通配表达进入 skipped。
func rulesetDomainRule(domain, group string) (Rule, bool) {
	typ := "DOMAIN"
	switch {
	case (strings.HasPrefix(domain, "+.") || strings.HasPrefix(domain, ".")) && strings.HasSuffix(domain, ".*"):
		typ = "DOMAIN-KEYWORD"
		domain = strings.TrimPrefix(strings.TrimPrefix(domain, "+"), ".")
		for strings.HasSuffix(domain, ".*") {
			domain = strings.TrimSuffix(domain, ".*")
		}
	case strings.HasPrefix(domain, "+."):
		typ, domain = "DOMAIN-SUFFIX", strings.TrimPrefix(domain, "+.")
	case strings.HasPrefix(domain, "."):
		typ, domain = "DOMAIN-SUFFIX", strings.TrimPrefix(domain, ".")
	}
	if domain == "" || len(domain) > 253 {
		return Rule{}, false
	}
	for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return Rule{}, false
		}
		for _, c := range label {
			if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '-' && c != '_' {
				return Rule{}, false
			}
		}
	}
	return ruleFromFields([]string{typ, domain}, group)
}
