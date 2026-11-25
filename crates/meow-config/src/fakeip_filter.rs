//! Compile FakeIP domain filters without making meow-dns depend on meow-rules.

use crate::dns_domain_matcher::build_reference;
use crate::dns_parser::{check_domain_key, expand_policy_keys};
use crate::raw::RawDns;
use crate::rule_provider::RuleProvider;
use anyhow::{anyhow, bail, Context, Result};
use meow_dns::fakeip::{Skipper, SkipperMode};
use meow_dns::resolver::NameserverPolicyMatcher;
use meow_rules::geosite::GeositeDB;
use std::{borrow::Cow, collections::HashMap, sync::Arc};
use tracing::warn;

pub(crate) fn build(
    dns: &RawDns,
    geosite: Option<&Arc<GeositeDB>>,
    providers: &HashMap<String, Arc<RuleProvider>>,
    strict: bool,
) -> Result<Skipper> {
    let filters = dns.fake_ip_filter.as_deref().unwrap_or(&[]);
    if dns.fake_ip_filter_mode.as_deref() == Some("rule") {
        let rules = filters
            .iter()
            .enumerate()
            .map(|(index, line)| {
                build_rule(line, geosite, providers, strict)
                    .map_err(|error| anyhow!("dns.fake-ip-filter[{index}]: {error}"))
            })
            .collect::<Result<Vec<_>>>()?;
        return Ok(Skipper::from_rules(rules));
    }
    let mode = match dns.fake_ip_filter_mode.as_deref() {
        Some("whitelist") | Some("white-list") => SkipperMode::WhiteList,
        Some("blacklist") | Some("black-list") | None => SkipperMode::BlackList,
        Some(other) => {
            warn!("dns.fake-ip-filter-mode '{other}' unknown; using 'blacklist'");
            SkipperMode::BlackList
        }
    };
    let mut patterns = Vec::new();
    let mut matchers = Vec::new();
    for (index, filter) in filters.iter().enumerate() {
        let key = filter.trim();
        // Only references expand comma lists. Ordinary domain patterns keep
        // their original DomainTrie meaning, including EXACT / +. / *. / . .
        if key.contains(':') {
            let keys = expand_policy_keys(key);
            if keys.is_empty() {
                // An empty prefixed list must still diagnose its missing name.
                build_reference(key, geosite, providers)
                    .map_err(|error| anyhow!("dns.fake-ip-filter[{index}]: {error}"))?;
            }
            for key in keys {
                let matcher = build_reference(&key, geosite, providers)
                    .map_err(|error| anyhow!("dns.fake-ip-filter[{index}]: {error}"))?
                    .context("fake-ip-filter reference requires geosite: or rule-set:")?;
                matchers.push(matcher);
            }
        } else {
            check_domain_key("dns.fake-ip-filter", filter, strict)?;
            patterns.push(filter.clone());
        }
    }
    Ok(Skipper::with_matchers(&patterns, mode, matchers))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RuleKind {
    Domain,
    Suffix,
    Keyword,
    Regex,
    Wildcard,
    Geosite,
    RuleSet,
    Match,
}

struct ParsedRule<'a> {
    kind: RuleKind,
    payload: &'a str,
    skip: bool,
}

/// Parse the rule grammar separately from `expand_policy_keys`: commas inside
/// a regex belong to the expression; only the last field is its action.
fn parse_rule(line: &str) -> Result<ParsedRule<'_>> {
    if line.len() > meow_rules::parser::MAX_RULE_LINE_LEN {
        bail!(
            "rule line exceeds {} bytes",
            meow_rules::parser::MAX_RULE_LINE_LEN
        );
    }
    let (kind, rest) = line
        .split_once(',')
        .context("rule needs a type and fake-ip/real-ip action")?;
    let kind = match kind.trim().to_ascii_uppercase().as_str() {
        "DOMAIN" => RuleKind::Domain,
        "DOMAIN-SUFFIX" => RuleKind::Suffix,
        "DOMAIN-KEYWORD" => RuleKind::Keyword,
        "DOMAIN-REGEX" => RuleKind::Regex,
        "DOMAIN-WILDCARD" => RuleKind::Wildcard,
        "GEOSITE" => RuleKind::Geosite,
        "RULE-SET" => RuleKind::RuleSet,
        "MATCH" => RuleKind::Match,
        other => bail!("unsupported FakeIP rule type: {other}"),
    };
    let (payload, action) = if kind == RuleKind::Match {
        if rest.contains(',') {
            bail!("MATCH needs only a fake-ip/real-ip action");
        }
        ("", rest.trim())
    } else {
        let (payload, action) = rest
            .rsplit_once(',')
            .context("rule needs a payload and fake-ip/real-ip action")?;
        let payload = payload.trim();
        if payload.is_empty() {
            bail!("rule payload is empty");
        }
        if !matches!(kind, RuleKind::Regex | RuleKind::Wildcard) && payload.contains(',') {
            bail!("rule needs exactly one payload and a fake-ip/real-ip action");
        }
        (payload, action.trim())
    };
    let skip = match action.to_ascii_lowercase().as_str() {
        "fake-ip" => false,
        "real-ip" => true,
        other => bail!("invalid FakeIP action '{other}'; expected fake-ip or real-ip"),
    };
    Ok(ParsedRule {
        kind,
        payload,
        skip,
    })
}

fn build_rule(
    line: &str,
    geosite: Option<&Arc<GeositeDB>>,
    providers: &HashMap<String, Arc<RuleProvider>>,
    strict: bool,
) -> Result<(NameserverPolicyMatcher, bool)> {
    let rule = parse_rule(line)?;
    let payload = rule.payload;
    // DNS accepts numeric labels and literal bytes that routing ingress's
    // is_valid_host rejects. Check label shapes, not that narrower alphabet;
    // provider.matches_domain keeps its existing contract independently.
    let dead = match rule.kind {
        RuleKind::Domain | RuleKind::Suffix | RuleKind::Wildcard => {
            payload.starts_with('.')
                || payload.ends_with('.')
                || meow_rules::domain_key_has_dead_label(payload)
        }
        RuleKind::Keyword => payload.contains(".."),
        _ => false,
    };
    if dead {
        let message = format!("rule '{line}' has a dead domain payload");
        if strict {
            bail!("{message} (strict mode)");
        }
        warn!("dns.fake-ip-filter: {message}; it can never match a normalized host");
    }
    // These predicates mirror meow-rules' domain rules, without allocating
    // Metadata (and a host SmolStr) for each DNS query. In particular suffix
    // matches a label boundary; wildcard '*' is nonempty and stays in a label.
    let matcher: NameserverPolicyMatcher = match rule.kind {
        RuleKind::Domain => {
            let domain = payload.to_lowercase();
            Arc::new(move |host| host.eq_ignore_ascii_case(&domain))
        }
        RuleKind::Suffix => {
            let suffix = payload.to_ascii_lowercase();
            Arc::new(move |host| {
                let host = host.as_bytes();
                let suffix = suffix.as_bytes();
                host.eq_ignore_ascii_case(suffix)
                    || (host.len() > suffix.len()
                        && host[host.len() - suffix.len() - 1] == b'.'
                        && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix))
            })
        }
        RuleKind::Keyword => {
            let keyword = payload.to_ascii_lowercase();
            Arc::new(move |host| {
                host.as_bytes()
                    .windows(keyword.len())
                    .any(|window| window.eq_ignore_ascii_case(keyword.as_bytes()))
            })
        }
        RuleKind::Regex => {
            let regex = regex::Regex::new(payload).context("invalid DOMAIN-REGEX pattern")?;
            Arc::new(move |host| regex.is_match(host))
        }
        RuleKind::Wildcard => {
            let expanded = regex::escape(payload).replace(r"\*", r"[^.]+");
            let regex = regex::Regex::new(&format!("^(?i){expanded}$"))
                .context("invalid DOMAIN-WILDCARD pattern")?;
            Arc::new(move |host| !host.is_empty() && regex.is_match(host))
        }
        RuleKind::Geosite | RuleKind::RuleSet => {
            let prefix = if rule.kind == RuleKind::Geosite {
                "geosite"
            } else {
                "rule-set"
            };
            build_reference(&format!("{prefix}:{payload}"), geosite, providers)?
                .context("rule requires a domain reference")?
        }
        RuleKind::Match => Arc::new(|_| true),
    };
    Ok((matcher, rule.skip))
}

/// Only active FakeIP references participate in provider/geodata discovery.
/// Typed rules are parsed here first, then represented as reference keys; the
/// entire comma-separated rule line is never expanded as a policy key.
pub(crate) fn dependency_keys(dns: &RawDns) -> impl Iterator<Item = Cow<'_, str>> {
    let active = dns.enable.unwrap_or(false) && dns.enhanced_mode.as_deref() == Some("fake-ip");
    let rules = dns.fake_ip_filter_mode.as_deref() == Some("rule");
    dns.fake_ip_filter.iter().flatten().filter_map(move |line| {
        if !active {
            return None;
        }
        if rules {
            // Invalid rules are diagnosed by the compiler, not silently
            // accepted by discovery. No regex/domain text is a reference.
            let rule = parse_rule(line).ok()?;
            let prefix = match rule.kind {
                RuleKind::Geosite => "geosite",
                RuleKind::RuleSet => "rule-set",
                _ => return None,
            };
            Some(Cow::Owned(format!("{prefix}:{}", rule.payload)))
        } else {
            let key = line.trim();
            let lower = key.to_ascii_lowercase();
            (lower.starts_with("geosite:") || lower.starts_with("rule-set:"))
                .then_some(Cow::Borrowed(key))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skipper(filters: &[&str], mode: &str) -> Skipper {
        let raw = crate::parse_raw_yaml("dns: {enable: true, enhanced-mode: fake-ip}\n").unwrap();
        let mut dns = raw.dns.unwrap();
        dns.fake_ip_filter_mode = Some(mode.to_string());
        dns.fake_ip_filter = Some(filters.iter().map(|line| (*line).to_string()).collect());
        build(&dns, None, &HashMap::new(), false).unwrap()
    }

    #[test]
    fn rules_use_first_verdict_and_default_to_fake_ip() {
        let filter = skipper(
            &[
                "DOMAIN,first.example,fake-ip",
                "DOMAIN-SUFFIX,example,real-ip",
            ],
            "rule",
        );
        assert!(!filter.should_skip("first.example"));
        assert!(filter.should_skip("other.example"));
        assert!(filter.should_skip("example"));
        assert!(!filter.should_skip("notexample"));
        assert!(!filter.should_skip("unmatched.test"));
        let filter = skipper(&["MATCH,real-ip"], "rule");
        assert!(filter.should_skip("unmatched.test"));
        assert!(!skipper(&[], "rule").should_skip("unmatched.test"));
    }

    #[test]
    fn domain_rule_predicates_keep_meow_semantics() {
        for (line, hit, miss) in [
            (
                "DOMAIN,EXAMPLE.TEST,real-ip",
                "example.test",
                "a.example.test",
            ),
            ("DOMAIN-KEYWORD,Key,real-ip", "a.KEY.test", "other.test"),
            (
                "DOMAIN-REGEX,^a{1,3}\\.test$,real-ip",
                "aaa.test",
                "aaaa.test",
            ),
            (
                "DOMAIN-WILDCARD,*.Example.Test,real-ip",
                "a.example.test",
                "a.b.example.test",
            ),
        ] {
            let filter = skipper(&[line], "rule");
            assert!(filter.should_skip(hit), "{line}: {hit}");
            assert!(!filter.should_skip(miss), "{line}: {miss}");
        }
        assert!(!skipper(&["DOMAIN-REGEX,^UPPER,real-ip"], "rule").should_skip("upper.test"));
        assert!(!skipper(&["DOMAIN-WILDCARD,?.test,real-ip"], "rule").should_skip("a.test"));
    }

    #[test]
    fn strict_checks_label_shapes_without_routing_ingress_restrictions() {
        let raw = crate::parse_raw_yaml("dns: {enable: true, enhanced-mode: fake-ip}\n").unwrap();
        let mut dns = raw.dns.unwrap();
        dns.fake_ip_filter_mode = Some("rule".to_string());
        for line in [
            "DOMAIN,a..b,real-ip",
            "DOMAIN-SUFFIX,.example.test,real-ip",
            "DOMAIN-WILDCARD,*.example.test.,real-ip",
            "DOMAIN-KEYWORD,a..b,real-ip",
        ] {
            dns.fake_ip_filter = Some(vec![line.to_string()]);
            assert!(build(&dns, None, &HashMap::new(), false).is_ok(), "{line}");
            let error = build(&dns, None, &HashMap::new(), true).err().unwrap();
            assert!(error.to_string().contains("dead domain payload"), "{error}");
        }
        for (line, host) in [
            ("DOMAIN,2130706433,real-ip", "2130706433"),
            ("DOMAIN,a?b.test,real-ip", "a?b.test"),
            ("DOMAIN-WILDCARD,?.test,real-ip", "?.test"),
        ] {
            dns.fake_ip_filter = Some(vec![line.to_string()]);
            assert!(
                build(&dns, None, &HashMap::new(), true)
                    .unwrap()
                    .should_skip(host),
                "{line}"
            );
        }
    }

    #[test]
    fn actions_accept_case_and_surrounding_whitespace() {
        let filter = skipper(
            &["domain,example.test, FAKE-IP ", "MATCH, Real-Ip "],
            "rule",
        );
        assert!(!filter.should_skip("example.test"));
        assert!(filter.should_skip("other.test"));
    }

    #[test]
    fn references_support_both_modes_empty_providers_and_explicit_errors() {
        let raw = crate::parse_raw_yaml(
            r#"dns: {enable: true, enhanced-mode: fake-ip}
rule-providers:
  Selected: {type: inline, behavior: domain, payload: ['+.selected.test']}
  Classical: {type: inline, behavior: classical, payload: ['DOMAIN,classic.test', 'IP-CIDR,192.0.2.0/24']}
  Empty: {type: inline, behavior: domain, payload: []}
  CIDRs: {type: inline, behavior: ipcidr, payload: ['192.0.2.0/24']}
"#,
        )
        .unwrap();
        let providers = crate::rule_provider::load_providers(
            raw.rule_providers.as_ref().unwrap(),
            None,
            &meow_rules::parser::ParserContext::empty(),
            None,
            true,
        )
        .unwrap();
        let mut db = GeositeDB::empty();
        db.insert("cn", "+.geo.test");
        db.insert("private", "private.test");
        let db = Arc::new(db);
        let mut dns = raw.dns.unwrap();
        dns.fake_ip_filter = Some(vec![
            "rUlE-SeT:Selected,Classical".to_string(),
            "GeOsItE:cn,private".to_string(),
            "exact.test".to_string(),
        ]);
        for mode in ["blacklist", "whitelist"] {
            dns.fake_ip_filter_mode = Some(mode.to_string());
            let filter = build(&dns, Some(&db), &providers, true).unwrap();
            for host in [
                "selected.test",
                "a.selected.test",
                "classic.test",
                "geo.test",
                "a.geo.test",
                "private.test",
                "exact.test",
            ] {
                assert_eq!(
                    filter.should_skip(host),
                    mode == "blacklist",
                    "{mode}: {host}"
                );
            }
            for host in ["other.test", "a.exact.test", "a.classic.test"] {
                assert_eq!(
                    filter.should_skip(host),
                    mode == "whitelist",
                    "{mode}: {host}"
                );
            }
        }
        dns.fake_ip_filter_mode = Some("whitelist".to_string());
        dns.fake_ip_filter = Some(vec!["rule-set:Empty".to_string()]);
        assert!(build(&dns, Some(&db), &providers, true)
            .unwrap()
            .should_skip("other.test"));
        for key in [
            "rule-set:missing",
            "rule-set:CIDRs",
            "rule-set:",
            "geosite:",
            "unsupported:x",
        ] {
            dns.fake_ip_filter = Some(vec![key.to_string()]);
            assert!(build(&dns, Some(&db), &providers, false).is_err(), "{key}");
        }
        dns.fake_ip_filter_mode = Some("rule".to_string());
        dns.fake_ip_filter = Some(vec![
            "RULE-SET,Selected,fake-ip".to_string(),
            "GEOSITE,private,real-ip".to_string(),
        ]);
        let filter = build(&dns, Some(&db), &providers, true).unwrap();
        assert!(!filter.should_skip("selected.test"));
        assert!(filter.should_skip("private.test"));
        assert!(!filter.should_skip("other.test"));
        dns.fake_ip_filter = Some(vec!["RULE-SET,CIDRs,real-ip".to_string()]);
        assert!(build(&dns, Some(&db), &providers, false).is_err());
    }

    #[test]
    fn invalid_rules_are_errors_in_both_strict_modes() {
        for strict in [false, true] {
            for (line, expected) in [
                ("DOMAIN,test,DIRECT", "invalid FakeIP action"),
                ("MATCH,realip", "invalid FakeIP action"),
                (
                    "IP-CIDR,192.0.2.0/24,real-ip",
                    "unsupported FakeIP rule type",
                ),
                ("DOMAIN,,real-ip", "payload is empty"),
                ("DOMAIN-REGEX,[,real-ip", "invalid DOMAIN-REGEX"),
                ("RULE-SET,missing,real-ip", "unknown rule-set"),
                ("GEOSITE,cn,real-ip", "requires a loaded database"),
                ("MATCH,real-ip,extra", "MATCH needs only"),
            ] {
                let raw =
                    crate::parse_raw_yaml("dns: {enable: true, enhanced-mode: fake-ip}\n").unwrap();
                let mut dns = raw.dns.unwrap();
                dns.fake_ip_filter_mode = Some("rule".to_string());
                dns.fake_ip_filter = Some(vec![line.to_string()]);
                let error = build(&dns, None, &HashMap::new(), strict)
                    .err()
                    .expect("invalid filter must fail");
                assert!(error.to_string().contains(expected), "{line}: {error}");
            }
        }
    }

    #[test]
    fn discovery_parses_only_real_reference_fields() {
        let raw = crate::parse_raw_yaml(
            r#"dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: rule
  fake-ip-filter:
    - 'GEOSITE,CN@ads,real-ip'
    - 'RULE-SET,Selected,fake-ip'
    - 'DOMAIN-REGEX,geosite:fake{1,3},real-ip'
    - 'DOMAIN,rule-set:fake,real-ip'
"#,
        )
        .unwrap();
        assert!(crate::dns_parser::dns_needs_rule_providers(&raw));
        assert!(crate::dns_policy_uses_geosite(&raw));
        let keys: Vec<_> = dependency_keys(raw.dns.as_ref().unwrap()).collect();
        assert_eq!(keys, ["geosite:CN@ads", "rule-set:Selected"]);
        let categories = crate::collect_dns_policy_geosite_categories(&raw);
        assert_eq!(
            categories,
            std::collections::HashSet::from(["cn".to_string()])
        );
        let mut inactive = raw.clone();
        inactive.dns.as_mut().unwrap().enhanced_mode = Some("redir-host".to_string());
        assert!(!crate::dns_parser::dns_needs_rule_providers(&inactive));
        assert!(!crate::dns_policy_uses_geosite(&inactive));
    }
}
