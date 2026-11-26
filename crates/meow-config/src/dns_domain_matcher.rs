//! Domain-reference matchers shared by DNS response rules and FakeIP filters.

use crate::rule_provider::RuleProvider;
use anyhow::{bail, Context, Result};
use meow_dns::resolver::NameserverPolicyMatcher;
use meow_rules::{geosite::GeositeDB, RuleSet, RuleSetBehavior};
use std::{collections::HashMap, sync::Arc};

/// Compile a `geosite:`/`rule-set:` key, returning `None` for a plain domain.
/// Hold the provider itself, never its snapshot: refreshes must be visible to
/// an already installed DNS resolver, including an initially empty provider.
pub(crate) fn build_reference(
    key: &str,
    geosite: Option<&Arc<GeositeDB>>,
    providers: &HashMap<String, Arc<RuleProvider>>,
) -> Result<Option<NameserverPolicyMatcher>> {
    let lower = key.to_ascii_lowercase();
    if let Some(category) = lower.strip_prefix("geosite:") {
        let category = category.trim();
        if category.is_empty() {
            bail!("geosite category is empty");
        }
        let db = Arc::clone(geosite.context("geosite condition requires a loaded database")?);
        // Resolve immutable category/attribute keys once. Query case folding
        // lives in GeositeDB, shared with classical RULE-SET providers.
        let keys = db.resolve_keys(category);
        return Ok(Some(Arc::new(move |host| {
            keys.as_ref()
                .is_some_and(|keys| keys.iter().all(|key| db.lookup_resolved(key, host)))
        })));
    }
    if lower.starts_with("rule-set:") {
        let name = key["rule-set:".len()..].trim();
        if name.is_empty() {
            bail!("'rule-set:' key has an empty provider name");
        }
        let provider = providers
            .get(name)
            .with_context(|| format!("unknown rule-set: {name}"))?;
        if provider.behavior == RuleSetBehavior::IpCidr {
            bail!("rule-set '{name}' must use domain or classical behavior");
        }
        let provider = Arc::clone(provider);
        return Ok(Some(Arc::new(move |host| provider.matches_domain(host))));
    }
    if lower.contains(':') {
        bail!("unsupported match prefix: {key}");
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(number: u8, value: &[u8]) -> Vec<u8> {
        assert!(value.len() < 128);
        let mut bytes = vec![(number << 3) | 2, value.len() as u8];
        bytes.extend_from_slice(value);
        bytes
    }

    #[test]
    fn geosite_dns_matchers_fold_ascii_and_resolve_attribute_keys() {
        let mut entry = field(1, b"fixture");
        for (kind, value) in [
            (0, b"needle".as_slice()),
            (1, b"^rx[0-9]+[.]test$".as_slice()),
        ] {
            let mut domain = vec![8, kind];
            domain.extend(field(2, value));
            domain.extend(field(3, &field(1, b"ads")));
            entry.extend(field(2, &domain));
        }
        let db = Arc::new(GeositeDB::from_bytes(&field(1, &entry), None).unwrap());
        for category in ["fixture", "fixture@ads"] {
            let matcher =
                build_reference(&format!("geosite:{category}"), Some(&db), &HashMap::new())
                    .unwrap()
                    .unwrap();
            for host in ["xneedle.test", "XNEEDLE.TEST", "rx12.test", "RX12.TEST"] {
                assert!(matcher(host), "{category}: {host}");
            }
            assert!(!matcher("outside.test"));
            let oversized = format!("{}NEEDLE.test", "A".repeat(300));
            assert!(matcher(&oversized));
        }
        let absent = build_reference("geosite:missing", Some(&db), &HashMap::new())
            .unwrap()
            .unwrap();
        assert!(!absent("XNEEDLE.TEST"));
    }
}
