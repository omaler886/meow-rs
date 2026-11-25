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
        let category = category.to_owned();
        return Ok(Some(Arc::new(move |host| db.lookup(&category, host))));
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
