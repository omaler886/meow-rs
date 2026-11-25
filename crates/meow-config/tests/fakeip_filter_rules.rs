use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use meow_config::{
    dns_parser::parse_dns, load_config, load_config_from_str, parse_raw_yaml, DnsConfig,
};
use meow_dns::{DnsServer, LocalAnswer, Resolver};
use meow_rules::geosite::GeositeDB;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::net::UdpSocket;

struct Upstream {
    address: SocketAddr,
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Upstream {
    async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            loop {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                let request = Message::from_vec(&buffer[..length]).unwrap();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.add_queries(request.queries.iter().cloned());
                let question = &request.queries[0];
                let data = match question.query_type {
                    RecordType::A => Some(RData::A(
                        "192.0.2.9".parse::<std::net::Ipv4Addr>().unwrap().into(),
                    )),
                    RecordType::AAAA => Some(RData::AAAA(
                        "2001:db8::9".parse::<std::net::Ipv6Addr>().unwrap().into(),
                    )),
                    _ => None,
                };
                if let Some(data) = data {
                    response.add_answer(Record::from_rdata(question.name.clone(), 60, data));
                }
                socket
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        Self {
            address,
            hits,
            task,
        }
    }
}

async fn inline_providers(
    yaml: &str,
) -> HashMap<String, Arc<meow_config::rule_provider::RuleProvider>> {
    load_config_from_str(yaml).await.unwrap().rule_providers
}

async fn configuration(
    upstream: SocketAddr,
    dns_options: &str,
    providers: &HashMap<String, Arc<meow_config::rule_provider::RuleProvider>>,
    geosite: Option<Arc<GeositeDB>>,
    prior: Option<&Resolver>,
    root_options: &str,
) -> anyhow::Result<DnsConfig> {
    let dns_options: String = dns_options
        .lines()
        .map(|line| format!("  {line}\n"))
        .collect();
    let raw = parse_raw_yaml(&format!(
        "ipv6: true\n{root_options}dns:\n  enable: true\n  use-system-hosts: false\n  nameserver: ['{upstream}']\n{dns_options}"
    ))?;
    parse_dns(&raw, None, None, &HashMap::new(), geosite, providers, prior).await
}

fn query(name: &str, kind: RecordType) -> Vec<u8> {
    let mut message = Message::new(42, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.metadata.checking_disabled = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true).set_max_payload(1400);
    message.edns = Some(edns);
    message.to_vec().unwrap()
}

async fn answer(resolver: &Resolver, name: &str, kind: RecordType) -> Message {
    let request = query(name, kind);
    let local = DnsServer::try_answer_local(&request, resolver);
    let response = DnsServer::handle_query(&request, resolver).await.unwrap();
    match local {
        LocalAnswer::Answer(inline) => assert_eq!(inline.response, response, "inline/task parity"),
        LocalAnswer::Upstream => {}
        LocalAnswer::Drop => panic!("valid DNS question dropped"),
    }
    Message::from_vec(&response).unwrap()
}

fn response_ip(response: &Message) -> IpAddr {
    match &response.answers.first().expect("address answer").data {
        RData::A(ip) => IpAddr::V4(ip.0),
        RData::AAAA(ip) => IpAddr::V6(ip.0),
        other => panic!("expected A/AAAA answer, got {other:?}"),
    }
}

fn assert_fake(resolver: &Resolver, response: &Message) {
    let ip = response_ip(response);
    assert!(resolver.is_fake_ip(ip), "expected FakeIP, got {ip}");
}

fn assert_real(response: &Message, expected: IpAddr) {
    assert_eq!(response_ip(response), expected);
}

fn assert_nodata(response: &Message) {
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.answers.is_empty());
}

fn test_providers_yaml() -> &'static str {
    r#"
rule-providers:
  domains:
    type: inline
    behavior: domain
    payload: [set.fixture, set.rule.fixture]
  more:
    type: inline
    behavior: domain
    payload: [more.fixture]
  classical:
    type: inline
    behavior: classical
    payload: ['DOMAIN,classical.rule.fixture', 'IP-CIDR,192.0.2.0/24', 'PROCESS-NAME,curl']
  empty:
    type: inline
    behavior: domain
    payload: []
  ip-only:
    type: inline
    behavior: ipcidr
    payload: ['192.0.2.0/24']
"#
}

fn geosite_fixture() -> Arc<GeositeDB> {
    let mut db = GeositeDB::empty();
    for (category, domain) in [
        ("fixture", "geo.fixture"),
        ("extra", "extra.fixture"),
        ("fixture", "geo.rule.fixture"),
    ] {
        db.insert(category, domain);
    }
    Arc::new(db)
}

#[tokio::test]
async fn blacklist_and_whitelist_references_filter_v4_v6_and_preserve_wire_priority() {
    let upstream = Upstream::start().await;
    let providers = inline_providers(test_providers_yaml()).await;
    let db = Some(geosite_fixture());

    let black = configuration(
        upstream.address,
        r#"enhanced-mode: fake-ip
fake-ip-range: '198.18.0.1/16'
fake-ip-range6: 'fd00::/112'
fake-ip-filter:
  - 'rUlE-SeT:domains,more,classical'
  - 'gEoSiTe:fixture,extra'
response-rules:
  - {match: geo.fixture, types: [HTTPS, SVCB], action: nodata}"#,
        &providers,
        db.clone(),
        None,
        "",
    )
    .await
    .unwrap();

    for name in [
        "set.fixture",
        "more.fixture",
        "classical.rule.fixture",
        "geo.fixture",
        "extra.fixture",
    ] {
        assert_real(
            &answer(&black.resolver, name, RecordType::A).await,
            IpAddr::V4("192.0.2.9".parse().unwrap()),
        );
        assert_real(
            &answer(&black.resolver, name, RecordType::AAAA).await,
            IpAddr::V6("2001:db8::9".parse().unwrap()),
        );
    }
    let fake_v4 = answer(&black.resolver, "unfiltered.fixture", RecordType::A).await;
    let fake_v4_ip = response_ip(&fake_v4);
    assert_fake(&black.resolver, &fake_v4);
    let IpAddr::V4(fake_v4_ip) = fake_v4_ip else {
        panic!("A query must return a v4 FakeIP");
    };
    assert_eq!(&fake_v4_ip.octets()[..2], &[198, 18]);
    let fake_v6 = answer(&black.resolver, "unfiltered.fixture", RecordType::AAAA).await;
    let fake_v6_ip = response_ip(&fake_v6);
    assert_fake(&black.resolver, &fake_v6);
    let IpAddr::V6(fake_v6_ip) = fake_v6_ip else {
        panic!("AAAA query must return a v6 FakeIP");
    };
    assert_eq!(fake_v6_ip.segments()[0], 0xfd00);
    for kind in [RecordType::HTTPS, RecordType::SVCB] {
        assert_nodata(&answer(&black.resolver, "geo.fixture", kind).await);
        assert_nodata(&answer(&black.resolver, "unfiltered.fixture", kind).await);
    }
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 12);

    let white = configuration(
        upstream.address,
        r#"enhanced-mode: fake-ip
fake-ip-range: '198.18.0.1/16'
fake-ip-range6: 'fd00::/112'
fake-ip-filter-mode: whitelist
fake-ip-filter:
  - 'rUlE-SeT:domains,more,classical'
  - 'gEoSiTe:fixture,extra'"#,
        &providers,
        db,
        None,
        "",
    )
    .await
    .unwrap();
    for name in [
        "set.fixture",
        "more.fixture",
        "classical.rule.fixture",
        "geo.fixture",
        "extra.fixture",
    ] {
        for kind in [RecordType::A, RecordType::AAAA] {
            assert_fake(&white.resolver, &answer(&white.resolver, name, kind).await);
        }
    }
    for kind in [RecordType::A, RecordType::AAAA] {
        let expected = if kind == RecordType::A {
            IpAddr::V4("192.0.2.9".parse().unwrap())
        } else {
            IpAddr::V6("2001:db8::9".parse().unwrap())
        };
        assert_real(
            &answer(&white.resolver, "unfiltered.fixture", kind).await,
            expected,
        );
    }
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 14);
}

#[tokio::test]
async fn empty_rule_set_is_a_real_filter_and_empty_whitelist_keeps_legacy_behavior() {
    let upstream = Upstream::start().await;
    let providers = inline_providers(test_providers_yaml()).await;
    assert_eq!(providers["empty"].rule_count(), 0);

    let white_reference = configuration(
        upstream.address,
        "enhanced-mode: fake-ip\nfake-ip-filter-mode: whitelist\nfake-ip-filter: ['rule-set:empty']",
        &providers,
        None,
        None,
        "",
    )
    .await
    .unwrap();
    assert_real(
        &answer(&white_reference.resolver, "any.fixture", RecordType::A).await,
        IpAddr::V4("192.0.2.9".parse().unwrap()),
    );

    let black_reference = configuration(
        upstream.address,
        "enhanced-mode: fake-ip\nfake-ip-filter-mode: blacklist\nfake-ip-filter: ['rule-set:empty']",
        &providers,
        None,
        None,
        "",
    )
    .await
    .unwrap();
    assert_fake(
        &black_reference.resolver,
        &answer(&black_reference.resolver, "black.fixture", RecordType::A).await,
    );

    let empty_whitelist = configuration(
        upstream.address,
        "enhanced-mode: fake-ip\nfake-ip-filter-mode: whitelist\nfake-ip-filter: []",
        &providers,
        None,
        None,
        "",
    )
    .await
    .unwrap();
    assert_fake(
        &empty_whitelist.resolver,
        &answer(&empty_whitelist.resolver, "legacy.fixture", RecordType::A).await,
    );
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn rule_mode_matches_all_domain_rule_types_in_order_and_defaults_to_fake_ip() {
    let upstream = Upstream::start().await;
    let providers = inline_providers(test_providers_yaml()).await;
    let config = configuration(
        upstream.address,
        r#"enhanced-mode: fake-ip
fake-ip-filter-mode: rule
fake-ip-filter:
  - 'dOmAiN,exact.rule.fixture,ReAl-Ip'
  - 'DOMAIN-SUFFIX,suffix.rule.fixture,real-ip'
  - 'DOMAIN-KEYWORD,needle,real-ip'
  - 'DOMAIN-REGEX,^rx[0-9]{1,3}\.rule\.fixture$,real-ip'
  - 'DOMAIN-WILDCARD,*.wild.rule.fixture,real-ip'
  - 'RULE-SET,domains,real-ip'
  - 'RULE-SET,classical,real-ip'
  - 'GEOSITE,fixture,real-ip'
  - 'DOMAIN,first.rule.fixture,FAKE-IP'
  - 'DOMAIN-SUFFIX,first.rule.fixture,real-ip'
  - 'MATCH,FAKE-IP'"#,
        &providers,
        Some(geosite_fixture()),
        None,
        "",
    )
    .await
    .unwrap();

    for name in [
        "exact.rule.fixture",
        "a.suffix.rule.fixture",
        "a.needle.fixture",
        "rx123.rule.fixture",
        "a.wild.rule.fixture",
        "set.rule.fixture",
        "classical.rule.fixture",
        "geo.rule.fixture",
    ] {
        assert_real(
            &answer(&config.resolver, name, RecordType::A).await,
            IpAddr::V4("192.0.2.9".parse().unwrap()),
        );
    }
    for name in [
        "first.rule.fixture",
        "not-suffix.rule.fixture",
        "otherwise.fixture",
    ] {
        assert_fake(
            &config.resolver,
            &answer(&config.resolver, name, RecordType::A).await,
        );
    }
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 8);

    let default_fake = configuration(
        upstream.address,
        "enhanced-mode: fake-ip\nfake-ip-filter-mode: rule\nfake-ip-filter: ['DOMAIN,declared.fixture,real-ip']",
        &providers,
        None,
        None,
        "",
    )
    .await
    .unwrap();
    assert_fake(
        &default_fake.resolver,
        &answer(
            &default_fake.resolver,
            "no-rule-matched.fixture",
            RecordType::A,
        )
        .await,
    );
    let empty_rules = configuration(
        upstream.address,
        "enhanced-mode: fake-ip\nfake-ip-filter-mode: rule\nfake-ip-filter: []",
        &providers,
        None,
        None,
        "",
    )
    .await
    .unwrap();
    assert_fake(
        &empty_rules.resolver,
        &answer(&empty_rules.resolver, "empty-rules.fixture", RecordType::A).await,
    );
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 8);
}

#[tokio::test]
async fn invalid_references_provider_behaviors_and_actions_fail_loading() {
    let providers = inline_providers(test_providers_yaml()).await;
    for (options, geosite, expected) in [
        (
            "enhanced-mode: fake-ip\nfake-ip-filter: ['rule-set:missing']",
            None,
            "unknown rule-set",
        ),
        (
            "enhanced-mode: fake-ip\nfake-ip-filter: ['rule-set:ip-only']",
            None,
            "domain or classical behavior",
        ),
        (
            "enhanced-mode: fake-ip\nfake-ip-filter: ['unknown:entry']",
            None,
            "unsupported match prefix",
        ),
        (
            "enhanced-mode: fake-ip\nfake-ip-filter-mode: rule\nfake-ip-filter: ['DOMAIN,host.fixture,direct']",
            None,
            "invalid FakeIP action",
        ),
        (
            "enhanced-mode: fake-ip\nfake-ip-filter-mode: rule\nfake-ip-filter: ['IP-CIDR,192.0.2.0/24,real-ip']",
            None,
            "unsupported FakeIP rule type",
        ),
        (
            "enhanced-mode: fake-ip\nfake-ip-filter-mode: rule\nfake-ip-filter: ['GEOSITE,fixture,real-ip']",
            None,
            "loaded database",
        ),
    ] {
        let error = configuration(
            "127.0.0.1:9".parse().unwrap(),
            options,
            &providers,
            geosite,
            None,
            "",
        )
        .await
        .err()
        .unwrap_or_else(|| panic!("configuration should fail: {options}"));
        assert!(format!("{error:#}").contains(expected), "{options}: {error:#}");
    }
}

#[tokio::test]
async fn unknown_filter_mode_remains_warn_and_blacklist_even_when_strict() {
    let upstream = Upstream::start().await;
    for strict in [false, true] {
        let root_options = if strict { "strict: true\n" } else { "" };
        let config = configuration(
            upstream.address,
            "enhanced-mode: fake-ip\nfake-ip-filter-mode: typo\nfake-ip-filter: ['blocked.fixture']",
            &HashMap::new(),
            None,
            None,
            root_options,
        )
        .await
        .unwrap();
        assert_real(
            &answer(&config.resolver, "blocked.fixture", RecordType::A).await,
            IpAddr::V4("192.0.2.9".parse().unwrap()),
        );
        assert_fake(
            &config.resolver,
            &answer(&config.resolver, "allowed.fixture", RecordType::A).await,
        );
    }
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn provider_refresh_updates_an_installed_resolver_without_rebuild() {
    let upstream = Upstream::start().await;
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("rules.yaml"),
        "payload:\n  - old.fixture\n",
    )
    .unwrap();
    let config_path = directory.path().join("config.yaml");
    std::fs::write(
        &config_path,
        format!(
            "ipv6: true\ndns:\n  enable: true\n  use-system-hosts: false\n  nameserver: ['{}']\n  enhanced-mode: fake-ip\n  fake-ip-filter-mode: blacklist\n  fake-ip-filter: ['rule-set:live']\nrule-providers:\n  live:\n    type: file\n    behavior: domain\n    format: yaml\n    path: rules.yaml\n",
            upstream.address
        ),
    )
    .unwrap();
    let config = load_config(config_path.to_str().unwrap()).await.unwrap();
    let resolver = Arc::clone(&config.dns.resolver);
    let provider = Arc::clone(&config.rule_providers["live"]);
    assert_eq!(provider.rule_count(), 1);

    assert_real(
        &answer(&resolver, "old.fixture", RecordType::A).await,
        IpAddr::V4("192.0.2.9".parse().unwrap()),
    );
    assert_fake(
        &resolver,
        &answer(&resolver, "new.fixture", RecordType::A).await,
    );

    std::fs::write(
        directory.path().join("rules.yaml"),
        "payload:\n  - new.fixture\n",
    )
    .unwrap();
    provider.refresh().await.unwrap();
    assert_eq!(provider.rule_count(), 1);
    assert!(Arc::ptr_eq(&resolver, &config.dns.resolver));
    assert_fake(
        &resolver,
        &answer(&resolver, "old.fixture", RecordType::A).await,
    );
    assert_real(
        &answer(&resolver, "new.fixture", RecordType::A).await,
        IpAddr::V4("192.0.2.9".parse().unwrap()),
    );
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn resolver_rebuild_with_new_provider_keeps_existing_fake_ip_mapping() {
    let upstream = Upstream::start().await;
    let initial = configuration(
        upstream.address,
        "enhanced-mode: fake-ip\nfake-ip-range: '198.18.0.1/16'",
        &HashMap::new(),
        None,
        None,
        "",
    )
    .await
    .unwrap();
    let before = answer(&initial.resolver, "sticky.fixture", RecordType::A).await;
    let previous_ip = response_ip(&before);
    assert!(initial.resolver.is_fake_ip(previous_ip));

    let providers = inline_providers(
        "rule-providers:\n  newly-added:\n    type: inline\n    behavior: domain\n    payload: [new.fixture]\n",
    )
    .await;
    let rebuilt = configuration(
        upstream.address,
        "enhanced-mode: fake-ip\nfake-ip-range: '198.18.0.1/16'\nfake-ip-filter: ['rule-set:newly-added']",
        &providers,
        None,
        Some(&initial.resolver),
        "",
    )
    .await
    .unwrap();
    let after = answer(&rebuilt.resolver, "sticky.fixture", RecordType::A).await;
    assert_eq!(
        response_ip(&after),
        previous_ip,
        "reload keeps issued FakeIP"
    );
    assert_eq!(
        rebuilt.resolver.reverse_lookup(previous_ip).as_deref(),
        Some("sticky.fixture")
    );
    assert_real(
        &answer(&rebuilt.resolver, "new.fixture", RecordType::A).await,
        IpAddr::V4("192.0.2.9".parse().unwrap()),
    );
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn offline_validation_does_not_fetch_a_referenced_http_provider() {
    const CHILD_ENV: &str = "MEOW_FAKEIP_OFFLINE_TEST_CHILD";
    if std::env::var_os(CHILD_ENV).is_some() {
        meow_config::set_offline_validate(true);
        let port = std::env::var("MEOW_FAKEIP_OFFLINE_TEST_PORT").unwrap();
        let yaml = format!(
            "dns:\n  enable: true\n  use-system-hosts: false\n  nameserver: ['127.0.0.1:9']\n  enhanced-mode: fake-ip\n  fake-ip-filter-mode: blacklist\n  fake-ip-filter: ['rule-set:remote']\nrule-providers:\n  remote:\n    type: http\n    behavior: domain\n    url: http://127.0.0.1:{port}/rules\n    path: ./remote.yaml\n    interval: 0\n"
        );
        let config = load_config_from_str(&yaml).await.unwrap();
        assert_eq!(config.rule_providers["remote"].rule_count(), 0);
        return;
    }

    let sentinel = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    sentinel.set_nonblocking(true).unwrap();
    let port = sentinel.local_addr().unwrap().port().to_string();
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "offline_validation_does_not_fetch_a_referenced_http_provider",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .env("MEOW_FAKEIP_OFFLINE_TEST_PORT", &port)
            .output(),
    )
    .await
    .expect("offline child must finish promptly")
    .unwrap();
    assert!(
        output.status.success(),
        "offline child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        sentinel.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "offline validation attempted an HTTP provider fetch"
    );
}
