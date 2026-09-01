use config::{Config, File, FileFormat};
use hyper::{server::conn::Http, service::service_fn, Body, Request, Response};
use rust_verusd_rpc_server::auth::{compute_token, AuthCheckFailure, AuthState};
use rust_verusd_rpc_server::{
    configured_api_keys, handle_req, BlocklistIdentityCache, RequestPolicy, RequestPolicyRejection,
    VerusRPC,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

const BLOCKED_IADDR: &str = "iEHpmxiynXmwZKNgMm7BpXWP3EqCJt663q";
const SAFE_IADDR: &str = "i8byHmWFAeFMajYdgrXiQ9qZ1Y9FqxJUx1";
const BLOCKED_RADDR: &str = "RDCr3h5wYGoMh2QF7akoZy2GNsjCeSqgpu";
const BLOCKED_TXID: &str = "db97193d1a91f047cb14aa32a975be2e953924e1f4f0747cc20981edef6f4c28";
const PARENT_IADDR: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";
const DERIVED_TEST_IADDR: &str = "i8jHXEEYEQ7KEoYe6eKXBib8cUBZ6vjWSd";

fn config_from_toml(toml: &str) -> Config {
    Config::builder()
        .add_source(File::from_str(toml, FileFormat::Toml))
        .build()
        .unwrap()
}

fn policy(addresses: Vec<&str>, txids: Vec<&str>) -> RequestPolicy {
    RequestPolicy::new(
        Vec::new(),
        addresses.into_iter().map(str::to_owned).collect(),
        txids.into_iter().map(str::to_owned).collect(),
    )
    .unwrap()
    .with_identity_name_resolution_for_blocklist(true)
}

fn policy_without_identity_name_resolution(
    addresses: Vec<&str>,
    txids: Vec<&str>,
) -> RequestPolicy {
    RequestPolicy::new(
        Vec::new(),
        addresses.into_iter().map(str::to_owned).collect(),
        txids.into_iter().map(str::to_owned).collect(),
    )
    .unwrap()
}

fn policy_requiring_canonical_identity_names(
    addresses: Vec<&str>,
    txids: Vec<&str>,
) -> RequestPolicy {
    policy(addresses, txids).with_canonical_identity_leaf_names_required(true)
}

#[test]
fn nonempty_method_whitelist_is_an_additional_exact_gate() {
    let restricted =
        RequestPolicy::new(vec!["getinfo".to_string()], Vec::new(), Vec::new()).unwrap();
    assert!(restricted.method_is_whitelisted("getinfo"));
    assert!(!restricted.method_is_whitelisted("coinsupply"));

    let unrestricted = RequestPolicy::default();
    assert!(unrestricted.method_is_whitelisted("coinsupply"));
}

#[test]
fn policy_loads_lists_from_conf_and_secrets() {
    let settings = config_from_toml(
        r#"
        method_whitelist = ["getinfo", "getblock"]
        resolve_identity_names_for_blocklist = true
        require_canonical_identity_leaf_names = true
        "#,
    );
    let secrets = config_from_toml(&format!(
        "address_blocklist = [\"{BLOCKED_IADDR}\"]\ntxid_blocklist = [\"{BLOCKED_TXID}\"]"
    ));
    let loaded = RequestPolicy::from_config(&settings, &secrets).unwrap();
    assert_eq!(loaded.method_whitelist_len(), 2);
    assert_eq!(loaded.address_blocklist_len(), 1);
    assert_eq!(loaded.txid_blocklist_len(), 1);
    assert!(loaded.resolves_identity_names_for_blocklist());
    assert!(loaded.requires_canonical_identity_leaf_names());
}

#[test]
fn identity_name_resolution_defaults_off_and_rejects_invalid_configuration() {
    let secrets = config_from_toml(&format!("address_blocklist = [\"{BLOCKED_IADDR}\"]"));
    let missing =
        RequestPolicy::from_config(&config_from_toml("logging = false"), &secrets).unwrap();
    assert!(!missing.resolves_identity_names_for_blocklist());

    let explicitly_disabled = RequestPolicy::from_config(
        &config_from_toml("resolve_identity_names_for_blocklist = false"),
        &secrets,
    )
    .unwrap();
    assert!(!explicitly_disabled.resolves_identity_names_for_blocklist());

    assert!(RequestPolicy::from_config(
        &config_from_toml("resolve_identity_names_for_blocklist = 'sometimes'"),
        &secrets,
    )
    .is_err());
}

#[test]
fn canonical_identity_name_requirement_defaults_off_and_rejects_invalid_configuration() {
    let secrets = config_from_toml(&format!("address_blocklist = [\"{BLOCKED_IADDR}\"]"));
    let missing =
        RequestPolicy::from_config(&config_from_toml("logging = false"), &secrets).unwrap();
    assert!(!missing.requires_canonical_identity_leaf_names());

    let explicitly_disabled = RequestPolicy::from_config(
        &config_from_toml("require_canonical_identity_leaf_names = false"),
        &secrets,
    )
    .unwrap();
    assert!(!explicitly_disabled.requires_canonical_identity_leaf_names());

    let enabled = RequestPolicy::from_config(
        &config_from_toml("require_canonical_identity_leaf_names = true"),
        &secrets,
    )
    .unwrap();
    assert!(enabled.requires_canonical_identity_leaf_names());

    assert!(RequestPolicy::from_config(
        &config_from_toml("require_canonical_identity_leaf_names = 'sometimes'"),
        &secrets,
    )
    .is_err());
}

#[test]
fn checked_in_conf_whitelists_exact_mobile_rpc_surface() {
    let settings = config_from_toml(include_str!("../Conf.toml"));
    let secrets = config_from_toml("rpc_user = 'user'");
    let loaded = RequestPolicy::from_config(&settings, &secrets).unwrap();
    let expected = [
        "estimateconversion",
        "fundrawtransaction",
        "getaddressbalance",
        "getaddressdeltas",
        "getaddressmempool",
        "getaddressutxos",
        "getblock",
        "getblockhash",
        "getcurrency",
        "getcurrencyconverters",
        "getidentitieswithaddress",
        "getidentity",
        "getidentitycontent",
        "getinfo",
        "getrawtransaction",
        "getvdxfid",
        "listcurrencies",
        "sendcurrency",
        "sendrawtransaction",
        "updateidentity",
    ];
    assert_eq!(loaded.method_whitelist_len(), expected.len());
    for method in expected {
        assert!(loaded.method_is_whitelisted(method), "{method}");
    }
    assert!(!loaded.method_is_whitelisted("signdata"));
    assert!(!loaded.resolves_identity_names_for_blocklist());
    assert!(!loaded.requires_canonical_identity_leaf_names());
}

#[test]
fn malformed_policy_entries_fail_configuration() {
    assert!(RequestPolicy::new(Vec::new(), vec!["alice@".to_string()], Vec::new()).is_err());
    assert!(RequestPolicy::new(Vec::new(), Vec::new(), vec!["not-a-txid".to_string()]).is_err());
    assert!(RequestPolicy::new(
        vec!["getinfo".to_string(), "getinfo".to_string()],
        Vec::new(),
        Vec::new(),
    )
    .is_err());
}

#[test]
fn auth_enabled_requires_valid_nonempty_api_keys() {
    let missing = config_from_toml("rpc_user = 'user'");
    assert!(configured_api_keys(true, &missing).is_err());

    let empty = config_from_toml("[api_keys]");
    assert!(configured_api_keys(true, &empty).is_err());

    let malformed = config_from_toml("api_keys = ['not', 'a', 'table']");
    assert!(configured_api_keys(true, &malformed).is_err());

    let valid = config_from_toml("[api_keys]\nmobile = 'secret'");
    let keys = configured_api_keys(true, &valid).unwrap().unwrap();
    assert_eq!(keys.get("mobile").map(String::as_str), Some("secret"));
}

#[test]
fn auth_disabled_does_not_require_or_parse_api_keys() {
    let malformed = config_from_toml("api_keys = ['not', 'a', 'table']");
    assert!(configured_api_keys(false, &malformed).unwrap().is_none());
}

fn auth_state(keys: &[(&str, &str)]) -> AuthState {
    AuthState::new(
        keys.iter()
            .map(|(app_id, key)| ((*app_id).to_string(), (*key).to_string()))
            .collect::<HashMap<_, _>>(),
    )
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

#[test]
fn invalid_auth_token_does_not_burn_legitimate_replay_tuple() {
    let auth = auth_state(&[("mobile", "secret")]);
    let body = r#"{"method":"getinfo","params":[]}"#;
    let timestamp = now_ms();
    let salt = "a".repeat(64);

    assert_eq!(
        auth.check_token_detailed(&"0".repeat(128), body, timestamp, "mobile", "2", &salt,),
        Err(AuthCheckFailure::InvalidToken)
    );

    let valid = compute_token("secret", body, timestamp, "mobile", "2", &salt);
    assert_eq!(
        auth.check_token_detailed(&valid, body, timestamp, "mobile", "2", &salt),
        Ok(())
    );
}

#[test]
fn replay_tuple_is_scoped_by_application_id() {
    let auth = auth_state(&[("mobile", "mobile-secret"), ("web", "web-secret")]);
    let body = r#"{"method":"getinfo","params":[]}"#;
    let timestamp = now_ms();
    let salt = "b".repeat(64);
    let mobile_token = compute_token("mobile-secret", body, timestamp, "mobile", "2", &salt);
    let web_token = compute_token("web-secret", body, timestamp, "web", "2", &salt);

    assert_eq!(
        auth.check_token_detailed(&mobile_token, body, timestamp, "mobile", "2", &salt),
        Ok(())
    );
    assert_eq!(
        auth.check_token_detailed(&web_token, body, timestamp, "web", "2", &salt),
        Ok(())
    );
    assert!(matches!(
        auth.check_token_detailed(&mobile_token, body, timestamp, "mobile", "2", &salt),
        Err(AuthCheckFailure::Replay { .. })
    ));
}

#[test]
fn extreme_auth_timestamps_are_rejected_without_overflow() {
    let auth = auth_state(&[("mobile", "secret")]);
    for timestamp in [i64::MIN, i64::MAX] {
        assert!(matches!(
            auth.check_token_detailed("", "body", timestamp, "mobile", "2", &"c".repeat(64)),
            Err(AuthCheckFailure::TimestampOutOfWindow { .. })
        ));
    }
}

#[test]
fn direct_address_is_blocked_for_every_configured_lookup_method() {
    let policy = policy(vec![BLOCKED_IADDR, BLOCKED_RADDR], Vec::new());
    let requests = [
        (
            "getaddressutxos",
            json!([{"addresses": [SAFE_IADDR, BLOCKED_IADDR]}]),
        ),
        ("getaddressmempool", json!([{"addresses": [BLOCKED_RADDR]}])),
        ("getaddressbalance", json!([{"addresses": [BLOCKED_IADDR]}])),
        ("getaddressdeltas", json!([{"addresses": [BLOCKED_RADDR]}])),
        (
            "getidentitieswithaddress",
            json!([{"address": BLOCKED_RADDR}]),
        ),
        ("getidentity", json!([BLOCKED_IADDR])),
        ("getidentitycontent", json!([BLOCKED_IADDR])),
    ];

    for (method, params) in requests {
        let result = policy.check_blocklists(
            method,
            params.as_array().unwrap(),
            |_| -> Result<String, ()> { panic!("direct address must not be resolved") },
        );
        assert_eq!(result, Err(RequestPolicyRejection::Blocked), "{method}");
    }

    let update = json!([{"identityaddress": BLOCKED_IADDR, "name": "alice"}, true]);
    assert_eq!(
        policy.check_blocklists(
            "updateidentity",
            update.as_array().unwrap(),
            |identity_name| {
                assert_eq!(identity_name, "alice@");
                Ok(BLOCKED_IADDR.to_string())
            },
        ),
        Err(RequestPolicyRejection::Blocked)
    );
}

#[test]
fn safe_direct_identity_address_is_allowed_without_resolution() {
    let policy = policy(vec![BLOCKED_IADDR], Vec::new());
    for method in ["getidentity", "getidentitycontent"] {
        let params = json!([SAFE_IADDR]);
        assert_eq!(
            policy.check_blocklists(
                method,
                params.as_array().unwrap(),
                |_| -> Result<String, ()> {
                    panic!("direct identity addresses must not be resolved")
                }
            ),
            Ok(()),
            "{method}"
        );
    }
}

#[test]
fn human_readable_identity_is_resolved_with_getvdxfid_semantics() {
    let policy = policy(vec![BLOCKED_IADDR], Vec::new());
    for method in ["getidentity", "getidentitycontent"] {
        let params = json!(["alice"]);
        let mut called = false;
        let result = policy.check_blocklists(method, params.as_array().unwrap(), |identity_name| {
            called = true;
            assert_eq!(identity_name, "alice@");
            Ok(BLOCKED_IADDR.to_string())
        });
        assert!(called, "{method}");
        assert_eq!(result, Err(RequestPolicyRejection::Blocked), "{method}");
    }
}

#[test]
fn explicitly_qualified_identity_name_is_resolved_without_rewriting() {
    let policy = policy(vec![BLOCKED_IADDR], Vec::new());
    let params = json!(["alice@other"]);
    assert_eq!(
        policy.check_blocklists("getidentity", params.as_array().unwrap(), |identity_name| {
            assert_eq!(identity_name, "alice@other");
            Ok(BLOCKED_IADDR.to_string())
        }),
        Err(RequestPolicyRejection::Blocked)
    );
}

#[test]
fn human_readable_identity_resolution_fails_closed() {
    let policy = policy(vec![BLOCKED_IADDR], Vec::new());
    let params = json!(["alice@"]);
    assert_eq!(
        policy.check_blocklists(
            "getidentitycontent",
            params.as_array().unwrap(),
            |_| Err(()),
        ),
        Err(RequestPolicyRejection::IdentityResolutionFailed)
    );
}

#[test]
fn identity_names_require_direct_i_addresses_when_resolution_is_disabled() {
    let policy = policy_without_identity_name_resolution(vec![BLOCKED_IADDR], Vec::new());

    for method in ["getidentity", "getidentitycontent"] {
        let blocked = json!([BLOCKED_IADDR]);
        assert_eq!(
            policy.check_blocklists(
                method,
                blocked.as_array().unwrap(),
                |_| -> Result<String, ()> { panic!("direct i-address must not be resolved") },
            ),
            Err(RequestPolicyRejection::Blocked),
            "{method}"
        );

        let friendly = json!(["alice"]);
        assert_eq!(
            policy.check_blocklists(
                method,
                friendly.as_array().unwrap(),
                |_| -> Result<String, ()> { panic!("identity lookup must remain disabled") },
            ),
            Err(RequestPolicyRejection::IdentityNameLookupDisabled),
            "{method}"
        );

        let transparent = json!([BLOCKED_RADDR]);
        assert_eq!(
            policy.check_blocklists(
                method,
                transparent.as_array().unwrap(),
                |_| -> Result<String, ()> { panic!("R-addresses must not be resolved") },
            ),
            Err(RequestPolicyRejection::InvalidAddress),
            "{method}"
        );

        let direct = json!([SAFE_IADDR]);
        assert_eq!(
            policy.check_blocklists(
                method,
                direct.as_array().unwrap(),
                |_| -> Result<String, ()> { panic!("direct i-address must not be resolved") },
            ),
            Ok(()),
            "{method}"
        );
    }
}

#[test]
fn address_index_methods_never_resolve_identity_names() {
    let policy = policy(vec![BLOCKED_IADDR], Vec::new());
    for method in [
        "getaddressutxos",
        "getaddressmempool",
        "getaddressbalance",
        "getaddressdeltas",
    ] {
        let params = json!([{"addresses": ["alice"]}]);
        assert_eq!(
            policy.check_blocklists(
                method,
                params.as_array().unwrap(),
                |_| -> Result<String, ()> { panic!("address-index inputs must not be resolved") },
            ),
            Err(RequestPolicyRejection::InvalidAddress),
            "{method}"
        );
    }

    let primary_address = json!([{"address": BLOCKED_RADDR}]);
    assert_eq!(
        policy.check_blocklists(
            "getidentitieswithaddress",
            primary_address.as_array().unwrap(),
            |_| -> Result<String, ()> { panic!("primary addresses must not be resolved") },
        ),
        Ok(())
    );
    let friendly = json!([{"address": "alice"}]);
    assert_eq!(
        policy.check_blocklists(
            "getidentitieswithaddress",
            friendly.as_array().unwrap(),
            |_| -> Result<String, ()> { panic!("primary addresses must not be resolved") },
        ),
        Err(RequestPolicyRejection::InvalidAddress)
    );
}

#[test]
fn empty_address_blocklist_never_resolves_or_rejects_identity_names() {
    for policy in [
        policy_without_identity_name_resolution(Vec::new(), Vec::new()),
        policy(Vec::new(), Vec::new()),
    ] {
        for (method, params) in [
            ("getidentity", json!(["alice"])),
            ("getidentitycontent", json!(["alice"])),
            ("updateidentity", json!([{"name": "alice"}, true])),
            ("updateidentity", json!([{"name": "alice@other"}, true])),
            (
                "updateidentity",
                json!([{
                    "name": "alice.child",
                    "parent": PARENT_IADDR,
                    "identityaddress": SAFE_IADDR
                }, true]),
            ),
            (
                "getaddressbalance",
                json!([{"addresses": ["not-an-address"]}]),
            ),
        ] {
            assert_eq!(
                policy.check_blocklists(
                    method,
                    params.as_array().unwrap(),
                    |_| -> Result<String, ()> { panic!("empty blocklist must bypass all lookups") },
                ),
                Ok(()),
                "{method}"
            );
        }
    }
}

#[test]
fn updateidentity_name_only_shape_is_resolved_and_allowed_when_not_blocked() {
    let policy = policy(vec![BLOCKED_IADDR], Vec::new());
    let params = json!([{"name": "alice"}, true]);
    let mut called = false;
    assert_eq!(
        policy.check_blocklists(
            "updateidentity",
            params.as_array().unwrap(),
            |identity_name| {
                called = true;
                assert_eq!(identity_name, "alice@");
                Ok(SAFE_IADDR.to_string())
            },
        ),
        Ok(())
    );
    assert!(called);
}

#[test]
fn canonical_identity_name_requirement_is_opt_in_and_independent_of_blocklists() {
    let permissive = policy_without_identity_name_resolution(Vec::new(), Vec::new());
    let strict = permissive
        .clone()
        .with_canonical_identity_leaf_names_required(true);

    for name in [
        "alice@other".to_string(),
        "alice.child".to_string(),
        "alice\n".to_string(),
        "x".repeat(65),
    ] {
        let params = json!([{"name": name}, true]);
        assert_eq!(
            permissive.check_blocklists(
                "updateidentity",
                params.as_array().unwrap(),
                |_| -> Result<String, ()> { panic!("empty blocklist must bypass lookups") },
            ),
            Ok(()),
            "{name:?}"
        );
        assert_eq!(
            strict.check_blocklists(
                "updateidentity",
                params.as_array().unwrap(),
                |_| -> Result<String, ()> { panic!("canonical validation must not use lookups") },
            ),
            Err(RequestPolicyRejection::NonCanonicalIdentityName),
            "{name:?}"
        );
    }

    let canonical = json!([{"name": "x".repeat(64)}, true]);
    assert_eq!(
        strict.check_blocklists(
            "updateidentity",
            canonical.as_array().unwrap(),
            |_| -> Result<String, ()> { panic!("empty blocklist must bypass lookups") },
        ),
        Ok(())
    );
}

#[test]
fn updateidentity_root_target_preserves_explicit_identity_qualifiers() {
    let policy = policy(vec![BLOCKED_IADDR], Vec::new());
    for (name, expected_selector) in [
        ("alice@other", "alice@other"),
        ("alice.child", "alice.child@"),
    ] {
        let params = json!([{"name": name}, true]);
        assert_eq!(
            policy.check_blocklists(
                "updateidentity",
                params.as_array().unwrap(),
                |identity_name| {
                    assert_eq!(identity_name, expected_selector);
                    Ok(SAFE_IADDR.to_string())
                },
            ),
            Ok(()),
            "{name:?}"
        );
    }
}

#[test]
fn updateidentity_noncanonical_parent_target_fails_closed_for_a_nonempty_blocklist() {
    let policy = policy(vec![BLOCKED_IADDR], Vec::new());
    let params = json!([{
        "name": "alice.child",
        "parent": PARENT_IADDR,
        "identityaddress": SAFE_IADDR
    }, true]);
    assert_eq!(
        policy.check_blocklists(
            "updateidentity",
            params.as_array().unwrap(),
            |_| -> Result<String, ()> { panic!("parented targets must not use name lookup") },
        ),
        Err(RequestPolicyRejection::IdentityResolutionFailed)
    );
}

#[test]
fn canonical_identity_name_requirement_composes_with_blocklist_checks() {
    let policy = policy_requiring_canonical_identity_names(vec![BLOCKED_IADDR], Vec::new());
    let noncanonical = json!([{"name": "alice@other"}, true]);
    assert_eq!(
        policy.check_blocklists(
            "updateidentity",
            noncanonical.as_array().unwrap(),
            |_| -> Result<String, ()> { panic!("invalid names must fail before lookup") },
        ),
        Err(RequestPolicyRejection::NonCanonicalIdentityName)
    );

    let canonical = json!([{"name": "alice"}, true]);
    assert_eq!(
        policy.check_blocklists(
            "updateidentity",
            canonical.as_array().unwrap(),
            |identity_name| {
                assert_eq!(identity_name, "alice@");
                Ok(SAFE_IADDR.to_string())
            },
        ),
        Ok(())
    );
}

#[test]
fn updateidentity_root_target_is_rejected_when_resolution_is_disabled() {
    let policy = policy_without_identity_name_resolution(vec![BLOCKED_IADDR], Vec::new());
    for params in [
        json!([{"name": "alice"}, true]),
        json!([{"name": "alice", "identityaddress": SAFE_IADDR}, true]),
    ] {
        assert_eq!(
            policy.check_blocklists(
                "updateidentity",
                params.as_array().unwrap(),
                |_| -> Result<String, ()> { panic!("root identity lookup must remain disabled") },
            ),
            Err(RequestPolicyRejection::IdentityNameLookupDisabled)
        );
    }
}

#[test]
fn updateidentity_parent_target_is_derived_and_must_match_supplied_address() {
    let unblocked_policy = policy_without_identity_name_resolution(vec![BLOCKED_IADDR], Vec::new());
    let missing_address = json!([{"name": "test", "parent": PARENT_IADDR}, true]);
    assert_eq!(
        unblocked_policy.check_blocklists(
            "updateidentity",
            missing_address.as_array().unwrap(),
            |_| -> Result<String, ()> { panic!("parented identities must be derived locally") },
        ),
        Err(RequestPolicyRejection::IdentityResolutionFailed)
    );

    let matching = json!([{
        "name": "test",
        "parent": PARENT_IADDR,
        "identityaddress": DERIVED_TEST_IADDR
    }, true]);
    assert_eq!(
        unblocked_policy.check_blocklists(
            "updateidentity",
            matching.as_array().unwrap(),
            |_| -> Result<String, ()> { panic!("parented identities must be derived locally") },
        ),
        Ok(())
    );

    let mismatched = json!([{
        "name": "test",
        "parent": PARENT_IADDR,
        "identityaddress": SAFE_IADDR
    }, true]);
    assert_eq!(
        unblocked_policy.check_blocklists(
            "updateidentity",
            mismatched.as_array().unwrap(),
            |_| -> Result<String, ()> { panic!("parented identities must be derived locally") },
        ),
        Err(RequestPolicyRejection::IdentityResolutionFailed)
    );

    let blocked_policy =
        policy_without_identity_name_resolution(vec![DERIVED_TEST_IADDR], Vec::new());
    assert_eq!(
        blocked_policy.check_blocklists(
            "updateidentity",
            matching.as_array().unwrap(),
            |_| -> Result<String, ()> { panic!("parented identities must be derived locally") },
        ),
        Err(RequestPolicyRejection::Blocked)
    );
}

#[test]
fn updateidentity_name_is_always_resolved_semantically() {
    let policy = policy(vec![BLOCKED_IADDR], Vec::new());
    let params = json!([{"name": SAFE_IADDR}, true]);
    assert_eq!(
        policy.check_blocklists(
            "updateidentity",
            params.as_array().unwrap(),
            |identity_name| {
                assert_eq!(identity_name, format!("{SAFE_IADDR}@"));
                Ok(BLOCKED_IADDR.to_string())
            },
        ),
        Err(RequestPolicyRejection::Blocked)
    );
}

#[test]
fn updateidentity_root_supplied_address_must_match_resolved_target() {
    let policy = policy(vec![BLOCKED_IADDR], Vec::new());
    let params = json!([{"name": "alice", "identityaddress": SAFE_IADDR}, true]);
    assert_eq!(
        policy.check_blocklists(
            "updateidentity",
            params.as_array().unwrap(),
            |identity_name| {
                assert_eq!(identity_name, "alice@");
                Ok(BLOCKED_IADDR.to_string())
            },
        ),
        Err(RequestPolicyRejection::IdentityResolutionFailed)
    );
}

#[test]
fn updateidentity_checks_all_address_bearing_identity_fields() {
    let policy = policy(vec![BLOCKED_RADDR], Vec::new());
    let params = json!([{
        "identityaddress": DERIVED_TEST_IADDR,
        "name": "test",
        "parent": PARENT_IADDR,
        "primaryaddresses": [BLOCKED_RADDR],
        "recoveryauthority": SAFE_IADDR,
        "revocationauthority": SAFE_IADDR,
        "systemid": SAFE_IADDR
    }, true]);
    assert_eq!(
        policy.check_blocklists(
            "updateidentity",
            params.as_array().unwrap(),
            |_| -> Result<String, ()> { panic!("parented identities must be derived locally") },
        ),
        Err(RequestPolicyRejection::Blocked)
    );
}

#[test]
fn txid_blocklist_is_case_insensitive() {
    let policy = policy(Vec::new(), vec![BLOCKED_TXID]);
    let raw_tx_params = json!([BLOCKED_TXID.to_ascii_uppercase(), 1]);
    assert_eq!(
        policy.check_blocklists(
            "getrawtransaction",
            raw_tx_params.as_array().unwrap(),
            |_| Err(()),
        ),
        Err(RequestPolicyRejection::Blocked)
    );
    let block_params = json!([BLOCKED_TXID]);
    assert_eq!(
        policy.check_blocklists("getblock", block_params.as_array().unwrap(), |_| Err(())),
        Ok(())
    );
}

async fn spawn_vdxf_backend(resolved: &'static str) -> (String, Arc<Mutex<Vec<String>>>) {
    spawn_vdxf_backend_with_responses(vec![resolved]).await
}

async fn spawn_vdxf_backend_with_responses(
    responses: Vec<&'static str>,
) -> (String, Arc<Mutex<Vec<String>>>) {
    assert!(!responses.is_empty());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let resolved_selectors = Arc::new(Mutex::new(Vec::new()));
    let resolved_selectors_in_server = resolved_selectors.clone();
    let responses = Arc::new(Mutex::new(responses));
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let resolved_selectors = resolved_selectors_in_server.clone();
            let responses = responses.clone();
            tokio::spawn(async move {
                let mut http = Http::new();
                http.http1_keep_alive(false)
                    .serve_connection(
                        tcp,
                        service_fn(move |request: Request<Body>| {
                            let resolved_selectors = resolved_selectors.clone();
                            let responses = responses.clone();
                            async move {
                                let bytes =
                                    hyper::body::to_bytes(request.into_body()).await.unwrap();
                                let request_json: Value = serde_json::from_slice(&bytes).unwrap();
                                assert_eq!(request_json["method"], "getvdxfid");
                                let selector = request_json["params"][0]
                                    .as_str()
                                    .expect("getvdxfid selector must be a string")
                                    .to_owned();
                                resolved_selectors
                                    .lock()
                                    .unwrap_or_else(|error| error.into_inner())
                                    .push(selector);
                                let resolved = {
                                    let mut responses =
                                        responses.lock().unwrap_or_else(|error| error.into_inner());
                                    if responses.len() > 1 {
                                        responses.remove(0)
                                    } else {
                                        responses[0]
                                    }
                                };
                                let response = json!({
                                    "result": {"vdxfid": resolved},
                                    "error": null,
                                    "id": request_json["id"]
                                });
                                // jsonrpc 0.12's SimpleHttpTransport reads the response
                                // body as a line, so terminate it explicitly.
                                let response_body = format!("{response}\n");
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .header(hyper::header::CONNECTION, "close")
                                        .header(hyper::header::CONTENT_LENGTH, response_body.len())
                                        .body(Body::from(response_body))
                                        .unwrap(),
                                )
                            }
                        }),
                    )
                    .await
                    .unwrap();
            });
        }
    });
    (addr.to_string(), resolved_selectors)
}

async fn blocked_identity_response(rpc: Arc<VerusRPC>, selector: &str) -> Value {
    let request = Request::post("/")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"method": "getidentitycontent", "params": [selector]}).to_string(),
        ))
        .unwrap();
    let response = handle_req(request, rpc, None, None).await.unwrap();
    serde_json::from_slice(&hyper::body::to_bytes(response.into_body()).await.unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_resolves_human_identity_and_rejects_blocked_result() {
    let (backend, resolved_selectors) = spawn_vdxf_backend(BLOCKED_IADDR).await;
    let policy = policy(vec![BLOCKED_IADDR], Vec::new());
    let rpc = Arc::new(VerusRPC::new_with_policy(&backend, "user", "pass", policy).unwrap());
    let request = Request::post("/")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"method":"getidentitycontent","params":["alice"]}"#,
        ))
        .unwrap();
    let response = handle_req(request, rpc, None, None).await.unwrap();
    let body: Value =
        serde_json::from_slice(&hyper::body::to_bytes(response.into_body()).await.unwrap())
            .unwrap();
    assert_eq!(body["error"]["code"], -32602);
    assert_eq!(
        *resolved_selectors
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
        vec!["alice@"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_shares_blocklist_identity_cache_across_rpc_connections() {
    let (backend, resolved_selectors) = spawn_vdxf_backend(BLOCKED_IADDR).await;
    let policy = policy(vec![BLOCKED_IADDR], Vec::new());
    let cache = Arc::new(BlocklistIdentityCache::new());

    for _ in 0..2 {
        let rpc = Arc::new(
            VerusRPC::new_with_policy_and_blocklist_identity_cache(
                &backend,
                "user",
                "pass",
                policy.clone(),
                cache.clone(),
            )
            .unwrap(),
        );
        let body = blocked_identity_response(rpc, "alice").await;
        assert_eq!(body["error"]["code"], -32602);
    }

    assert_eq!(
        *resolved_selectors
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
        vec!["alice@"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocklist_identity_cache_keeps_aliases_as_distinct_keys() {
    let (backend, resolved_selectors) = spawn_vdxf_backend(BLOCKED_IADDR).await;
    let policy = policy(vec![BLOCKED_IADDR], Vec::new());
    let cache = Arc::new(BlocklistIdentityCache::new());
    let rpc = Arc::new(
        VerusRPC::new_with_policy_and_blocklist_identity_cache(
            &backend, "user", "pass", policy, cache,
        )
        .unwrap(),
    );

    for selector in ["alice", "alice@other", "alice", "alice@other"] {
        let body = blocked_identity_response(rpc.clone(), selector).await;
        assert_eq!(body["error"]["code"], -32602);
    }

    assert_eq!(
        *resolved_selectors
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
        vec!["alice@", "alice@other"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocklist_identity_cache_does_not_store_malformed_daemon_results() {
    let (backend, resolved_selectors) =
        spawn_vdxf_backend_with_responses(vec!["not-an-i-address", BLOCKED_IADDR]).await;
    let policy = policy(vec![BLOCKED_IADDR], Vec::new());
    let cache = Arc::new(BlocklistIdentityCache::new());
    let rpc = Arc::new(
        VerusRPC::new_with_policy_and_blocklist_identity_cache(
            &backend, "user", "pass", policy, cache,
        )
        .unwrap(),
    );

    for _ in 0..3 {
        let body = blocked_identity_response(rpc.clone(), "alice").await;
        assert_eq!(body["error"]["code"], -32602);
    }

    assert_eq!(
        *resolved_selectors
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
        vec!["alice@", "alice@"]
    );
}

#[tokio::test]
async fn handler_rejects_identity_name_when_resolution_is_disabled() {
    let policy = policy_without_identity_name_resolution(vec![BLOCKED_IADDR], Vec::new());
    let rpc = Arc::new(VerusRPC::new_with_policy("127.0.0.1:1", "user", "pass", policy).unwrap());
    let request = Request::post("/")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"method":"getidentity","params":["alice"]}"#))
        .unwrap();
    let response = handle_req(request, rpc, None, None).await.unwrap();
    let body: Value =
        serde_json::from_slice(&hyper::body::to_bytes(response.into_body()).await.unwrap())
            .unwrap();
    assert_eq!(body["error"]["code"], -32602);
}

#[tokio::test]
async fn handler_applies_method_whitelist_after_builtin_allowlist() {
    let policy = RequestPolicy::new(vec!["getinfo".to_string()], Vec::new(), Vec::new()).unwrap();
    let rpc = Arc::new(VerusRPC::new_with_policy("127.0.0.1:1", "user", "pass", policy).unwrap());
    let request = Request::post("/")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"method":"coinsupply","params":[]}"#))
        .unwrap();
    let response = handle_req(request, rpc, None, None).await.unwrap();
    let body: Value =
        serde_json::from_slice(&hyper::body::to_bytes(response.into_body()).await.unwrap())
            .unwrap();
    assert_eq!(body["error"]["code"], -32601);
}
