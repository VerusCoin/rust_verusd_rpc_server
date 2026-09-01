use rust_verusd_rpc_server::allowlist::{
    is_method_allowed, MAX_ADDRESS_COUNT, MAX_RAW_TRANSACTION_BYTES, MAX_UTXO_COUNT,
};
use serde_json::value::RawValue;
use serde_json::{json, Value};

fn raw(s: &str) -> Box<RawValue> {
    RawValue::from_string(s.to_string()).unwrap()
}

fn raw_json(value: Value) -> Box<RawValue> {
    raw(&value.to_string())
}

const TXID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const IADDR: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";
const CHILD_IADDR: &str = "i8jHXEEYEQ7KEoYe6eKXBib8cUBZ6vjWSd";
const SPACED_CHILD_IADDR: &str = "i8Wnt3KJNEN91fdXmwJNHGtD6PxMJPuE6p";
const UTXO: &str =
    "{\"txid\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"voutnum\":0}";
const SEND_OUTPUT: &str = "[{\"currency\":\"VRSC\",\"amount\":1.25,\"address\":\"Rdestination\"}]";

// ── check_params behavior via is_method_allowed ───────────────────────────────
// check_params is an internal function; its type-checking and arity logic is
// exercised here through the public is_method_allowed surface.

#[test]
fn type_check_int_accepted() {
    assert!(is_method_allowed("getblockhash", &[raw("100")]));
}

#[test]
fn type_check_string_rejected_for_int_param() {
    assert!(!is_method_allowed("getblockhash", &[raw("\"100\"")]));
}

#[test]
fn arity_fewer_params_than_declared_accepted() {
    // decoderawtransaction takes [str, bool]; one param is fine (bool is optional)
    assert!(is_method_allowed(
        "decoderawtransaction",
        &[raw("\"deadbeef\"")]
    ));
}

#[test]
fn arity_more_params_than_declared_rejected() {
    // getinfo takes no params; one extra is rejected
    assert!(!is_method_allowed("getinfo", &[raw("\"extra\"")]));
}

#[test]
fn type_check_obj_accepted() {
    assert!(is_method_allowed(
        "getaddressbalance",
        &[raw("{\"addresses\":[\"Raddress\"]}")]
    ));
}

#[test]
fn type_check_array_rejected_for_obj_param() {
    assert!(!is_method_allowed("getaddressbalance", &[raw("[1, 2]")]));
}

#[test]
fn type_check_arr_accepted() {
    assert!(is_method_allowed(
        "createmultisig",
        &[raw("2"), raw("[\"addr1\"]")]
    ));
}

#[test]
fn type_check_obj_rejected_for_arr_param() {
    assert!(!is_method_allowed("createmultisig", &[raw("2"), raw("{}")]));
}

#[test]
fn type_check_float_accepted() {
    // registeridentity: [obj, bool, float, str] — param[2] is float
    assert!(is_method_allowed(
        "registeridentity",
        &[raw("{}"), raw("true"), raw("0.001"), raw("\"addr\""),]
    ));
}

#[test]
fn type_check_integer_rejected_for_float_param() {
    // Integer `1` is not an f64 in serde_json
    assert!(!is_method_allowed(
        "registeridentity",
        &[raw("{}"), raw("true"), raw("1"), raw("\"addr\""),]
    ));
}

#[test]
fn type_check_bool_accepted() {
    assert!(is_method_allowed(
        "decoderawtransaction",
        &[raw("\"hex\""), raw("true")]
    ));
    assert!(is_method_allowed(
        "decoderawtransaction",
        &[raw("\"hex\""), raw("false")]
    ));
}

#[test]
fn type_check_integer_rejected_for_bool_param() {
    assert!(!is_method_allowed(
        "decoderawtransaction",
        &[raw("\"hex\""), raw("1")]
    ));
}

// ── Read-only methods ─────────────────────────────────────────────────────────

#[test]
fn getinfo_no_params_allowed() {
    assert!(is_method_allowed("getinfo", &[]));
}

#[test]
fn getinfo_with_params_blocked() {
    assert!(!is_method_allowed("getinfo", &[raw("\"unexpected\"")]));
}

#[test]
fn getblock_string_hash_allowed() {
    assert!(is_method_allowed("getblock", &[raw("\"000abc\"")]));
}

#[test]
fn getblock_quoted_numeric_string_allowed() {
    // handle() converts raw integers to "\"N\"" before calling is_method_allowed;
    // the allowlist only ever sees the quoted form.
    assert!(is_method_allowed("getblock", &[raw("\"12345\"")]));
}

#[test]
fn getblock_raw_integer_blocked() {
    // A raw integer bypasses handle()'s conversion and fails the "str" type check.
    assert!(!is_method_allowed("getblock", &[raw("12345")]));
}

#[test]
fn getblockhash_int_allowed() {
    assert!(is_method_allowed("getblockhash", &[raw("100")]));
}

#[test]
fn getblockhash_string_blocked() {
    assert!(!is_method_allowed("getblockhash", &[raw("\"100\"")]));
}

#[test]
fn getrawtransaction_str_int_allowed() {
    assert!(is_method_allowed(
        "getrawtransaction",
        &[raw(&format!("\"{TXID}\"")), raw("1")]
    ));
}

#[test]
fn getidentity_string_param_allowed() {
    assert!(is_method_allowed("getidentity", &[raw("\"test@\"")]));
}

#[test]
fn totally_unknown_methods_blocked() {
    for m in &[
        "getbalance",
        "listaccounts",
        "importprivkey",
        "dumpprivkey",
        "stop",
    ] {
        assert!(!is_method_allowed(m, &[]), "{} should be blocked", m);
    }
}

// ── Write operations requiring simulation flag ────────────────────────────────

#[test]
fn sendcurrency_simulation_true_allowed() {
    assert!(is_method_allowed(
        "sendcurrency",
        &[
            raw("\"*\""),
            raw(SEND_OUTPUT),
            raw("1"),
            raw("0.0001"),
            raw("true"),
        ]
    ));
}

#[test]
fn sendcurrency_simulation_false_blocked() {
    assert!(!is_method_allowed(
        "sendcurrency",
        &[
            raw("\"*\""),
            raw(SEND_OUTPUT),
            raw("1"),
            raw("0.0001"),
            raw("false"),
        ]
    ));
}

#[test]
fn sendcurrency_missing_simulation_flag_blocked() {
    assert!(!is_method_allowed(
        "sendcurrency",
        &[raw("\"*\""), raw(SEND_OUTPUT), raw("1"), raw("0.0001"),]
    ));
}

#[test]
fn registeridentity_simulation_true_allowed() {
    assert!(is_method_allowed(
        "registeridentity",
        &[raw("{}"), raw("true"), raw("0.001"), raw("\"\""),]
    ));
}

#[test]
fn registeridentity_simulation_false_blocked() {
    assert!(!is_method_allowed(
        "registeridentity",
        &[raw("{}"), raw("false"), raw("0.001"), raw("\"\""),]
    ));
}

#[test]
fn updateidentity_simulation_true_allowed() {
    assert!(is_method_allowed(
        "updateidentity",
        &[raw("{\"name\":\"alice\"}"), raw("true")]
    ));
}

#[test]
fn revokeidentity_simulation_true_allowed() {
    assert!(is_method_allowed(
        "revokeidentity",
        &[
            raw("\"id@\""),
            raw("true"),
            raw("false"),
            raw("0.001"),
            raw("\"\""),
        ]
    ));
}

#[test]
fn recoveridentity_simulation_true_allowed() {
    assert!(is_method_allowed(
        "recoveridentity",
        &[
            raw("{}"),
            raw("true"),
            raw("false"),
            raw("0.001"),
            raw("\"\""),
        ]
    ));
}

#[test]
fn setidentitytimelock_simulation_at_index2_true_allowed() {
    assert!(is_method_allowed(
        "setidentitytimelock",
        &[
            raw("\"id@\""),
            raw("{}"),
            raw("true"),
            raw("0.001"),
            raw("\"\""),
        ]
    ));
}

#[test]
fn setidentitytimelock_simulation_false_blocked() {
    assert!(!is_method_allowed(
        "setidentitytimelock",
        &[
            raw("\"id@\""),
            raw("{}"),
            raw("false"),
            raw("0.001"),
            raw("\"\""),
        ]
    ));
}

// ── signdata address guard ────────────────────────────────────────────────────

#[test]
fn signdata_with_address_field_blocked() {
    assert!(!is_method_allowed(
        "signdata",
        &[raw("{\"address\":\"R1\",\"data\":\"aa\"}")]
    ));
}

#[test]
fn signdata_without_address_field_allowed() {
    assert!(is_method_allowed(
        "signdata",
        &[raw("{\"data\":\"aabbcc\"}")]
    ));
}

#[test]
fn signdata_empty_object_allowed() {
    assert!(is_method_allowed("signdata", &[raw("{}")]));
}

#[test]
fn signdata_non_object_blocked() {
    assert!(!is_method_allowed("signdata", &[raw("\"notanobj\"")]));
}

#[test]
fn signdata_zero_params_blocked() {
    assert!(!is_method_allowed("signdata", &[]));
}

#[test]
fn signdata_two_params_blocked() {
    assert!(!is_method_allowed(
        "signdata",
        &[raw("{\"data\":\"aa\"}"), raw("{\"extra\":1}")]
    ));
}

#[test]
fn filename_is_rejected_at_any_depth() {
    assert!(!is_method_allowed(
        "signdata",
        &[raw_json(json!({"filename": "Secrets.toml"}))]
    ));
    assert!(!is_method_allowed(
        "signdata",
        &[raw_json(json!({
            "mmrdata": [{"message": "safe"}, {"filename": "VRSC.conf"}]
        }))]
    ));
    assert!(!is_method_allowed(
        "submitimports",
        &[raw_json(json!({"outer": [{"inner": {"filename": "x"}}]}))]
    ));
}

#[test]
fn sendcurrency_nested_filename_is_rejected() {
    assert!(!is_method_allowed(
        "sendcurrency",
        &[
            raw("\"*\""),
            raw_json(json!([{
                "currency": "VRSC",
                "amount": 1,
                "address": "zsDestination",
                "data": {"mmrdata": [{"filename": "Secrets.toml"}]}
            }])),
            raw("1"),
            raw("0.0001"),
            raw("true"),
        ]
    ));
}

#[test]
fn updateidentity_nested_filename_is_rejected() {
    assert!(!is_method_allowed(
        "updateidentity",
        &[
            raw_json(json!({
                "name": "alice",
                "contentmultimap": {
                    "iVdxfKey": {
                        "data": {"mmrdata": [{"filename": "VRSC.conf"}]}
                    }
                }
            })),
            raw("true"),
        ]
    ));
}

// ── fundrawtransaction ────────────────────────────────────────────────────────

#[test]
fn fundrawtransaction_4_params_allowed() {
    assert!(is_method_allowed(
        "fundrawtransaction",
        &[
            raw("\"deadbeef\""),
            raw(&format!("[{UTXO}]")),
            raw("\"VRSC\""),
            raw("0.001"),
        ]
    ));
}

#[test]
fn fundrawtransaction_3_params_allowed() {
    assert!(is_method_allowed(
        "fundrawtransaction",
        &[
            raw("\"deadbeef\""),
            raw(&format!("[{UTXO}]")),
            raw("\"VRSC\""),
        ]
    ));
}

#[test]
fn fundrawtransaction_wrong_first_type_blocked() {
    assert!(!is_method_allowed(
        "fundrawtransaction",
        &[raw("123"), raw(&format!("[{UTXO}]")), raw("\"VRSC\""),]
    ));
}

#[test]
fn fundrawtransaction_5_params_blocked() {
    assert!(!is_method_allowed(
        "fundrawtransaction",
        &[
            raw("\"deadbeef\""),
            raw(&format!("[{UTXO}]")),
            raw("\"VRSC\""),
            raw("0.001"),
            raw("true"),
        ]
    ));
}

#[test]
fn fundrawtransaction_validates_utxo_schema_and_count() {
    assert!(!is_method_allowed(
        "fundrawtransaction",
        &[raw("\"deadbeef\""), raw("[]"), raw("\"Rchange\"")]
    ));
    assert!(!is_method_allowed(
        "fundrawtransaction",
        &[
            raw("\"deadbeef\""),
            raw_json(json!([{"txid": TXID, "voutnum": 0, "script": "00"}])),
            raw("\"Rchange\""),
        ]
    ));

    let too_many_utxos = Value::Array(
        (0..=MAX_UTXO_COUNT)
            .map(|_| json!({"txid": TXID, "voutnum": 0}))
            .collect(),
    );
    assert!(!is_method_allowed(
        "fundrawtransaction",
        &[
            raw("\"deadbeef\""),
            raw_json(too_many_utxos),
            raw("\"Rchange\""),
        ]
    ));
}

// ── Transaction relay ─────────────────────────────────────────────────────────

#[test]
fn sendrawtransaction_string_param_allowed() {
    assert!(is_method_allowed(
        "sendrawtransaction",
        &[raw("\"deadbeef\"")]
    ));
}

#[test]
fn sendrawtransaction_no_params_is_blocked() {
    assert!(!is_method_allowed("sendrawtransaction", &[]));
}

#[test]
fn raw_transaction_hex_and_decoded_size_are_validated() {
    for invalid in ["", "0", "0g", "not-hex"] {
        assert!(!is_method_allowed(
            "sendrawtransaction",
            &[raw_json(json!(invalid))]
        ));
    }

    let oversized = "00".repeat(MAX_RAW_TRANSACTION_BYTES + 1);
    assert!(!is_method_allowed(
        "sendrawtransaction",
        &[raw_json(json!(oversized))]
    ));
}

#[test]
fn sendcurrency_rejects_non_mobile_output_modes_and_multiple_outputs() {
    assert!(!is_method_allowed(
        "sendcurrency",
        &[
            raw("\"*\""),
            raw_json(json!([{
                "currency": "VRSC",
                "amount": 1,
                "address": "Rdestination",
                "memo": "not part of the Mobile template contract"
            }])),
            raw("1"),
            raw("0.0001"),
            raw("true"),
        ]
    ));
    assert!(!is_method_allowed(
        "sendcurrency",
        &[
            raw("\"*\""),
            raw_json(json!([
                {"currency": "VRSC", "amount": 1, "address": "Rone"},
                {"currency": "VRSC", "amount": 1, "address": "Rtwo"}
            ])),
            raw("1"),
            raw("0.0001"),
            raw("true"),
        ]
    ));
}

#[test]
fn updateidentity_requires_mobile_shape_and_known_top_level_fields() {
    assert!(!is_method_allowed(
        "updateidentity",
        &[raw_json(json!({"name": "alice"})), raw("false")]
    ));
    assert!(!is_method_allowed(
        "updateidentity",
        &[
            raw_json(json!({"name": "alice"})),
            raw("true"),
            raw("false"),
        ]
    ));
    assert!(!is_method_allowed(
        "updateidentity",
        &[
            raw_json(json!({"name": "alice", "sourceoffunds": "Rserver"})),
            raw("true"),
        ]
    ));
    assert!(!is_method_allowed(
        "updateidentity",
        &[raw_json(json!({})), raw("true")]
    ));
    assert!(!is_method_allowed(
        "updateidentity",
        &[
            raw_json(json!({"identityaddress": "i-not-an-address", "name": "alice"})),
            raw("true"),
        ]
    ));
    assert!(!is_method_allowed(
        "updateidentity",
        &[
            raw_json(json!({"name": "alice", "parent": "not-an-i-address"})),
            raw("true"),
        ]
    ));
    assert!(!is_method_allowed(
        "updateidentity",
        &[raw_json(json!({"identityaddress": IADDR})), raw("true")]
    ));
    assert!(!is_method_allowed(
        "updateidentity",
        &[
            raw_json(json!({"name": "alice", "parent": IADDR})),
            raw("true"),
        ]
    ));
    assert!(is_method_allowed(
        "updateidentity",
        &[
            raw_json(json!({
                "name": "test",
                "parent": IADDR,
                "identityaddress": CHILD_IADDR
            })),
            raw("true"),
        ]
    ));
    assert!(!is_method_allowed(
        "updateidentity",
        &[
            raw_json(json!({
                "name": "test",
                "parent": IADDR,
                "identityaddress": IADDR
            })),
            raw("true"),
        ]
    ));
    for ambiguous_name in [
        "test.child",
        "test@",
        "test@other",
        "test  name",
        "test\nname",
        "test\u{00a0}\u{00a0}name",
    ] {
        for identity in [
            json!({"name": ambiguous_name}),
            json!({
                "name": ambiguous_name,
                "parent": IADDR,
                "identityaddress": CHILD_IADDR
            }),
        ] {
            assert!(
                is_method_allowed("updateidentity", &[raw_json(identity), raw("true")]),
                "{ambiguous_name}"
            );
        }
    }
    assert!(is_method_allowed(
        "updateidentity",
        &[raw_json(json!({"name": "x".repeat(65)})), raw("true")]
    ));
    assert!(is_method_allowed(
        "updateidentity",
        &[raw_json(json!({"name": "x".repeat(256)})), raw("true")]
    ));
    assert!(!is_method_allowed(
        "updateidentity",
        &[raw_json(json!({"name": "x".repeat(257)})), raw("true")]
    ));
    assert!(!is_method_allowed(
        "updateidentity",
        &[raw_json(json!({"name": ""})), raw("true")]
    ));
    assert!(is_method_allowed(
        "updateidentity",
        &[raw_json(json!({"name": "test name"})), raw("true")]
    ));
    assert!(is_method_allowed(
        "updateidentity",
        &[
            raw_json(json!({
                "name": "test name",
                "parent": IADDR,
                "identityaddress": SPACED_CHILD_IADDR
            })),
            raw("true"),
        ]
    ));
}

#[test]
fn getcurrencyconverters_rejects_duplicate_keys() {
    let duplicate_root = r#"{"convertto":"iDestination","fromcurrency":[{"currency":"VRSC"}],"amount":1,"amount":2,"slippage":1}"#;
    let duplicate_nested = r#"{"convertto":"iDestination","fromcurrency":[{"currency":"VRSC","currency":"VRSCTEST"}],"amount":1,"slippage":1}"#;
    let escaped_duplicate = r#"{"convertto":"iDestination","fromcurrency":[{"currency":"VRSC"}],"amount":1,"\u0061mount":2,"slippage":1}"#;

    for query in [duplicate_root, duplicate_nested, escaped_duplicate] {
        assert!(!is_method_allowed(
            "getcurrencyconverters",
            &[raw_json(json!(query))]
        ));
    }
}

#[test]
fn address_queries_require_bounded_nonempty_string_arrays() {
    assert!(!is_method_allowed(
        "getaddressbalance",
        &[raw_json(json!({"addresses": []}))]
    ));
    assert!(!is_method_allowed(
        "getaddressbalance",
        &[raw_json(json!({"addresses": ["Rone"], "unknown": true}))]
    ));

    let maximum = vec!["Raddress"; MAX_ADDRESS_COUNT];
    assert!(is_method_allowed(
        "getaddressutxos",
        &[raw_json(json!({"addresses": maximum}))]
    ));
    let too_many = vec!["Raddress"; MAX_ADDRESS_COUNT + 1];
    assert!(!is_method_allowed(
        "getaddressutxos",
        &[raw_json(json!({"addresses": too_many}))]
    ));
}

#[test]
fn exact_mobile_rpc_schemas_are_accepted() {
    assert!(is_method_allowed(
        "estimateconversion",
        &[raw_json(json!({
            "currency": "VRSC",
            "convertto": "iCurrency",
            "amount": 1.25,
            "via": null,
            "preconvert": false
        }))]
    ));
    for method in [
        "getaddressbalance",
        "getaddressdeltas",
        "getaddressmempool",
        "getaddressutxos",
    ] {
        let mut query = json!({"addresses": ["Raddress"], "friendlynames": true});
        if matches!(method, "getaddressdeltas" | "getaddressmempool") {
            query["verbosity"] = json!(1);
        }
        assert!(is_method_allowed(method, &[raw_json(query)]), "{method}");
    }
    assert!(is_method_allowed(
        "getblock",
        &[raw("\"12345\""), raw("true")]
    ));
    assert!(is_method_allowed("getblockhash", &[raw("12345")]));
    assert!(is_method_allowed("getcurrency", &[raw("\"VRSC\"")]));

    let converter_query = json!({
        "convertto": "iDestination",
        "fromcurrency": [{"currency": "VRSC"}],
        "amount": 1,
        "slippage": 1
    })
    .to_string();
    assert!(is_method_allowed(
        "getcurrencyconverters",
        &[raw_json(json!(converter_query))]
    ));
    assert!(is_method_allowed(
        "getidentitieswithaddress",
        &[raw_json(json!({"address": "Raddress", "unspent": true}))]
    ));
    assert!(is_method_allowed(
        "getidentity",
        &[raw("\"alice@\""), raw("123")]
    ));
    assert!(is_method_allowed(
        "getidentitycontent",
        &[raw("\"alice@\"")]
    ));
    assert!(is_method_allowed("getinfo", &[]));
    assert!(is_method_allowed(
        "getrawtransaction",
        &[raw_json(json!(TXID)), raw("0")]
    ));
    assert!(is_method_allowed(
        "getvdxfid",
        &[raw("\"vrsc::identity.credential\"")]
    ));
    assert!(is_method_allowed(
        "listcurrencies",
        &[raw_json(json!({"systemtype": "local"})), raw("0")]
    ));
    assert!(is_method_allowed(
        "sendrawtransaction",
        &[raw("\"deadbeef\"")]
    ));
}

#[test]
fn createrawtransaction_arr_obj_allowed() {
    assert!(is_method_allowed(
        "createrawtransaction",
        &[raw("[]"), raw("{}")]
    ));
}

// ── verify methods ────────────────────────────────────────────────────────────

#[test]
fn verifymessage_str_str_str_allowed() {
    assert!(is_method_allowed(
        "verifymessage",
        &[raw("\"addr\""), raw("\"sig\""), raw("\"msg\""),]
    ));
}

#[test]
fn verifysignature_obj_allowed() {
    assert!(is_method_allowed(
        "verifysignature",
        &[raw("{\"signature\":\"sig\"}")]
    ));
}

#[test]
fn verifysignature_obj_with_filename_blocked() {
    assert!(!is_method_allowed(
        "verifysignature",
        &[raw("{\"filename\":\"evil.txt\"}")]
    ));
}

#[test]
fn verifysignature_obj_with_filename_and_other_keys_blocked() {
    assert!(!is_method_allowed(
        "verifysignature",
        &[raw("{\"signature\":\"sig\",\"filename\":\"x\"}")]
    ));
}

#[test]
fn verifysignature_non_object_blocked() {
    assert!(!is_method_allowed(
        "verifysignature",
        &[raw("\"notanobj\"")]
    ));
}

#[test]
fn verifysignature_zero_params_allowed() {
    assert!(!is_method_allowed("verifysignature", &[]));
}

#[test]
fn verifysignature_two_params_blocked() {
    assert!(!is_method_allowed(
        "verifysignature",
        &[raw("{}"), raw("{}")]
    ));
}
