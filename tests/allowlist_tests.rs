use rust_verusd_rpc_server::allowlist::is_method_allowed;
use serde_json::value::RawValue;

fn raw(s: &str) -> Box<RawValue> {
    RawValue::from_string(s.to_string()).unwrap()
}

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
    assert!(is_method_allowed("decoderawtransaction", &[raw("\"deadbeef\"")]));
}

#[test]
fn arity_more_params_than_declared_rejected() {
    // getinfo takes no params; one extra is rejected
    assert!(!is_method_allowed("getinfo", &[raw("\"extra\"")]));
}

#[test]
fn type_check_obj_accepted() {
    assert!(is_method_allowed("getaddressbalance", &[raw("{\"addresses\": []}")]));
}

#[test]
fn type_check_array_rejected_for_obj_param() {
    assert!(!is_method_allowed("getaddressbalance", &[raw("[1, 2]")]));
}

#[test]
fn type_check_arr_accepted() {
    assert!(is_method_allowed("createmultisig", &[raw("2"), raw("[\"addr1\"]")]));
}

#[test]
fn type_check_obj_rejected_for_arr_param() {
    assert!(!is_method_allowed("createmultisig", &[raw("2"), raw("{}")]));
}

#[test]
fn type_check_float_accepted() {
    // registeridentity: [obj, bool, float, str] — param[2] is float
    assert!(is_method_allowed("registeridentity", &[
        raw("{}"), raw("true"), raw("0.001"), raw("\"addr\""),
    ]));
}

#[test]
fn type_check_integer_rejected_for_float_param() {
    // Integer `1` is not an f64 in serde_json
    assert!(!is_method_allowed("registeridentity", &[
        raw("{}"), raw("true"), raw("1"), raw("\"addr\""),
    ]));
}

#[test]
fn type_check_bool_accepted() {
    assert!(is_method_allowed("decoderawtransaction", &[raw("\"hex\""), raw("true")]));
    assert!(is_method_allowed("decoderawtransaction", &[raw("\"hex\""), raw("false")]));
}

#[test]
fn type_check_integer_rejected_for_bool_param() {
    assert!(!is_method_allowed("decoderawtransaction", &[raw("\"hex\""), raw("1")]));
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
    assert!(is_method_allowed("getrawtransaction", &[raw("\"abc\""), raw("1")]));
}

#[test]
fn getidentity_string_param_allowed() {
    assert!(is_method_allowed("getidentity", &[raw("\"test@\"")]));
}

#[test]
fn totally_unknown_methods_blocked() {
    for m in &["getbalance", "listaccounts", "importprivkey", "dumpprivkey", "stop"] {
        assert!(!is_method_allowed(m, &[]), "{} should be blocked", m);
    }
}

// ── Write operations requiring simulation flag ────────────────────────────────

#[test]
fn sendcurrency_simulation_true_allowed() {
    assert!(is_method_allowed("sendcurrency", &[
        raw("\"*\""), raw("[]"), raw("0"), raw("0.001"), raw("true"),
    ]));
}

#[test]
fn sendcurrency_simulation_false_blocked() {
    assert!(!is_method_allowed("sendcurrency", &[
        raw("\"*\""), raw("[]"), raw("0"), raw("0.001"), raw("false"),
    ]));
}

#[test]
fn sendcurrency_missing_simulation_flag_blocked() {
    assert!(!is_method_allowed("sendcurrency", &[
        raw("\"*\""), raw("[]"), raw("0"), raw("0.001"),
    ]));
}

#[test]
fn registeridentity_simulation_true_allowed() {
    assert!(is_method_allowed("registeridentity", &[
        raw("{}"), raw("true"), raw("0.001"), raw("\"\""),
    ]));
}

#[test]
fn registeridentity_simulation_false_blocked() {
    assert!(!is_method_allowed("registeridentity", &[
        raw("{}"), raw("false"), raw("0.001"), raw("\"\""),
    ]));
}

#[test]
fn updateidentity_simulation_true_allowed() {
    assert!(is_method_allowed("updateidentity", &[
        raw("{}"), raw("true"), raw("false"), raw("0.001"), raw("\"\""),
    ]));
}

#[test]
fn revokeidentity_simulation_true_allowed() {
    assert!(is_method_allowed("revokeidentity", &[
        raw("\"id@\""), raw("true"), raw("false"), raw("0.001"), raw("\"\""),
    ]));
}

#[test]
fn recoveridentity_simulation_true_allowed() {
    assert!(is_method_allowed("recoveridentity", &[
        raw("{}"), raw("true"), raw("false"), raw("0.001"), raw("\"\""),
    ]));
}

#[test]
fn setidentitytimelock_simulation_at_index2_true_allowed() {
    assert!(is_method_allowed("setidentitytimelock", &[
        raw("\"id@\""), raw("{}"), raw("true"), raw("0.001"), raw("\"\""),
    ]));
}

#[test]
fn setidentitytimelock_simulation_false_blocked() {
    assert!(!is_method_allowed("setidentitytimelock", &[
        raw("\"id@\""), raw("{}"), raw("false"), raw("0.001"), raw("\"\""),
    ]));
}

// ── signdata address guard ────────────────────────────────────────────────────

#[test]
fn signdata_with_address_field_blocked() {
    assert!(!is_method_allowed("signdata", &[raw("{\"address\":\"R1\",\"data\":\"aa\"}")]));
}

#[test]
fn signdata_without_address_field_allowed() {
    assert!(is_method_allowed("signdata", &[raw("{\"data\":\"aabbcc\"}")]));
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
    assert!(!is_method_allowed("signdata", &[raw("{\"data\":\"aa\"}"), raw("{\"extra\":1}")]));
}

// ── fundrawtransaction ────────────────────────────────────────────────────────

#[test]
fn fundrawtransaction_4_params_allowed() {
    assert!(is_method_allowed("fundrawtransaction", &[
        raw("\"deadbeef\""), raw("[]"), raw("\"VRSC\""), raw("0.001"),
    ]));
}

#[test]
fn fundrawtransaction_3_params_allowed() {
    assert!(is_method_allowed("fundrawtransaction", &[
        raw("\"deadbeef\""), raw("[]"), raw("\"VRSC\""),
    ]));
}

#[test]
fn fundrawtransaction_wrong_first_type_blocked() {
    assert!(!is_method_allowed("fundrawtransaction", &[
        raw("123"), raw("[]"), raw("\"VRSC\""),
    ]));
}

#[test]
fn fundrawtransaction_5_params_blocked() {
    assert!(!is_method_allowed("fundrawtransaction", &[
        raw("\"deadbeef\""), raw("[]"), raw("\"VRSC\""), raw("0.001"), raw("true"),
    ]));
}

// ── Transaction relay ─────────────────────────────────────────────────────────

#[test]
fn sendrawtransaction_string_param_allowed() {
    assert!(is_method_allowed("sendrawtransaction", &[raw("\"deadbeef\"")]));
}

#[test]
fn sendrawtransaction_no_params_passes_allowlist() {
    // LOW-3: check_params only rejects *more* params than declared, not fewer.
    // Zero params passes the allowlist; verusd itself rejects the malformed call.
    assert!(is_method_allowed("sendrawtransaction", &[]));
}

#[test]
fn createrawtransaction_arr_obj_allowed() {
    assert!(is_method_allowed("createrawtransaction", &[raw("[]"), raw("{}")]));
}

// ── verify methods ────────────────────────────────────────────────────────────

#[test]
fn verifymessage_str_str_str_allowed() {
    assert!(is_method_allowed("verifymessage", &[
        raw("\"addr\""), raw("\"sig\""), raw("\"msg\""),
    ]));
}

#[test]
fn verifysignature_obj_allowed() {
    assert!(is_method_allowed("verifysignature", &[raw("{\"signature\":\"sig\"}")]));
}
