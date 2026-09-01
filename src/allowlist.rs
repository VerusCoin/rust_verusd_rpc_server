use crate::identity::derive_parented_identity_address;
use serde_json::value::RawValue;
use serde_json::{Map, Value};

pub const MAX_ADDRESS_COUNT: usize = 100;
pub const MAX_UTXO_COUNT: usize = 1_000;
pub const MAX_RAW_TRANSACTION_BYTES: usize = 2_000_000;

const MAX_IDENTIFIER_LENGTH: usize = 256;
const MAX_VDXF_URI_LENGTH: usize = 2_048;
const MAX_EMBEDDED_QUERY_BYTES: usize = 16 * 1024;
const MAX_UPDATE_IDENTITY_BYTES: usize = 512 * 1024;
const MAX_CONTENT_MULTIMAP_ENTRIES: usize = 256;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_NODES: usize = 4_096;

fn parse_params(params: &[Box<RawValue>]) -> Option<Vec<Value>> {
    params
        .iter()
        .map(|param| serde_json::from_str(param.get()).ok())
        .collect()
}

fn contains_filename(value: &Value) -> bool {
    match value {
        Value::Object(object) => object
            .iter()
            .any(|(key, value)| key == "filename" || contains_filename(value)),
        Value::Array(array) => array.iter().any(contains_filename),
        _ => false,
    }
}

fn has_only_keys(object: &Map<String, Value>, allowed: &[&str]) -> bool {
    object
        .keys()
        .all(|key| allowed.iter().any(|allowed_key| key == allowed_key))
}

fn is_bounded_string(value: &Value, max_length: usize) -> bool {
    matches!(value, Value::String(string) if !string.is_empty() && string.len() <= max_length)
}

fn is_optional_bounded_string(object: &Map<String, Value>, key: &str, max_length: usize) -> bool {
    object
        .get(key)
        .is_none_or(|value| value.is_null() || is_bounded_string(value, max_length))
}

fn is_nonnegative_integer(value: &Value) -> bool {
    matches!(value, Value::Number(number) if number.as_u64().is_some())
}

fn is_nonnegative_number(value: &Value) -> bool {
    matches!(value, Value::Number(number) if number.as_f64().is_some_and(|number| number.is_finite() && number >= 0.0))
}

fn is_hex_string(string: &str) -> bool {
    !string.is_empty()
        && string.len().is_multiple_of(2)
        && string.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_txid(value: &Value) -> bool {
    matches!(value, Value::String(string) if string.len() == 64 && is_hex_string(string))
}

fn is_canonical_i_address(value: &Value) -> bool {
    const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    matches!(value, Value::String(address)
        if address.len() == 34
            && address.starts_with('i')
            && address.bytes().all(|byte| BASE58_ALPHABET.contains(&byte)))
}

fn is_raw_transaction(value: &Value) -> bool {
    matches!(value, Value::String(string)
        if is_hex_string(string) && string.len() / 2 <= MAX_RAW_TRANSACTION_BYTES)
}

fn json_shape_within_limits(value: &Value, depth: usize, nodes: &mut usize) -> bool {
    if depth > MAX_JSON_DEPTH || *nodes >= MAX_JSON_NODES {
        return false;
    }
    *nodes += 1;

    match value {
        Value::Array(array) => array
            .iter()
            .all(|value| json_shape_within_limits(value, depth + 1, nodes)),
        Value::Object(object) => object
            .values()
            .all(|value| json_shape_within_limits(value, depth + 1, nodes)),
        _ => true,
    }
}

fn validate_address_array(value: &Value) -> bool {
    let Some(addresses) = value.as_array() else {
        return false;
    };

    !addresses.is_empty()
        && addresses.len() <= MAX_ADDRESS_COUNT
        && addresses
            .iter()
            .all(|address| is_bounded_string(address, MAX_IDENTIFIER_LENGTH))
}

fn validate_optional_bool(object: &Map<String, Value>, key: &str) -> bool {
    object.get(key).is_none_or(Value::is_boolean)
}

fn validate_optional_height(object: &Map<String, Value>, key: &str) -> bool {
    object.get(key).is_none_or(is_nonnegative_integer)
}

fn validate_optional_verbosity(object: &Map<String, Value>) -> bool {
    object
        .get("verbosity")
        .is_none_or(|value| value.as_u64().is_some_and(|verbosity| verbosity <= 2))
}

fn validate_address_query(value: &Value, method: &str) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };

    let allowed_keys: &[&str] = match method {
        "getaddressbalance" => &["addresses", "friendlynames"],
        "getaddressutxos" => &["addresses", "chaininfo", "friendlynames"],
        "getaddressdeltas" | "getaddressmempool" => &[
            "addresses",
            "start",
            "end",
            "chaininfo",
            "verbosity",
            "friendlynames",
        ],
        _ => return false,
    };

    if !has_only_keys(object, allowed_keys)
        || !object.get("addresses").is_some_and(validate_address_array)
        || !validate_optional_bool(object, "friendlynames")
        || !validate_optional_bool(object, "chaininfo")
        || !validate_optional_height(object, "start")
        || !validate_optional_height(object, "end")
        || !validate_optional_verbosity(object)
    {
        return false;
    }

    match (
        object.get("start").and_then(Value::as_u64),
        object.get("end").and_then(Value::as_u64),
    ) {
        (Some(start), Some(end)) => start <= end,
        _ => true,
    }
}

fn validate_estimate_conversion(params: &[Value]) -> bool {
    let [Value::Object(output)] = params else {
        return false;
    };

    has_only_keys(
        output,
        &["currency", "convertto", "amount", "via", "preconvert"],
    ) && output
        .get("currency")
        .is_some_and(|value| is_bounded_string(value, MAX_IDENTIFIER_LENGTH))
        && output
            .get("convertto")
            .is_some_and(|value| is_bounded_string(value, MAX_IDENTIFIER_LENGTH))
        && output.get("amount").is_some_and(is_nonnegative_number)
        && is_optional_bounded_string(output, "via", MAX_IDENTIFIER_LENGTH)
        && output.get("preconvert").is_none_or(Value::is_boolean)
}

fn validate_fund_raw_transaction(params: &[Value]) -> bool {
    if !(params.len() == 3 || params.len() == 4)
        || !is_raw_transaction(&params[0])
        || !is_bounded_string(&params[2], MAX_IDENTIFIER_LENGTH)
        || params.get(3).is_some_and(|fee| !is_nonnegative_number(fee))
    {
        return false;
    }

    let Some(utxos) = params[1].as_array() else {
        return false;
    };

    !utxos.is_empty()
        && utxos.len() <= MAX_UTXO_COUNT
        && utxos.iter().all(|utxo| {
            let Some(utxo) = utxo.as_object() else {
                return false;
            };

            has_only_keys(utxo, &["txid", "voutnum"])
                && utxo.len() == 2
                && utxo.get("txid").is_some_and(is_txid)
                && utxo
                    .get("voutnum")
                    .and_then(Value::as_u64)
                    .is_some_and(|vout| vout <= u32::MAX as u64)
        })
}

fn validate_get_block(params: &[Value]) -> bool {
    matches!(params, [block] if is_bounded_string(block, 128))
        || matches!(params, [block, Value::Bool(_)] if is_bounded_string(block, 128))
}

fn validate_get_currency_converters(params: &[Value]) -> bool {
    let [Value::String(query)] = params else {
        return false;
    };
    if query.len() > MAX_EMBEDDED_QUERY_BYTES {
        return false;
    }

    let Ok(query) = serde_json::from_str::<CurrencyConverterQuery>(query) else {
        return false;
    };
    if !is_bounded_string(&query.convertto, MAX_IDENTIFIER_LENGTH)
        || !is_nonnegative_number(&query.amount)
        || !is_nonnegative_number(&query.slippage)
    {
        return false;
    }

    query.fromcurrency.len() <= MAX_ADDRESS_COUNT
        && query
            .fromcurrency
            .iter()
            .all(|source| is_bounded_string(&source.currency, MAX_IDENTIFIER_LENGTH))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrencyConverterQuery {
    convertto: Value,
    fromcurrency: Vec<CurrencyConverterSource>,
    amount: Value,
    slippage: Value,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrencyConverterSource {
    currency: Value,
}

fn validate_get_identities_with_address(params: &[Value]) -> bool {
    let [Value::Object(query)] = params else {
        return false;
    };

    has_only_keys(query, &["address", "fromheight", "toheight", "unspent"])
        && query
            .get("address")
            .is_some_and(|value| is_bounded_string(value, MAX_IDENTIFIER_LENGTH))
        && validate_optional_height(query, "fromheight")
        && validate_optional_height(query, "toheight")
        && validate_optional_bool(query, "unspent")
        && match (
            query.get("fromheight").and_then(Value::as_u64),
            query.get("toheight").and_then(Value::as_u64),
        ) {
            (Some(from), Some(to)) => from <= to,
            _ => true,
        }
}

fn validate_get_identity(params: &[Value]) -> bool {
    if params.is_empty()
        || params.len() > 4
        || !is_bounded_string(&params[0], MAX_IDENTIFIER_LENGTH)
    {
        return false;
    }

    params.get(1).is_none_or(is_nonnegative_integer)
        && params.get(2).is_none_or(Value::is_boolean)
        && params.get(3).is_none_or(is_nonnegative_integer)
}

fn validate_get_identity_content(params: &[Value]) -> bool {
    if params.is_empty()
        || params.len() > 6
        || !is_bounded_string(&params[0], MAX_IDENTIFIER_LENGTH)
    {
        return false;
    }

    params.get(1).is_none_or(is_nonnegative_integer)
        && params.get(2).is_none_or(is_nonnegative_integer)
        && params.get(3).is_none_or(Value::is_boolean)
        && params.get(4).is_none_or(is_nonnegative_integer)
        && params
            .get(5)
            .is_none_or(|value| is_bounded_string(value, MAX_IDENTIFIER_LENGTH))
}

fn validate_get_vdxf_id(params: &[Value]) -> bool {
    if params.is_empty() || params.len() > 2 || !is_bounded_string(&params[0], MAX_VDXF_URI_LENGTH)
    {
        return false;
    }
    let Some(initial_data) = params.get(1) else {
        return true;
    };
    let Some(initial_data) = initial_data.as_object() else {
        return false;
    };

    !initial_data.is_empty()
        && has_only_keys(initial_data, &["vdxfkey", "uint256", "indexnum"])
        && initial_data
            .get("vdxfkey")
            .is_none_or(|value| is_bounded_string(value, MAX_IDENTIFIER_LENGTH))
        && initial_data.get("uint256").is_none_or(
            |value| matches!(value, Value::String(hash) if hash.len() == 64 && is_hex_string(hash)),
        )
        && initial_data.get("indexnum").is_none_or(|value| {
            value
                .as_i64()
                .is_some_and(|index| i32::MIN as i64 <= index && index <= i32::MAX as i64)
        })
}

fn validate_list_currencies(params: &[Value]) -> bool {
    if params.is_empty() {
        return true;
    }
    if !(params.len() == 2 || params.len() == 3) {
        return false;
    }

    let Some(query) = params[0].as_object() else {
        return false;
    };
    if !has_only_keys(
        query,
        &["launchstate", "systemtype", "fromsystem", "converter"],
    ) || !query.get("launchstate").is_none_or(|value| {
        matches!(
            value.as_str(),
            Some("prelaunch" | "launched" | "refund" | "complete")
        )
    }) || !query.get("systemtype").is_none_or(|value| {
        matches!(
            value.as_str(),
            Some("local" | "imported" | "gateway" | "pbaas")
        )
    }) || !is_optional_bounded_string(query, "fromsystem", MAX_IDENTIFIER_LENGTH)
        || !query.get("converter").is_none_or(|value| {
            value.as_array().is_some_and(|currencies| {
                currencies.len() <= MAX_ADDRESS_COUNT
                    && currencies
                        .iter()
                        .all(|currency| is_bounded_string(currency, MAX_IDENTIFIER_LENGTH))
            })
        })
    {
        return false;
    }

    is_nonnegative_integer(&params[1])
        && params.get(2).is_none_or(is_nonnegative_integer)
        && params
            .get(2)
            .is_none_or(|end| params[1].as_u64() <= end.as_u64())
}

fn validate_send_currency(params: &[Value]) -> bool {
    let [from_address, Value::Array(outputs), min_confirmations, fee, Value::Bool(true)] = params
    else {
        return false;
    };
    if !is_bounded_string(from_address, MAX_IDENTIFIER_LENGTH)
        || outputs.len() != 1
        || min_confirmations.as_u64() != Some(1)
        || fee.as_f64() != Some(0.0001)
    {
        return false;
    }

    let Some(output) = outputs[0].as_object() else {
        return false;
    };
    has_only_keys(
        output,
        &[
            "currency",
            "amount",
            "address",
            "exportto",
            "convertto",
            "feecurrency",
            "via",
            "preconvert",
            "vdxftag",
        ],
    ) && output
        .get("currency")
        .is_some_and(|value| is_bounded_string(value, MAX_IDENTIFIER_LENGTH))
        && output.get("amount").is_some_and(is_nonnegative_number)
        && output
            .get("address")
            .is_some_and(|value| is_bounded_string(value, MAX_IDENTIFIER_LENGTH))
        && is_optional_bounded_string(output, "exportto", MAX_IDENTIFIER_LENGTH)
        && is_optional_bounded_string(output, "convertto", MAX_IDENTIFIER_LENGTH)
        && is_optional_bounded_string(output, "feecurrency", MAX_IDENTIFIER_LENGTH)
        && is_optional_bounded_string(output, "via", MAX_IDENTIFIER_LENGTH)
        && is_optional_bounded_string(output, "vdxftag", MAX_IDENTIFIER_LENGTH)
        && output.get("preconvert").is_none_or(Value::is_boolean)
}

fn validate_update_identity(params: &[Value]) -> bool {
    let [Value::Object(identity), Value::Bool(true)] = params else {
        return false;
    };
    if Value::Object(identity.clone()).to_string().len() > MAX_UPDATE_IDENTITY_BYTES
        || !has_only_keys(
            identity,
            &[
                "contentmap",
                "contentmultimap",
                "flags",
                "identityaddress",
                "minimumsignatures",
                "name",
                "parent",
                "primaryaddresses",
                "privateaddress",
                "recoveryauthority",
                "revocationauthority",
                "systemid",
                "timelock",
                "version",
            ],
        )
    {
        return false;
    }

    let has_identity_address = identity
        .get("identityaddress")
        .is_some_and(is_canonical_i_address);
    let has_name = identity
        .get("name")
        .is_some_and(|value| is_bounded_string(value, MAX_IDENTIFIER_LENGTH));
    if !has_name
        || identity
            .get("identityaddress")
            .is_some_and(|value| !is_canonical_i_address(value))
        || identity
            .get("parent")
            .is_some_and(|value| !is_canonical_i_address(value))
        || (identity.contains_key("parent") && !has_identity_address)
    {
        return false;
    }

    if let Some(parent) = identity.get("parent").and_then(Value::as_str) {
        let Some(name) = identity.get("name").and_then(Value::as_str) else {
            return false;
        };
        let Some(identity_address) = identity.get("identityaddress").and_then(Value::as_str) else {
            return false;
        };
        if let Some(derived) = derive_parented_identity_address(name, parent) {
            if derived != identity_address {
                return false;
            }
        }
    }

    for key in [
        "privateaddress",
        "recoveryauthority",
        "revocationauthority",
        "systemid",
    ] {
        if identity
            .get(key)
            .is_some_and(|value| !is_bounded_string(value, MAX_IDENTIFIER_LENGTH))
        {
            return false;
        }
    }
    for key in ["flags", "minimumsignatures", "timelock", "version"] {
        if !identity.get(key).is_none_or(is_nonnegative_integer) {
            return false;
        }
    }
    if !identity
        .get("primaryaddresses")
        .is_none_or(validate_address_array)
    {
        return false;
    }
    if !identity.get("contentmap").is_none_or(|value| {
        value.as_object().is_some_and(|map| {
            map.len() <= MAX_CONTENT_MULTIMAP_ENTRIES
                && map.iter().all(|(key, value)| {
                    !key.is_empty() && key.len() <= MAX_IDENTIFIER_LENGTH && value.is_string()
                })
        })
    }) {
        return false;
    }
    if !identity.get("contentmultimap").is_none_or(|value| {
        value.as_object().is_some_and(|map| {
            map.len() <= MAX_CONTENT_MULTIMAP_ENTRIES
                && map
                    .keys()
                    .all(|key| !key.is_empty() && key.len() <= MAX_IDENTIFIER_LENGTH)
        })
    }) {
        return false;
    }

    let mut nodes = 0;
    json_shape_within_limits(&Value::Object(identity.clone()), 0, &mut nodes)
}

fn check_params(params: &[Box<RawValue>], expected_types: &[&str]) -> bool {
    if params.len() > expected_types.len() {
        return false;
    }
    for (param, &expected_type) in params.iter().zip(expected_types) {
        let value: Value = serde_json::from_str(&param.to_string()).unwrap();
        match expected_type {
            "obj" => {
                if !matches!(value, Value::Object(_)) {
                    return false;
                }
            }
            "arr" => {
                if !matches!(value, Value::Array(_)) {
                    return false;
                }
            }
            "int" => {
                if !matches!(value, Value::Number(n) if n.is_i64()) {
                    return false;
                }
            }
            "float" => {
                if !matches!(value, Value::Number(n) if n.is_f64()) {
                    return false;
                }
            }
            "str" => {
                if !matches!(value, Value::String(_)) {
                    return false;
                }
            }
            "bool" => {
                if !matches!(value, Value::Bool(_)) {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

pub fn is_method_allowed(method: &str, params: &[Box<RawValue>]) -> bool {
    let Some(parsed_params) = parse_params(params) else {
        return false;
    };
    if parsed_params.iter().any(contains_filename) {
        return false;
    }

    match method {
        "fundrawtransaction" => validate_fund_raw_transaction(&parsed_params),
        "signdata" => {
            if params.len() != 1 {
                return false;
            }
            matches!(&parsed_params[..], [Value::Object(object)] if !object.contains_key("address"))
        }
        "recoveridentity" => {
            parsed_params.get(1).and_then(Value::as_bool) == Some(true)
                && check_params(params, &["obj", "bool", "bool", "float", "str"])
        }
        "registeridentity" => {
            parsed_params.get(1).and_then(Value::as_bool) == Some(true)
                && check_params(params, &["obj", "bool", "float", "str"])
        }
        "revokeidentity" => {
            parsed_params.get(1).and_then(Value::as_bool) == Some(true)
                && check_params(params, &["str", "bool", "bool", "float", "str"])
        }
        "updateidentity" => validate_update_identity(&parsed_params),
        "setidentitytimelock" => {
            parsed_params.get(2).and_then(Value::as_bool) == Some(true)
                && check_params(params, &["str", "obj", "bool", "float", "str"])
        }
        "sendcurrency" => validate_send_currency(&parsed_params),
        "coinsupply" => check_params(params, &[]),
        "convertpassphrase" => check_params(params, &["str"]),
        "createmultisig" => check_params(params, &["int", "arr"]),
        "createrawtransaction" => check_params(params, &["arr", "obj", "int", "int"]),
        "decoderawtransaction" => check_params(params, &["str", "bool"]),
        "decodescript" => check_params(params, &["str", "bool"]),
        "estimateconversion" => validate_estimate_conversion(&parsed_params),
        "estimatefee" => check_params(params, &["int"]),
        "estimatepriority" => check_params(params, &["int"]),
        "getaddressmempool" | "getaddressutxos" | "getaddressbalance" | "getaddressdeltas" => {
            matches!(&parsed_params[..], [query] if validate_address_query(query, method))
        }
        "getaddresstxids" => check_params(params, &["obj"]),
        "getbestblockhash" => check_params(params, &[]),
        "getbestproofroot" => check_params(params, &["obj"]),
        "getblock" => validate_get_block(&parsed_params),
        "getblockchaininfo" => check_params(params, &[]),
        "getblockcount" => check_params(params, &[]),
        "getblockhashes" => check_params(params, &["int", "int"]),
        "getblockhash" => {
            matches!(&parsed_params[..], [height] if is_nonnegative_integer(height))
        }
        "getblockheader" => check_params(params, &["str"]),
        "getblocksubsidy" => check_params(params, &["int"]),
        "getblocktemplate" => check_params(params, &["obj"]),
        "getchaintips" => check_params(params, &[]),
        "getcurrency" => {
            matches!(&parsed_params[..], [currency] if is_bounded_string(currency, MAX_IDENTIFIER_LENGTH))
        }
        "getcurrencyconverters" => validate_get_currency_converters(&parsed_params),
        "getcurrencystate" => check_params(params, &["str", "str", "str"]),
        "getcurrencytrust" => check_params(params, &["arr"]),
        "getdifficulty" => check_params(params, &[]),
        "getexports" => check_params(params, &["str", "int", "int"]),
        "getinfo" => parsed_params.is_empty(),
        "getinitialcurrencystate" => check_params(params, &["str"]),
        "getidentitieswithaddress" => validate_get_identities_with_address(&parsed_params),
        "getidentitieswithrevocation" => check_params(params, &["obj"]),
        "getidentitieswithrecovery" => check_params(params, &["obj"]),
        "getidentity" => validate_get_identity(&parsed_params),
        "getidentitytrust" => check_params(params, &["arr"]),
        "getidentitycontent" => validate_get_identity_content(&parsed_params),
        "getidentityhistory" => check_params(params, &["str", "int", "int", "bool", "int"]),
        "getlastimportfrom" => check_params(params, &["str"]),
        "getlaunchinfo" => check_params(params, &["str"]),
        "getmempoolinfo" => check_params(params, &[]),
        "getmininginfo" => check_params(params, &[]),
        "getnetworkinfo" => check_params(params, &[]),
        "getnotarizationdata" => check_params(params, &["str"]),
        "getoffers" => check_params(params, &["str", "bool", "bool"]),
        "getpendingtransfers" => check_params(params, &["str"]),
        "getrawmempool" => check_params(params, &[]),
        "getrawtransaction" => {
            matches!(&parsed_params[..], [txid] if is_txid(txid))
                || matches!(&parsed_params[..], [txid, verbosity]
                    if is_txid(txid) && matches!(verbosity.as_u64(), Some(0 | 1)))
        }
        "getreservedeposits" => check_params(params, &["str"]),
        "getsaplingtree" => check_params(params, &["int"]),
        "getspentinfo" => check_params(params, &["obj"]),
        "gettxout" => check_params(params, &["str", "int", "bool"]),
        "gettxoutsetinfo" => check_params(params, &[]),
        "getvdxfid" => validate_get_vdxf_id(&parsed_params),
        "hashdata" => check_params(params, &["str", "str", "str"]),
        "help" => check_params(params, &[]),
        "listcurrencies" => validate_list_currencies(&parsed_params),
        "sendrawtransaction" => {
            matches!(&parsed_params[..], [tx] if is_raw_transaction(tx))
                || matches!(&parsed_params[..], [tx, Value::Bool(_)] if is_raw_transaction(tx))
        }
        "submitacceptednotarization" => check_params(params, &["obj", "obj"]),
        "submitimports" => check_params(params, &["obj"]),
        "verifymessage" => check_params(params, &["str", "str", "str", "bool"]),
        "verifyhash" => check_params(params, &["str", "str", "str", "bool"]),
        "verifysignature" => {
            if params.len() > 1 {
                return false;
            }
            if params.is_empty() {
                return false;
            }
            matches!(&parsed_params[..], [Value::Object(_)])
        }
        _ => false,
    }
}
