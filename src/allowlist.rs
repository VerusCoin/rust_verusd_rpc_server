use serde_json::{Value};
use serde_json::value::RawValue;

fn check_params(params: &[Box<RawValue>], expected_types: &[&str]) -> bool {
    if params.len() > expected_types.len() {
        return false;
    }
    for (param, &expected_type) in params.iter().zip(expected_types) {
        let value: Value = serde_json::from_str(&param.to_string()).unwrap();
        match expected_type {
            "obj" => if !matches!(value, Value::Object(_)) { return false; },
            "arr" => if !matches!(value, Value::Array(_)) { return false; },
            "int" => if !matches!(value, Value::Number(n) if n.is_i64()) { return false; },
            "float" => if !matches!(value, Value::Number(n) if n.is_f64()) { return false; },
            "str" => if !matches!(value, Value::String(_)) { return false; },
            "bool" => if !matches!(value, Value::Bool(_)) { return false; },
            _ => return false,
        }
    }
    true
}

pub fn is_method_allowed(method: &str, params: &[Box<RawValue>]) -> bool {
    match method {
        "fundrawtransaction" => {
            if params.len() != 4 {
                return false;
            }
            match (serde_json::from_str::<Value>(&params[0].to_string()),
                   serde_json::from_str::<Value>(&params[1].to_string()),
                   serde_json::from_str::<Value>(&params[2].to_string()),
                   serde_json::from_str::<Value>(&params[3].to_string())) {
                (Ok(Value::String(_)), Ok(Value::Array(_)), Ok(Value::String(_)), Ok(Value::Number(_))) => true,
                _ => false,
            }
        },
        "recoveridentity" => params.get(1).and_then(|p| serde_json::from_str::<Value>(&p.to_string()).ok()).map_or(false, |v| v.as_bool().unwrap_or(false)) && check_params(params, &["obj", "bool", "bool", "float", "str"]),
        "registeridentity" => params.get(1).and_then(|p| serde_json::from_str::<Value>(&p.to_string()).ok()).map_or(false, |v| v.as_bool().unwrap_or(false)) && check_params(params, &["obj", "bool", "float", "str"]),
        "revokeidentity" => params.get(1).and_then(|p| serde_json::from_str::<Value>(&p.to_string()).ok()).map_or(false, |v| v.as_bool().unwrap_or(false)) && check_params(params, &["str", "bool", "bool", "float", "str"]),
        "updateidentity" => params.get(1).and_then(|p| serde_json::from_str::<Value>(&p.to_string()).ok()).map_or(false, |v| v.as_bool().unwrap_or(false)) && check_params(params, &["obj", "bool", "bool", "float", "str"]),
        "setidentitytimelock" => params.get(2).and_then(|p| serde_json::from_str::<Value>(&p.to_string()).ok()).map_or(false, |v| v.as_bool().unwrap_or(false)) && check_params(params, &["str", "obj", "bool", "float", "str"]),
        "sendcurrency" => params.get(4).and_then(|p| serde_json::from_str::<Value>(&p.to_string()).ok()).map_or(false, |v| v.as_bool().unwrap_or(false)) && check_params(params, &["str", "arr", "int", "float", "bool"]),
        "coinsupply" => check_params(params, &[]),
        "convertpassphrase" => check_params(params, &["str"]),
        "createmultisig" => check_params(params, &["int", "arr"]),
        "createrawtransaction" => check_params(params, &["arr", "obj", "int", "int"]),
        "decoderawtransaction" => check_params(params, &["str", "bool"]),
        "decodescript" => check_params(params, &["str", "bool"]),
        "estimateconversion" => check_params(params, &["obj"]),
        "estimatefee" => check_params(params, &["int"]),
        "estimatepriority" => check_params(params, &["int"]),
        "getaddressmempool" => check_params(params, &["obj"]),
        "getaddressutxos" => check_params(params, &["obj"]),
        "getaddressbalance" => check_params(params, &["obj"]),
        "getaddressdeltas" => check_params(params, &["obj"]),
        "getaddresstxids" => check_params(params, &["obj"]),
        "getbestblockhash" => check_params(params, &[]),
        "getbestproofroot" => check_params(params, &["obj"]),
        "getblock" => check_params(params, &["str", "bool"]),
        "getblockchaininfo" => check_params(params, &[]),
        "getblockcount" => check_params(params, &[]),
        "getblockhashes" => check_params(params, &["int", "int"]),
        "getblockhash" => check_params(params, &["int"]),
        "getblockheader" => check_params(params, &["str"]),
        "getblocksubsidy" => check_params(params, &["int"]),
        "getblocktemplate" => check_params(params, &["obj"]),
        "getchaintips" => check_params(params, &[]),
        "getcurrency" => check_params(params, &["str"]),
        "getcurrencyconverters" => check_params(params, &["str", "str", "str"]),
        "getcurrencystate" => check_params(params, &["str","int"]),
        "getcurrencytrust" => check_params(params, &["arr"]),
        "getdifficulty" => check_params(params, &[]),
        "getexports" => check_params(params, &["str", "int", "int"]),
        "getinfo" => check_params(params, &[]),
        "getinitialcurrencystate" => check_params(params, &["str"]),
        "getidentitieswithaddress" => check_params(params, &["obj"]),
        "getidentitieswithrevocation" => check_params(params, &["obj"]),
        "getidentitieswithrecovery" => check_params(params, &["obj"]),
        "getidentity" => check_params(params, &["str", "int", "bool", "int"]),
        "getidentitytrust" => check_params(params, &["arr"]),
        "getlastimportfrom" => check_params(params, &["str"]),
        "getlaunchinfo" => check_params(params, &["str"]),
        "getmempoolinfo" => check_params(params, &[]),
        "getmininginfo" => check_params(params, &[]),
        "getnetworkinfo" => check_params(params, &[]),
        "getnotarizationdata" => check_params(params, &["str"]),
        "getoffers" => check_params(params, &["str", "bool", "bool"]),
        "getpendingtransfers" => check_params(params, &["str"]),
        "getrawmempool" => check_params(params, &[]),
        "getrawtransaction" => check_params(params, &["str", "int"]),
        "getreservedeposits" => check_params(params, &["str"]),
        "getsaplingtree" => check_params(params, &["int"]),
        "getspentinfo" => check_params(params, &["obj"]),
        "gettxout" => check_params(params, &["str", "int", "bool"]),
        "gettxoutsetinfo" => check_params(params, &[]),
        "getvdxfid" => check_params(params, &["str", "obj"]),
        "hashdata" => check_params(params, &["str", "str", "str"]),
        "help" => check_params(params, &[]),
        "listcurrencies" => check_params(params, &["obj", "int", "int"]),
        "sendrawtransaction" => check_params(params, &["str"]),
        "submitacceptednotarization" => check_params(params, &["obj", "obj"]),
        "submitimports" => check_params(params, &["obj"]),
        "verifymessage" => check_params(params, &["str", "str", "str", "bool"]),
        "verifyhash" => check_params(params, &["str", "str", "str", "bool"]),
        "verifysignature" => check_params(params, &["obj"]),
        _ => false,
    }
}
