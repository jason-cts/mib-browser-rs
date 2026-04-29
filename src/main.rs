// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{cell::RefCell, error::Error, fs, path::Path, process, rc::Rc, time::{Duration, SystemTime, UNIX_EPOCH}};

use hex::ToHex;
use mib_rs::Loader;
use slint::Model;
use snmp2::{Oid, SyncSession, Value as SnmpValue};
use yaml_rust2::{Yaml, YamlEmitter, YamlLoader};

slint::include_modules!();

// ---------------------------------------------------------------------------
// Config helpers (yaml-rust2)
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Profile {
    name: String,
    host: String,
    version: String,
    community: String,
    security_engine_id: String,
    context_engine_id: String,
    security_level: String,
    auth_protocol: String,
    auth_passphrase: String,
    privacy_protocol: String,
    privacy_passphrase: String,
}

#[derive(Clone, Default)]
struct Config {
    mibs: Vec<String>,
    active_profile: String,
    profiles: Vec<Profile>,
}

fn load_config() -> Config {
    let mut config = Config::default();
    let config_path = Path::new("config.yaml");
    if !config_path.exists() {
        return config;
    }
    let raw = match fs::read_to_string(config_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read config.yaml");
            return config;
        }
    };
    let docs = match YamlLoader::load_from_str(&raw) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "failed to parse config.yaml");
            return config;
        }
    };
    let Some(doc) = docs.first() else {
        return config;
    };

    if let Yaml::Array(mibs) = &doc["mibs"] {
        config.mibs = mibs
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .filter(|s| !s.is_empty())
            .collect();
    }

    if let Some(active) = doc["active_profile"].as_str() {
        config.active_profile = active.to_string();
    }

    if let Yaml::Array(profiles) = &doc["profiles"] {
        for p in profiles {
            if let Yaml::Hash(hash) = p {
                for (k, v) in hash {
                    if let (Some(name), Yaml::Hash(props)) = (k.as_str(), v) {
                        let mut profile = Profile {
                            name: name.to_string(),
                            ..Default::default()
                        };
                        
                        let get_str = |key: &str| -> String {
                            props.get(&Yaml::String(key.to_string()))
                                 .and_then(|y| y.as_str())
                                 .unwrap_or("")
                                 .to_string()
                        };

                        profile.host = get_str("host");
                        profile.version = get_str("version");
                        profile.community = get_str("community");
                        profile.security_engine_id = get_str("security_engine_id");
                        profile.context_engine_id = get_str("context_engine_id");
                        profile.security_level = get_str("security_level");
                        profile.auth_protocol = get_str("auth-proto");
                        profile.auth_passphrase = get_str("auth-key");
                        profile.privacy_protocol = get_str("priv-proto");
                        profile.privacy_passphrase = get_str("priv-key");

                        config.profiles.push(profile);
                    }
                }
            }
        }
    }

    config
}

fn save_config(config: &Config) {
    let mut root = yaml_rust2::yaml::Hash::new();

    let mut mib_arr = yaml_rust2::yaml::Array::new();
    for m in &config.mibs {
        mib_arr.push(Yaml::String(m.clone()));
    }
    root.insert(Yaml::String("mibs".into()), Yaml::Array(mib_arr));

    if !config.active_profile.is_empty() {
        root.insert(
            Yaml::String("active_profile".into()),
            Yaml::String(config.active_profile.clone()),
        );
    }

    let mut prof_arr = yaml_rust2::yaml::Array::new();
    for p in &config.profiles {
        let mut props = yaml_rust2::yaml::Hash::new();
        
        let mut insert_str = |key: &str, val: &str| {
            if !val.is_empty() {
                props.insert(Yaml::String(key.into()), Yaml::String(val.into()));
            }
        };

        insert_str("host", &p.host);
        insert_str("version", &p.version);
        insert_str("community", &p.community);
        insert_str("security_engine_id", &p.security_engine_id);
        insert_str("context_engine_id", &p.context_engine_id);
        insert_str("security_level", &p.security_level);
        insert_str("auth-proto", &p.auth_protocol);
        insert_str("auth-key", &p.auth_passphrase);
        insert_str("priv-proto", &p.privacy_protocol);
        insert_str("priv-key", &p.privacy_passphrase);

        let mut entry = yaml_rust2::yaml::Hash::new();
        entry.insert(Yaml::String(p.name.clone()), Yaml::Hash(props));
        prof_arr.push(Yaml::Hash(entry));
    }
    if !prof_arr.is_empty() {
        root.insert(Yaml::String("profiles".into()), Yaml::Array(prof_arr));
    }

    let doc = Yaml::Hash(root);

    let mut out = String::new();
    let mut emitter = YamlEmitter::new(&mut out);
    emitter.dump(&doc).unwrap();

    if let Err(e) = fs::write("config.yaml", &out) {
        tracing::warn!(error = %e, "failed to write config.yaml");
    }
}

// ---------------------------------------------------------------------------
// MIB parsing & tree flattening
// ---------------------------------------------------------------------------

/// Holds the extracted property info for a single OID node (used in the UI).
#[derive(Clone, Default)]
struct MibInfo {
    name: String,
    oid: String,
    mib_module: String,
    syntax: String,
    access: String,
    status: String,
    defval: String,
    indexes: String,
    descr: String,
}

#[derive(Clone)]
struct TreeItem {
    name: String,
    oid: String,
    indent: i32,
    has_children: bool,
    is_expanded: bool,
    info: MibInfo,
}

impl TreeItem {
    fn to_mib_node(&self) -> MibNode {
        let oid_last_part = self.oid.split('.').last().unwrap_or("");
        MibNode {
            tree_name: format!("{} ({})", self.name, oid_last_part).into(),
            name: self.name.clone().into(),
            oid: self.oid.clone().into(),
            indent: self.indent,
            is_expanded: self.is_expanded,
            has_children: self.has_children,
        }
    }
}

/// Loads the given MIB file paths using mib-rs and returns the flattened full tree state.
fn build_mib_tree(mib_paths: &[String]) -> Vec<TreeItem> {
    let mut all_items: Vec<TreeItem> = Vec::new();

    if mib_paths.is_empty() {
        return all_items;
    }

    // Build a loader with all the file sources.
    let mut loader = Loader::new();
    for path in mib_paths {
        let p = Path::new(path);
        if p.exists() {
            match mib_rs::source::file(p) {
                Ok(src) => {
                    loader = loader.source(src);
                }
                Err(e) => {
                    tracing::warn!(path = %path, error = %e, "failed to create source for MIB file");
                }
            }
        } else {
            tracing::warn!(path = %path, "MIB file does not exist, skipping");
        }
    }

    let mib = match loader.load() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "mib-rs load failed");
            return all_items;
        }
    };

    // Walk the OID tree starting from the root, depth-first.
    let root = mib.root_node();

    fn walk(
        node: mib_rs::mib::handle::Node<'_>,
        depth: i32,
        all_items: &mut Vec<TreeItem>,
    ) {
        let oid_str = format!(".{}", node.oid());
        let has_children = node.children().next().is_some();

        // Build info struct.
        let mut name = node.name().to_string().trim().to_string();
        if name.is_empty() {
            name = format!(".{}", oid_str.split('.').last().unwrap_or(&oid_str));
        }
        let mut info = MibInfo {
            name: name.clone(),
            oid: oid_str.clone(),
            mib_module: node
                .module()
                .map(|m| m.name().to_string())
                .unwrap_or_default(),
            status: "".to_string(),
            ..Default::default()
        };

        let node_descr = node.description();
        if !node_descr.is_empty() {
            info.descr = node_descr.to_string();
        }

        // If node has an attached OBJECT-TYPE, extract more details.
        if let Some(obj) = node.object() {
            let status = obj.status();
            info.status = match status {
                mib_rs::Status::Mandatory => "Mandatory".to_string(),
                mib_rs::Status::Optional => "Optional".to_string(),
                mib_rs::Status::Current => "Current".to_string(),
                mib_rs::Status::Deprecated => "Deprecated".to_string(),
                mib_rs::Status::Obsolete => "Obsolete".to_string(),
            };

            let access = obj.access();
            info.access = format!("{:?}", access);

            let obj_descr = obj.description();
            if !obj_descr.is_empty() {
                info.descr = obj_descr.split('\n').map(|l| l.trim()).collect::<Vec<&str>>().join("\n");
            }

            if let Some(ty) = obj.ty() {
                // Build syntax string like "DisplayString (OctetString) (SIZE 0..255)"
                let type_name = ty.name().to_string();
                let base_name = format!("{:?}", ty.effective_base());
                let sizes: Vec<String> = ty
                    .effective_sizes()
                    .iter()
                    .map(|r| format!("{}..{}", r.min, r.max))
                    .collect();
                let ranges: Vec<String> = ty
                    .effective_ranges()
                    .iter()
                    .map(|r| format!("{}..{}", r.min, r.max))
                    .collect();
                let enums: Vec<String> = obj.effective_enums()
                    .iter()
                    .map(|e| format!("{}({})", e.label, e.value))
                    .collect();

                let mut syntax = if type_name != base_name {
                    format!("{} ({})", type_name, base_name)
                } else {
                    type_name
                };

                if !sizes.is_empty() {
                    syntax.push_str(&format!(" (SIZE ({}))", sizes.join(" | ")));
                }
                if !ranges.is_empty() {
                    syntax.push_str(&format!(" ({})", ranges.join(" | ")));
                }
                if !enums.is_empty() {
                    syntax.push_str(&format!(" {{{}}}", enums.join(", ")));
                }
                info.syntax = syntax;
            }

            // Indexes
            let idx_names: Vec<String> = obj
                .effective_indexes()
                .map(|idx| idx.name().to_string())
                .collect();
            if !idx_names.is_empty() {
                info.indexes = idx_names.join(", ");
            }

            // DEFVAL
            if let Some(dv) = obj.default_value() {
                info.defval = format!("{:?}", dv);
            }
        }

        all_items.push(TreeItem {
            name,
            oid: oid_str,
            indent: depth,
            is_expanded: depth < 3,
            has_children,
            info,
        });

        for child in node.children() {
            walk(child, depth + 1, all_items);
        }
    }

    // Start with root's children so we skip the synthetic root node itself.
    for child in root.children() {
        walk(child, 0, &mut all_items);
    }

    all_items
}

fn get_visible_items(all_items: &[TreeItem]) -> (Vec<MibNode>, Vec<usize>) {
    let mut visible_nodes = Vec::new();
    let mut visible_indices = Vec::new();

    let mut skip_indent = None;
    for (i, item) in all_items.iter().enumerate() {
        if let Some(skip_level) = skip_indent {
            if item.indent > skip_level {
                continue;
            } else {
                skip_indent = None;
            }
        }

        visible_nodes.push(item.to_mib_node());
        visible_indices.push(i);

        if item.has_children && !item.is_expanded {
            skip_indent = Some(item.indent);
        }
    }

    (visible_nodes, visible_indices)
}

// ---------------------------------------------------------------------------
// SNMP helpers
// ---------------------------------------------------------------------------

/// Parse a dotted OID string like ".1.3.6.1.2.1.1.1.0" into Vec<u64>.
fn parse_oid_str(s: &str) -> Option<Vec<u64>> {
    let s = s.trim().trim_start_matches('.');
    if s.is_empty() {
        return None;
    }
    s.split('.').map(|p| p.parse::<u64>().ok()).collect()
}

/// Map a MIB syntax string to one of the SNMPSetDialog ComboBox option values.
fn syntax_to_snmp_type(syntax: &str) -> &'static str {
    let lower = syntax.to_lowercase();
    if lower.contains("counter64") {
        "unsigned int64"
    } else if lower.contains("integer") {
        "INTEGER"
    } else if lower.contains("counter") || lower.contains("gauge") || lower.contains("unsigned32") {
        "unsigned INTEGER"
    } else if lower.contains("timeticks") {
        "TIMETICKS"
    } else if lower.contains("ipaddress") {
        "IPADDRESS"
    } else if lower.contains("object identifier") || lower.contains("objectidentifier") {
        "OID"
    } else {
        // OctetString, DisplayString, etc.
        "STRING"
    }
}

/// Return the ComboBox index for a given SNMP type string.
fn data_type_to_index(s: &str) -> i32 {
    const TYPES: &[&str] = &[
        "INTEGER",
        "unsigned INTEGER",
        "TIMETICKS",
        "IPADDRESS",
        "OID",
        "STRING",
        "HEX STRING",
        "DECIMAL STRING",
        "BITS",
        "unsigned int64",
        "signed int64",
        "float",
        "double",
    ];
    TYPES.iter().position(|&t| t == s).unwrap_or(5) as i32
}

fn find_oid_item(all_items: &[TreeItem], oid: &str) -> Option<TreeItem> {
    let mut current = oid.trim_end_matches('.').to_string();
    loop {
        if let Some(item) = all_items.iter().find(|i| i.oid == current) {
            return Some(item.clone());
        }
        match current.rfind('.') {
            Some(pos) if pos > 0 => current.truncate(pos),
            _ => break,
        }
    }
    return None
}

/// Walk up the OID (strip last component each time) to find a MIB item with a
/// known syntax, then return the mapped SNMP type string.
fn find_data_type_for_oid(all_items: &[TreeItem], oid: &str) -> String {
    if let Some(item) = find_oid_item(all_items, oid) {
        if !item.info.syntax.is_empty() {
            return syntax_to_snmp_type(&item.info.syntax).to_string();
        }
    }

    return "STRING".to_string()
}

/// Format an Oid as ".1.3.6.1..." (leading dot).
fn oid_to_dotted(oid: &Oid) -> String {
    format!(".{}", oid.to_id_string())
}

/// Human-readable type label for an SNMP value.
fn value_to_type_str(v: &SnmpValue) -> &'static str {
    match v {
        SnmpValue::Boolean(_) => "Boolean",
        SnmpValue::Null => "Null",
        SnmpValue::Integer(_) => "INTEGER",
        SnmpValue::OctetString(_) => "OctetString",
        SnmpValue::ObjectIdentifier(_) => "OID",
        SnmpValue::IpAddress(_) => "IpAddress",
        SnmpValue::Counter32(_) => "Counter32",
        SnmpValue::Unsigned32(_) => "Unsigned32",
        SnmpValue::Timeticks(_) => "Timeticks",
        SnmpValue::Opaque(_) => "Opaque",
        SnmpValue::Counter64(_) => "Counter64",
        SnmpValue::EndOfMibView => "EndOfMibView",
        SnmpValue::NoSuchObject => "NoSuchObject",
        SnmpValue::NoSuchInstance => "NoSuchInstance",
        _ => "Unknown",
    }
}

/// Format an SNMP value for display.
fn value_to_display_str(v: &SnmpValue) -> String {
    match v {
        SnmpValue::Boolean(b) => b.to_string(),
        SnmpValue::Null => "(null)".to_string(),
        SnmpValue::Integer(n) => n.to_string(),
        SnmpValue::OctetString(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        SnmpValue::ObjectIdentifier(oid) => format!(".{}", oid.to_id_string()),
        SnmpValue::IpAddress(a) => format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
        SnmpValue::Counter32(n) => n.to_string(),
        SnmpValue::Unsigned32(n) => n.to_string(),
        SnmpValue::Timeticks(n) => n.to_string(),
        SnmpValue::Opaque(bytes) => hex::encode(bytes),
        SnmpValue::Counter64(n) => n.to_string(),
        SnmpValue::EndOfMibView => "(end of MIB view)".to_string(),
        SnmpValue::NoSuchObject => "(no such object)".to_string(),
        SnmpValue::NoSuchInstance => "(no such instance)".to_string(),
        _ => "(unknown)".to_string(),
    }
}

/// Look up the MIB name for a dotted OID. Tries exact match first, then
/// strips trailing index components until a match is found.
fn lookup_name_for_oid(all_items: &[TreeItem], dotted_oid: &str) -> String {
    let mut current = dotted_oid.trim_end_matches('.').to_string();
    loop {
        if let Some(item) = all_items.iter().find(|i| i.oid == current) {
            return item.name.clone();
        }
        match current.rfind('.') {
            Some(pos) if pos > 0 => current.truncate(pos),
            _ => break,
        }
    }
    String::new()
}

/// Return current UTC time as "HH:MM:SSZ".
fn now_time_str() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}Z", h, m, s)
}

/// Owned SNMP result row suitable for crossing thread boundaries.
#[derive(Clone)]
struct SnmpQueryResult {
    oid: String,
    value_type: String,
    value: String,
}

/// Build an SNMP session for the given profile.
fn make_session(profile: &Profile) -> Result<SyncSession, String> {
    let host = if profile.host.contains(':') {
        profile.host.clone()
    } else {
        format!("{}:161", profile.host)
    };
    let community = profile.community.as_bytes().to_vec();
    let timeout = Some(Duration::from_secs(5));

    let sess = match profile.version.as_str() {
        "1" => SyncSession::new_v1(host.as_str(), &community, timeout, 0),
        _ => SyncSession::new_v2c(host.as_str(), &community, timeout, 0),
    };
    sess.map_err(|e| format!("connect error: {}", e))
}

/// Collect varbinds from a PDU into owned results.
fn collect_pdu_results(pdu: snmp2::Pdu<'_>) -> Vec<SnmpQueryResult> {
    pdu.varbinds
        .into_iter()
        .map(|(oid, val)| SnmpQueryResult {
            oid: oid_to_dotted(&oid),
            value_type: value_to_type_str(&val).to_string(),
            value: value_to_display_str(&val),
        })
        .collect()
}

fn do_snmp_get(profile: Profile, oid_str: String) -> Result<Vec<SnmpQueryResult>, String> {
    let nums = parse_oid_str(&oid_str).ok_or_else(|| format!("invalid OID: {}", oid_str))?;
    let oid = Oid::from(&nums).map_err(|e| format!("OID build error: {:?}", e))?;
    let mut sess = make_session(&profile)?;
    let pdu = sess.get(&oid).map_err(|e| e.to_string())?;
    Ok(collect_pdu_results(pdu))
}

fn do_snmp_getnext(profile: Profile, oid_str: String) -> Result<Vec<SnmpQueryResult>, String> {
    let nums = parse_oid_str(&oid_str).ok_or_else(|| format!("invalid OID: {}", oid_str))?;
    let oid = Oid::from(&nums).map_err(|e| format!("OID build error: {:?}", e))?;
    let mut sess = make_session(&profile)?;
    let pdu = sess.getnext(&oid).map_err(|e| e.to_string())?;
    Ok(collect_pdu_results(pdu))
}

fn do_snmp_walk(profile: Profile, oid_str: String) -> Result<Vec<SnmpQueryResult>, String> {
    let nums = parse_oid_str(&oid_str).ok_or_else(|| format!("invalid OID: {}", oid_str))?;
    let base_oid = Oid::from(&nums).map_err(|e| format!("OID build error: {:?}", e))?;
    let mut sess = make_session(&profile)?;

    let mut results = Vec::new();
    let mut current: Oid<'static> = base_oid.to_owned();

    loop {
        let pdu = sess.getnext(&current).map_err(|e| e.to_string())?;
        let mut varbinds = pdu.varbinds.into_iter();
        match varbinds.next() {
            None => break,
            Some((next_oid, val)) => {
                match val {
                    SnmpValue::EndOfMibView
                    | SnmpValue::NoSuchObject
                    | SnmpValue::NoSuchInstance => break,
                    _ => {
                        if !next_oid.starts_with(&base_oid) {
                            break;
                        }
                        results.push(SnmpQueryResult {
                            oid: oid_to_dotted(&next_oid),
                            value_type: value_to_type_str(&val).to_string(),
                            value: value_to_display_str(&val),
                        });
                        current = next_oid.to_owned();
                    }
                }
            }
        }
    }
    Ok(results)
}

fn do_snmp_set(
    profile: Profile,
    oid_str: String,
    type_str: String,
    value_str: String,
) -> Result<Vec<SnmpQueryResult>, String> {
    let nums = parse_oid_str(&oid_str).ok_or_else(|| format!("invalid OID: {}", oid_str))?;
    let oid = Oid::from(&nums).map_err(|e| format!("OID build error: {:?}", e))?;
    let mut sess = make_session(&profile)?;

    // Build the SNMP value from (type_str, value_str).
    // OctetString needs a backing buffer that lives long enough, so we collect
    // it into a local Vec before building the value.
    let octet_buf: Vec<u8>;
    let oid_buf: Vec<u64>;
    let snmp_val: SnmpValue = match type_str.as_str() {
        "INTEGER" => {
            let n: i64 = value_str.parse().map_err(|_| "value must be an integer".to_string())?;
            SnmpValue::Integer(n)
        }
        "unsigned INTEGER" => {
            let n: u32 = value_str.parse().map_err(|_| "value must be an unsigned integer".to_string())?;
            SnmpValue::Unsigned32(n)
        }
        "TIMETICKS" => {
            let n: u32 = value_str.parse().map_err(|_| "value must be a u32".to_string())?;
            SnmpValue::Timeticks(n)
        }
        "IPADDRESS" => {
            let parts: Vec<u8> = value_str
                .split('.')
                .map(|p| p.parse::<u8>().map_err(|_| "invalid IP octet".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            if parts.len() != 4 {
                return Err("IP address must have 4 octets".to_string());
            }
            SnmpValue::IpAddress([parts[0], parts[1], parts[2], parts[3]])
        }
        "OID" => {
            oid_buf = parse_oid_str(&value_str)
                .ok_or_else(|| format!("invalid OID value: {}", value_str))?;
            let v_oid = Oid::from(&oid_buf).map_err(|e| format!("{:?}", e))?;
            SnmpValue::ObjectIdentifier(v_oid)
        }
        "unsigned int64" => {
            let n: u64 = value_str.parse().map_err(|_| "value must be a u64".to_string())?;
            SnmpValue::Counter64(n)
        }
        _ => {
            // STRING / HEX STRING / DECIMAL STRING / BITS / etc.
            octet_buf = value_str.into_bytes();
            SnmpValue::OctetString(&octet_buf)
        }
    };

    let pdu = sess.set(&[(&oid, snmp_val)]).map_err(|e| e.to_string())?;
    Ok(collect_pdu_results(pdu))
}

/// Push SNMP query results (or an error) into the UI result list.
/// New results are prepended (newest at top).
fn push_snmp_results(
    res: Result<Vec<SnmpQueryResult>, String>,
    all_items: &[TreeItem],
    model: &slint::VecModel<SNMPResultRow>,
    host: &str,
) {
    match res {
        Err(e) => {
            let err_win = match SNMPResponseErrorWindow::new() {
                Ok(w) => w,
                Err(_) => return,
            };
            err_win.set_messages(e.into());
            let _ = err_win.show();
        }
        Ok(rows) => {
            let time = now_time_str();
            // Insert newest at top, preserving per-operation order.
            for (insert_pos, row) in rows.iter().enumerate() {
                let name = lookup_name_for_oid(all_items, &row.oid);

                let row_value_parsed = if row.value.chars().any(|c| c.is_control() && !c.is_whitespace()) {
                    let mut result: String = row.value.encode_hex();
                    result.push_str(" (HEX)");
                    result
                } else {
                    row.value.clone()
                };


                model.insert(
                    insert_pos,
                    SNMPResultRow {
                        host: host.into(),
                        name: name.into(),
                        oid: row.oid.clone().into(),
                        value: row_value_parsed.into(),
                        value_type: row.value_type.clone().into(),
                        rx_time_iso8601: time.clone().into(),
                    },
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let ui = AppWindow::new()?;

    // -- Load config & build initial tree --
    let config = Rc::new(RefCell::new(load_config()));
    let mib_paths = Rc::new(RefCell::new(config.borrow().mibs.clone()));
    let all_items = Rc::new(RefCell::new(build_mib_tree(&mib_paths.borrow())));

    let profile_names: Vec<slint::SharedString> = config.borrow().profiles.iter().map(|p| p.name.clone().into()).collect();
    let profiles_model = Rc::new(slint::VecModel::from(profile_names));
    ui.set_host_profiles(profiles_model.clone().into());
    ui.set_active_profile(config.borrow().active_profile.clone().into());

    let config_clone = config.clone();
    ui.on_host_selected(move |name| {
        let mut cfg = config_clone.borrow_mut();
        cfg.active_profile = name.to_string();
        save_config(&cfg);
    });
    // -- SNMP results model --
    let snmp_results_model = Rc::new(slint::VecModel::<SNMPResultRow>::from(vec![]));
    ui.set_snmp_result_rows(snmp_results_model.clone().into());

    let (initial_flat, initial_indices) = get_visible_items(&all_items.borrow());

    let mib_model = Rc::new(slint::VecModel::from(initial_flat));
    ui.set_mib_tree_model(mib_model.clone().into());

    let visible_indices = Rc::new(RefCell::new(initial_indices));

    // -- Click tree element: populate properties pane --
    let _ui_weak = ui.as_weak();
    let items_for_click = all_items.clone();
    let indices_for_click = visible_indices.clone();
    ui.on_click_mib_tree_element(move |idx| {
        let indices = indices_for_click.borrow();
        let items = items_for_click.borrow();
        
        if let Some(&real_idx) = indices.get(idx as usize) {
            if let Some(item) = items.get(real_idx) {
                let info = &item.info;
                if let Some(ui) = _ui_weak.upgrade() {
                    ui.set_current_mib_properties(MibPropertyValues {
                        name: info.name.clone().into(),
                        oid: info.oid.clone().into(),
                        mib_module: info.mib_module.clone().into(),
                        syntax: info.syntax.clone().into(),
                        access: info.access.clone().into(),
                        status: info.status.clone().into(),
                        defval: info.defval.clone().into(),
                        indexes: info.indexes.clone().into(),
                        descr: info.descr.clone().into(),
                    });
                }
            }
        }
    });

    // -- Clear SNMP results --
    let results_for_clear = snmp_results_model.clone();
    ui.on_snmp_result_clear(move || {
        results_for_clear.set_vec(vec![]);
    });

    // -- SNMP Go! button --
    let ui_weak_for_go = ui.as_weak();
    let config_for_go = config.clone();
    let all_items_for_go = all_items.clone();
    let results_for_go = snmp_results_model.clone();

    ui.on_toolbar_snmp_go_button_clicked(move || {
        let Some(ui_ref) = ui_weak_for_go.upgrade() else { return };
        let oid_str = ui_ref.get_toolbar_oid_text().to_string();
        let op = ui_ref.get_toolbar_snmp_op_value().to_string();
        let active = ui_ref.get_active_profile().to_string();

        if oid_str.trim().is_empty() {
            return;
        }

        let cfg = config_for_go.borrow();
        let Some(profile) = cfg.profiles.iter().find(|p| p.name == active).cloned() else {
            return;
        };
        drop(cfg);

        if op.as_str() == "SET" {
            let data_type = find_data_type_for_oid(&all_items_for_go.borrow(), &oid_str);
            let idx = data_type_to_index(&data_type);

            let set_dialog = match SNMPSetDialog::new() {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to create SNMPSetDialog");
                    return;
                }
            };
            set_dialog.set_data_type_index(idx);
            set_dialog.set_value_text("".into());

            let results2 = results_for_go.clone();
            let oid2 = oid_str.clone();
            let profile2 = profile.clone();
            let all_items2 = all_items_for_go.clone();
            let host2 = profile.host.clone();

            set_dialog.on_set(move |type_str, val_str| {
                let oid = oid2.clone();
                let prof = profile2.clone();
                let ts = type_str.to_string();
                let vs = val_str.to_string();
                let results = results2.clone();
                let items = all_items2.clone();
                let host = host2.clone();

                slint::spawn_local(async move {
                    let res = tokio::task::spawn_blocking(move || {
                        do_snmp_set(prof, oid, ts, vs)
                    })
                    .await
                    .unwrap_or_else(|e| Err(e.to_string()));
                    push_snmp_results(res, &items.borrow(), &results, &host);
                })
                .unwrap();
            });

            if let Err(e) = set_dialog.show() {
                tracing::warn!(error = %e, "failed to show SNMPSetDialog");
            }
        } else {
            let results = results_for_go.clone();
            let items = all_items_for_go.clone();
            let oid = oid_str.clone();
            let host = profile.host.clone();

            let op = op.clone();
            slint::spawn_local(async move {
                let op = op;

                let op_4_snmp_action = op.clone();
                let op_4_get_next_result = op.clone();

                let res = tokio::task::spawn_blocking(move || match op_4_snmp_action.as_str() {
                    "GET" => do_snmp_get(profile, oid),
                    "GET NEXT" => do_snmp_getnext(profile, oid),
                    "WALK" => do_snmp_walk(profile, oid),
                    _ => Err(format!("unknown op: {}", op_4_snmp_action)),
                })
                .await
                .unwrap_or_else(|e| Err(e.to_string()));

                if let Ok(res) = &res && op_4_get_next_result.as_str() == "GET NEXT" {
                    // GET NEXT should only have an element in the vector
                    if let Some(res) = res.iter().next() {
                        ui_ref.set_toolbar_oid_text(res.oid.clone().into());
                    }
                }
                push_snmp_results(res, &items.borrow(), &results, &host);

            })
            .unwrap();
        }
    });

    // -- Toggle tree element: expand/collapse --
    let items_for_toggle = all_items.clone();
    let indices_for_toggle = visible_indices.clone();
    let model_for_toggle = mib_model.clone();
    ui.on_toggle_mib_tree_element(move |idx| {
        let real_idx = {
            let indices = indices_for_toggle.borrow();
            indices.get(idx as usize).copied()
        };
        
        if let Some(real_idx) = real_idx {
            {
                let mut items = items_for_toggle.borrow_mut();
                if let Some(item) = items.get_mut(real_idx) {
                    if item.has_children {
                        item.is_expanded = !item.is_expanded;
                    }
                }
            }
            // Rebuild visible list
            let (new_flat, new_indices) = get_visible_items(&items_for_toggle.borrow());
            model_for_toggle.set_vec(new_flat);
            *indices_for_toggle.borrow_mut() = new_indices;
        }
    });

    // -- File -> Load MIBs --
    let ui_weak = ui.as_weak();
    let paths_for_load = mib_paths.clone();
    let model_for_load = mib_model.clone();
    let items_for_load = all_items.clone();
    let indices_for_load = visible_indices.clone();
    let config_for_load = config.clone();
    ui.on_menu_file_load(move || {
        let files = rfd::FileDialog::new()
            .add_filter("MIB text file", &["txt", "mib"])
            .add_filter("All files", &["*"])
            .pick_files();

        let Some(picked) = files else { return };
        if picked.is_empty() {
            return;
        }

        let mut paths = paths_for_load.borrow_mut();
        for file in &picked {
            let abs = file.to_string_lossy().to_string();
            if !paths.contains(&abs) {
                paths.push(abs);
            }
        }

        // Rebuild tree with new set of MIBs.
        let new_all_items = build_mib_tree(&paths);
        let (new_flat, new_indices) = get_visible_items(&new_all_items);

        // Update model.
        model_for_load.set_vec(new_flat);
        *items_for_load.borrow_mut() = new_all_items;
        *indices_for_load.borrow_mut() = new_indices;

        // Persist config.
        let mut cfg = config_for_load.borrow_mut();
        cfg.mibs = paths.clone();
        save_config(&cfg);

        // Reset properties pane.
        if let Some(ui) = ui_weak.upgrade() {
            ui.set_current_mib_properties(MibPropertyValues::default());
        }
    });

    // -- File -> Unload MIBs --
    let ui_weak = ui.as_weak();
    let paths_for_unload = mib_paths.clone();
    let model_for_unload = mib_model.clone();
    let items_for_unload = all_items.clone();
    let indices_for_unload = visible_indices.clone();
    let config_for_unload = config.clone();
    ui.on_menu_file_unload(move || {
        let paths = paths_for_unload.borrow().clone();

        let unload_dialog = UnloadMibDialog::new().unwrap();

        // Populate the loaded MIBs list.
        let items: Vec<UnloadMibItem> = paths
            .iter()
            .map(|p| UnloadMibItem {
                path: p.clone().into(),
                checked: false,
            })
            .collect();
        let items_model = Rc::new(slint::VecModel::from(items));
        unload_dialog.set_loaded_mibs(items_model.into());

        // Wire the "Unload Selected" callback.
        let paths_ref = paths_for_unload.clone();
        let model_ref = model_for_unload.clone();
        let items_ref = items_for_unload.clone();
        let indices_ref = indices_for_unload.clone();
        let dialog_weak = unload_dialog.as_weak();
        let ui_weak_inner = ui_weak.clone();
        let config_for_unload_inner = config_for_unload.clone();
        unload_dialog.on_do_unload(move |selected_items| {
            // Gather the paths that were checked for removal.
            let count = selected_items.row_count();
            let mut to_remove: Vec<String> = Vec::new();
            for i in 0..count {
                let item = selected_items.row_data(i).unwrap();
                if item.checked {
                    to_remove.push(item.path.to_string());
                }
            }

            if to_remove.is_empty() {
                return;
            }

            let mut paths = paths_ref.borrow_mut();
            paths.retain(|p| !to_remove.contains(p));

            // Rebuild tree.
            let new_all_items = build_mib_tree(&paths);
            let (new_flat, new_indices) = get_visible_items(&new_all_items);
            model_ref.set_vec(new_flat);
            *items_ref.borrow_mut() = new_all_items;
            *indices_ref.borrow_mut() = new_indices;
            let mut cfg = config_for_unload_inner.borrow_mut();
            cfg.mibs = paths.clone();
            save_config(&cfg);

            // Reset properties pane.
            if let Some(ui) = ui_weak_inner.upgrade() {
                ui.set_current_mib_properties(MibPropertyValues::default());
            }

            // Close dialog.
            if let Some(d) = dialog_weak.upgrade() {
                d.hide().unwrap();
            }
        });

        // Wire close button.
        let dialog_weak_close = unload_dialog.as_weak();
        unload_dialog.on_close_dialog(move || {
            if let Some(d) = dialog_weak_close.upgrade() {
                d.hide().unwrap();
            }
        });

        unload_dialog.show().unwrap();
    });

    ui.on_menu_file_exit(move || {
        process::exit(0);
    });

    ui.on_menu_help_about(move || {
        let about = HelpAboutDialog::new().unwrap();
        about.show().unwrap();
        about.on_close({
            let about_weak = about.as_weak();
            move || {
                about_weak.unwrap().hide().unwrap();
            }
        });
    });

    fn sync_main_window_profiles(ui: &AppWindow, cfg: &Config) {
        let profile_names: Vec<slint::SharedString> = cfg.profiles.iter().map(|p| p.name.clone().into()).collect();
        let new_model = Rc::new(slint::VecModel::from(profile_names));
        ui.set_host_profiles(new_model.into());
        ui.set_active_profile(cfg.active_profile.clone().into());
    }

    let config_for_host_window = config.clone();
    let ui_weak_for_host = ui.as_weak();

    ui.on_open_host_config(move || {
        let host_config_window = HostConfigWindow::new().unwrap();

        let profiles: Vec<HostProfile> = config_for_host_window.borrow().profiles.iter().map(|p| {
            HostProfile {
                name: p.name.clone().into(),
                host: p.host.clone().into(),
                version: p.version.clone().into(),
                community: p.community.clone().into(),
                security_engine_id: p.security_engine_id.clone().into(),
                context_engine_id: p.context_engine_id.clone().into(),
                security_level: p.security_level.clone().into(),
                auth_protocol: p.auth_protocol.clone().into(),
                auth_passphrase: p.auth_passphrase.clone().into(),
                privacy_protocol: p.privacy_protocol.clone().into(),
                privacy_passphrase: p.privacy_passphrase.clone().into(),
            }
        }).collect();
        let profiles_model = Rc::new(slint::VecModel::from(profiles));
        host_config_window.set_profiles(profiles_model.clone().into());

        let host_config_window_weak = host_config_window.as_weak();
        let config_for_apply = config_for_host_window.clone();
        let ui_weak_for_apply = ui_weak_for_host.clone();
        let profiles_model_for_apply = profiles_model.clone();

        let apply_logic = Rc::new(move || {
            if let Some(hcw) = host_config_window_weak.upgrade() {
                let current_idx = hcw.get_current_profile_index();
                if current_idx >= 0 {
                    let current_profile = hcw.get_current_profile();
                    profiles_model_for_apply.set_row_data(current_idx as usize, current_profile.clone());
                    
                    {
                        let mut cfg = config_for_apply.borrow_mut();
                        let mut check_active_profile = false;
                        if let Some(p) = cfg.profiles.get_mut(current_idx as usize) {
                            let old_name = p.name.clone();
                            p.name = current_profile.name.to_string();
                            p.host = current_profile.host.to_string();
                            p.version = current_profile.version.to_string();
                            p.community = current_profile.community.to_string();
                            p.security_engine_id = current_profile.security_engine_id.to_string();
                            p.context_engine_id = current_profile.context_engine_id.to_string();
                            p.security_level = current_profile.security_level.to_string();
                            p.auth_protocol = current_profile.auth_protocol.to_string();
                            p.auth_passphrase = current_profile.auth_passphrase.to_string();
                            p.privacy_protocol = current_profile.privacy_protocol.to_string();
                            p.privacy_passphrase = current_profile.privacy_passphrase.to_string();
                            
                            if old_name != p.name {
                                check_active_profile = cfg.active_profile == old_name;
                            }
                        }
                        if check_active_profile {
                            cfg.active_profile = current_profile.name.to_string();
                        }
                        save_config(&cfg);
                        
                        if let Some(ui) = ui_weak_for_apply.upgrade() {
                            sync_main_window_profiles(&ui, &cfg);
                        }
                    }
                }
            }
        });

        let apply_logic_for_apply = apply_logic.clone();
        host_config_window.on_host_config_apply(move || {
            apply_logic_for_apply();
        });

        let apply_logic_for_ok = apply_logic.clone();
        let host_config_window_weak_for_ok = host_config_window.as_weak();
        host_config_window.on_host_config_ok(move || {
            apply_logic_for_ok();
            if let Some(hcw) = host_config_window_weak_for_ok.upgrade() {
                hcw.hide().unwrap();
            }
        });

        let host_config_window_weak_for_close = host_config_window.as_weak();
        host_config_window.on_host_config_close(move || {
            if let Some(hcw) = host_config_window_weak_for_close.upgrade() {
                hcw.hide().unwrap();
            }
        });

        host_config_window.on_host_config_profile_new({
            let hcw_weak = host_config_window.as_weak();
            let profiles_model = profiles_model.clone();
            let config = config_for_host_window.clone();
            let ui_weak = ui_weak_for_host.clone();
            move || {
                let mut cfg = config.borrow_mut();
                let new_profile = Profile {
                    name: "Unnamed Profile".to_string(),
                    ..Default::default()
                };
                cfg.profiles.push(new_profile.clone());
                
                let slint_profile = HostProfile {
                    name: new_profile.name.into(),
                    host: new_profile.host.into(),
                    version: new_profile.version.into(),
                    community: new_profile.community.into(),
                    security_engine_id: new_profile.security_engine_id.into(),
                    context_engine_id: new_profile.context_engine_id.into(),
                    security_level: new_profile.security_level.into(),
                    auth_protocol: new_profile.auth_protocol.into(),
                    auth_passphrase: new_profile.auth_passphrase.into(),
                    privacy_protocol: new_profile.privacy_protocol.into(),
                    privacy_passphrase: new_profile.privacy_passphrase.into(),
                };
                profiles_model.push(slint_profile.clone());
                
                if let Some(hcw) = hcw_weak.upgrade() {
                    let new_idx = (profiles_model.row_count() - 1) as i32;
                    hcw.set_current_profile_index(new_idx);
                    hcw.set_current_profile(slint_profile);
                }
                
                save_config(&cfg);
                if let Some(ui) = ui_weak.upgrade() {
                    sync_main_window_profiles(&ui, &cfg);
                }
            }
        });

        host_config_window.on_host_config_profile_delete({
            let hcw_weak = host_config_window.as_weak();
            let profiles_model = profiles_model.clone();
            let config = config_for_host_window.clone();
            let ui_weak = ui_weak_for_host.clone();
            move || {
                if let Some(hcw) = hcw_weak.upgrade() {
                    let idx = hcw.get_current_profile_index();
                    if idx >= 0 && idx < profiles_model.row_count() as i32 {
                        let mut cfg = config.borrow_mut();
                        
                        // Check if we are deleting the active profile
                        let deleting_active = cfg.profiles[idx as usize].name == cfg.active_profile;
                        
                        cfg.profiles.remove(idx as usize);
                        profiles_model.remove(idx as usize);
                        
                        let new_count = profiles_model.row_count();
                        if new_count == 0 {
                            hcw.set_current_profile_index(-1);
                            hcw.set_current_profile(HostProfile::default());
                            if deleting_active {
                                cfg.active_profile = String::new();
                            }
                        } else {
                            let new_idx = if idx >= new_count as i32 {
                                (new_count - 1) as i32
                            } else {
                                idx
                            };
                            hcw.set_current_profile_index(new_idx);
                            hcw.set_current_profile(profiles_model.row_data(new_idx as usize).unwrap());
                            
                            if deleting_active {
                                cfg.active_profile = cfg.profiles[new_idx as usize].name.clone();
                            }
                        }
                        
                        save_config(&cfg);
                        if let Some(ui) = ui_weak.upgrade() {
                            sync_main_window_profiles(&ui, &cfg);
                        }
                    }
                }
            }
        });

        host_config_window.on_host_config_profile_duplicate({
            let hcw_weak = host_config_window.as_weak();
            let profiles_model = profiles_model.clone();
            let config = config_for_host_window.clone();
            let ui_weak = ui_weak_for_host.clone();
            move || {
                if let Some(hcw) = hcw_weak.upgrade() {
                    let idx = hcw.get_current_profile_index();
                    if idx >= 0 && idx < profiles_model.row_count() as i32 {
                        let mut cfg = config.borrow_mut();
                        let source_prof = cfg.profiles[idx as usize].clone();
                        let mut new_prof = source_prof.clone();
                        new_prof.name = format!("Duplicated of {}", source_prof.name);
                        
                        let insert_idx = (idx + 1) as usize;
                        cfg.profiles.insert(insert_idx, new_prof.clone());
                        
                        let slint_prof = HostProfile {
                            name: new_prof.name.into(),
                            host: new_prof.host.into(),
                            version: new_prof.version.into(),
                            community: new_prof.community.into(),
                            security_engine_id: new_prof.security_engine_id.into(),
                            context_engine_id: new_prof.context_engine_id.into(),
                            security_level: new_prof.security_level.into(),
                            auth_protocol: new_prof.auth_protocol.into(),
                            auth_passphrase: new_prof.auth_passphrase.into(),
                            privacy_protocol: new_prof.privacy_protocol.into(),
                            privacy_passphrase: new_prof.privacy_passphrase.into(),
                        };
                        profiles_model.insert(insert_idx, slint_prof.clone());
                        
                        hcw.set_current_profile_index(insert_idx as i32);
                        hcw.set_current_profile(slint_prof);
                        
                        save_config(&cfg);
                        if let Some(ui) = ui_weak.upgrade() {
                            sync_main_window_profiles(&ui, &cfg);
                        }
                    }
                }
            }
        });

        host_config_window.show().unwrap();
    });

    ui.run()?;
    Ok(())
}
