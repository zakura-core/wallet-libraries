//! The service's init document, parsed into what the wallet checks.
//!
//! Not behind the HTTP feature: a wallet with its own transport still has to
//! read the same document, and a second parser would be a second place for the
//! two to disagree about a field.

use crate::sync::{GeometryParams, ServiceGeometry};
use crate::transport::BoxError;

/// Parses the service's init document into what the wallet checks it against.
///
/// The service publishes one entry per geometry it holds. The wallet re-derives
/// each scheme from the dimensions published beside it and refuses any that
/// does not reproduce. The dithered schemes are optional: a service that
/// predates them publishes none, and one that does not reproduce is not used.
pub fn parse_init(raw: &[u8]) -> Result<ServiceGeometry, BoxError> {
    let init: serde_json::Value = serde_json::from_slice(raw)?;
    let schema = init["schema"]
        .as_str()
        .ok_or("init carries no schema")?
        .to_string();
    let mut geometries = Vec::new();
    for entry in init["geometries"]
        .as_array()
        .ok_or("init publishes no geometries")?
    {
        let u64_at = |key: &str| {
            entry[key]
                .as_u64()
                .ok_or_else(|| format!("init geometry lacks {key}"))
        };
        // Absent from a service that predates dithered queries; the wallet
        // then sends the 49-bit query it still accepts.
        let optional_scheme = |key: &str| -> Result<_, BoxError> {
            match entry.get(key) {
                None | Some(serde_json::Value::Null) => Ok(None),
                Some(value) => Ok(Some(serde_json::from_value(value.clone())?)),
            }
        };
        geometries.push(GeometryParams {
            name: entry["name"]
                .as_str()
                .ok_or("init geometry lacks a name")?
                .to_string(),
            directory_rows: u64_at("directory_rows")?,
            directory_row_bytes: u64_at("directory_row_bytes")? as u32,
            directory_scheme: serde_json::from_value(entry["directory_scheme"].clone())?,
            directory_scheme_dq44: optional_scheme("directory_scheme_dq44")?,
            directory_setup_seed: u64_at("directory_setup_seed")?,
            page_rows: u64_at("page_rows")?,
            page_row_bytes: u64_at("page_row_bytes")? as u32,
            pages_scheme: serde_json::from_value(entry["pages_scheme"].clone())?,
            pages_scheme_dq44: optional_scheme("pages_scheme_dq44")?,
            pages_setup_seed: u64_at("pages_setup_seed")?,
        });
    }
    Ok(ServiceGeometry { schema, geometries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use transparent_native::TableProfile;

    fn entry(dithered: bool) -> serde_json::Value {
        let table = |name: &str| {
            TableProfile::new(transparent_shard::SCHEMA, "recent-4k", name, 4_096, 4_096).unwrap()
        };
        let (directory, pages) = (table("directory"), table("pages"));
        let mut entry = serde_json::json!({
            "name": "recent-4k",
            "directory_rows": 4_096,
            "directory_row_bytes": 4_096,
            "directory_scheme": directory.scheme,
            "directory_setup_seed": 1,
            "page_rows": 4_096,
            "page_row_bytes": 4_096,
            "pages_scheme": pages.scheme,
            "pages_setup_seed": 2,
        });
        if dithered {
            // The history tables have no second width; a 16-bit table's
            // dithered scheme stands in for one a service might advertise.
            let wide = table("sixteen-bit").dithered_scheme;
            entry["directory_scheme_dq44"] = serde_json::json!(wide);
            entry["pages_scheme_dq44"] = serde_json::json!(wide);
        }
        entry
    }

    fn init(entry: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": transparent_shard::SCHEMA,
            "geometries": [entry],
        }))
        .unwrap()
    }

    #[test]
    fn dithered_schemes_are_read_when_published() {
        let parsed = parse_init(&init(entry(true))).unwrap();
        let g = &parsed.geometries[0];
        assert_eq!(g.directory_scheme_dq44.as_ref().unwrap().query_bits, 44);
        assert_eq!(g.pages_scheme_dq44.as_ref().unwrap().query_bits, 44);
        assert_eq!(g.directory_scheme.query_bits, 28);
    }

    #[test]
    fn a_service_without_dithered_schemes_still_parses() {
        let parsed = parse_init(&init(entry(false))).unwrap();
        let g = &parsed.geometries[0];
        assert!(g.directory_scheme_dq44.is_none() && g.pages_scheme_dq44.is_none());

        let mut nulls = entry(false);
        nulls["directory_scheme_dq44"] = serde_json::Value::Null;
        let parsed = parse_init(&init(nulls)).unwrap();
        assert!(parsed.geometries[0].directory_scheme_dq44.is_none());
    }

    #[test]
    fn a_malformed_dithered_scheme_is_refused() {
        let mut bad = entry(true);
        bad["pages_scheme_dq44"] = serde_json::json!({"profile": 7});
        assert!(parse_init(&init(bad)).is_err());
    }
}
