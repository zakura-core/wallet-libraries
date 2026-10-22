//! Labeled server URLs advertised by a dynamic config.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::url::{UrlError, validate_https_url};

/// A server a config advertises, with a label the application can show and
/// persist as the user's selection.
///
/// Which server is used, and whether the application ever moves between
/// them, is application policy; this crate never picks one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabeledEndpoint {
    pub label: String,
    pub url: String,
}

/// An advertised server list that cannot be used.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EndpointListError {
    #[error("{field} must contain at least one entry")]
    Empty { field: String },
    #[error(transparent)]
    Url(#[from] UrlError),
    #[error("{field}[{index}].label must not be empty")]
    EmptyLabel { field: String, index: usize },
    /// Labels identify a stored selection, so they must be unique.
    #[error("{field}[{index}].label is a duplicate: {label}")]
    DuplicateLabel {
        field: String,
        index: usize,
        label: String,
    },
}

/// Checks that `endpoints` is non-empty, every URL is HTTPS, and every label
/// is non-empty and unique within the list.
pub fn validate_labeled_endpoints(
    endpoints: &[LabeledEndpoint],
    field: &str,
) -> Result<(), EndpointListError> {
    if endpoints.is_empty() {
        return Err(EndpointListError::Empty {
            field: field.to_string(),
        });
    }
    for (index, endpoint) in endpoints.iter().enumerate() {
        validate_https_url(&endpoint.url, &format!("{field}[{index}].url"))?;
        if endpoint.label.is_empty() {
            return Err(EndpointListError::EmptyLabel {
                field: field.to_string(),
                index,
            });
        }
        if endpoints[..index].iter().any(|e| e.label == endpoint.label) {
            return Err(EndpointListError::DuplicateLabel {
                field: field.to_string(),
                index,
                label: endpoint.label.clone(),
            });
        }
    }
    Ok(())
}
