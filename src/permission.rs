//! Permission definitions and the [`PermissionSet`] configuration abstraction.
//!
//! A [`Permission`] binds an HTTP method and an Actix route pattern to a specific
//! bit index in the role bitset. A [`PermissionSet`] holds the complete collection
//! of permissions for an application and can be loaded from JSON.
//!
//! # Example
//!
//! ```
//! use actix_web::http::Method;
//! use actixutils::middleware::{Permission, PermissionSet};
//!
//! let set = PermissionSet::new(vec![
//!     Permission::new(Method::GET, "/users", 0).unwrap(),
//!     Permission::new(Method::POST, "/users", 1).unwrap(),
//! ]).unwrap();
//!
//! assert!(set.find(&Method::GET, "/users").is_some());
//! assert!(set.find(&Method::POST, "/users").is_some());
//! assert!(set.find(&Method::DELETE, "/users").is_none());
//! ```

use super::error::PermissionError;
use actix_web::dev::ResourceDef;
use actix_web::http::Method;
use serde::Deserialize;
use std::collections::HashSet;

/// A single permission binding an HTTP method and route pattern to a bit index.
///
/// The `bit_id` identifies which bit in the principal's `u128` role must be set
/// for access to be granted. Bit `0` corresponds to `1 << 0`, bit `1` to `1 << 1`,
/// and so on up to bit `127`.
#[derive(Debug, Clone)]
pub struct Permission {
    /// The HTTP method this permission applies to.
    pub method: Method,
    /// The Actix route/resource definition this permission matches against.
    pub url: ResourceDef,
    /// The bit index in the `u128` role bitset (must be `0..128`).
    pub bit_id: u8,
}


/// Internal struct for deserializing permission entries from JSON.
#[derive(Debug, Deserialize)]
struct PermissionJson {
    method: String,
    url: String,
    #[serde(deserialize_with = "deserialize_bit_id")]
    bit_id: u64,
}

/// Custom deserializer for `bit_id` that accepts any integer but validates range.
fn deserialize_bit_id<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let val = u64::deserialize(deserializer)?;
    Ok(val)
}

/// Internal struct for deserializing the top-level JSON object.
#[derive(Debug, Deserialize)]
struct PermissionsJson {
    permissions: Vec<PermissionJson>,
}

/// A collection of permissions that can be queried by HTTP method and request path.
///
/// `PermissionSet` is immutable after construction and is designed to be wrapped
/// in an [`Arc`](std::sync::Arc) and shared across requests by the middleware.
///
/// # Construction
///
/// - [`PermissionSet::new`] — from a `Vec<Permission>`.
/// - [`PermissionSet::from_file`] — from a JSON file path.
/// - [`PermissionSet::from_reader`] — from any `std::io::Read` source.
/// - [`PermissionSet::from_json`] — from a [`serde_json::Value`].
///
/// # Validation
///
/// All constructors validate that:
/// - `bit_id` is in the range `0..128`.
/// - HTTP method strings are valid (e.g., `"GET"`, `"POST"`).
/// - No duplicate `(method, route)` pairs exist.
#[derive(Debug, Clone)]
pub struct PermissionSet {
    permissions: Vec<Permission>,
}

impl PermissionSet {
    /// Creates a `PermissionSet` from a vector of [`Permission`] values.
    ///
    /// # Errors
    ///
    /// Returns [`PermissionError::InvalidBitId`] if any permission has `bit_id >= 128`.
    /// Returns [`PermissionError::DuplicatePermission`] if the same method and
    /// route pattern appear more than once.
    ///
    /// # Examples
    ///
    /// ```
    /// use actix_web::http::Method;
    /// use actixutils::middleware::{Permission, PermissionSet};
    ///
    /// let set = PermissionSet::new(vec![
    ///     Permission::new(Method::GET, "/users", 0).unwrap(),
    /// ]).unwrap();
    /// ```
    pub fn new(permissions: Vec<Permission>) -> Result<Self, PermissionError> {
        let mut seen = HashSet::with_capacity(permissions.len());
        for perm in &permissions {
            if perm.bit_id >= 128 {
                return Err(PermissionError::InvalidBitId {
                    bit_id: u64::from(perm.bit_id),
                });
            }
            let route = perm.url.pattern().unwrap_or_default();
            let key = format!("{}:{}", perm.method, route);

            if !seen.insert(key) {
                return Err(PermissionError::DuplicatePermission {
                    method: perm.method.to_string(),
                    route: route.to_string(),
                });
            }
        }
        Ok(Self { permissions })
    }

    /// Loads a `PermissionSet` from a JSON file at the given path.
    ///
    /// # Errors
    ///
    /// Returns [`PermissionError::Io`] if the file cannot be opened,
    /// [`PermissionError::Json`] if the JSON is malformed, or a validation error
    /// if the configuration is invalid.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use actixutils::middleware::PermissionSet;
    ///
    /// let set = PermissionSet::from_file("permissions.json").unwrap();
    /// ```
    pub fn from_file(path: &str) -> Result<Self, PermissionError> {
        let file = std::fs::File::open(path)?;
        Self::from_reader(file)
    }

    /// Loads a `PermissionSet` from any type implementing [`std::io::Read`].
    ///
    /// # Errors
    ///
    /// Same error conditions as [`PermissionSet::from_file`].
    pub fn from_reader<R: std::io::Read>(reader: R) -> Result<Self, PermissionError> {
        let json: PermissionsJson = serde_json::from_reader(reader)?;
        Self::from_deserialized(json)
    }

    /// Internal helper that converts the deserialized JSON representation into a
    /// validated `PermissionSet`.
    fn from_deserialized(json: PermissionsJson) -> Result<Self, PermissionError> {
        let mut permissions = Vec::with_capacity(json.permissions.len());

        for perm_json in json.permissions {
            let method = perm_json
                .method
                .parse::<Method>()
                .map_err(|_| PermissionError::InvalidMethod(perm_json.method.clone()))?;

            if perm_json.bit_id >= 128 {
                return Err(PermissionError::InvalidBitId {
                    bit_id: perm_json.bit_id,
                });
            }

            let url = ResourceDef::new(&perm_json.url);

            permissions.push(Permission {
                method,
                url,
                bit_id: perm_json.bit_id as u8,
            });
        }

        Self::new(permissions)
    }

    /// Finds the first permission that matches the given HTTP method and request path.
    ///
    /// Matching uses Actix's native [`ResourceDef`] semantics, so dynamic segments
    /// (`{id}`), regex segments (`{id:\d+}`), and tail patterns (`{tail:.*}`)
    /// are all supported.
    ///
    /// Returns `None` if no permission matches, which triggers a **403 Forbidden**
    /// response in the middleware (default-deny policy).
    ///
    /// # Examples
    ///
    /// ```
    /// use actix_web::http::Method;
    /// use actixutils::middleware::{Permission, PermissionSet};
    ///
    /// let set = PermissionSet::new(vec![
    ///     Permission::new(Method::GET, "/users/{id}", 2).unwrap(),
    /// ]).unwrap();
    ///
    /// assert!(set.find(&Method::GET, "/users/42").is_some());
    /// assert!(set.find(&Method::POST, "/users/42").is_none());
    /// ```
    pub fn find(&self, method: &Method, path: &str) -> Option<&Permission> {
        self.permissions
            .iter()
            .find(|p| p.method == *method && p.url.is_match(path))
    }
}

