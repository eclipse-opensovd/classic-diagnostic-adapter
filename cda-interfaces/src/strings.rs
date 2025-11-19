/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */
use std::{
    fmt::{Debug, Display},
    ops::Deref,
    sync::LazyLock,
};

use parking_lot::RwLock;

use crate::{HashMap, HashMapExtensions};

/// Strings manager that provides a thread-safe way to store and retrieve strings by their IDs.
///
/// Uses a `Vec<String>` to store the strings and a `HashMap<String, StringId>` for fast
/// lookups.<br>
/// Both the vector and the hash map are protected by `parking_lot::RwLock` for concurrent
/// access.<br>
/// `StringId` is simply an index into the vector, allowing for efficient retrieval of strings.
#[derive(Debug)]
pub struct Strings {
    strings: RwLock<Vec<String>>,
    lookup: RwLock<HashMap<String, StringId>>,
}

/// Type alias for string IDs, which are simply indices into the `Vec<String>` in `Strings`.
#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StringId(usize);

impl StringId {
    pub const MAX: Self = Self(usize::MAX);
}
impl Display for StringId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StringId({})",
            STRINGS.get(*self).unwrap_or("<unknown>".to_owned())
        )
    }
}

impl Debug for StringId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl Deref for StringId {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<usize> for StringId {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

impl Strings {
    #[must_use]
    pub fn new() -> Self {
        Self {
            strings: RwLock::new(Vec::new()),
            lookup: RwLock::new(HashMap::new()),
        }
    }

    /// Get a `String` by its `StringId` from the strings manager.
    ///
    /// `Strings` locks the internal `Vec` in read mode to allow concurrent reads,
    /// and retrieves the string at the specified `StringId`.
    /// [slice::get](https://doc.rust-lang.org/std/primitive.slice.html#method.get)
    /// is used to safely access the string at the index,
    pub fn get(&self, id: StringId) -> Option<String> {
        self.strings.read().get(*id).cloned()
    }

    /// Get a `StringId` for a given `String` value, inserting it if it does not exist.
    #[tracing::instrument(skip(self), fields(string_length = value.len()))]
    pub fn get_or_insert(&self, value: &str) -> StringId {
        if let Some(id) = self.lookup.read().get(value) {
            return *id;
        }
        let mut strings = self.strings.write();
        strings.push(value.to_owned());
        let id = strings.len() - 1;
        let str_id: StringId = id.into();
        self.lookup.write().insert(value.to_owned(), str_id);
        str_id
    }
}

pub static STRINGS: LazyLock<Strings> = LazyLock::new(Strings::new);

impl Default for Strings {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper macro to retrieve a string by its ID.
///
/// This macro tries to retrieve a `String` by its `StringId`, returning a
/// `Result<String, DiagServiceError>`.
///
/// The macro takes an optional mapping function that can be applied to the retrieved string.
///
/// # Example
/// ### Without mapping function
/// ```ignore
/// let original_string = "Hello, World!";
/// let my_string_id = STRINGS.get_or_insert(original_string);
///
/// let my_string = get_string!(my_string_id);
/// assert_eq!(my_string, Ok(original_string.to_string()));
/// ```
/// ### With mapping function
/// ```ignore
/// let original_string = "Hello, World!";
/// let my_string_id = STRINGS.get_or_insert(original_string);
///
/// let my_string = get_string!(my_string_id, |s| s.to_uppercase());
/// assert_eq!(my_string, Ok(original_string.to_uppercase()));
/// ```
/// ### With error
/// ```ignore
/// let my_invalid_id = 999; // Example invalid ID
/// let my_string = get_string!(my_invalid_id);
/// assert!(my_string.is_err());
/// ```
///
/// # Errors
/// If the ID is not found, it returns a `DiagServiceError::InvalidDatabase` error containing the
/// file, line and column of the caller.
#[macro_export]
macro_rules! get_string {
    (@get $id:expr) => {
        match cda_interfaces::STRINGS.get($id) {
            Some(s) => Ok(s),
            None => Err(DiagServiceError::InvalidDatabase(format!(
                "String lookup failed at [{}:{}:{}]",
                std::file!(),
                std::line!(),
                std::column!()
            ))),
        }
    };

    ($id:expr) => {
        cda_interfaces::get_string!(@get $id)
    };
    ($id:expr, $map:expr) => {
        cda_interfaces::get_string!(@get $id).map($map)
    };
}

/// Helper macro to retrieve a string by its ID, returning an empty string if the ID is not found.
///
/// In the case that the ID was not found, an error is logged containing the file, line and column
/// of the caller.<br>
/// This macro takes an optional mapping function that can be applied to the retrieved string.
///
/// See [`get_string!`] for more details.
#[macro_export]
macro_rules! get_string_with_default {
    (@get_or_default $id:expr) => {
        match $id {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "String lookup failed, using empty string");
                String::new() // Return an empty string if the ID is not found
            }
        }
    };
    ($id:expr) => {
        get_string_with_default!(@get_or_default cda_interfaces::get_string!($id))
    };
    ($id:expr, $map:expr) => {
        get_string_with_default!(@get_or_default cda_interfaces::get_string!($id, $map))
    };
}

/// Helper macro to retrieve a string by its ID, but for the case that the ID was an
/// `Option<StringId>`.
///
/// This macro retrieves a string from an `Option<StringId>`, returning an empty string if the
/// option is `None`.<br>
/// It logs a warning message if the ID is not found, containing the file, line and column of the
/// caller.<br>
/// The macro takes an optional mapping function that can be applied to the retrieved string.
///
/// # Example
/// ## Without mapping function
/// ```ignore
/// let original_string = "Hello, World!";
/// let my_string_id = STRINGS.get_or_insert(original_string);
///
/// let my_id_opt = Some(my_string_id); // Example StringId
/// let my_string = get_string_from_option!(my_id_opt);
/// assert_eq!(my_string, Some(original_string.to_string()));
///
/// let my_none_id = None; // Example None case
/// let my_none_string = get_string_from_option!(my_none_id);
/// assert_eq!(my_none_string, None);
/// ```
#[macro_export]
macro_rules! get_string_from_option {
    (@and_then $opt:expr) => {
        $opt.and_then(|id| match cda_interfaces::get_string!(id) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::error!(error = %e, "String lookup failed, returning None");
                None // Return None if the ID is not found
            }
        })
    };

    ($opt:expr) => {
        cda_interfaces::get_string_from_option!(@and_then $opt)
    };
    ($opt:expr, $map:expr) => {
        cda_interfaces::get_string_from_option!(@and_then $opt).map($map)
    };
}

/// Helper macro to retrieve a string from an `Option<StringId>`, returning an empty string if the
/// option is `None`.
///
/// See [`get_string_from_option!`] for more details.
#[macro_export]
macro_rules! get_string_from_option_with_default {
    (@and_then $opt:expr) => {
        cda_interfaces::get_string_from_option!($opt)
    };

    ($opt:expr) => {
        cda_interfaces::get_string_from_option_with_default!(@and_then $opt)
            .unwrap_or_default()
    };
    ($opt:expr, $map:expr) => {
        cda_interfaces::get_string_from_option_with_default!(@and_then $opt)
            .map($map).unwrap_or_default()
    };
}
