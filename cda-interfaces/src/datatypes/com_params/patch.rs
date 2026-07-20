/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
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

use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use struct_patch::Patch;

use super::{ComParamConfig, ComParamName, ComParamPrecedence};

/// Patch for [`ComParamConfig`].
/// This is a manual implementation, because `struct_patch`'s derive does not work with generics.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct ComParamConfigPatch<T: Serialize + Debug> {
    pub name: Option<ComParamName>,
    pub value: Option<T>,
    #[serde(default)]
    pub precedence: Option<ComParamPrecedence>,
}

impl<T: Serialize + Debug> Patch<ComParamConfigPatch<T>> for ComParamConfig<T> {
    fn apply(&mut self, patch: ComParamConfigPatch<T>) {
        let ComParamConfigPatch {
            name,
            value,
            precedence,
        } = patch;

        if let Some(name) = name {
            self.name = name;
        }
        if let Some(value) = value {
            self.value = value;
        }
        if let Some(precedence) = precedence {
            self.precedence = precedence;
        }
    }

    fn into_patch(self) -> ComParamConfigPatch<T> {
        let Self {
            name,
            value,
            precedence,
        } = self;

        ComParamConfigPatch {
            name: Some(name),
            value: Some(value),
            precedence: Some(precedence),
        }
    }

    fn into_patch_by_diff(self, _previous: Self) -> ComParamConfigPatch<T> {
        unimplemented!(
            "`ComParamConfigPatch::into_patch_by_diff` is currently unimplemented. Implement it, \
             if you need it."
        )
    }

    fn new_empty_patch() -> ComParamConfigPatch<T> {
        ComParamConfigPatch::default()
    }
}

impl<T: Serialize + Debug> Default for ComParamConfigPatch<T> {
    fn default() -> Self {
        Self {
            name: None,
            value: None,
            precedence: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use struct_patch::Patch;

    use super::*;

    #[test]
    fn should_merge_into_com_param_config_correctly() {
        // Previous implementation used Figment's merge strategy,
        // so this is modeled after that: https://docs.rs/figment/0.10.19/figment/struct.Figment.html#method.merge

        let config = ComParamConfig {
            name: String::from("my_param"),
            value: 123,
            precedence: ComParamPrecedence::default(),
        };

        {
            //no-op patch
            let mut result = config.clone();

            result.apply(ComParamConfigPatch::default());

            assert_eq!(result, config);
        }

        {
            //changed value
            let mut result = config.clone();

            result.apply(ComParamConfigPatch {
                value: Some(456),
                ..Default::default()
            });

            assert_eq!(
                result,
                ComParamConfig {
                    value: 456,
                    ..config
                }
            );
        }
    }
}
