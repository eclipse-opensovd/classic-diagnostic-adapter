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

pub mod sovd2uds {
    pub mod bulk_data {
        pub mod flash_files {
            pub mod get {
                pub type Response = crate::sovd2uds::FileList;
            }
        }
    }

    pub mod data {
        pub mod network_structure {
            pub mod get {
                pub type Response = crate::DataItem;
            }
        }
    }
}
