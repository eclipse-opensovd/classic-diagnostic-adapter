# SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env bash
## Call cargo check to trigger the build script with the feature `gen-protos` enabled.
cargo check -p cda-database --features gen-protos
