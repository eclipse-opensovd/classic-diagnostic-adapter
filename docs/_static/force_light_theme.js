// SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Diagrams are always rendered on a white background (see
// force_light_theme.css for details), so this documentation intentionally
// only supports light mode. Furo defaults to whatever theme was last stored
// in localStorage, or the OS/browser preference ("auto") if nothing is
// stored yet. Override that here so the page always starts - and stays -
// in light mode, regardless of the user's OS setting or a stale
// localStorage value from before this was put in place.
localStorage.setItem("theme", "light");
document.body.dataset.theme = "light";
