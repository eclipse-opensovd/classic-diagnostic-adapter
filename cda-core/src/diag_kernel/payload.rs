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

use std::collections::VecDeque;

use cda_interfaces::DiagServiceError;

pub(in crate::diag_kernel) struct Payload<'a> {
    data: &'a [u8],
    current_index: usize,
    slices: VecDeque<(usize, usize)>,
    last_read_byte_pos: usize,
    bytes_to_skip: usize,
}

impl<'a> Payload<'a> {
    pub(in crate::diag_kernel) fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            current_index: 0,
            slices: VecDeque::new(),
            last_read_byte_pos: 0,
            bytes_to_skip: 0,
        }
    }
    pub(in crate::diag_kernel) fn set_last_read_byte_pos(&mut self, pos: usize) {
        if pos > self.len() {
            self.last_read_byte_pos = self.len();
        } else {
            self.last_read_byte_pos = pos;
        }
    }

    pub(in crate::diag_kernel) fn set_bytes_to_skip(&mut self, count: usize) {
        self.bytes_to_skip = self.bytes_to_skip.saturating_add(count);
    }

    pub(in crate::diag_kernel) fn bytes_to_skip(&self) -> usize {
        self.bytes_to_skip
    }

    pub(in crate::diag_kernel) fn last_read_byte_pos(&self) -> usize {
        self.last_read_byte_pos
    }

    pub(in crate::diag_kernel) fn data(&self) -> Result<&[u8], DiagServiceError> {
        if let Some(&(start, end)) = self.slices.back() {
            self.data.get(start..end)
        } else {
            self.data.get(self.pos()..)
        }
        .ok_or(DiagServiceError::BadPayload(
            "Slice out of bounds".to_owned(),
        ))
    }

    pub(in crate::diag_kernel) fn pos(&self) -> usize {
        if let Some(&(start, _)) = self.slices.back() {
            start
        } else {
            self.current_index
        }
    }

    pub(in crate::diag_kernel) fn consume(&mut self) -> usize {
        let advance_len = self.last_read_byte_pos.saturating_add(self.bytes_to_skip);
        if self.pos().saturating_add(advance_len) > self.data.len() {
            self.current_index = self.data.len(); // Move to the end if we exceed
        } else {
            self.current_index = self.current_index.saturating_add(advance_len);
        }
        self.last_read_byte_pos = 0;
        self.bytes_to_skip = 0;
        advance_len
    }

    pub(in crate::diag_kernel) fn len(&self) -> usize {
        if let Some(&(start, end)) = self.slices.back() {
            end.saturating_sub(start)
        } else {
            self.data.len()
        }
    }

    pub(in crate::diag_kernel) fn exhausted(&self) -> bool {
        if let Some(&(_, end)) = self.slices.back() {
            self.current_index >= end
        } else {
            self.current_index >= self.data.len()
        }
    }

    pub(in crate::diag_kernel) fn first(&self) -> Option<&u8> {
        self.data.get(self.pos())
    }

    pub(in crate::diag_kernel) fn push_slice_to_abs_end(
        &mut self,
        start: usize,
    ) -> Result<(), DiagServiceError> {
        self.push_slice(start, self.data.len())
    }

    pub(in crate::diag_kernel) fn push_slice(
        &mut self,
        start: usize,
        end: usize,
    ) -> Result<(), DiagServiceError> {
        // when pushing a new slice, it's _relative_ to the last slice or the whole data if no slice
        let current_start = self.pos();
        let current_len = self.len();

        if start > end || end > current_len {
            return Err(DiagServiceError::BadPayload(
                "Invalid range for restricting view".to_owned(),
            ));
        }

        // Convert relative positions to absolute positions
        let absolute_start = current_start.saturating_add(start);
        let absolute_end = current_start.saturating_add(end).min(self.data.len());

        self.slices.push_back((absolute_start, absolute_end));
        Ok(())
    }

    pub(in crate::diag_kernel) fn pop_slice(&mut self) -> Result<(), DiagServiceError> {
        if self.slices.pop_back().is_none() {
            return Err(DiagServiceError::BadPayload(
                "No restricted view to pop".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_payload_type() {
        let raw_payload = vec![
            0xA3, 0x4F, 0x9C, 0xD1, 0x7E, 0x2B, 0x88, 0x5A, 0xB4, 0x3D, 0xE7, 0x0F, 0x61, 0x92,
            0xBC, 0x47, 0x19, 0xFA, 0x33, 0x6D,
        ];
        let mut payload = super::Payload::new(&raw_payload);
        assert_eq!(payload.len(), 20);
        assert_eq!(payload.data().unwrap(), &raw_payload);

        assert!(payload.push_slice(0, 10).is_ok());
        assert_eq!(payload.data().unwrap(), raw_payload.get(0..10).unwrap());
        assert!(payload.push_slice(0, 10).is_ok()); // relative to previous slice (0..10)
        assert_eq!(payload.data().unwrap(), raw_payload.get(0..10).unwrap());
        assert!(payload.push_slice(0, 15).is_err()); // out of bounds of current slice

        assert!(payload.pop_slice().is_ok());
        assert!(payload.pop_slice().is_ok());

        payload.set_last_read_byte_pos(20);
        payload.consume();
        assert!(payload.exhausted()); // should be exhausted now
    }
}
