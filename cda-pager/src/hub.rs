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

//! Global userfaultfd-backed pager shared across every opened `.mdd` file.
//!
//! Ported from the `pager-rs` demo (mmap + userfaultfd + madvise), but
//! reshaped from a single-file CLI demo into a process-wide, multi-file
//! service:
//!
//! - One [`PagerHub`] owns a single `userfaultfd` descriptor and a single
//!   background handler thread for the whole process.
//! - Any number of files can be registered with the hub (via
//!   [`PagerHub::open_file`]); each gets its own anonymous mmap "arena" sized
//!   to the file, registered against the shared `userfaultfd`.
//! - Residency and eviction bookkeeping (the replacement policy and the
//!   `loaded_count` counter) are *global*, not per file: `pool_size_bytes`
//!   caps the number of resident pages across all currently-open files
//!   combined, so pages from one file can evict pages from another.
//! - *Which* page gets evicted is delegated to a pluggable
//!   [`crate::replacement::ReplacementPolicy`] (FIFO by default); the hub
//!   only decides *how many* pages must go and performs the `madvise`.
//! - Pages are read-only and never written back; a `MADV_DONTNEED` eviction
//!   only drops the physical frame, the page remains registered with
//!   userfaultfd and re-faults (and is re-read from its backing file) on the
//!   next touch.
//!
//! Requires Linux (userfaultfd).

#![allow(
    clippy::arithmetic_side_effects,
    reason = "Page index and counter arithmetic on bounded values in the paging hot path; \
              overflow is impossible by construction (indices are below the region page count)"
)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    reason = "Address and page math between u64 file offsets, usize page counts and kernel ABI \
              integer types; all values are bounded by the file size and the page pool"
)]
#![allow(
    clippy::indexing_slicing,
    reason = "Indices are bounded by the region page count / batch size established when the \
              region is opened, a failed lookup would indicate a broken pager invariant"
)]

use std::{
    collections::BTreeMap,
    ffi::c_void,
    fs::File,
    os::unix::{
        fs::FileExt,
        io::{AsRawFd, FromRawFd, RawFd},
    },
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
};

use nix::errno::Errno;
use parking_lot::Mutex;
use userfaultfd::{Event, Uffd};

use crate::{
    PagerConfig, PagerError,
    replacement::{self, PageRef, ReplacementPolicy},
};

/// Cumulative, process-wide pager counters, snapshotted on demand.
#[derive(Clone, Copy, Debug, Default)]
pub struct PagerStats {
    pub loads: u64,
    pub evicts: u64,
    pub misses: u64,
    pub resident_pages: usize,
    pub open_regions: usize,
    /// Name of the active replacement policy.
    pub policy: &'static str,
    /// Number of `madvise(MADV_DONTNEED)` syscalls issued. Compared against
    /// `evicts` this exposes how well a policy's victim batches coalesce:
    /// FIFO over a linear scan approaches one call per batch, while random
    /// selection approaches one call per page.
    pub madvise_calls: u64,
}

/// Heap buffer with a guaranteed alignment, as required for `O_DIRECT`
/// reads (buffer address must be aligned to the logical block size; the
/// pager page size, >= 4096 and a power of two, always satisfies that).
struct AlignedBuf {
    ptr: ptr::NonNull<u8>,
    layout: std::alloc::Layout,
}

// SAFETY: `AlignedBuf` uniquely owns its allocation, like a `Vec<u8>`.
unsafe impl Send for AlignedBuf {}

impl AlignedBuf {
    fn new(len: usize, align: usize) -> Self {
        let layout = std::alloc::Layout::from_size_align(len.max(1), align)
            .expect("valid aligned buffer layout");
        // SAFETY: `layout` has non-zero size.
        let raw = unsafe { std::alloc::alloc_zeroed(layout) };
        let ptr = ptr::NonNull::new(raw).unwrap_or_else(|| std::alloc::handle_alloc_error(layout));
        Self { ptr, layout }
    }
}

impl std::ops::Deref for AlignedBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: allocation of `layout.size()` initialised (zeroed) bytes.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.layout.size()) }
    }
}

impl std::ops::DerefMut for AlignedBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: as above, and `&mut self` guarantees uniqueness.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.layout.size()) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        // SAFETY: allocated in `new` with exactly this layout.
        unsafe { std::alloc::dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

/// Per-file backing info tracked by the hub. Keyed in [`HubState::regions`]
/// by the region's arena base address, which also doubles as a stable
/// "region id" for the eviction queue and for [`PagedRegionHandle`].
struct RegionInfo {
    arena: usize,
    total_pages: usize,
    file: File,
    file_size: u64,
    /// Per-region residency bitmap. Only written under the hub lock;
    /// atomic so the lock-free read path can publish/observe residency.
    pages: Arc<[AtomicBool]>,
}

struct HubState {
    /// Keyed by arena base address for O(log n) "which region owns this
    /// fault address" lookups via `range(..=addr).next_back()`.
    regions: BTreeMap<usize, RegionInfo>,
    /// The installed page-replacement strategy, shared by all regions. It
    /// owns the eviction ordering; the hub owns the residency bitmaps and
    /// the `madvise` calls. Its resident set is kept exactly in sync via
    /// `on_insert` / `take_victims` / `on_region_closed`.
    policy: Box<dyn ReplacementPolicy>,
    /// Reused scratch buffer for the victim batch returned by the policy,
    /// sized for `prefetch_pages`.
    victim_buf: Vec<PageRef>,
    /// Global count of currently-resident pages across all regions,
    /// compared against `pool_size_pages`.
    loaded_count: usize,
    /// Reused scratch buffer for batched reads, sized for `prefetch_pages`.
    io_buf: AlignedBuf,
    stat_loads: u64,
    stat_evicts: u64,
    stat_misses: u64,
    stat_madvise_calls: u64,
}

pub struct PagerHub {
    uffd: Uffd,
    pool_size_pages: usize,
    page_size: usize,
    prefetch_pages: usize,
    prefetch_backward: bool,
    /// Minimum number of pages to evict per eviction round, derived from
    /// `PagerConfig.eviction_batch_fraction`. See that field's docs.
    eviction_batch_pages: usize,
    /// See [`PagerConfig::direct_io`].
    direct_io: bool,
    state: Mutex<HubState>,
    shutdown: Arc<AtomicBool>,
    handler: Mutex<Option<JoinHandle<()>>>,
}

impl PagerHub {
    /// Creates the hub and starts its fault handler thread.
    ///
    /// # Errors
    /// Returns an error if the configuration is invalid or userfaultfd is
    /// unavailable.
    pub fn new(config: PagerConfig) -> Result<Arc<Self>, PagerError> {
        config.validate()?;
        // SAFETY: `sysconf` has no preconditions.
        let system_page =
            usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096);
        if config.page_size < system_page {
            return Err(PagerError::InvalidConfig(format!(
                "page size {} is smaller than the system page size {system_page}",
                config.page_size
            )));
        }

        let pool_size_pages = (config.pool_size_bytes / config.page_size).max(1);
        // A batch larger than the pool could never be resident at once.
        let prefetch_pages = config.prefetch_pages.min(pool_size_pages);
        if prefetch_pages < config.prefetch_pages {
            tracing::warn!(
                configured = config.prefetch_pages,
                capped = prefetch_pages,
                "Prefetch batch exceeds the pool size, capping it"
            );
        }
        let eviction_batch_pages = ((pool_size_pages as f64 * config.eviction_batch_fraction)
            .round() as usize)
            .min(pool_size_pages);
        let uffd = create_uffd()?;

        let hub = Arc::new(Self {
            uffd,
            pool_size_pages,
            page_size: config.page_size,
            prefetch_pages,
            prefetch_backward: config.prefetch_backward,
            eviction_batch_pages,
            direct_io: config.direct_io,
            state: Mutex::new(HubState {
                regions: BTreeMap::new(),
                policy: replacement::build(config.eviction),
                victim_buf: Vec::with_capacity(prefetch_pages.max(eviction_batch_pages)),
                loaded_count: 0,
                io_buf: AlignedBuf::new(prefetch_pages * config.page_size, config.page_size),
                stat_loads: 0,
                stat_evicts: 0,
                stat_misses: 0,
                stat_madvise_calls: 0,
            }),
            shutdown: Arc::new(AtomicBool::new(false)),
            handler: Mutex::new(None),
        });

        let handler = {
            let hub = Arc::clone(&hub);
            let shutdown = Arc::clone(&hub.shutdown);
            thread::spawn(move || uffd_handler_loop(&hub, &shutdown))
        };
        *hub.handler.lock() = Some(handler);

        Ok(hub)
    }

    /// Registers `path` as a new paged region and returns a handle whose
    /// `AsRef<[u8]>` implementation exposes the file's contents, faulted in
    /// on demand and capped by the hub's shared, global resident-page pool.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or registered with userfaultfd.
    pub fn open_file(self: &Arc<Self>, path: &str) -> Result<PagedRegionHandle, PagerError> {
        let file = self.open_data_file(path).map_err(|error| {
            PagerError::Io(format!("Failed to open MDD file '{path}': {error}"))
        })?;
        let file_size = file
            .metadata()
            .map_err(|error| PagerError::Io(format!("Failed to stat MDD file '{path}': {error}")))?
            .len();
        if file_size == 0 {
            return Err(PagerError::Io(format!("MDD file '{path}' is empty")));
        }

        let page_size = self.page_size;
        let too_large = || PagerError::Io(format!("MDD file '{path}' is too large to page"));
        let total_pages = usize::try_from(file_size)
            .map_err(|_| too_large())?
            .div_ceil(page_size);
        let arena_len = total_pages.checked_mul(page_size).ok_or_else(too_large)?;

        // mmap() only guarantees alignment to the system page size, not to
        // our (possibly larger) custom page size. Over-map by one extra
        // page and trim the unaligned head/tail so `arena` is guaranteed to
        // be page_size-aligned.
        let map_len = arena_len.checked_add(page_size).ok_or_else(too_large)?;
        let map_base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                map_len,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if map_base == libc::MAP_FAILED {
            return Err(PagerError::Syscall(format!(
                "mmap arena for '{path}': {}",
                std::io::Error::last_os_error()
            )));
        }

        let aligned_addr = (map_base as usize + page_size - 1) & !(page_size - 1);
        let head_slack = aligned_addr - map_base as usize;
        let tail_slack = page_size - head_slack;
        if head_slack > 0 {
            unsafe { libc::munmap(map_base, head_slack) };
        }
        if tail_slack > 0 {
            unsafe {
                libc::munmap(
                    (map_base as usize + head_slack + arena_len) as *mut c_void,
                    tail_slack,
                )
            };
        }
        let arena = aligned_addr;

        if let Err(error) = self.uffd.register(arena as *mut c_void, arena_len) {
            unsafe { libc::munmap(arena as *mut c_void, arena_len) };
            return Err(PagerError::Syscall(format!(
                "uffd register for '{path}': {error}"
            )));
        }

        let region = RegionInfo {
            arena,
            total_pages,
            file,
            file_size,
            pages: (0..total_pages).map(|_| AtomicBool::new(false)).collect(),
        };

        let mut state = self.state.lock();
        state.regions.insert(arena, region);
        drop(state);

        Ok(PagedRegionHandle {
            hub: Arc::clone(self),
            region_id: arena,
            arena,
            file_size,
        })
    }

    /// Opens `path` for page loads, with `O_DIRECT` if requested and
    /// supported by the filesystem (tmpfs, for one, rejects it with EINVAL).
    fn open_data_file(&self, path: &str) -> std::io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt;
        if self.direct_io {
            match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECT)
                .open(path)
            {
                Ok(file) => return Ok(file),
                Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
                    tracing::warn!(path, "O_DIRECT not supported, using buffered reads");
                }
                Err(e) => return Err(e),
            }
        }
        File::open(path)
    }

    /// Unregisters and unmaps a region. Called from [`PagedRegionHandle`]'s
    /// `Drop` impl once the last `Bytes` clone referencing it is released.
    fn close_region(&self, region_id: usize, arena: usize) {
        let mut state = self.state.lock();
        let Some(region) = state.regions.remove(&region_id) else {
            return;
        };
        let arena_len = region.total_pages * self.page_size;
        let resident = region
            .pages
            .iter()
            .filter(|p| p.load(Ordering::Relaxed))
            .count();
        state.loaded_count = state.loaded_count.saturating_sub(resident);
        // Keep the policy's resident set exact: it must never offer up a
        // page of a region that no longer exists.
        state.policy.on_region_closed(region_id);
        drop(state);

        let _ = self.uffd.unregister(arena as *mut c_void, arena_len);
        unsafe { libc::munmap(arena as *mut c_void, arena_len) };
    }

    pub fn stats(&self) -> PagerStats {
        let state = self.state.lock();
        PagerStats {
            loads: state.stat_loads,
            evicts: state.stat_evicts,
            misses: state.stat_misses,
            resident_pages: state.loaded_count,
            open_regions: state.regions.len(),
            policy: state.policy.name(),
            madvise_calls: state.stat_madvise_calls,
        }
    }

    pub fn pool_size_pages(&self) -> usize {
        self.pool_size_pages
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }
}

impl Drop for PagerHub {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(handler) = self.handler.lock().take() {
            let _ = handler.join();
        }
        // Remaining regions should already have been closed via
        // `PagedRegionHandle::drop`, but defensively clean up anything left.
        let mut state = self.state.lock();
        let page_size = self.page_size;
        let regions = std::mem::take(&mut state.regions);
        for (arena, region) in regions {
            let arena_len = region.total_pages * page_size;
            let _ = self.uffd.unregister(arena as *mut c_void, arena_len);
            unsafe { libc::munmap(arena as *mut c_void, arena_len) };
        }
    }
}

/// A handle to one file registered with a [`PagerHub`]. Implements
/// `AsRef<[u8]>` so it can be wrapped directly via `bytes::Bytes::from_owner`,
/// the same pattern used for the plain `memmap2::Mmap` load path.
pub struct PagedRegionHandle {
    hub: Arc<PagerHub>,
    region_id: usize,
    arena: usize,
    file_size: u64,
}

impl AsRef<[u8]> for PagedRegionHandle {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: `arena` was mmap'd (and registered with userfaultfd) for
        // at least `file_size` bytes in `PagerHub::open_file`, and remains
        // valid until this handle is dropped (which unregisters/unmaps it).
        unsafe { std::slice::from_raw_parts(self.arena as *const u8, self.file_size as usize) }
    }
}

impl Drop for PagedRegionHandle {
    fn drop(&mut self) {
        self.hub.close_region(self.region_id, self.arena);
    }
}

// SAFETY: the arena is read-only from userland's perspective (all mutation
// happens via UFFDIO_COPY performed by the kernel on behalf of the handler
// thread), and the handle's only requirement for `bytes::Bytes::from_owner`
// is `Send`.
unsafe impl Send for PagedRegionHandle {}

/*
 * Create the userfaultfd object via the raw `userfaultfd(2)` syscall rather
 * than the `userfaultfd` crate's `UffdBuilder`, which prefers opening
 * `/dev/userfaultfd` when that device node exists. On some systems the node
 * exists but is not accessible to unprivileged users, which makes the
 * builder fail outright instead of falling back to the syscall. We
 * negotiate UFFDIO_API ourselves and then hand the fd to the crate's safe
 * `Uffd` wrapper for everything else.
 */
fn create_uffd() -> Result<Uffd, PagerError> {
    let flags = libc::O_CLOEXEC | libc::O_NONBLOCK | userfaultfd_sys::UFFD_USER_MODE_ONLY as i32;
    let raw_fd = unsafe { libc::syscall(libc::SYS_userfaultfd, flags) };
    if raw_fd < 0 {
        return Err(PagerError::Syscall(format!(
            "userfaultfd: {}",
            std::io::Error::last_os_error()
        )));
    }
    let raw_fd = raw_fd as RawFd;

    // Initialize userfaultfd
    let mut api = userfaultfd_sys::uffdio_api {
        api: userfaultfd_sys::UFFD_API,
        features: 0,
        ioctls: 0,
    };
    let ret = unsafe { libc::ioctl(raw_fd, userfaultfd_sys::UFFDIO_API as _, &mut api) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(raw_fd) };
        return Err(PagerError::Syscall(format!("UFFDIO_API: {err}")));
    }

    Ok(unsafe { Uffd::from_raw_fd(raw_fd) })
}

/// Release the physical frames backing the contiguous page range
/// [start, start+len) of `region` with a single `madvise()` call. The
/// virtual pages remain registered with userfaultfd, so the next access to
/// any of them re-faults.
fn evict_range(region: &RegionInfo, page_size: usize, start: usize, len: usize) {
    if len == 0 {
        return;
    }
    let addr = (region.arena + start * page_size) as *mut c_void;
    let ret = unsafe { libc::madvise(addr, len * page_size, libc::MADV_DONTNEED) };
    if ret < 0 {
        tracing::error!(
            error = %std::io::Error::last_os_error(),
            "madvise DONTNEED failed"
        );
    }
}

/// Frees room for `need` more resident pages under the hub's global cap.
///
/// The hub decides *how many* pages must go and performs the `madvise`; the
/// installed [`ReplacementPolicy`] decides *which* ones. Because
/// `take_victims` transfers ownership of the returned pages out of the
/// policy, there are no stale entries to filter here - every victim is
/// resident by construction.
///
/// The batch is sorted before eviction so that even a policy returning
/// scattered pages (e.g. `random`) coalesces contiguous runs into single
/// `madvise` calls where possible. Sorting is negligible: the batch is at
/// most `prefetch_pages` entries. `stat_madvise_calls` records how well the
/// coalescing actually worked for the active policy.
fn evict_to_limit(hub: &PagerHub, state: &mut HubState, need: usize) {
    let need = need.min(hub.pool_size_pages);
    if state.loaded_count + need <= hub.pool_size_pages {
        return;
    }
    let shortfall = state.loaded_count + need - hub.pool_size_pages;
    // Evict at least `eviction_batch_pages` at a time, if configured, to
    // amortize eviction overhead across fewer/larger rounds. Never more than
    // what's actually resident.
    let shortfall = shortfall
        .max(hub.eviction_batch_pages)
        .min(state.loaded_count);

    // Split borrow of disjoint fields: `take_victims` needs `&mut policy`
    // while the eviction pass needs `&mut regions`.
    let HubState {
        regions,
        policy,
        victim_buf,
        loaded_count,
        stat_evicts,
        stat_madvise_calls,
        ..
    } = state;

    victim_buf.clear();
    policy.take_victims(shortfall, victim_buf);
    victim_buf.sort_unstable();

    let page_size = hub.page_size;
    let mut run_region: Option<usize> = None;
    let mut run_start = 0usize;
    let mut run_len = 0usize;

    for page in victim_buf.iter().copied() {
        match regions.get_mut(&page.region) {
            Some(region) => {
                // A policy that honours the ownership contract can only ever
                // hand back resident pages; anything else would desynchronise
                // `loaded_count`, so refuse it rather than corrupt the count.
                debug_assert!(
                    region.pages[page.index].load(Ordering::Relaxed),
                    "replacement policy returned non-resident page {page:?}"
                );
                if !region.pages[page.index].load(Ordering::Relaxed) {
                    continue;
                }
                region.pages[page.index].store(false, Ordering::Release);
            }
            None => continue,
        }
        *loaded_count -= 1;
        *stat_evicts += 1;

        if run_len > 0 && (run_region != Some(page.region) || page.index != run_start + run_len) {
            if let Some(prev_region) = run_region.and_then(|id| regions.get(&id)) {
                evict_range(prev_region, page_size, run_start, run_len);
                *stat_madvise_calls += 1;
            }
            run_len = 0;
        }
        if run_len == 0 {
            run_region = Some(page.region);
            run_start = page.index;
        }
        run_len += 1;
    }

    if run_len > 0
        && let Some(region) = run_region.and_then(|id| regions.get(&id))
    {
        evict_range(region, page_size, run_start, run_len);
        *stat_madvise_calls += 1;
    }
    victim_buf.clear();
}

/// Resolve a MISSING page fault for page index `idx` of `region_id` at
/// arena-relative address `fault_addr` (already page-aligned). Speculatively
/// loads a contiguous batch of up to `prefetch_pages` pages with a single
/// `pread()`-equivalent + a single `UFFDIO_COPY`. By default the batch starts
/// at `idx` and extends forward; if `hub.prefetch_backward` is set it instead
/// ends at `idx` and extends backward, i.e. the faulting page is the *last*
/// page loaded rather than the first. Either way the batch is clamped to the
/// region's bounds and to pages not already resident. The tail past EOF on
/// the last page is zero-filled. Read-only - nothing is ever written back.
fn load_page(hub: &PagerHub, state: &mut HubState, region_id: usize, idx: usize, fault_addr: u64) {
    let page_size = hub.page_size;
    // Report the miss before making room or inserting.
    state.policy.on_fault(PageRef::new(region_id, idx));
    let (batch, start_idx, offset, file_size) = {
        let region = state.regions.get(&region_id).expect("region must exist");
        let mut batch = 1usize;
        let start_idx = if hub.prefetch_backward {
            let max_batch = hub.prefetch_pages.min(idx + 1);
            while batch < max_batch && !region.pages[idx - batch].load(Ordering::Relaxed) {
                batch += 1;
            }
            idx + 1 - batch
        } else {
            let mut max_batch = hub.prefetch_pages;
            if idx + max_batch > region.total_pages {
                max_batch = region.total_pages - idx;
            }
            while batch < max_batch && !region.pages[idx + batch].load(Ordering::Relaxed) {
                batch += 1;
            }
            idx
        };
        (
            batch,
            start_idx,
            (start_idx * page_size) as u64,
            region.file_size,
        )
    };

    evict_to_limit(hub, state, batch);

    let want = batch * page_size;
    let valid = if offset + want as u64 <= file_size {
        want
    } else {
        (file_size - offset) as usize
    };

    let buf = &mut state.io_buf[..want];
    if valid < want {
        buf[valid..].fill(0);
    }
    {
        // Read the full, page-aligned batch length rather than just `valid`
        // bytes: O_DIRECT requires aligned lengths, and a read past EOF
        // simply comes back short (the tail is already zero-filled above).
        let region = state.regions.get(&region_id).expect("region must exist");
        let mut total = 0usize;
        while total < valid {
            match region
                .file
                .read_at(&mut buf[total..want], offset + total as u64)
            {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    tracing::error!(error = %e, "Failed to read file page");
                    break;
                }
            }
        }
    }

    // The batch may start before the faulting page (backward prefetch), so
    // the copy destination is the batch start, not `fault_addr` itself.
    let dest_addr = fault_addr - ((idx - start_idx) * page_size) as u64;
    let copy_result = unsafe {
        hub.uffd.copy(
            buf.as_ptr().cast::<c_void>(),
            dest_addr as *mut c_void,
            want,
            true,
        )
    };
    if let Err(e) = copy_result {
        if let userfaultfd::Error::CopyFailed(Errno::EEXIST) = e {
            // Page was already populated (shouldn't happen with the lock held).
            let _ = hub.uffd.wake(fault_addr as *mut c_void, page_size);
        } else {
            tracing::error!(error = %e, "UFFDIO_COPY failed");
        }
        return;
    }

    let HubState {
        regions,
        policy,
        loaded_count,
        stat_loads,
        ..
    } = state;
    let region = regions.get_mut(&region_id).expect("region must exist");
    for k in 0..batch {
        let page_idx = start_idx + k;
        region.pages[page_idx].store(true, Ordering::Release);
        // Only `page_idx == idx` actually faulted; the rest are speculative
        // neighbours (forward or backward) the policy may want to treat
        // differently.
        policy.on_insert(PageRef::new(region_id, page_idx), page_idx == idx);
        *loaded_count += 1;
        *stat_loads += 1;
    }
}

/// Polls the userfaultfd descriptor with a short timeout so the thread can
/// notice `shutdown` promptly without blocking forever.
fn uffd_handler_loop(hub: &Arc<PagerHub>, shutdown: &AtomicBool) {
    let fd = hub.uffd.as_raw_fd();
    loop {
        if shutdown.load(Ordering::Acquire) {
            break;
        }

        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(ptr::addr_of_mut!(pfd), 1, 100) };
        if ret <= 0 {
            continue;
        }

        let event = match hub.uffd.read_event() {
            Ok(Some(e)) => e,
            Ok(None) => continue,
            Err(e) => {
                tracing::error!(error = %e, "Failed to read uffd event");
                break;
            }
        };

        let Event::Pagefault { addr, .. } = event else {
            continue;
        };
        let page_size = hub.page_size;
        let addr = (addr as u64) & !(page_size as u64 - 1);

        let mut state = hub.state.lock();
        let Some((&region_id, region)) = state.regions.range(..=(addr as usize)).next_back() else {
            // No region claims this address (e.g. it was just closed); wake
            // it up so the faulting thread doesn't hang.
            let _ = hub.uffd.wake(addr as *mut c_void, page_size);
            continue;
        };
        if (addr as usize) >= region.arena + region.total_pages * page_size {
            let _ = hub.uffd.wake(addr as *mut c_void, page_size);
            continue;
        }
        let idx = (addr as usize - region.arena) / page_size;

        let resident = state
            .regions
            .get(&region_id)
            .is_some_and(|region| region.pages[idx].load(Ordering::Relaxed));
        if resident {
            // Already loaded (shouldn't normally reach here) - just wake.
            let _ = hub.uffd.wake(addr as *mut c_void, page_size);
        } else {
            state.stat_misses += 1;
            load_page(hub, &mut state, region_id, idx, addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::EvictionKind;

    fn write_temp_file(name: &str, len: usize) -> String {
        let path = std::env::temp_dir().join(format!(
            "mdd-access-sim-pager-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut f = File::create(&path).unwrap();
        // Distinct byte pattern per file so we can verify content integrity
        // through the pager, not just presence/absence of faults.
        let byte = name.as_bytes()[0];
        f.write_all(&vec![byte; len]).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// Creates a hub, or `None` (skipping the test) on kernels or sandboxes
    /// without userfaultfd support.
    fn new_hub(config: PagerConfig) -> Option<Arc<PagerHub>> {
        match PagerHub::new(config) {
            Ok(hub) => Some(hub),
            Err(PagerError::Syscall(error)) => {
                eprintln!("skipping, userfaultfd unavailable: {error}");
                None
            }
            Err(error) => panic!("unexpected pager error: {error}"),
        }
    }

    const ALL_KINDS: [EvictionKind; 3] = [
        EvictionKind::Fifo,
        EvictionKind::Random,
        EvictionKind::PrefetchFirst,
    ];

    fn config(page_size: usize, cap_pages: usize, eviction: EvictionKind) -> PagerConfig {
        PagerConfig {
            pool_size_bytes: page_size * cap_pages,
            page_size,
            prefetch_pages: 16,
            prefetch_backward: false,
            eviction,
            eviction_batch_fraction: 0.0,
            direct_io: false,
            enabled: true,
        }
    }

    /// Two files, each 4 pages, but a global cap of only 6 pages: opening
    /// and fully touching both must trigger cross-file eviction (the global
    /// cap is shared, not per file) while still returning correct content
    /// for both files via re-fault-on-touch.
    ///
    /// Run against every replacement policy: whichever pages a policy
    /// chooses, the data handed back to the caller must be identical, since
    /// eviction only drops frames that are re-read from the backing file.
    #[test]
    fn global_cap_is_shared_across_files() {
        for eviction in ALL_KINDS {
            let page_size = 4096;
            let path_a = write_temp_file("a", page_size * 4);
            let path_b = write_temp_file("b", page_size * 4);

            let Some(hub) = new_hub(config(page_size, 6, eviction)) else {
                return;
            };

            let handle_a = hub.open_file(&path_a).unwrap();
            let handle_b = hub.open_file(&path_b).unwrap();

            // Touch every page of both files: 8 pages total requested against
            // a 6-page global cap, so eviction must occur, but content read
            // back must still be correct (re-faulted from the backing file).
            let bytes_a = handle_a.as_ref().to_vec();
            let bytes_b = handle_b.as_ref().to_vec();

            let policy = eviction.as_str();
            assert!(
                bytes_a.iter().all(|&b| b == b'a'),
                "{policy}: file A corrupt"
            );
            assert!(
                bytes_b.iter().all(|&b| b == b'b'),
                "{policy}: file B corrupt"
            );
            assert_eq!(bytes_a.len(), page_size * 4);
            assert_eq!(bytes_b.len(), page_size * 4);

            let stats = hub.stats();
            assert_eq!(stats.policy, policy);
            assert!(
                stats.evicts > 0,
                "{policy}: expected the shared 6-page cap to force eviction across the two 4-page \
                 files, but no eviction was recorded: {stats:?}"
            );
            assert!(
                stats.resident_pages <= 6,
                "{policy}: resident pages ({}) must never exceed the global cap (6)",
                stats.resident_pages
            );
            assert!(
                stats.madvise_calls > 0 && stats.madvise_calls <= stats.evicts,
                "{policy}: madvise calls ({}) must be non-zero and coalesce at least as well as \
                 one call per evicted page ({})",
                stats.madvise_calls,
                stats.evicts
            );
            assert_eq!(stats.open_regions, 2);

            // Re-touch file A from the start: any pages evicted while reading
            // B must be transparently reloaded with correct content.
            let bytes_a_again = handle_a.as_ref().to_vec();
            assert!(
                bytes_a_again.iter().all(|&b| b == b'a'),
                "{policy}: file A corrupt after re-fault"
            );

            drop(handle_a);
            drop(handle_b);
            let _ = std::fs::remove_file(&path_a);
            let _ = std::fs::remove_file(&path_b);
        }
    }

    /// Closing a region must drop its pages from both the hub's resident
    /// count *and* the policy's own set. If they drift apart, the policy
    /// will later hand back a page of a dead region and the resident count
    /// underflows; this catches that for every policy.
    #[test]
    fn closing_a_region_keeps_policy_and_hub_in_sync() {
        for eviction in ALL_KINDS {
            let policy = eviction.as_str();
            let page_size = 4096;
            let path_a = write_temp_file("a", page_size * 4);
            let path_b = write_temp_file("b", page_size * 4);

            let Some(hub) = new_hub(config(page_size, 6, eviction)) else {
                return;
            };

            let handle_a = hub.open_file(&path_a).unwrap();
            let handle_b = hub.open_file(&path_b).unwrap();
            let _ = handle_a.as_ref().to_vec();
            let _ = handle_b.as_ref().to_vec();

            drop(handle_a);
            let after_close = hub.stats();
            assert_eq!(after_close.open_regions, 1, "{policy}");
            assert!(
                after_close.resident_pages <= 4,
                "{policy}: closing file A left {} resident pages, but only file B (4 pages) \
                 remains",
                after_close.resident_pages
            );

            // Keep faulting on B: this is where a stale victim from the
            // closed region would surface.
            let bytes_b = handle_b.as_ref().to_vec();
            assert!(
                bytes_b.iter().all(|&b| b == b'b'),
                "{policy}: file B corrupt"
            );
            assert!(hub.stats().resident_pages <= 6, "{policy}");

            drop(handle_b);
            assert_eq!(hub.stats().resident_pages, 0, "{policy}: pages leaked");

            let _ = std::fs::remove_file(&path_a);
            let _ = std::fs::remove_file(&path_b);
        }
    }

    /// With `prefetch_backward`, a fault must pull in the batch *ending* at
    /// the faulting page rather than starting at it: touching page 5 of an
    /// 8-page file with a 4-page prefetch budget should load pages 2..=5,
    /// not 5..=8.
    #[test]
    fn prefetch_backward_loads_pages_before_the_fault() {
        let page_size = 4096usize;
        let total_pages = 8usize;
        // Distinct byte per page so loaded content proves *which* pages the
        // batch covered, not just how many.
        let mut contents = vec![0u8; page_size * total_pages];
        for (page, chunk) in contents.chunks_mut(page_size).enumerate() {
            chunk.fill(page as u8 + 1);
        }
        let path = std::env::temp_dir().join(format!(
            "mdd-access-sim-pager-test-backward-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, &contents).unwrap();

        let mut cfg = config(page_size, total_pages, EvictionKind::Fifo);
        cfg.prefetch_pages = 4;
        cfg.prefetch_backward = true;
        let Some(hub) = new_hub(cfg) else {
            return;
        };
        let handle = hub.open_file(path.to_str().unwrap()).unwrap();

        // Touch a single byte of page 5 only; everything else must come in
        // purely via speculative prefetch.
        let fault_page = 5usize;
        let touched = handle.as_ref()[fault_page * page_size];
        assert_eq!(touched, fault_page as u8 + 1);

        let stats = hub.stats();
        assert_eq!(
            stats.misses, 1,
            "exactly one real fault should have occurred"
        );
        assert_eq!(
            stats.loads, 4,
            "batch should be clamped to prefetch_pages (4)"
        );
        assert_eq!(stats.resident_pages, 4);

        // Pages 2..=5 must be resident with correct content; 0,1,6,7 must
        // not have been touched by this single backward-prefetch batch.
        let bytes = handle.as_ref();
        for page in 2..=fault_page {
            assert_eq!(
                bytes[page * page_size],
                page as u8 + 1,
                "page {page} should have been speculatively loaded (backward batch)"
            );
        }
        assert_eq!(
            hub.stats().resident_pages,
            4,
            "reading already-resident pages must not fault"
        );

        drop(handle);
        let _ = std::fs::remove_file(&path);
    }
}
