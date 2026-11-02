//! C ABI (Swift on iOS, or any non-Rust app). One node per process.
//! Returns 0 on success, negative on error. All pointers are checked for NULL.
//!
//! # Safety
//! For every function: non-NULL pointers must be valid for the documented size (`kek` 32 B, ids 32 B,
//! apps 16 B, `out` `cap` B, `token` `len` B) and strings must be NUL-terminated UTF-8.
#![allow(clippy::missing_safety_doc)] // documented once above
use crate::{Node, Relay, Svc, app, open_notification};
use std::{ffi::{CStr, c_char, c_void}, path::Path, sync::{Arc, OnceLock}};

static NODE: OnceLock<Arc<Node>> = OnceLock::new();
static STATUS: OnceLock<(StatusCb, Ctx)> = OnceLock::new();

/// Relay status: `url` (NUL-terminated, NULL when offline) and whether it is n0's public fallback.
pub type StatusCb = extern "C" fn(ctx: *mut c_void, url: *const c_char, fallback: bool);

/// Push callback: 32-byte sender id, 16-byte app, payload. Runs on irpush's thread.
pub type Cb = extern "C" fn(ctx: *mut c_void, from: *const u8, app: *const u8, data: *const u8, len: usize);

struct Ctx(*mut c_void);
unsafe impl Send for Ctx {}
unsafe impl Sync for Ctx {}
impl Ctx { fn get(&self) -> *mut c_void { self.0 } } // whole-struct capture keeps it Send

/// SAFETY (all helpers): pointers come from the C caller; NULL is rejected, sizes are fixed by the ABI.
unsafe fn s<'a>(p: *const c_char) -> Option<&'a str> { if p.is_null() { None } else { unsafe { CStr::from_ptr(p) }.to_str().ok() } }
unsafe fn k(p: *const u8) -> Option<[u8; 32]> { if p.is_null() { None } else { Some(unsafe { *(p as *const [u8; 32]) }) } }
unsafe fn relays(r: *const c_char) -> Vec<Relay> { unsafe { s(r) }.and_then(|r| Relay::list(r).ok()).unwrap_or_default() }

fn start(n: anyhow::Result<Node>, cb: Cb, ctx: *mut c_void) -> i32 {
    let n = match n { Ok(n) => Arc::new(n), Err(e) => { tracing::warn!("irpush: {e:#}"); return -1 } };
    if NODE.set(n.clone()).is_err() { return -2 }
    let ctx = Ctx(ctx);
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return };
        let mut w = n.relay_watch();
        let status = async {
            let Some((scb, sctx)) = STATUS.get() else { return };
            while w.changed().await.is_ok() {
                let u = w.borrow_and_update().clone();
                let c = u.as_deref().and_then(|u| std::ffi::CString::new(u).ok());
                scb(sctx.get(), c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()), u.as_deref().is_some_and(crate::is_n0));
            }
        };
        let _ = rt.block_on(async { tokio::join!(n.run(|from, app, d| cb(ctx.get(), from.as_bytes().as_ptr(), app.as_ptr(), d.as_ptr(), d.len())), status) });
    });
    0
}

/// Optional, before `irp_join`/`irp_open`: called whenever the relay in use changes, so the app can
/// show a notice while on n0's public fallback.
#[unsafe(no_mangle)]
pub extern "C" fn irp_status(cb: StatusCb, ctx: *mut c_void) -> i32 { if STATUS.set((cb, Ctx(ctx))).is_ok() { 0 } else { -2 } }

/// First launch: join with a ticket. `path`: state file in the App Group container; `kek`: 32 bytes;
/// `relays`: the app's default push relays "https://r.example#hextoken,..." or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn irp_join(path: *const c_char, kek: *const u8, ticket: *const c_char, relays_: *const c_char, cb: Cb, ctx: *mut c_void) -> i32 {
    let (Some(p), Some(kek), Some(t)) = (unsafe { s(path) }, unsafe { k(kek) }, unsafe { s(ticket) }) else { return -3 };
    start(Node::join(p, kek, t, unsafe { relays(relays_) }), cb, ctx)
}

/// Every later launch.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn irp_open(path: *const c_char, kek: *const u8, relays_: *const c_char, cb: Cb, ctx: *mut c_void) -> i32 {
    let (Some(p), Some(kek)) = (unsafe { s(path) }, unsafe { k(kek) }) else { return -3 };
    start(Node::open(p, kek, unsafe { relays(relays_) }), cb, ctx)
}

/// APNs device token from didRegisterForRemoteNotificationsWithDeviceToken. `topic`: bundle id.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn irp_route(sandbox: bool, topic: *const c_char, token: *const u8, len: usize) -> i32 {
    let (Some(n), Some(t)) = (NODE.get(), unsafe { s(topic) }) else { return -3 };
    if token.is_null() || len == 0 { return -3 }
    let tok = unsafe { std::slice::from_raw_parts(token, len) };
    n.set_route(if sandbox { Svc::ApnsSandbox } else { Svc::Apns }, t, tok).map_or(-1, |_| 0)
}

#[unsafe(no_mangle)] pub extern "C" fn irp_pause(p: bool) { if let Some(n) = NODE.get() { n.pause(p) } }
#[unsafe(no_mangle)] pub extern "C" fn irp_network(id: u64) { if let Some(n) = NODE.get() { n.network(id) } }
#[unsafe(no_mangle)] pub extern "C" fn irp_kick() { if let Some(n) = NODE.get() { n.kick() } }

/// This device's id (32 bytes): what hosts push to.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn irp_id(out: *mut u8) -> i32 {
    let Some(n) = NODE.get().filter(|_| !out.is_null()) else { return -3 };
    unsafe { out.copy_from_nonoverlapping(n.id().as_bytes().as_ptr(), 32) };
    0
}

/// 16-byte app address for a bundle id / package name.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn irp_app(name: *const c_char, out: *mut u8) -> i32 {
    let Some(n) = (unsafe { s(name) }).filter(|_| !out.is_null()) else { return -3 };
    unsafe { out.copy_from_nonoverlapping(app(n).as_ptr(), 16) };
    0
}

/// Notification Service Extension: decrypt userInfo["f"] on the phone. Needs no running node.
/// Returns payload length; -1: not ours or already delivered; -2: error or `cap` too small.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn irp_notification(path: *const c_char, kek: *const u8, f: *const c_char, from: *mut u8, app: *mut u8, out: *mut u8, cap: usize) -> isize {
    let (Some(p), Some(kek), Some(f)) = (unsafe { s(path) }, unsafe { k(kek) }, unsafe { s(f) }) else { return -2 };
    if from.is_null() || app.is_null() || out.is_null() { return -2 }
    match open_notification(Path::new(p), &kek, f) {
        Ok(Some((id, a, d))) if d.len() <= cap => unsafe {
            from.copy_from_nonoverlapping(id.as_bytes().as_ptr(), 32);
            app.copy_from_nonoverlapping(a.as_ptr(), 16);
            out.copy_from_nonoverlapping(d.as_ptr(), d.len());
            d.len() as isize
        },
        Ok(None) => -1,
        _ => -2,
    }
}
