//! JNI for the Android library (`android/`, class `org.irpush.Native`), linked
//! into the app's own native library (feature `jni`): the node of the app that
//! owns this phone's irpush connection. Pushes are pulled by `next` on a Kotlin
//! thread, so Rust never calls into the JVM.
use crate::{Node, OFFLINE, app};
use jni::{JNIEnv, objects::{JByteArray, JClass, JString}, sys::{jboolean, jbyteArray, jlong, jstring}};
use std::{collections::VecDeque, path::Path, sync::{Arc, Condvar, Mutex, OnceLock}};

static NODE: OnceLock<Arc<Node>> = OnceLock::new();
static Q: (Mutex<VecDeque<Vec<u8>>>, Condvar) = (Mutex::new(VecDeque::new()), Condvar::new());

fn s(e: &mut JNIEnv, j: &JString) -> Option<String> { (!j.is_null()).then(|| e.get_string(j).ok().map(String::from)).flatten() }

fn run(n: Node) -> Arc<Node> {
    let n = NODE.get_or_init(|| Arc::new(n)).clone();
    let m = n.clone();
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return };
        let _ = rt.block_on(m.run(|from, app, d| {
            let mut q = Q.0.lock().unwrap_or_else(|e| e.into_inner());
            if q.len() < 1024 { q.push_back([from.as_bytes(), &app[..], d].concat()) }
            Q.1.notify_one();
        }));
    });
    n
}

/// Open the node at `path`, or join with `ticket` when there is none yet; a
/// running node joins `ticket`'s mesh too. Returns the device id (hex), null
/// when not joined.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_irpush_Native_start(mut e: JNIEnv, _: JClass, path: JString, kek: JByteArray, ticket: JString) -> jstring {
    let t = s(&mut e, &ticket);
    let id = NODE.get().cloned().inspect(|n| if let Some(t) = &t { let _ = n.add(t).map_err(|x| tracing::warn!("irpush: {x:#}")); }).or_else(|| {
        let p = s(&mut e, &path)?;
        let k: [u8; 32] = e.convert_byte_array(&kek).ok()?.try_into().ok()?;
        let n = if Path::new(&p).exists() { Node::open(&p, k, vec![]) } else { Node::join(&p, k, &t?, vec![]) };
        n.map_err(|x| tracing::warn!("irpush: {x:#}")).ok().map(run)
    });
    id.and_then(|n| e.new_string(n.id().to_string()).ok()).map_or(std::ptr::null_mut(), |j| j.into_raw())
}

/// Whether the node has `host` (hex) as a peer: a join with its ticket is done.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_irpush_Native_has(mut e: JNIEnv, _: JClass, host: JString) -> jboolean {
    let h = s(&mut e, &host).and_then(|h| h.parse().ok());
    (NODE.get().zip(h).is_some_and(|(n, h)| n.has(&h))) as jboolean
}

/// Block until a push arrives: 32-byte sender, 16-byte app, payload.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_irpush_Native_next(e: JNIEnv, _: JClass) -> jbyteArray {
    let q = Q.1.wait_while(Q.0.lock().unwrap_or_else(|e| e.into_inner()), |q| q.is_empty());
    let f = q.unwrap_or_else(|e| e.into_inner()).pop_front().unwrap_or_default();
    e.byte_array_from_slice(&f).map_or(std::ptr::null_mut(), |a| a.into_raw())
}

/// 16-byte app address of a package name.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_irpush_Native_app(mut e: JNIEnv, _: JClass, name: JString) -> jbyteArray {
    let a = s(&mut e, &name).map(|n| app(&n)).unwrap_or_default();
    e.byte_array_from_slice(&a).map_or(std::ptr::null_mut(), |a| a.into_raw())
}

/// ConnectivityManager: stable id per network; negative when offline.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_irpush_Native_network(_: JNIEnv, _: JClass, id: jlong) {
    if let Some(n) = NODE.get() { n.network(if id < 0 { OFFLINE } else { id as u64 }) }
}

/// AlarmManager: heartbeat now; seconds until the next alarm (0: no node).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_irpush_Native_kick(_: JNIEnv, _: JClass) -> jlong {
    NODE.get().map_or(0, |n| n.kick().as_secs() as jlong)
}
