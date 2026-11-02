//! Hosts post sealed frames straight to Apple (no gateway). Apple sees topic, device token, timing and
//! a constant-size opaque blob; the phone's Notification Service Extension decrypts locally.
use crate::proto::{App, app, now};
use anyhow::{Context, Result, ensure};
use data_encoding::BASE64URL_NOPAD;

const ALERT: &str = "New notification"; // shown only if the extension fails

/// How a device is reached when its relay socket is down.
#[derive(Clone, Copy, PartialEq, Debug)]
#[repr(u8)]
pub enum Svc { Apns = 0, ApnsSandbox = 1 }

pub(crate) struct Route { pub sandbox: bool, pub topic: String, pub token: Vec<u8> }

/// One device carries one route per app (several apps share the device):
/// entry = app (16) | svc | topic len | topic | token len | token; a blob is entries concatenated.
pub(crate) fn route(svc: Svc, topic: &str, token: &[u8]) -> Result<Vec<u8>> {
    ensure!(!topic.is_empty() && topic.len() < 256 && !token.is_empty() && token.len() < 256, "bad APNs route");
    Ok([&app(topic)[..], &[svc as u8, topic.len() as u8], topic.as_bytes(), &[token.len() as u8], token].concat())
}

fn entries(b: &[u8]) -> impl Iterator<Item = (App, &[u8])> {
    let mut r = b;
    std::iter::from_fn(move || {
        let a: App = r.get(..16)?.try_into().ok()?;
        let tl = *r.get(17)? as usize;
        let n = 19 + tl + *r.get(18 + tl)? as usize;
        let e = r.get(..n)?;
        r = &r[n..];
        Some((a, e))
    })
}

/// Well formed: every byte belongs to an entry, each addressed to the app its topic names.
pub(crate) fn valid(b: &[u8]) -> bool {
    let ok = |(a, e): &(App, &[u8])| e[16] <= Svc::ApnsSandbox as u8 && std::str::from_utf8(&e[18..18 + e[17] as usize]).is_ok_and(|t| app(t) == *a);
    entries(b).try_fold(0, |n, e| ok(&e).then_some(n + e.1.len())) == Some(b.len())
}

/// `blob` with `entry` replacing the entry for the same app (or added).
pub(crate) fn merge(blob: &[u8], entry: &[u8]) -> Vec<u8> {
    let a: App = entry[..16].try_into().expect("route entry");
    entries(blob).filter(|e| e.0 != a).flat_map(|e| e.1.to_vec()).chain(entry.iter().copied()).collect()
}

pub(crate) fn remove(blob: &[u8], a: &App) -> Vec<u8> { entries(blob).filter(|e| e.0 != *a).flat_map(|e| e.1.to_vec()).collect() }

pub(crate) fn parse_route(blob: &[u8], a: &App) -> Result<Route> {
    let (_, e) = entries(blob).find(|e| e.0 == *a).context("no APNs route for this app")?;
    let tl = e[17] as usize;
    Ok(Route { sandbox: e[16] == Svc::ApnsSandbox as u8, topic: String::from_utf8(e[18..18 + tl].to_vec())?, token: e[19 + tl..].to_vec() })
}

/// Provider token: ES256 JWT {kid} {iss, iat}. Apple accepts it for 1 h; callers refresh every 40 min.
pub(crate) fn jwt(creds: &str) -> Result<String> {
    use p256::{ecdsa::{Signature, SigningKey, signature::Signer}, pkcs8::DecodePrivateKey};
    let (head, pem) = creds.split_once('\n').context("apns creds")?;
    let (kid, team) = head.split_once(' ').context("apns creds")?;
    ensure!(kid.chars().chain(team.chars()).all(|c| c.is_ascii_alphanumeric()), "key id / team id: alphanumeric");
    let key = SigningKey::from_pkcs8_pem(pem.trim()).ok().context("invalid .p8 key")?;
    let enc = |s: String| BASE64URL_NOPAD.encode(s.as_bytes());
    let m = format!("{}.{}", enc(format!(r#"{{"alg":"ES256","kid":"{kid}"}}"#)), enc(format!(r#"{{"iss":"{team}","iat":{}}}"#, now())));
    let sig: Signature = key.sign(m.as_bytes());
    Ok(format!("{m}.{}", BASE64URL_NOPAD.encode(&sig.to_bytes())))
}

pub(crate) enum Sent { Ok, Gone, Retry(String) }

pub(crate) async fn post(http: &reqwest::Client, r: &Route, auth: &str, frame_b64: &str) -> Result<Sent> {
    #[cfg(debug_assertions)] // tests point this at a mock; release builds always talk to Apple
    let base = std::env::var("IRPUSH_APNS_URL").ok();
    #[cfg(not(debug_assertions))]
    let base: Option<String> = None;
    let host = if r.sandbox { "https://api.sandbox.push.apple.com" } else { "https://api.push.apple.com" };
    let res = http.post(format!("{}/3/device/{}", base.as_deref().unwrap_or(host), hex::encode(&r.token)))
        .bearer_auth(auth).header("apns-topic", &r.topic).header("apns-push-type", "alert")
        .header("apns-priority", "10").header("apns-expiration", (now() + 86400).to_string())
        .body(format!(r#"{{"aps":{{"alert":{{"body":"{ALERT}"}},"mutable-content":1}},"f":"{frame_b64}"}}"#))
        .send().await;
    let res = match res { Ok(r) => r, Err(e) => return Ok(Sent::Retry(e.to_string())) };
    let s = res.status().as_u16();
    let why = res.text().await.unwrap_or_default();
    match s {
        200 => Ok(Sent::Ok),
        410 => Ok(Sent::Gone), // token unregistered: stop using it
        400 if why.contains("BadDeviceToken") || why.contains("DeviceTokenNotForTopic") => Ok(Sent::Gone),
        429 | 500.. => Ok(Sent::Retry(format!("apns {s}: {why}"))),
        _ => anyhow::bail!("apns {s}: {why}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{ecdsa::{Signature, SigningKey, VerifyingKey, signature::Verifier}, pkcs8::{EncodePrivateKey, LineEnding}};

    #[test]
    fn jwt_verifies_and_route_roundtrips() {
        let k = SigningKey::from_bytes(&crate::proto::rnd::<32>().into()).unwrap();
        let pem = k.to_pkcs8_pem(LineEnding::LF).unwrap();
        let t = jwt(&format!("ABC123DEFG TEAM123456\n{}", pem.as_str())).unwrap();
        let (m, s) = t.rsplit_once('.').unwrap();
        let sig = Signature::from_slice(&BASE64URL_NOPAD.decode(s.as_bytes()).unwrap()).unwrap();
        VerifyingKey::from(&k).verify(m.as_bytes(), &sig).unwrap();
        assert!(jwt(&format!("A\"B TEAM\n{}", pem.as_str())).is_err());
        let (a, b) = (route(Svc::ApnsSandbox, "org.x.app", &[9; 32]).unwrap(), route(Svc::Apns, "org.x.other", &[1; 32]).unwrap());
        let blob = merge(&merge(&a, &b), &route(Svc::ApnsSandbox, "org.x.app", &[7; 32]).unwrap()); // replaces, keeps order of others
        assert!(valid(&blob) && !valid(&blob[..blob.len() - 1]));
        let mut forged = a.clone();
        forged[..16].copy_from_slice(&app("org.x.other"));
        assert!(!valid(&forged), "an entry's app must be its topic's");
        let r = parse_route(&blob, &app("org.x.app")).unwrap();
        assert!(r.sandbox && r.topic == "org.x.app" && r.token == [7; 32]);
        assert_eq!(parse_route(&blob, &app("org.x.other")).unwrap().token, [1; 32]);
        assert!(parse_route(&remove(&blob, &app("org.x.app")), &app("org.x.app")).is_err());
        assert!(route(Svc::Apns, "", &[1]).is_err() && route(Svc::Apns, "x", &[]).is_err());
    }
}
