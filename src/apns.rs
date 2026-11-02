//! Hosts post sealed frames straight to Apple (no gateway). Apple sees topic, device token, timing and
//! a constant-size opaque blob; the phone's Notification Service Extension decrypts locally.
use crate::proto::now;
use anyhow::{Context, Result, ensure};
use data_encoding::BASE64URL_NOPAD;

const ALERT: &str = "New notification"; // shown only if the extension fails

/// How a device is reached when its relay socket is down.
#[derive(Clone, Copy, PartialEq, Debug)]
#[repr(u8)]
pub enum Svc { Apns = 0, ApnsSandbox = 1 }

pub(crate) struct Route { pub sandbox: bool, pub topic: String, pub token: Vec<u8> }

pub(crate) fn route(svc: Svc, topic: &str, token: &[u8]) -> Result<Vec<u8>> {
    ensure!(!topic.is_empty() && topic.len() < 256 && !token.is_empty() && token.len() <= 255, "bad APNs route");
    Ok([&[svc as u8, topic.len() as u8][..], topic.as_bytes(), token].concat())
}

pub(crate) fn parse_route(b: &[u8]) -> Result<Route> {
    let (&svc, rest) = b.split_first().context("route")?;
    let (&n, rest) = rest.split_first().context("route")?;
    let (topic, token) = rest.split_at_checked(n as usize).context("route")?;
    Ok(Route { sandbox: svc == Svc::ApnsSandbox as u8, topic: String::from_utf8(topic.to_vec())?, token: token.to_vec() })
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

pub(crate) enum Sent { Ok, Gone }

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
        .send().await?;
    match res.status().as_u16() {
        200 => Ok(Sent::Ok),
        410 => Ok(Sent::Gone), // token unregistered: stop using it
        s => anyhow::bail!("apns {s}: {}", res.text().await.unwrap_or_default()),
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
        let r = parse_route(&route(Svc::ApnsSandbox, "org.x.app", &[9; 32]).unwrap()).unwrap();
        assert!(r.sandbox && r.topic == "org.x.app" && r.token == [9; 32]);
    }
}
