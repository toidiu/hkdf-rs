use aws_lc_rs::hkdf;
use aws_lc_rs::hkdf::KeyType;
use aws_lc_rs::hmac;

// HMAC specific SHA256 algo.
const ALGO_HMAC: hmac::Algorithm = hmac::HMAC_SHA256;
// HKDF specific SHA256 algo.
const ALGO_HKDF: hkdf::Algorithm = hkdf::HKDF_SHA256;

fn main() {
    println!("generating keys of len {}", ALGO_HKDF.len());

    let ikm = Ikm {
        data: b"secret input keying material".to_vec(),
    };
    let info = b"implement hkdf from scratch using hmac!!";
    let salt = vec![];

    // custom implementation
    let custom_okm = {
        let prk = extract(&salt, &ikm);
        let okm = expand(&prk, info, ALGO_HMAC.len());
        println!("{:?}", okm.data.as_slice());
        okm
    };

    // awslc hkdf
    // https://docs.rs/aws-lc-rs/latest/aws_lc_rs/hkdf/index.html
    let awslc_okm = {
        let salt = hkdf::Salt::new(ALGO_HKDF, &salt);
        let pseudo_random_key = salt.extract(&ikm.data);
        // this is annoying. why does awslc take a nested array?
        let temp_info: &[&[u8]] = &[info];
        let awslc_okm = pseudo_random_key.expand(temp_info, ALGO_HKDF).unwrap();

        let mut out = vec![0; ALGO_HKDF.len()];
        awslc_okm.fill(&mut out).unwrap();
        println!("{:?}", out);
        out
    };

    assert_eq!(custom_okm.data, awslc_okm);
}

struct Ikm {
    data: Vec<u8>,
}

struct Prk {
    data: hmac::Tag,
}

struct Okm {
    data: Vec<u8>,
}

// HKDF-Extract(salt, IKM) -> PRK
//
// Inputs:
//   salt     optional salt value (a non-secret random value);
//        if not provided, it is set to a string of HashLen zeros.
//   IKM      input keying material
//
// Output:
//   PRK      a pseudorandom key (of HashLen octets)
//
// The output PRK is calculated as follows:
//   PRK = HMAC-Hash(salt, IKM)/
fn extract(salt: &[u8], ikm: &Ikm) -> Prk {
    let key = hmac::Key::new(ALGO_HMAC, salt);
    let data = hmac::sign(&key, &ikm.data);
    Prk { data }
}

// HKDF-Expand(PRK, info, L) -> OKM
// Options:
//   Hash   a hash function; HashLen denotes the length of the
//          hash function output in octets
//
// Inputs:
//   PRK    a pseudorandom key of at least HashLen octets
//          (usually, the output from the extract step)
//   info   optional context and application specific information
//          (can be a zero-length string)
//   L      length of output keying material in octets
//          (<= 255*HashLen)
//
// Output:
//   OKM      output keying material (of L octets)
//
// The output OKM is calculated as follows:
//    N = ceil(L/HashLen)
//    T = T(1) | T(2) | T(3) | ... | T(N)
//    OKM = first L octets of T
//
//    where:
//    T(0) = empty string (zero length)
//    T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
//    T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
//    T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
//    ...
//
// (where the constant concatenated to the end of each T(n) is a single octet.)
fn expand(prk: &Prk, info: &[u8], len: usize) -> Okm {
    let mut okm: Vec<u8> = Vec::new();

    let n: u64 = (len as f64 / ALGO_HMAC.len() as f64).ceil() as u64;
    assert!(n < u8::MAX.into());
    let n = n as u8;

    // T(0) = empty string (zero length)
    let mut prev_t: Vec<u8> = vec![];
    for i in 1..=n {
        let hmac_data = [&prev_t, info, &[i]].concat();
        let key = hmac::Key::new(ALGO_HMAC, prk.data.as_ref());
        let t = hmac::sign(&key, &hmac_data);
        prev_t = t.as_ref().to_vec();

        okm.extend(t.as_ref());
    }

    // truncate to len bytes
    okm = okm.into_iter().take(len).collect();
    assert_eq!(okm.len(), len);
    Okm { data: okm }
}
