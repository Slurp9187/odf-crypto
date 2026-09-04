//! Stage A: streaming `ManifestImport` — XML → ordered property bags.

use std::collections::HashMap;

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::types::{EncryptedKey, KdfId, KeyInfo, PropertyBag};
use crate::uris;
use crate::DetectError;

struct StackFrame {
    converted_name: String,
    namespaces: HashMap<String, String>,
    valid: bool,
}

/// Deeper than any manifest shape LO acts on: `startElement` dispatches levels
/// 1–6 and invalidates the rest, so nothing below this can affect a bag. It
/// bounds `convert_name`'s stack scan, keeping parsing linear in element count.
const MAX_DEPTH: usize = 16;

struct Import {
    stack: Vec<StackFrame>,
    /// Elements entered past `MAX_DEPTH`, counted rather than pushed so that
    /// `end_element` stays balanced without growing the stack.
    beyond_cap: usize,
    bags: Vec<PropertyBag>,
    bag: PropertyBag,
    ignore_encrypt_data: bool,
    pgp_encryption: bool,
    /// `nDerivedKeySize`. 0 means unset. Reset per `encryption-data`.
    derived_key_size: i32,
    package_version: Option<String>,
    keys: Vec<EncryptedKey>,
    current_key: Option<EncryptedKey>,
    current_characters: String,
}

impl Import {
    fn new() -> Self {
        Self {
            stack: Vec::new(),
            beyond_cap: 0,
            bags: Vec::new(),
            bag: PropertyBag::default(),
            ignore_encrypt_data: false,
            pgp_encryption: false,
            derived_key_size: 0,
            package_version: None,
            keys: Vec::new(),
            current_key: None,
            current_characters: String::new(),
        }
    }

    fn convert_name_with_ns(name: &str, namespaces: &HashMap<String, String>) -> Option<String> {
        let (alias, local) = match name.find(':') {
            Some(i) => (&name[..i], &name[i + 1..]),
            None => ("", name),
        };
        namespaces
            .get(alias)
            .filter(|uri| uris::is_manifest_namespace(uri))
            .map(|_| format!("{}{}", uris::MANIFEST_PREFIX, local))
    }

    fn convert_name(&self, name: &str) -> String {
        for frame in self.stack.iter().rev() {
            if !frame.namespaces.is_empty() {
                if let Some(converted) = Self::convert_name_with_ns(name, &frame.namespaces) {
                    return converted;
                }
            }
        }
        name.to_string()
    }

    fn push_name_and_namespaces(
        &mut self,
        raw_name: &str,
        raw_attrs: Vec<(String, String)>,
    ) -> (String, HashMap<String, String>) {
        let mut namespaces = HashMap::new();
        let mut other = Vec::new();
        for (key, value) in raw_attrs {
            if key == "xmlns" {
                namespaces.insert(String::new(), value);
            } else if let Some(prefix) = key.strip_prefix("xmlns:") {
                namespaces.insert(prefix.to_string(), value);
            } else {
                other.push((key, value));
            }
        }

        let converted = Self::convert_name_with_ns(raw_name, &namespaces)
            .unwrap_or_else(|| self.convert_name(raw_name));
        self.stack.push(StackFrame {
            converted_name: converted.clone(),
            namespaces,
            valid: true,
        });

        let mut attrs = HashMap::new();
        for (key, value) in other {
            attrs.insert(self.convert_name(&key), value);
        }
        (converted, attrs)
    }

    fn parent_valid(&self) -> bool {
        self.stack
            .iter()
            .rev()
            .nth(1)
            .map(|f| f.valid)
            .unwrap_or(true)
    }

    fn invalidate_current(&mut self) {
        if let Some(frame) = self.stack.last_mut() {
            frame.valid = false;
        }
    }

    fn start_element(&mut self, raw_name: &str, raw_attrs: Vec<(String, String)>) {
        if self.beyond_cap > 0 || self.stack.len() >= MAX_DEPTH {
            self.beyond_cap += 1;
            return;
        }
        let (converted, attrs) = self.push_name_and_namespaces(raw_name, raw_attrs);
        let level = self.stack.len();

        // LO's `case 2:` has no parent-validity check; it starts at `case 3:`.
        if level >= 3 && !self.parent_valid() {
            self.invalidate_current();
            return;
        }
        match level {
            1 => {
                if let Some(v) = attrs.get(uris::ATTR_VERSION) {
                    if !v.is_empty() {
                        self.package_version = Some(v.clone());
                    }
                }
                if converted != uris::ELEMENT_MANIFEST {
                    self.invalidate_current();
                }
            }
            2 => {
                if converted == uris::ELEMENT_FILE_ENTRY {
                    self.do_file_entry(&attrs);
                } else if converted == uris::ELEMENT_LOEXT_KEYINFO
                    || converted == uris::ELEMENT_MANIFEST_ENCRYPTED_KEY
                {
                    if converted == uris::ELEMENT_MANIFEST_ENCRYPTED_KEY {
                        self.do_encrypted_key();
                    }
                } else {
                    self.invalidate_current();
                }
            }
            3 => {
                if converted == uris::ELEMENT_ENCRYPTION_DATA {
                    self.do_encryption_data(&attrs);
                } else if converted == uris::ELEMENT_LOEXT_ENCRYPTED_KEY {
                    self.do_encrypted_key();
                } else if converted == uris::ELEMENT_MANIFEST_ENCRYPTION_METHOD {
                    self.do_encryption_method(&attrs, uris::ATTR_PGP_ALGORITHM);
                } else if converted == uris::ELEMENT_MANIFEST_KEYINFO
                    || converted == uris::ELEMENT_MANIFEST_CIPHER_DATA
                {
                } else {
                    self.invalidate_current();
                }
            }
            4 => {
                if converted == uris::ELEMENT_ALGORITHM {
                    self.do_algorithm(&attrs);
                } else if converted == uris::ELEMENT_KEY_DERIVATION {
                    self.do_key_derivation(&attrs);
                } else if converted == uris::ELEMENT_START_KEY_GENERATION {
                    self.do_start_key_alg(&attrs);
                } else if converted == uris::ELEMENT_LOEXT_ENCRYPTION_METHOD {
                    self.do_encryption_method(&attrs, uris::ATTR_PGP_ALGORITHM_LO);
                } else if converted == uris::ELEMENT_LOEXT_KEYINFO_DSIG
                    || converted == uris::ELEMENT_LOEXT_CIPHER_DATA
                    || converted == uris::ELEMENT_MANIFEST_PGP_DATA
                {
                } else if converted == uris::ELEMENT_MANIFEST_CIPHER_VALUE {
                    self.current_characters.clear();
                } else {
                    self.invalidate_current();
                }
            }
            5 => {
                if converted == uris::ELEMENT_LOEXT_PGP_DATA {
                } else if converted == uris::ELEMENT_LOEXT_CIPHER_VALUE
                    || converted == uris::ELEMENT_MANIFEST_PGP_KEY_ID
                    || converted == uris::ELEMENT_MANIFEST_PGP_KEY_PACKET
                {
                    self.current_characters.clear();
                } else {
                    self.invalidate_current();
                }
            }
            6 => {
                if converted == uris::ELEMENT_LOEXT_PGP_KEY_ID
                    || converted == uris::ELEMENT_LOEXT_PGP_KEY_PACKET
                {
                    self.current_characters.clear();
                } else {
                    self.invalidate_current();
                }
            }
            _ => self.invalidate_current(),
        }
    }

    fn end_element(&mut self, raw_name: &str) {
        if self.beyond_cap > 0 {
            self.beyond_cap -= 1;
            return;
        }
        if self.stack.is_empty() {
            return;
        }
        let converted = self.convert_name(raw_name);
        if self.stack.last().map(|f| f.converted_name.as_str()) != Some(converted.as_str()) {
            return;
        }
        let valid = self.stack.last().map(|f| f.valid).unwrap_or(false);
        let level = self.stack.len();

        if converted == uris::ELEMENT_FILE_ENTRY && valid {
            if self.bags.is_empty() && self.package_version.is_some() && self.bag.version.is_none()
            {
                self.bag.version = self.package_version.clone();
            }
            if !self.ignore_encrypt_data && !self.keys.is_empty() && self.bags.is_empty() {
                self.bag.key_info = Some(KeyInfo {
                    keys: self.keys.clone(),
                });
            }
            self.ignore_encrypt_data = false;
            self.bags.push(std::mem::take(&mut self.bag));
        } else if (converted == uris::ELEMENT_LOEXT_ENCRYPTED_KEY
            || converted == uris::ELEMENT_MANIFEST_ENCRYPTED_KEY)
            && valid
        {
            if !self.ignore_encrypt_data {
                // A nested `encrypted-key` leaves the outer slot empty; LO still
                // pushes that zero-length key (`ManifestImport.cxx` 483–487).
                self.keys.push(self.current_key.take().unwrap_or_default());
                self.pgp_encryption = true;
            }
            self.current_key = None;
        }

        if (converted == uris::ELEMENT_MANIFEST_CIPHER_VALUE && level == 4)
            || (converted == uris::ELEMENT_LOEXT_CIPHER_VALUE && level == 5)
        {
            self.do_encrypted_cipher_value();
        } else if (converted == uris::ELEMENT_MANIFEST_PGP_KEY_ID && level == 5)
            || (converted == uris::ELEMENT_LOEXT_PGP_KEY_ID && level == 6)
        {
            self.do_encrypted_key_id();
        } else if (converted == uris::ELEMENT_MANIFEST_PGP_KEY_PACKET && level == 5)
            || (converted == uris::ELEMENT_LOEXT_PGP_KEY_PACKET && level == 6)
        {
            self.do_encrypted_key_packet();
        }

        self.stack.pop();
    }

    fn characters(&mut self, text: &str) {
        self.current_characters.push_str(text);
    }

    fn do_file_entry(&mut self, attrs: &HashMap<String, String>) {
        self.bag = PropertyBag::default();
        if let Some(path) = attrs.get(uris::ATTR_FULL_PATH) {
            self.bag.full_path = path.clone();
        }
        // MediaType is always written (`ManifestImport.cxx` 77–78), even as "".
        self.bag.media_type = Some(
            attrs
                .get(uris::ATTR_MEDIA_TYPE)
                .cloned()
                .unwrap_or_default(),
        );
        if let Some(v) = attrs.get(uris::ATTR_VERSION) {
            if !v.is_empty() {
                self.bag.version = Some(v.clone());
            }
        }
        if let Some(size) = attrs.get(uris::ATTR_SIZE) {
            if !size.is_empty() {
                self.bag.size = Some(parse_i64(size));
            }
        }
    }

    fn do_encrypted_key(&mut self) {
        self.current_key = Some(EncryptedKey {
            key_id: Vec::new(),
            key_packet: Vec::new(),
            cipher_value: Vec::new(),
        });
    }

    fn do_encryption_method(&mut self, attrs: &HashMap<String, String>, algo_attr: &str) {
        let algo = attrs.get(algo_attr).map(String::as_str).unwrap_or("");
        if self.current_key.is_none() || !uris::is_pgp_wrap_uri(algo) {
            self.ignore_encrypt_data = true;
        }
    }

    fn take_chars_decoded(&mut self) -> Vec<u8> {
        // LO only clears the character buffer when starting a cdata slot,
        // not when consuming it.
        decode_b64(&self.current_characters)
    }

    fn do_encrypted_cipher_value(&mut self) {
        let value = self.take_chars_decoded();
        if let Some(key) = self.current_key.as_mut() {
            key.cipher_value = value;
        } else {
            self.ignore_encrypt_data = true;
        }
    }

    fn do_encrypted_key_id(&mut self) {
        let value = self.take_chars_decoded();
        if let Some(key) = self.current_key.as_mut() {
            key.key_id = value;
        } else {
            self.ignore_encrypt_data = true;
        }
    }

    fn do_encrypted_key_packet(&mut self) {
        let value = self.take_chars_decoded();
        if let Some(key) = self.current_key.as_mut() {
            key.key_packet = value;
        } else {
            self.ignore_encrypt_data = true;
        }
    }

    fn do_encryption_data(&mut self, attrs: &HashMap<String, String>) {
        self.derived_key_size = 0;
        if self.ignore_encrypt_data {
            return;
        }
        let checksum_type = attrs
            .get(uris::ATTR_CHECKSUM_TYPE)
            .map(String::as_str)
            .unwrap_or("");
        if let Some(alg) = uris::checksum_alg_from_type(checksum_type) {
            self.bag.digest_alg = Some(alg);
        }
        if self.bag.digest_alg.is_some() {
            let checksum = attrs
                .get(uris::ATTR_CHECKSUM)
                .map(String::as_str)
                .unwrap_or("");
            self.bag.digest = Some(decode_b64(checksum));
        }
    }

    fn do_algorithm(&mut self, attrs: &HashMap<String, String>) {
        if self.ignore_encrypt_data {
            return;
        }
        let name = attrs
            .get(uris::ATTR_ALGORITHM_NAME)
            .map(String::as_str)
            .unwrap_or("");
        match uris::cipher_from_algorithm_name(name) {
            Ok((cipher, implied)) => {
                self.bag.enc_alg = Some(cipher);
                if let Some(len) = implied {
                    self.derived_key_size = i32::from(len);
                }
                let iv = attrs.get(uris::ATTR_IV).map(String::as_str).unwrap_or("");
                self.bag.iv = Some(decode_b64(iv));
            }
            Err(()) => {
                self.ignore_encrypt_data = true;
            }
        }
    }

    fn do_start_key_alg(&mut self, attrs: &HashMap<String, String>) {
        // Does not check `bIgnoreEncryptData` first (`ManifestImport.cxx` 306).
        let name = attrs
            .get(uris::ATTR_START_KEY_NAME)
            .map(String::as_str)
            .unwrap_or("");
        match uris::start_key_from_name(name) {
            Ok(alg) => self.bag.start_key_alg = Some(alg),
            Err(()) => self.ignore_encrypt_data = true,
        }
    }

    fn do_key_derivation(&mut self, attrs: &HashMap<String, String>) {
        if self.ignore_encrypt_data {
            return;
        }
        let name = attrs
            .get(uris::ATTR_KEY_DERIVATION_NAME)
            .map(String::as_str)
            .unwrap_or("");
        if let Some(kdf) = uris::password_kdf_from_name(name) {
            self.bag.kdf = Some(kdf);
            if kdf == KdfId::Argon2id {
                let t = parse_i32(argon2_attr(
                    attrs,
                    uris::ATTR_ARGON2_T,
                    uris::ATTR_ARGON2_T_LO,
                ));
                let m = parse_i32(argon2_attr(
                    attrs,
                    uris::ATTR_ARGON2_M,
                    uris::ATTR_ARGON2_M_LO,
                ));
                let p = parse_i32(argon2_attr(
                    attrs,
                    uris::ATTR_ARGON2_P,
                    uris::ATTR_ARGON2_P_LO,
                ));
                if t > 0 && m > 0 && p > 0 {
                    self.bag.argon2_args = Some((t, m, p));
                } else {
                    self.ignore_encrypt_data = true;
                }
            } else {
                let count = attrs
                    .get(uris::ATTR_ITERATION_COUNT)
                    .map(String::as_str)
                    .unwrap_or("");
                self.bag.iteration_count = Some(parse_i32(count));
            }
            let salt = attrs.get(uris::ATTR_SALT).map(String::as_str).unwrap_or("");
            self.bag.salt = Some(decode_b64(salt));
            if let Some(key_size) = attrs.get(uris::ATTR_KEY_SIZE) {
                if !key_size.is_empty() {
                    self.derived_key_size = parse_i32(key_size);
                } else if self.derived_key_size == 0 {
                    self.derived_key_size = 16;
                }
            } else if self.derived_key_size == 0 {
                self.derived_key_size = 16;
            }
            self.bag.derived_key_size = Some(self.derived_key_size);
        } else if self.pgp_encryption && name == uris::PGP_NAME {
            self.bag.kdf = Some(KdfId::PgpRsaOaepMgf1p);
        } else {
            self.ignore_encrypt_data = true;
        }
    }
}

fn argon2_attr<'a>(attrs: &'a HashMap<String, String>, manifest: &str, loext: &str) -> &'a str {
    attrs
        .get(manifest)
        .or_else(|| attrs.get(loext))
        .map(String::as_str)
        .unwrap_or("")
}

fn lo_is_whitespace(c: char) -> bool {
    let u = c as u32;
    if u <= 32 && u != 0 {
        return true;
    }
    if !(0x2000..=0x2029).contains(&u) {
        return false;
    }
    u <= 0x200B || u >= 0x2028
}

fn parse_i32(s: &str) -> i32 {
    parse_lo_int(s, i32::MIN as i64, i32::MAX as i64) as i32
}

fn parse_i64(s: &str) -> i64 {
    parse_lo_int(s, i64::MIN, i64::MAX)
}

/// `OUString::toInt` / `HandleSignChar`: one optional sign, ASCII digits, 0 on overflow.
fn parse_lo_int(s: &str, min: i64, max: i64) -> i64 {
    let mut chars = s.chars().peekable();
    while chars.peek().copied().is_some_and(lo_is_whitespace) {
        chars.next();
    }
    let Some(first) = chars.peek().copied() else {
        return 0;
    };
    let neg = if first == '-' {
        chars.next();
        true
    } else {
        if first == '+' {
            chars.next();
        }
        false
    };
    let limit = if neg { min.unsigned_abs() } else { max as u64 };
    let div = limit / 10;
    let rem = limit % 10;
    let mut n: u64 = 0;
    let mut saw_digit = false;
    while let Some(c) = chars.peek().copied() {
        if !c.is_ascii_digit() {
            break;
        }
        saw_digit = true;
        let d = u64::from(c as u8 - b'0');
        if n > div || (n == div && d > rem) {
            return 0;
        }
        n = n * 10 + d;
        chars.next();
    }
    if !saw_digit {
        return 0;
    }
    if neg {
        if n == min.unsigned_abs() {
            min
        } else {
            -(n as i64)
        }
    } else {
        n as i64
    }
}

/// `Base64::decodeSomeChars`: skip non-alphabet chars, emit complete quads.
pub(crate) fn decode_b64(s: &str) -> Vec<u8> {
    const TABLE: [u8; 80] = [
        62, 255, 255, 255, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255, 0, 255, 255,
        255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 255, 255, 255, 255, 255, 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
        40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    ];
    let mut out = Vec::new();
    let mut acc = [0u8; 4];
    let mut n = 0;
    let mut got = 3;
    for c in s.chars() {
        if !('+'..='z').contains(&c) {
            continue;
        }
        let byte = TABLE[(c as u8 - b'+') as usize];
        if byte == 255 {
            continue;
        }
        acc[n] = byte;
        n += 1;
        if c == '=' && n > 2 {
            got -= 1;
        }
        if n == 4 {
            let v = (u32::from(acc[0]) << 18)
                + (u32::from(acc[1]) << 12)
                + (u32::from(acc[2]) << 6)
                + u32::from(acc[3]);
            out.push(((v >> 16) & 0xff) as u8);
            if got > 1 {
                out.push(((v >> 8) & 0xff) as u8);
            }
            if got > 2 {
                out.push((v & 0xff) as u8);
            }
            n = 0;
            got = 3;
        }
    }
    out
}

/// Plain RFC 4648 base64 with `=` padding -- LO's own writer produces ordinary
/// padded base64 on output (`ManifestExport.cxx`'s use of `Sequence2Base64`),
/// so unlike [`decode_b64`] there is no lenient-parsing quirk to reproduce
/// here: this only has to be valid input for a decoder that already exists.
/// Only `encrypt.rs`'s manifest writer calls this outside its own round-trip
/// test below.
///
/// Gated rather than allowed: a detection-only build genuinely has no caller,
/// and `cfg` says that where `allow(dead_code)` would only silence it. `test` is
/// in the gate because the round-trip and known-vector tests below compile in
/// every configuration.
#[cfg(any(feature = "crypto-ops", test))]
pub(crate) fn encode_b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied();
        let b2 = chunk.get(2).copied();
        let n =
            (u32::from(b0) << 16) | (u32::from(b1.unwrap_or(0)) << 8) | u32::from(b2.unwrap_or(0));
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(if b1.is_some() {
            ALPHABET[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if b2.is_some() {
            ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn expand_ref(name: &str) -> String {
    if let Some(rest) = name.strip_prefix('#') {
        let code = if let Some(hex) = rest.strip_prefix(['x', 'X']) {
            u32::from_str_radix(hex, 16).ok()
        } else {
            rest.parse().ok()
        };
        return code
            .and_then(char::from_u32)
            .map(|c| c.to_string())
            .unwrap_or_default();
    }
    match name {
        "amp" => "&".into(),
        "lt" => "<".into(),
        "gt" => ">".into(),
        "apos" => "'".into(),
        "quot" => "\"".into(),
        _ => String::new(),
    }
}

/// XML §3.3.3: literal tab/CR/LF become space; character references are not.
fn normalize_attr_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '&' => {
                let mut ent = String::new();
                for e in chars.by_ref() {
                    if e == ';' {
                        break;
                    }
                    ent.push(e);
                }
                out.push_str(&expand_ref(&ent));
            }
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push(' ');
            }
            '\n' | '\t' => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

/// Parse `META-INF/manifest.xml` into ordered Stage A bags.
///
/// XML / encoding errors discard every row (`ManifestReader.cxx` 46–75): LO
/// still opens the package, so this function has no error path — every
/// failure returns an empty row list.
pub(crate) fn parse_manifest(xml: &[u8]) -> Result<Vec<PropertyBag>, DetectError> {
    let mut reader = Reader::from_reader(xml);
    let config = reader.config_mut();
    config.expand_empty_elements = true;
    config.trim_text(false);

    let mut import = Import::new();
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let raw_name = qname_to_string(e.name().as_ref());
                let mut attrs = Vec::new();
                for attr in e.attributes() {
                    let Ok(attr) = attr else {
                        return Ok(Vec::new());
                    };
                    let key = qname_to_string(attr.key.as_ref());
                    let raw = match std::str::from_utf8(attr.value.as_ref()) {
                        Ok(s) => s,
                        Err(_) => return Ok(Vec::new()),
                    };
                    attrs.push((key, normalize_attr_value(raw)));
                }
                import.start_element(&raw_name, attrs);
            }
            Ok(Event::End(e)) => {
                let raw_name = qname_to_string(e.name().as_ref());
                import.end_element(&raw_name);
            }
            Ok(Event::Text(t)) => match t.decode() {
                Ok(text) => import.characters(&text),
                Err(_) => return Ok(Vec::new()),
            },
            Ok(Event::CData(t)) => match t.decode() {
                Ok(text) => import.characters(&text),
                Err(_) => return Ok(Vec::new()),
            },
            Ok(Event::GeneralRef(r)) => match r.decode() {
                Ok(name) => import.characters(&expand_ref(&name)),
                Err(_) => return Ok(Vec::new()),
            },
            Ok(Event::Eof) => {
                if !import.stack.is_empty() {
                    return Ok(Vec::new());
                }
                break;
            }
            Err(_) => return Ok(Vec::new()),
            _ => {}
        }
        buf.clear();
    }
    Ok(import.bags)
}

fn qname_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
pub(crate) fn parse_manifest_for_test(xml: &str) -> Vec<PropertyBag> {
    parse_manifest(xml.as_bytes()).expect("manifest should parse")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_int_matches_handle_sign_char() {
        assert_eq!(parse_i32("+3"), 3);
        assert_eq!(parse_i32("+100000"), 100000);
        assert_eq!(parse_i32("+32"), 32);
        assert_eq!(parse_i32("12-3"), 12);
        assert_eq!(parse_i32("-8"), -8);
        assert_eq!(parse_i32("256"), 256);
        assert_eq!(parse_i64("+100"), 100);
        // U+00A0 is not LO whitespace.
        assert_eq!(parse_i32("\u{00A0}3"), 0);
        assert_eq!(parse_i32("  7"), 7);
    }

    #[test]
    fn decode_b64_skips_junk_and_accepts_unpadded() {
        assert_eq!(decode_b64("AQIDBA"), vec![1, 2, 3]);
        assert_eq!(decode_b64("QUJD="), vec![65, 66, 67]);
        assert_eq!(decode_b64("AQIDBA=="), vec![1, 2, 3, 4]);
    }

    #[test]
    fn encode_b64_round_trips_through_decode_b64() {
        let cases: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"f".to_vec(),
            b"fo".to_vec(),
            b"foo".to_vec(),
            (0..16u8).collect(),
            (0..12u8)
                .map(|i| i.wrapping_mul(37).wrapping_add(5))
                .collect(),
        ];
        for bytes in cases {
            let encoded = encode_b64(&bytes);
            assert_eq!(decode_b64(&encoded), bytes, "round-trip of {bytes:?}");
        }
    }

    #[test]
    fn encode_b64_matches_known_vectors() {
        assert_eq!(encode_b64(b""), "");
        assert_eq!(encode_b64(b"f"), "Zg==");
        assert_eq!(encode_b64(b"fo"), "Zm8=");
        assert_eq!(encode_b64(b"foo"), "Zm9v");
        assert_eq!(encode_b64(&[1, 2, 3, 4]), "AQIDBA==");
    }

    #[test]
    fn malformed_xml_yields_zero_rows() {
        let truncated = br#"<?xml version="1.0"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
 <manifest:file-entry manifest:full-path="content.xml""#;
        assert!(parse_manifest(truncated).unwrap().is_empty());
        assert!(parse_manifest(b"<not-even-xml").unwrap().is_empty());
    }
}
