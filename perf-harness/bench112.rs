use std::fs::File;
use std::io::{self, Cursor, Read, Write};
use std::time::Instant;
use odf_crypto::{classify_reader, decrypt_to, encrypt_with_params, Argon2Params};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = &args[2];
    if args[1] == "make" {
        let golden = std::fs::read("tests/goldens/lo-unencrypted.odt").unwrap();
        let mut src = ZipArchive::new(Cursor::new(golden)).unwrap();
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        for i in 0..src.len() {
            let f = src.by_index(i).unwrap();
            if f.name().unwrap() == "content.xml" { continue; }
            w.raw_copy_file(f).unwrap();
        }
        let mut x: u64 = 0x9E3779B97F4A7C15;
        let mut noise = vec![0u8; 8 << 20];
        for b in noise.iter_mut() { x ^= x << 13; x ^= x >> 7; x ^= x << 17; *b = x as u8; }
        w.start_file("content.xml", SimpleFileOptions::default().compression_method(CompressionMethod::Stored)).unwrap();
        w.write_all(&noise).unwrap();
        let plain = w.finish().unwrap().into_inner();
        let sealed = encrypt_with_params(&plain, "pw", Argon2Params::new(2, 8192, 2).unwrap()).unwrap();
        std::fs::write(path, sealed).unwrap();
        return;
    }
    if args[1] == "encp" {
        // encp PLAIN REPS: encrypt_to a plain package; MiB/s of input, median, and output size.
        let reps: usize = args[3].parse().unwrap();
        let plain = std::fs::read(path).unwrap();
        let mut v = Vec::new();
        let mut size = 0;
        for _ in 0..reps {
            let t = Instant::now();
            let mut out = Cursor::new(Vec::new());
            odf_crypto::encrypt_with_params_to(Cursor::new(&plain), &mut out, "pw", Argon2Params::new(2, 8192, 2).unwrap()).unwrap();
            v.push(plain.len() as f64 / (1 << 20) as f64 / t.elapsed().as_secs_f64());
            size = out.into_inner().len();
        }
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!("encp {} {:.1}", size, v[reps / 2]);
        return;
    }
    if args[1] == "enc" {
        let sealed = std::fs::read(path).unwrap();
        let mut plain = Vec::new();
        decrypt_to(Cursor::new(&sealed), &mut plain, "pw").unwrap();
        for _ in 0..3 {
            let t = Instant::now();
            let mut out = Cursor::new(Vec::new());
            odf_crypto::encrypt_with_params_to(Cursor::new(&plain), &mut out, "pw", Argon2Params::new(2, 8192, 2).unwrap()).unwrap();
            println!("enc {:.1} MiB/s", plain.len() as f64 / (1<<20) as f64 / t.elapsed().as_secs_f64());
        }
        return;
    }
    if args[1] == "re" {
        // re FILE REPS: reencrypt_to into memory, MiB/s of input, median.
        let reps: usize = args[3].parse().unwrap();
        let pw = std::env::var("PW").unwrap_or("pw".into());
        let mib = std::fs::metadata(path).unwrap().len() as f64 / (1 << 20) as f64;
        let mut v = Vec::new();
        for _ in 0..reps {
            let t = Instant::now();
            let mut out = Cursor::new(Vec::new());
            odf_crypto::reencrypt_to(File::open(path).unwrap(), &mut out, &pw, "new", Default::default(), Argon2Params::new(2, 8192, 2).unwrap()).unwrap();
            v.push(if std::env::var("MS").is_ok() { t.elapsed().as_secs_f64() * 1e3 } else { mib / t.elapsed().as_secs_f64() });
        }
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!("re 0 {:.1}", v[reps / 2]);
        return;
    }
    let reps: usize = args[3].parse().unwrap();
    let mib = std::fs::metadata(path).unwrap().len() as f64 / (1 << 20) as f64;
    let mut cls = Vec::new();
    let mut dec = Vec::new();
    for _ in 0..reps {
        let t = Instant::now();
        classify_reader(File::open(path).unwrap()).unwrap();
        cls.push(t.elapsed().as_secs_f64() * 1e3);
        let t = Instant::now();
        decrypt_to(File::open(path).unwrap(), io::sink(), &std::env::var("PW").unwrap_or("pw".into())).unwrap();
        dec.push(if std::env::var("MS").is_ok() { t.elapsed().as_secs_f64()*1e3 } else { mib / t.elapsed().as_secs_f64() });
    }
    cls.sort_by(|a, b| a.partial_cmp(b).unwrap());
    dec.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let _ = io::stdin().read(&mut []);
    println!("{} {:.3} {:.1}", args[1], cls[reps / 2], dec[reps / 2]);
}
