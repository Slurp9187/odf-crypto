import base64, hashlib, io, os, re, sys, zipfile, zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
golden, out_path, mib = sys.argv[1], sys.argv[2], int(sys.argv[3])
z = zipfile.ZipFile(golden)
man = z.read("META-INF/manifest.xml").decode()
src = open('/usr/share/mime/packages/freedesktop.org.xml', 'rb').read()
xml = bytearray()
i = 0
while len(xml) < (mib << 20):
    xml += src.replace(b'<mime-type ', b'<mime-type n="%d" ' % i); i += 1
xml = bytes(xml[:mib << 20])
c = zlib.compressobj(6, zlib.DEFLATED, -15); deflated = c.compress(xml) + c.flush()
fe = re.search(r'<manifest:file-entry manifest:full-path="content.xml".*?</manifest:file-entry>', man, re.S).group(0)
salt = base64.b64decode(re.search(r'manifest:salt="([^"]+)"', fe).group(1))
iv = base64.b64decode(re.search(r'manifest:initialisation-vector="([^"]+)"', fe).group(1))
key = hashlib.pbkdf2_hmac("sha1", hashlib.sha256(b"password").digest(), salt, 100000, 32)
pad = 16 - len(deflated) % 16
enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
blob = enc.update(deflated + bytes([pad]) * pad) + enc.finalize()
new_fe = re.sub(r'manifest:size="\d+"', 'manifest:size="%d"' % len(xml), fe)
new_fe = re.sub(r'manifest:checksum="[^"]+"', 'manifest:checksum="%s"' % base64.b64encode(hashlib.sha256(deflated[:1024]).digest()).decode(), new_fe)
man = man.replace(fe, new_fe)
with zipfile.ZipFile(out_path, "w") as w:
    for info in z.infolist():
        data = z.read(info)
        if info.filename == "content.xml": data = blob
        if info.filename == "META-INF/manifest.xml": data = man.encode()
        w.writestr(info, data)
print(out_path, os.path.getsize(out_path), "inflated", len(xml), "deflated", len(deflated))
