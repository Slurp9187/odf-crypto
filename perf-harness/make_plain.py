import sys, os, zipfile, re
golden, out, mode = sys.argv[1], sys.argv[2], sys.argv[3]
src = open('/usr/share/mime/packages/freedesktop.org.xml','rb').read()
xml = bytearray(); i = 0
while len(xml) < (24 << 20):
    xml += src.replace(b'<mime-type ', b'<mime-type n="%d" ' % i); i += 1
z = zipfile.ZipFile(golden)
man = z.read('META-INF/manifest.xml').decode()
pics = [os.urandom(4 << 20) for _ in range(8)] if mode == 'lo' else []
rows = ''.join(' <manifest:file-entry manifest:full-path="Pictures/p%d.jpg" manifest:media-type="image/jpeg"/>\n' % k for k in range(len(pics)))
man = man.replace('</manifest:manifest>', rows + '</manifest:manifest>')
meth = zipfile.ZIP_DEFLATED if mode == 'lo' else zipfile.ZIP_STORED
with zipfile.ZipFile(out, 'w') as w:
    for info in z.infolist():
        if info.filename == 'content.xml':
            w.writestr('content.xml', bytes(xml), compress_type=meth)
        elif info.filename == 'META-INF/manifest.xml':
            w.writestr(info, man.encode())
        else:
            w.writestr(info, z.read(info))
    for k, p in enumerate(pics):
        w.writestr('Pictures/p%d.jpg' % k, p, compress_type=zipfile.ZIP_STORED)
print(out, os.path.getsize(out))
