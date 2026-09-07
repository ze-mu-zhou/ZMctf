"""Read the official MSI database and extract its CAB, without installing it."""
from pathlib import Path
import ctypes as c
import json, subprocess
HERE=Path(__file__).resolve().parent
dest=HERE/'tools'
msi=c.WinDLL('msi')
U=c.c_uint
def ok(v):
    if v: raise OSError(v)
db=U()
msi.MsiOpenDatabaseW.argtypes=[c.c_wchar_p,c.c_void_p,c.POINTER(U)]
ok(msi.MsiOpenDatabaseW(str(dest/'cbmc.msi'),None,c.byref(db)))
def query(sql):
    view=U()
    msi.MsiDatabaseOpenViewW.argtypes=[U,c.c_wchar_p,c.POINTER(U)]
    ok(msi.MsiDatabaseOpenViewW(db,sql,c.byref(view)))
    ok(msi.MsiViewExecute(view,0))
    while True:
        rec=U(); code=msi.MsiViewFetch(view,c.byref(rec))
        if code==259: break
        ok(code)
        yield rec
        msi.MsiCloseHandle(rec)
    msi.MsiCloseHandle(view)
def string(rec,field):
    n=U(4096);buf=c.create_unicode_buffer(n.value)
    ok(msi.MsiRecordGetStringW(rec,field,buf,c.byref(n)))
    return buf.value
for rec in query('SELECT `Name`, `Data` FROM `_Streams`'):
    name=string(rec,1)
    if not name.endswith('.cab'):continue
    target=dest/Path(name).name
    with target.open('wb') as f:
        while True:
            n=U(65536);buf=c.create_string_buffer(n.value)
            ok(msi.MsiRecordReadStream(rec,2,buf,c.byref(n)))
            if not n.value:break
            f.write(buf.raw[:n.value])
    print('CAB',target.name,target.stat().st_size)
    subprocess.run(['C:/msys64/usr/bin/bsdtar.exe','-xf',str(target),'-C',str(dest)],check=True)
names={string(r,1):string(r,2).split('|')[-1] for r in query('SELECT `File`, `FileName` FROM `File`')}
for key,name in names.items():
    src=dest/key
    if src.is_file() and name.endswith(('.exe','.dll')):
        src.rename(dest/name)
(dest/'msi_files.json').write_text(json.dumps(names,indent=2))
msi.MsiCloseHandle(db)
