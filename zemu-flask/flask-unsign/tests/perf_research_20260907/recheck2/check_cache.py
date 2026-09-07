"""Black-box cache lifecycle and WordSet format checks against the source snapshot."""
from pathlib import Path
import hashlib, json, os, subprocess, time
from itsdangerous import URLSafeTimedSerializer
HERE=Path(__file__).resolve().parent
env={k:v for k,v in os.environ.items() if not k.startswith('ZK_')}
env.update(ZK_NOPROG='1',ZK_PROF='1',ZK_GPUTHRESH='1')
process=subprocess.Popen([str(HERE/'zemu-flask.exe'),'serve'],stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',env=env)
results=[]
def run(label, key, path, engine='cpu', hit=True, salt='cookie-session', cache=None):
    c=URLSafeTimedSerializer(key,salt=salt,signer_kwargs={'key_derivation':'hmac','digest_method':hashlib.sha1}).dumps({'x':1})
    cmd=['flask','crack','--cookie',c,'--wordlist',str(path),'--engine',engine,'--threads','2','--salt',salt]
    process.stdin.write(json.dumps(cmd)+'\n');process.stdin.flush()
    lines=[]
    for line in process.stdout:
        if line.startswith('<<<zk-rc='): rc=int(line[9:-4]);break
        lines.append(line.rstrip('\n'))
    else: raise RuntimeError('serve exited')
    output='\n'.join(lines)
    ok=rc==(0 if hit else 1) and (not hit or key in lines)
    if cache is not None: ok &= ('缓存命中' in output)==cache
    results.append(dict(name=label,passed=bool(ok),rc=rc,output=output))
    print('PASS' if ok else 'FAIL',label,flush=True)
p=HERE/'cache_words.txt'
p.write_bytes(b'\r\n\nfirst\r\r\nA\x00B\n'+b'L'*40+b'\n space \r\n'+ '中文'.encode()+b'\nlast')
for engine in ['cpu','gpu','auto','gpu']:
    for key in ['first','A\x00B','L'*40,' space ','中文','last']:
        run('formats-'+engine+'-'+repr(key),key,p,engine)
run('custom-salt-cache-reuse','first',p,'gpu',salt='different-salt',cache=True)
p.write_bytes(b'new-key\n')
run('size-invalidation','new-key',p,cache=False)
p.write_bytes(b'alt-key\n')
ns=p.stat().st_mtime_ns+2_000_000_000
os.utime(p,ns=(ns,ns))
run('mtime-invalidation','alt-key',p,cache=False)
run('cache-hit','alt-key',p,cache=True)
run('no-hit','absent',p,'auto',hit=False,cache=True)
p.unlink()
run('deleted-dictionary','alt-key',p,hit=False,cache=False)
p.write_bytes(b'Q'*40+b'\nA\x00B\n')
for engine in ['gpu','auto','gpu']:
    run('all-skipped-'+engine,'A\x00B',p,engine)
process.stdin.close()
process.wait(timeout=15)
(HERE/'cache_results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
# Deliberately retain excess input capacity after compaction.
(HERE/'capacity_fixture.txt').write_bytes(b'\n'*(10*1024*1024)+b'key\n')
raise SystemExit(0 if all(r['passed'] for r in results) else 1)
