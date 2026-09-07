"""Interleaved local end-to-end timings; no absolute performance claims."""
from pathlib import Path
import hashlib, json, os, statistics, subprocess, time
from itsdangerous import URLSafeTimedSerializer
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
env={k:v for k,v in os.environ.items() if not k.startswith('ZK_')}
env.update(ZK_NOPROG='1')
cookie=URLSafeTimedSerializer('review-absent-key!',salt='cookie-session',signer_kwargs={'key_derivation':'hmac','digest_method':hashlib.sha1}).dumps({'x':1})
rows=[]
configs=[('previous-cpu',HERE.parent/'recheck'/'zemu-flask.exe','cpu',None),
         ('current-cpu',HERE/'zemu-flask.exe','cpu',None),
         ('current-gpu-cache-off',HERE/'zemu-flask.exe','gpu','0'),
         ('current-gpu-cache-default',HERE/'zemu-flask.exe','gpu',None)]
for rep in range(4):
    for name,exe,engine,budget in configs[::1 if rep%2==0 else -1]:
        runenv=env.copy()
        if budget is not None: runenv['ZK_DICTCACHE_MB']=budget
        args=[str(exe),'flask','crack','--cookie',cookie,'--wordlist',str(ROOT/'tests'/'wl-bench16.txt'),'--engine',engine,'--threads','16']
        t=time.perf_counter()
        p=subprocess.run(args,capture_output=True,encoding='utf-8',env=runenv,timeout=60)
        sec=time.perf_counter()-t
        assert p.returncode==1 and '跑完未命中' in p.stderr,(name,p.stderr)
        rows.append(dict(name=name,rep=rep,warmup=rep==0,seconds=sec,stderr=p.stderr))
        print(name,rep,round(sec,4),flush=True)
medians={name:statistics.median(r['seconds'] for r in rows if r['name']==name and not r['warmup']) for name,*_ in configs}
result=dict(rows=rows,medians=medians,wordlist_bytes=(ROOT/'tests'/'wl-bench16.txt').stat().st_size,
            binaries={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for _,p,*_ in configs})
(HERE/'benchmark_results.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(medians),flush=True)
