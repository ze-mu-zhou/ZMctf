import hashlib
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EXE = HERE / 'baseline.exe'
WL = ROOT / 'tests/wl-bench16.txt'
ENV = {k: v for k, v in os.environ.items() if not k.startswith('ZK_')}
ENV.update(ZK_NOPROG='1', ZK_PROF='1')
rows = []
rng = random.Random(42)
for rep in range(6):
    modes = ['getline', 'reserve', 'flat']
    rng.shuffle(modes)
    for mode in modes:
        p = subprocess.run([str(HERE/'loader_probe.exe'), mode, str(WL)], capture_output=True,
                           encoding='utf-8', check=True, timeout=30)
        row = json.loads(p.stdout)
        row['repeat'] = rep
        rows.append(row)
        print('loader', rep, mode, round(row['load_s'], 4), flush=True)
assert len({(r['checksum'],r['count']) for r in rows}) == 1
(HERE/'loader_results.json').write_text(json.dumps(rows, indent=2), encoding='utf-8')

# Check loader byte semantics on CRLF, bare repeated CR, NUL, Unicode and no final LF.
edge = HERE/'loader_edge_fixture.txt'
edge.write_bytes(b'\n\r\nabc\r\r\nq\0r\n'+ '中文'.encode() + b'\nlast')
edge_rows = [json.loads(subprocess.run([str(HERE/'loader_probe.exe'),m,str(edge)],
             capture_output=True,encoding='utf-8',check=True).stdout) for m in ['getline','reserve','flat']]
assert len({(r['checksum'],r['count']) for r in edge_rows}) == 1

def sign(secret):
    return subprocess.run([str(EXE),'flask','sign','--secret',secret,'--json','{"flag":"x"}'],
                           capture_output=True,encoding='utf-8',check=True).stdout.strip()

# Retain a single CLI process and measure each completed protocol request.
def serving(commands, env):
    p = subprocess.Popen([str(EXE),'serve'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT,encoding='utf-8',env=env,bufsize=1)
    out=[]
    try:
        for label,args in commands:
            start=time.perf_counter()
            p.stdin.write(json.dumps(args)+'\n')
            p.stdin.flush()
            lines=[]
            while True:
                line=p.stdout.readline()
                if not line: raise RuntimeError('serve exited unexpectedly')
                lines.append(line)
                if line.startswith('<<<zk-rc='): break
            row={'name':label,'wall_s':time.perf_counter()-start,'output':''.join(lines)}
            out.append(row)
            print('serve',label,round(row['wall_s'],4),flush=True)
    finally:
        p.stdin.close()
        p.wait(timeout=30)
        p.stdout.close()
    return out

cookie=sign('RESEARCH-ABSENT-SECRET!')
commands=[('initial-gpuinfo',['gpuinfo'])]
for rep in range(3):
    for kind,flags in [('mask100M',['--mask','?d'*8]),('dict16M',['--wordlist',str(WL)])]:
        for engine,nt in [('cpu',32),('gpu',16),('auto',32)]:
            commands.append((f'{kind}-{engine}-{nt}-{rep}', ['flask','crack','--cookie',cookie,*flags,
                             '--engine',engine,'--threads',str(nt)]))
serve=serving(commands,ENV)
assert all('<<<zk-rc=1>>>' in r['output'] and '跑完未命中' in r['output'] for r in serve[1:])
(HERE/'serve_results.json').write_text(json.dumps({'edge':edge_rows,'runs':serve},ensure_ascii=False,indent=2),encoding='utf-8')

# A GPU-ineligible target at dictionary head; make CPU work from a substantial tail.
target='L'*40
fixture=HERE/'hybrid_long_fixture.txt'
with fixture.open('wb') as dst, WL.open('rb') as src:
    dst.write(target.encode()+b'\n')
    dst.write(src.read(20_000_000))
c=sign(target)
cmds=[('initial-gpuinfo',['gpuinfo'])]
for eng in ['cpu','gpu','auto','auto','auto']:
    cmds.append((eng,['flask','crack','--cookie',c,'--wordlist',str(fixture),'--engine',eng,'--threads','1']))
correctness=serving(cmds,dict(ENV,ZK_GPUTHRESH='1'))
(HERE/'hybrid_correctness.json').write_text(json.dumps(correctness,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(correctness,ensure_ascii=False,indent=2))
