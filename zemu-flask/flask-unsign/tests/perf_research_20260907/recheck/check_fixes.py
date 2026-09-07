"""Review current source with an isolated binary; preserve prior research results."""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import sys
from itsdangerous import URLSafeTimedSerializer

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
EXE = HERE / 'zemu-flask.exe'
if not EXE.is_file():
    raise SystemExit('Build the isolated review executable before running checks')
env = {k:v for k,v in os.environ.items() if not k.startswith('ZK_')}
env.update(PYTHONIOENCODING='utf-8', ZK_NOPROG='1')
results = {}
for name in ['test_vectors', 'adversarial_test']:
    source_file = ROOT / 'tests' / (name+'.py')
    source = source_file.read_text(encoding='utf-8')
    # Use a lambda replacement to retain Windows backslashes verbatim.
    source = re.sub(r'^TOOL = .*$', lambda _: 'TOOL = '+repr(str(EXE)), source, flags=re.M)
    wrapper = HERE / ('run_'+name+'.py')
    wrapper.write_text('__file__ = '+repr(str(source_file))+'\n'+source,encoding='utf-8')
    p=subprocess.run([sys.executable,str(wrapper)],capture_output=True,encoding='utf-8',env=env,timeout=180)
    (HERE/(name+'.log')).write_text(p.stdout+p.stderr,encoding='utf-8')
    results[name]={'returncode':p.returncode,'pass':sum(x.startswith('PASS') for x in p.stdout.splitlines()),
                   'fail':[x for x in p.stdout.splitlines() if x.startswith('FAIL')]}
    print(name,json.dumps(results[name]),flush=True)

def cookie(key):
    return URLSafeTimedSerializer(key,salt='cookie-session',
        signer_kwargs={'key_derivation':'hmac','digest_method':hashlib.sha1}).dumps({'x':1})

commands=[['gpuinfo']]
labels=[]
expected=[]
long_file=HERE.parent/'hybrid_long_fixture.txt'
for i in range(3):
    labels.append('original-long-head-'+str(i)); expected.append('L'*40)
    commands.append(['flask','crack','--cookie',cookie('L'*40),'--wordlist',str(long_file),
                     '--engine','auto','--threads','1'])
nul_file=HERE/'nul_fixture.txt'
nul_file.write_bytes(b'A\x00B\n'+b'wrong-key\n'*2_000_000)
for nt in [1,4]:
    labels.append('nul-head-'+str(nt)); expected.append('A\x00B')
    commands.append(['flask','crack','--cookie',cookie('A\x00B'),'--wordlist',str(nul_file),
                     '--engine','auto','--threads',str(nt)])
for nt in [1,4]:
    for key in ['00000000','16777215','16777216','99999999']:
        labels.append('mask-boundary-'+key+'-'+str(nt));expected.append(key)
        commands.append(['flask','crack','--cookie',cookie(key),'--mask','?d'*8,
                         '--engine','auto','--threads',str(nt)])
commands.append(['flask','crack','--cookie',cookie('not-digits!'),'--mask','?d'*8,'--engine','auto','--threads','4'])
labels.append('mask-no-hit');expected.append(None)
run=subprocess.run([str(EXE),'serve'],input=''.join(json.dumps(c)+'\n' for c in commands),
                   capture_output=True,encoding='utf-8',env=dict(env,ZK_GPUTHRESH='1'),timeout=120)
(HERE/'targeted.log').write_text(run.stdout+run.stderr,encoding='utf-8')
parts=re.split(r'<<<zk-rc=(\d+)>>>\r?\n',run.stdout)
assert len(parts)==2*len(commands)+1,(len(parts),len(commands))
targeted=[]
for i,(name,value) in enumerate(zip(labels,expected),start=1):
    output,rc=parts[2*i:2*i+2]
    ok=rc==('1' if value is None else '0') and (value is None or value in output.splitlines())
    targeted.append({'name':name,'pass':ok,'returncode':int(rc),'output':output})
    print('PASS' if ok else 'FAIL',name,flush=True)
results['targeted']=targeted
results['source_hashes']={str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest()
                          for f in (ROOT/'src').rglob('*') if f.is_file()}
results['exe_sha256']=hashlib.sha256(EXE.read_bytes()).hexdigest()
(HERE/'results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
sys.exit(0 if all(r['returncode']==0 for r in [results['test_vectors'],results['adversarial_test']])
            and all(r['pass'] for r in targeted) else 1)
