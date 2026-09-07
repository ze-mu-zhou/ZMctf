"""Read-only production benchmark; artifacts stay beside this script."""
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
WORDLIST = ROOT / 'tests/wl-bench16.txt'
ENV = {k: v for k, v in os.environ.items() if not k.startswith('ZK_')}
ENV.update(ZK_NOPROG='1', ZK_PROF='1')
sign = subprocess.run([str(EXE), 'flask', 'sign', '--secret', 'RESEARCH-ABSENT-SECRET!',
                       '--json', '{"flag":"x"}'], capture_output=True, encoding='utf-8', check=True)
cookie = sign.stdout.strip()
cases = {}
for workload, flags in [('mask100M', ['--mask', '?d'*8]), ('dict16M', ['--wordlist', str(WORDLIST)])]:
    for engine, threads in [('cpu', 16), ('cpu', 32), ('gpu', 16), ('auto', 16), ('auto', 32)]:
        name = f'{workload}-{engine}-{threads}'
        cases[name] = ['flask', 'crack', '--cookie', cookie, *flags, '--engine', engine, '--threads', str(threads)]

def run(name):
    start = time.time()
    t0 = time.perf_counter()
    p = subprocess.run([str(EXE), *cases[name]], env=ENV, capture_output=True,
                       encoding='utf-8', timeout=90)
    elapsed = time.perf_counter()-t0
    if p.returncode != 1 or '跑完未命中' not in p.stderr:
        raise RuntimeError((name, p.returncode, p.stdout, p.stderr))
    return {'start_epoch': start, 'end_epoch': time.time(), 'wall_s': elapsed, 'stderr': p.stderr}

results = {'exe_sha256': hashlib.sha256(EXE.read_bytes()).hexdigest(), 'file_bytes': WORDLIST.stat().st_size,
           'conditions': 'warm file and kernel caches; fresh CLI; no hits; no clock/power settings changed',
           'cases': cases, 'warmups': {}, 'runs': {n: [] for n in cases}}
telemetry = open(HERE / 'gpu_telemetry.csv', 'w', encoding='utf-8')
monitor = subprocess.Popen(['nvidia-smi', '--query-gpu=timestamp,name,pstate,temperature.gpu,power.draw,clocks.sm,clocks.mem,utilization.gpu',
                            '--format=csv', '-lms', '200'], stdout=telemetry, stderr=subprocess.DEVNULL,
                           creationflags=subprocess.CREATE_NO_WINDOW)
try:
    for name in cases:
        results['warmups'][name] = run(name)
        print('warm', name, round(results['warmups'][name]['wall_s'], 4), flush=True)
    rng = random.Random(20260907)
    for rep in range(3):
        order = list(cases)
        rng.shuffle(order)
        for name in order:
            row = run(name)
            results['runs'][name].append(row)
            print(rep+1, name, round(row['wall_s'], 4), flush=True)
            (HERE / 'benchmark_results.json').write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
finally:
    monitor.terminate()
    monitor.wait(timeout=10)
    telemetry.close()
results['summary'] = {n: {'median_s': statistics.median(r['wall_s'] for r in rows),
                           'min_s': min(r['wall_s'] for r in rows), 'max_s': max(r['wall_s'] for r in rows)}
                      for n, rows in results['runs'].items()}
(HERE / 'benchmark_results.json').write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(results['summary'], indent=2))
