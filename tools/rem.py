import json,sys,re
# usage: rem.py <recs.json> <bench.txt> <Section[,Section]> [ID ... | L1]
#   e.g. rem.py recs.json bench.txt Audit,Remediation 5.1.7
RECS=sys.argv[1]; BENCH=sys.argv[2]; mode=sys.argv[3]; ids=sys.argv[4:]
recs=json.load(open(RECS))
idx={r['id']:n for n,r in enumerate(recs)}
txt=open(BENCH).read().split('\n')
def body(n):
    r=recs[n]; s=r['line']-2; e=recs[n+1]['line']-3 if n+1<len(recs) else len(txt)
    out=[]
    for l in txt[s:e]:
        if re.search(r'Internal Only|^\s*Page \d+\s*$',l) or not l.strip(): continue
        out.append(re.sub(r'^ {1,12}','',l.rstrip()))
    return out
if not ids or ids==['L1']:
    ids=[r['id'] for r in recs if 'Level 1 - Server' in r['profiles']]
for i in ids:
    b=body(idx[i]); title=b[0]
    sec={}
    cur=None
    for l in b[1:]:
        m=re.match(r'^\s*(Profile Applicability|Description|Rationale|Impact|Audit|Remediation|Default Value|References|CIS Controls|Additional Information|MITRE ATT&CK Mappings):\s*(.*)$',l)
        if m: cur=m.group(1); sec[cur]=[m.group(2)] if m.group(2) else []; continue
        if cur: sec.setdefault(cur,[]).append(l)
    print('='*10,i,recs[idx[i]]['title'])
    for k in mode.split(','):
        if k in sec:
            print('--',k); print('\n'.join(sec[k]))
