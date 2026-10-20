# usage: pdftotext -layout CIS_Ubuntu_Linux_26.04_LTS_Benchmark_v1.0.0.pdf bench.txt
#        python3 parse.py bench.txt recs.json   (expects 350 recommendations)
import re, json, sys
txt=open(sys.argv[1]).read().split('\n')
recs=[]; cur=None
hdr=re.compile(r'^\s{0,16}(\d+(?:\.\d+){1,4})\s+(.+?)\s*$')
i=0
# find recommendation headers: line with number+title immediately followed (possibly after wrapped title lines) by "Profile Applicability:"
for idx,l in enumerate(txt):
    if l.strip()=='Profile Applicability:':
        # walk back to header
        j=idx-1; title_lines=[]
        while j>idx-6:
            t=txt[j].strip()
            m=re.match(r'^(\d+(?:\.\d+){1,4})\s+(.*)$',t)
            title_lines.insert(0,t)
            if m: break
            j-=1
        full=' '.join(title_lines)
        m=re.match(r'^(\d+(?:\.\d+){1,4})\s+(.*)$',full)
        if not m: print('NOHDR',idx,full,file=sys.stderr); continue
        rid,title=m.group(1),m.group(2)
        # profiles
        prof=[]; k=idx+1
        while k<idx+10:
            t=txt[k].strip()
            if t.startswith('•'): prof.append(t.lstrip('• ').strip())
            if t.startswith('Description'): break
            k+=1
        recs.append(dict(id=rid,title=title,profiles=prof,line=idx+1))
# add end line + body
for n,r in enumerate(recs):
    end = recs[n+1]['line']-8 if n+1<len(recs) else len(txt)
    r['end']=end
json.dump(recs,open(sys.argv[2],'w'),indent=1,ensure_ascii=False)
print(len(recs))
