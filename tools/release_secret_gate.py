"""Fail-closed Gitleaks gate with exact reviewed file versions; no raw values."""
import hashlib,json,os,subprocess,sys
from pathlib import Path

def main():
 root=Path(__file__).resolve().parents[1]
 policy=json.loads((root/'tools/release-secret-review.json').read_text())
 if policy.get('schemaVersion')!=1:raise ValueError('invalid review ledger')
 result=subprocess.run(['git','ls-files','-z'],cwd=root,capture_output=True,check=True)
 names=sorted(set(result.stdout.decode('utf-8').split('\0'))-{''})
 chunks=[];location=[];line=1
 for name in names:
  path=root/name
  if path.is_symlink():raise ValueError('unsupported source symlink')
  if not path.exists():continue
  if not path.is_file() or not path.resolve().is_relative_to(root):raise ValueError('unsafe source input')
  data=path.read_bytes()+b'\n';chunks.append(data);location.append((line,line+data.count(b'\n'),name));line+=data.count(b'\n')+1
 exe=os.environ.get('RELEASE_GITLEAKS',str(root/'gitleaks'))
 # Scanner output is redacted and kept in memory, never written as a report.
 scanner=subprocess.run([exe,'stdin','--no-banner','--no-color','--log-level','error','--redact=100',
  '--config',str(root/'.gitleaks.toml'),'--ignore-gitleaks-allow','--gitleaks-ignore-path',os.devnull,
  '--exit-code','42','--report-format','json','--report-path','-'],input=b'\n'.join(chunks),capture_output=True)
 if scanner.returncode not in (0,42):raise ValueError('scanner execution failed')
 findings=json.loads(scanner.stdout or b'[]');blocked=[];reviewed=0
 for item in findings:
  src=next((x for x in location if x[0]<=item['StartLine']<=x[1]),None)
  if src is None:raise ValueError('unmapped scanner finding')
  name=src[2];approved=policy['entries'].get(name,{})
  if approved.get('sha256')==hashlib.sha256((root/name).read_bytes().replace(b'\r\n',b'\n')).hexdigest():reviewed+=1
  else:blocked.append({'file':name,'line':item['StartLine']-src[0]+1,'rule':item['RuleID']})
 print(json.dumps({'status':'blocked' if blocked else 'passed','scannedFiles':len(names),'reviewedFindings':reviewed,'blocked':blocked,'valuesEmitted':False}))
 return 1 if blocked else 0

if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception:print('{"status":"failed","diagnosticsSuppressed":true}');raise SystemExit(2)
