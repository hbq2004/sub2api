#!/usr/bin/env python3
"""Cloud monitor: fixed aggregate SQL, bounded TLS mail, secret-free state."""
import argparse, datetime as dt, email.message, fcntl, json, math, os, pathlib, smtplib, ssl, subprocess, time, urllib.request

STATE=pathlib.Path('/var/lib/sub2api-security-monitor')
MAIL=pathlib.Path('/etc/sub2api/monitor-mail.json')
REASONS={'UsageSpike','LoginFailures','SecurityQueryFailed','MonitorStale','SiteUnavailable','OAuthErrors','Recovery','Test'}

def now(): return dt.datetime.now(dt.timezone.utc)
def stamp(t): return t.isoformat()
def timestamp(s): return dt.datetime.fromisoformat(s)
def initial(): return {'schemaVersion':3,'lastSuccessUtc':None,'lastAttemptUtc':None,'lastSent':{},'notificationStatus':'not-needed','lastErrorCategory':None,'activeAlerts':[],'recoveryPending':False}
def load(directory):
    p=directory/'state.json'
    if not p.exists(): return initial()
    s=json.loads(p.read_text())
    if s.get('schemaVersion')!=3 or not isinstance(s.get('lastSent'),dict): raise ValueError('invalid-state')
    return s
def save(directory,state):
    directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    p=directory/'state.pending'; fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'w') as f: json.dump(state,f,separators=(',',':'))
    os.chmod(p,0o600); os.replace(p,directory/'state.json')

def send(reason,settings_path=MAIL):
    reasons=[reason] if isinstance(reason,str) else reason
    if not reasons or any(r not in REASONS for r in reasons): raise ValueError('invalid-reason')
    label=', '.join(reasons)
    mode=settings_path.stat().st_mode
    if mode&0o077 or settings_path.stat().st_uid!=0: raise ValueError('unsafe-mail-permissions')
    cfg=json.loads(settings_path.read_text())
    if set(cfg)!= {'sender','recipient','password'}: raise ValueError('invalid-mail-settings')
    msg=email.message.EmailMessage(); msg['From']=cfg['sender']; msg['To']=cfg['recipient']
    msg['Subject']='Sub2API cloud alert: '+label
    msg.set_content('Sub2API cloud security monitor: '+label+'.\nTime (UTC): '+stamp(now())+'\nInspect https://api.zynexus.top administrator usage/audit views and cloud systemd monitor state.\nThis notification runs on the cloud server and does not depend on the Windows computer.\nNo credentials or account details are included.')
    last=None
    for port in [465,587]:
        client=None
        try:
            ctx=ssl.create_default_context()
            if port==465: client=smtplib.SMTP_SSL('smtp.qq.com',465,timeout=15,context=ctx)
            else:
                client=smtplib.SMTP('smtp.qq.com',587,timeout=15); client.ehlo(); client.starttls(context=ctx); client.ehlo()
            client.login(cfg['sender'],cfg['password'])
            if client.send_message(msg): raise RuntimeError('recipient-rejected')
            return {'status':'smtp-accepted','port':port}
        except Exception as e: last=type(e).__name__
        finally:
            if client:
                try: client.quit()
                except Exception: client.close()
    raise RuntimeError('mail-delivery-failed-'+str(last))

def query(start,end):
    q="""BEGIN READ ONLY; SET LOCAL statement_timeout='20s';
    SELECT json_build_object(
      'hourly_usd',COALESCE((SELECT round(sum(actual_cost)::numeric,2) FROM usage_logs WHERE created_at > TIMESTAMPTZ '%s' - INTERVAL '1 hour' AND created_at <= TIMESTAMPTZ '%s'),0),
      'failed_logins_window',(SELECT count(*) FROM audit_logs WHERE created_at > TIMESTAMPTZ '%s' AND created_at <= TIMESTAMPTZ '%s' AND action IN ('auth.login','auth.login.2fa') AND status_code BETWEEN 400 AND 499),
      'oauth_errors',(SELECT count(*) FROM accounts WHERE deleted_at IS NULL AND type='oauth' AND status='error' AND updated_at > TIMESTAMPTZ '%s' AND updated_at <= TIMESTAMPTZ '%s'));
      ROLLBACK;"""%(stamp(end),stamp(end),stamp(start),stamp(end),stamp(start),stamp(end))
    p=subprocess.run(['docker','exec','-i','sub2api-postgres','psql','-X','-Atq','-v','ON_ERROR_STOP=1','-U','sub2api','-d','sub2api','-f','-'],input=q,text=True,capture_output=True,timeout=30)
    if p.returncode: raise RuntimeError('query-failed')
    return json.loads(p.stdout)

def health():
    try:
        for url in ['http://127.0.0.1:8080/health','https://api.zynexus.top/health']:
            with urllib.request.urlopen(url,timeout=10) as r:
                if r.status!=200 or json.load(r).get('status')!='ok': return False
        return True
    except Exception: return False

def signals(sample,healthy,stale=False):
    usage=sample['hourly_usd']; failures=sample['failed_logins_window']; errors=sample['oauth_errors']
    if isinstance(usage,bool) or not isinstance(usage,(int,float)) or not math.isfinite(usage) or usage<0: raise ValueError('invalid-usage')
    if any(type(v) is not int or v<0 for v in [failures,errors]): raise ValueError('invalid-count')
    result=[]
    if usage>=5: result.append('UsageSpike')
    if failures>=5: result.append('LoginFailures')
    if errors: result.append('OAuthErrors')
    if not healthy: result.append('SiteUnavailable')
    if stale: result.append('MonitorStale')
    return result

def notify(state,reasons,t,sender=send):
    pending=[]
    for reason in reasons:
        last=state['lastSent'].get(reason)
        # Each recovery closes a distinct incident; a previous successful
        # Recovery must not suppress this one, or a failed retry.
        if reason!='Recovery' and last and (t-timestamp(last)).total_seconds()<3600: continue
        pending.append(reason)
    if not pending: return True
    try:
        result=sender(pending[0] if len(pending)==1 else pending)
        for reason in pending: state['lastSent'][reason]=stamp(t)
        state['notificationStatus']='smtp-accepted'
        state['lastDeliveryUtc']=stamp(t); state['lastDeliveryReason']=', '.join(pending)
        state['lastDeliveryTransportPort']=result.get('port')
    except Exception:
        state['notificationStatus']='failed'; state['lastErrorCategory']='notification-failed'
        return False
    return True

def poll(state,t,query_fn=query,health_fn=health,sender=send):
    state['lastAttemptUtc']=stamp(t); state['notificationStatus']='not-needed'; state['lastErrorCategory']=None
    start=t-dt.timedelta(minutes=15); stale=False
    if state['lastSuccessUtc']:
        last=timestamp(state['lastSuccessUtc'])
        if last>t+dt.timedelta(minutes=5): raise ValueError('future-cursor')
        stale=(t-last).total_seconds()>900
        start=min(start,last-dt.timedelta(minutes=1))
    try:
        sample=query_fn(start,t); reasons=signals(sample,health_fn(),stale)
    except Exception:
        state['lastErrorCategory']='query-failed'
        notify(state,['SecurityQueryFailed'],t,sender)
        state['activeAlerts']=['SecurityQueryFailed']
        return False
    previous=list(state.get('activeAlerts',[]))
    # A recovery message is itself a durable obligation. If delivery failed,
    # keep retrying it on the next healthy poll instead of clearing the alert
    # and advancing the cursor as though the notification had been accepted.
    recovery_pending=bool(state.get('recoveryPending',False))
    if (previous or recovery_pending) and not reasons: reasons=['Recovery']
    ok=notify(state,reasons,t,sender)
    if 'Recovery' in reasons:
        state['recoveryPending']=not ok
    state['activeAlerts']=[x for x in reasons if x!='Recovery']
    if not ok and 'Recovery' in reasons:
        state['activeAlerts']=previous
    if ok: state['lastSuccessUtc']=stamp(t)
    state['lastQueryUtc']=stamp(t)
    state['windowMinutes']=math.ceil((t-start).total_seconds()/60)
    state['lastSample']={k:sample[k] for k in ['hourly_usd','failed_logins_window','oauth_errors']}
    state['siteHealthy']='SiteUnavailable' not in reasons
    return ok

def watchdog(state,t,sender=send):
    last=state.get('lastSuccessUtc')
    stale=not last or (t-timestamp(last)).total_seconds()>900 or timestamp(last)>t+dt.timedelta(minutes=5)
    if not stale: return True
    state['lastErrorCategory']='monitor-stale'
    return notify(state,['MonitorStale'],t,sender)

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--watchdog',action='store_true'); parser.add_argument('--test-alert',choices=sorted(REASONS)); args=parser.parse_args()
    STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    with open(STATE/'lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        t=now()
        try: state=load(STATE)
        except Exception:
            state=initial(); state['lastErrorCategory']='invalid-state'
            notify(state,['MonitorStale'],t); save(STATE,state)
            print('{"ok":false,"errorCategory":"invalid-state"}')
            return 1
        if args.test_alert:
            try:
                result=send(args.test_alert); state['lastTestAlert']={'reason':args.test_alert,'at':stamp(t),**result}; ok=True
            except Exception:
                state['lastTestAlert']={'reason':args.test_alert,'at':stamp(t),'status':'failed'}; ok=False
        elif args.watchdog: ok=watchdog(state,t)
        else: ok=poll(state,t)
        save(STATE,state)
        print(json.dumps({'ok':ok,'mode':'test' if args.test_alert else 'watchdog' if args.watchdog else 'poll','lastSuccessUtc':state.get('lastSuccessUtc'),'notificationStatus':state['notificationStatus'],'errorCategory':state['lastErrorCategory']}))
        return 0 if ok else 1

if __name__=='__main__':
    try: raise SystemExit(main())
    except Exception:
        print('{"ok":false,"errorCategory":"monitor-runtime-failed"}')
        raise SystemExit(1)
