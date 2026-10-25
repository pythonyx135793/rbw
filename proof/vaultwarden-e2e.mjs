// Real disposable Vaultwarden + official Bitwarden CLI oracle. No real account.
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import {writeFileSync} from 'node:fs';
import * as crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {once} from 'node:events';

const [rbwArg, agentArg, bwArg, upstream, evidenceArg] = process.argv.slice(2);
const base='https://127.0.0.1:18443';
const rbw=path.resolve(rbwArg), agent=path.resolve(agentArg), bw=path.resolve(bwArg), evidence=path.resolve(evidenceArg);
await fs.mkdir(evidence,{recursive:true});
const root=await fs.mkdtemp(path.join(path.dirname(evidence),'vaultwarden-fictional-'));
const email='rbw-attachment-'+crypto.randomBytes(6).toString('hex')+'@example.invalid';
const password='Synthetic real-server fixture 2026 only';
const iterations=600000;
const master=crypto.pbkdf2Sync(password,email,iterations,32,'sha256');
const expanded=Buffer.concat(['enc','mac'].map(info=>crypto.createHmac('sha256',master).update(info).update(Buffer.from([1])).digest()));
const userKey=crypto.randomBytes(64), rsa=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
function enc(data,key) {
  const iv=crypto.randomBytes(16),c=crypto.createCipheriv('aes-256-cbc',key.subarray(0,32),iv);
  const ciphertext=Buffer.concat([c.update(data),c.final()]);
  const mac=crypto.createHmac('sha256',key.subarray(32)).update(iv).update(ciphertext).digest();
  return `2.${iv.toString('base64')}|${ciphertext.toString('base64')}|${mac.toString('base64')}`;
}
const checks=[];
const env={...process.env,BITWARDENCLI_APPDATA_DIR:path.join(root,'bw'),
  BW_NOINTERACTION:'true',RBW_PROFILE:'vaultwarden-proof',HOME:path.join(root,'home'),
  XDG_CONFIG_HOME:path.join(root,'config'),XDG_CACHE_HOME:path.join(root,'cache'),
  XDG_DATA_HOME:path.join(root,'data'),XDG_RUNTIME_DIR:path.join(root,'run'),
  PATH:path.dirname(rbw)+path.delimiter+process.env.PATH};
for(const dir of ['bw','home','config','cache','data','run'])await fs.mkdir(path.join(root,dir),{recursive:true,mode:0o700});
async function command(exe,args,input) {
  console.log('BEGIN '+path.basename(exe)+' '+args[0]);
  const child=spawn(exe,args,{env,stdio:['pipe','pipe','pipe']});const out=[],err=[];
  child.stdout.on('data',b=>out.push(b));child.stderr.on('data',b=>err.push(b));child.stdin.end(input);
  const timer=setTimeout(()=>child.kill('SIGKILL'),45000);
  const [code]=await once(child,'close');clearTimeout(timer);
  console.log('END '+path.basename(exe)+' '+args[0]+' exit='+code+' signal='+child.signalCode);
  const stderr=Buffer.concat(err).toString();assert.equal(code,0,`${path.basename(exe)} ${args[0]}: ${stderr}`);
  return Buffer.concat(out);
}
const bwRun=(...args)=>command(process.execPath,[bw,...args]);
const rbwRun=(...args)=>command(rbw,args);
const pass=name=>{checks.push(name);console.log('PASS '+name);writeFileSync(path.join(evidence,'vaultwarden-progress.json'),JSON.stringify({checks,at:new Date().toISOString(),cleanup_complete:false},null,2));};
const caFile=path.join(root,'fixture-ca.pem'), caKey=path.join(root,'fixture-ca.key');
const certFile=path.join(root,'fixture-server.pem'), certKey=path.join(root,'fixture-server.key');
const csrFile=path.join(root,'fixture-server.csr'), extensions=path.join(root,'fixture-server.ext');
await command('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=Disposable rbw fixture CA','-addext','basicConstraints=critical,CA:TRUE,pathlen:0','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',caKey,'-out',caFile]);
await command('openssl',['req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-keyout',certKey,'-out',csrFile]);
await fs.writeFile(extensions,'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n');
await command('openssl',['x509','-req','-in',csrFile,'-CA',caFile,'-CAkey',caKey,'-CAcreateserial','-days','1','-extfile',extensions,'-out',certFile]);
const ca=await fs.readFile(caFile);
env.NODE_EXTRA_CA_CERTS=caFile;
env.SSL_CERT_FILE=caFile;
const proxy=https.createServer({key:await fs.readFile(certKey),cert:await fs.readFile(certFile)},(request,response)=>{
  const forwarded=http.request(new URL(request.url,upstream),{method:request.method,headers:{...request.headers,'x-forwarded-proto':'https'}},reply=>{response.writeHead(reply.statusCode,reply.headers);reply.pipe(response);});
  forwarded.on('error',error=>{response.writeHead(502);response.end(String(error));});request.pipe(forwarded);
});
const upgradeSockets=new Set();
const proxySockets=new Set();
proxy.on('connection',socket=>{proxySockets.add(socket);socket.on('close',()=>proxySockets.delete(socket));});
proxy.on('upgrade',(request,socket,head)=>{
  upgradeSockets.add(socket);socket.on('close',()=>upgradeSockets.delete(socket));
  const forwarded=http.request(new URL(request.url,upstream),{method:request.method,headers:{...request.headers,'x-forwarded-proto':'https'}});
  forwarded.on('upgrade',(response,peer,peerHead)=>{
    upgradeSockets.add(peer);peer.on('close',()=>upgradeSockets.delete(peer));
    const headers=[];for(let i=0;i<response.rawHeaders.length;i+=2)headers.push(response.rawHeaders[i]+': '+response.rawHeaders[i+1]);
    socket.write(`HTTP/1.1 ${response.statusCode} ${response.statusMessage}\r\n${headers.join('\r\n')}\r\n\r\n`);
    if(peerHead.length)socket.write(peerHead);if(head.length)peer.write(head);
    socket.on('error',()=>peer.destroy());peer.on('error',()=>socket.destroy());
    socket.on('close',()=>peer.destroy());peer.on('close',()=>socket.destroy());
    socket.pipe(peer);peer.pipe(socket);
  });
  forwarded.on('response',response=>{socket.write(`HTTP/1.1 ${response.statusCode} ${response.statusMessage}\r\nConnection: close\r\n\r\n`);response.pipe(socket);});
  forwarded.on('error',()=>socket.destroy());forwarded.end();
});
proxy.listen(18443,'127.0.0.1');await once(proxy,'listening');
async function postJSON(route,value) {
  return new Promise((resolve,reject)=>{
    const request=https.request(base+route,{method:'POST',ca,headers:{'Content-Type':'application/json','Accept':'application/json'}},response=>{
      const chunks=[];response.on('data',b=>chunks.push(b));response.on('end',()=>{
        try {const body=Buffer.concat(chunks).toString();assert.equal(response.statusCode,200,body);resolve(JSON.parse(body));}catch(error){reject(error);}
      });
    });request.on('error',reject);request.end(JSON.stringify(value));
  });
}
const pinentry=path.join(root,'pinentry');
await fs.writeFile(pinentry,`#!/usr/bin/env python3
import sys
from pathlib import Path
p=Path(__file__).parent
print('OK synthetic pinentry',flush=True)
for line in sys.stdin:
 if line.startswith('GETPIN'):
  with (p/'pinentry-count').open('a') as f:f.write('GETPIN\\n')
  print('D ${password}',flush=True)
 print('OK',flush=True)
`,{mode:0o700});
const pinCount=async()=>((await fs.readFile(path.join(root,'pinentry-count'),'utf8').catch(()=>'' )).match(/GETPIN/g)||[]).length;
const log=await fs.open(path.join(evidence,'vaultwarden-agent.log'),'w');
let child,done,failure=null,attachmentId,entryId;
try {
  const registration={email,name:'Fictional attachment fixture',masterPasswordHash:crypto.pbkdf2Sync(master,password,1,32,'sha256').toString('base64'),
    key:enc(userKey,expanded),keys:{publicKey:rsa.publicKey.export({type:'spki',format:'der'}).toString('base64'),
      encryptedPrivateKey:enc(rsa.privateKey.export({type:'pkcs8',format:'der'}),userKey)},kdf:0,kdfIterations:iterations};
  // Vaultwarden 1.37.4's normal no-mail signup returns a token, then finishes
  // registration through identity. This is a disposable local fixture account.
  registration.emailVerificationToken=await postJSON('/identity/accounts/register/send-verification-email',{email,name:registration.name});
  assert.equal(typeof registration.emailVerificationToken,'string');
  await postJSON('/identity/accounts/register/finish',registration);
  await bwRun('config','server',base);
  env.BW_SESSION=(await bwRun('login',email,password,'--raw')).toString().trim();
  assert.ok(env.BW_SESSION.length>20);pass('official CLI logs into disposable real Vaultwarden');
  const item={type:1,name:'Real attachment fixture',notes:'Fictional test data only',login:{username:'fixture-user',password:'not-a-real-password',uris:[]}};
  const created=JSON.parse(await bwRun('create','item',Buffer.from(JSON.stringify(item)).toString('base64')));entryId=created.id;
  const bytes=Buffer.concat([Buffer.from(Array.from({length:256},(_,i)=>i)),Buffer.from([0,255,128,13,10,10])]);
  const input=path.join(root,'real payload.bin');await fs.writeFile(input,bytes);
  const withFile=JSON.parse(await bwRun('create','attachment','--file',input,'--itemid',entryId));
  attachmentId=withFile.attachments[0].id;
  const oracle=path.join(root,'official.out');await bwRun('get','attachment',attachmentId,'--itemid',entryId,'--output',oracle);
  assert.deepEqual(await fs.readFile(oracle),bytes);pass('official CLI creates and retrieves exact encrypted binary attachment');
  const profile='rbw-vaultwarden-proof';
  await fs.mkdir(path.join(env.XDG_CONFIG_HOME,profile),{recursive:true,mode:0o700});
  await fs.writeFile(path.join(env.XDG_CONFIG_HOME,profile,'config.json'),JSON.stringify({email,base_url:base,pinentry,sync_interval:0,lock_timeout:3600}));
  child=spawn(agent,['--no-daemonize'],{env,stdio:['ignore',log.fd,log.fd]});done=once(child,'close');
  const socket=path.join(env.XDG_RUNTIME_DIR,profile,'socket');const deadline=Date.now()+10000;
  while(!await fs.access(socket).then(()=>true,()=>false)){assert.equal(child.exitCode,null);assert.ok(Date.now()<deadline);await new Promise(r=>setTimeout(r,25));}
  await rbwRun('login');await rbwRun('sync');pass('rbw authenticates and syncs actual Vaultwarden attachment metadata');
  const raw=JSON.parse(await rbwRun('get',entryId,'--raw'));
  assert.equal(raw.attachments[0].id,attachmentId);assert.equal(raw.attachments[0].file_name,'real payload.bin');
  const output=path.join(root,'rbw.out');await rbwRun('get',entryId,'--attachment',attachmentId,'--output',output);
  assert.deepEqual(await fs.readFile(output),await fs.readFile(oracle));pass('rbw ID download matches original and official CLI byte-for-byte');
  const named=path.join(root,'named.out');await rbwRun('get','Real attachment fixture','fixture-user','--attachment','real payload.bin','--output',named);
  assert.deepEqual(await fs.readFile(named),bytes);pass('actual username and filename selection download');
  const stdout=await rbwRun('get',entryId,'--attachment',attachmentId,'--output','-');assert.deepEqual(stdout,bytes);
  pass('actual Vaultwarden binary stdout is exact');
  const protectedItem=JSON.parse(await bwRun('get','item',entryId));protectedItem.reprompt=1;
  await bwRun('edit','item',entryId,Buffer.from(JSON.stringify(protectedItem)).toString('base64'));
  await rbwRun('sync');const before=await pinCount();
  const protectedOut=path.join(root,'protected.out');await rbwRun('get',entryId,'--attachment',attachmentId,'--output',protectedOut);
  assert.equal((await pinCount())-before,1);assert.deepEqual(await fs.readFile(protectedOut),bytes);
  pass('actual server protected attachment requires fresh password reprompt');
} catch(error) {failure={message:error.message,stack:error.stack};console.error(error.stack);}
finally {
  await fs.writeFile(path.join(evidence,'vaultwarden-before-cleanup.json'),JSON.stringify({checks,passed:checks.length,failure,cleanup_complete:false},null,2));
  if(child){
    if(child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');
    let cleanupTimer;const terminated=done.then(()=>true,()=>true);
    const graceful=await Promise.race([terminated,new Promise(resolve=>{cleanupTimer=setTimeout(()=>resolve(false),3000);})]);
    clearTimeout(cleanupTimer);
    if(!graceful){child.kill('SIGKILL');await terminated;}
  }
  const closed=new Promise(resolve=>proxy.close(()=>resolve(true)));
  for(const socket of upgradeSockets)socket.destroy();
  for(const socket of proxySockets)socket.destroy();
  proxy.closeAllConnections();
  let closeTimer;const proxyClosed=await Promise.race([closed,new Promise(resolve=>{closeTimer=setTimeout(()=>resolve(false),3000);})]);clearTimeout(closeTimer);
  if(!proxyClosed&&!failure)failure={message:'owned HTTPS fixture did not close',stack:null};
  await log.close();
  await fs.writeFile(path.join(evidence,'vaultwarden-e2e-results.json'),JSON.stringify({checks,passed:checks.length,failure,
    synthetic_only:true,real_server:true,official_cli:'2025.12.1',server_release:'1.37.4',
    entry_id:entryId,attachment_id:attachmentId,agent_exit:child?.exitCode,agent_signal:child?.signalCode,cleanup:proxyClosed&&(!child||child.exitCode!==null||child.signalCode!==null),
    tls:'Ephemeral local CA, hostname-valid server certificate, Node extra CA and Rust native roots; certificate verification enabled'},null,2));
}
if(failure)process.exitCode=1;
