// Fictional vault only. Independent Node/OpenSSL fixtures exercise the real
// production CLI, Unix socket, agent, pinentry protocol and HTTP boundaries.
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as crypto from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {once} from 'node:events';

const [rbwArg, agentArg, evidenceArg] = process.argv.slice(2);
const rbw = path.resolve(rbwArg), agent = path.resolve(agentArg);
const evidence = path.resolve(evidenceArg);
await fs.mkdir(evidence, {recursive:true});
const root = await fs.mkdtemp(path.join(path.dirname(evidence), 'rbw-fictional-'));
const checks = [], requests = [];
const password = 'Synthetic attachment fixture only 2026';
const email = 'attachment-fixture@example.invalid';
const iterations = 600000;
const master = crypto.pbkdf2Sync(password, email, iterations, 32, 'sha256');
const expanded = Buffer.concat(['enc','mac'].map(info => crypto.createHmac('sha256', master).update(info).update(Buffer.from([1])).digest()));
const userKey = crypto.randomBytes(64), orgKey = crypto.randomBytes(64);
const rsa = crypto.generateKeyPairSync('rsa', {modulusLength:2048});
function encrypt(data, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key.subarray(0,32), iv);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const mac = crypto.createHmac('sha256', key.subarray(32)).update(iv).update(encrypted).digest();
  return {text:`2.${iv.toString('base64')}|${encrypted.toString('base64')}|${mac.toString('base64')}`,
    binary:Buffer.concat([Buffer.from([2]),iv,mac,encrypted])};
}
const protectedKey = encrypt(userKey, expanded).text;
const privateKey = encrypt(rsa.privateKey.export({type:'pkcs8',format:'der'}),userKey).text;
const orgId = crypto.randomUUID(), entryId = crypto.randomUUID();
const orgWrapped = '4.'+crypto.publicEncrypt({key:rsa.publicKey,padding:crypto.constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha1'},orgKey).toString('base64');
let current, blobs = new Map(), token='synthetic-token', mode='ok';
let blobGate=null, refreshGate=null;
let base;
const server = http.createServer(async (req,res) => {
  try {
    const url = new URL(req.url, base);
    requests.push({path:url.pathname,bearer_present:Boolean(req.headers.authorization)});
    const json = (status, value) => {res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify(value));};
    if(url.pathname==='/identity/connect/token') {
      let body='';for await (const chunk of req) body+=chunk;
      assert.equal(new URLSearchParams(body).get('grant_type'),'refresh_token');
      if(refreshGate) {refreshGate.started(); await refreshGate.wait;}
      token='refreshed-synthetic-token';
      return json(200,{access_token:token});
    }
    if(url.pathname.startsWith('/api/')) {
      if(req.headers.authorization!==`Bearer ${token}`) return json(401,{});
      if(url.pathname===`/api/ciphers/${entryId}`) {
        if(mode==='wrong-entry') return json(200,{...current,id:crypto.randomUUID()});
        if(mode==='forbidden-entry') return json(403,{});
        return json(200,current);
      }
      if(url.pathname.startsWith(`/api/ciphers/${entryId}/attachment/`)) {
        if(mode==='legacy') return json(404,{});
        if(mode==='forbidden-url') return json(403,{});
        const id=decodeURIComponent(url.pathname.split('/').at(-1));
        const a=current.attachments.find(a=>a.id===id);
        return a?json(200,{...a,url:`${base}/blob/${id}`}):json(404,{});
      }
      return json(404,{});
    }
    if(url.pathname.startsWith('/blob/')) {
      assert.equal(req.headers.authorization,undefined,'vault token leaked to blob');
      if(blobGate) {blobGate.started();await blobGate.wait;}
      const data=blobs.get(url.pathname.split('/').at(-1));
      if(!data) return json(404,{});
      const out=Buffer.from(data);
      if(mode==='corrupt') out[17]^=1;
      if(mode==='unsupported') out[0]=0;
      res.writeHead(200,{'Content-Type':'application/octet-stream'});res.end(out);return;
    }
    return json(403,{}); // An expired URL must never be used by modern flow.
  } catch(error) {res.writeHead(500);res.end(String(error));}
});
server.listen(0,'127.0.0.1');await once(server,'listening');
base=`http://127.0.0.1:${server.address().port}`;
const profile='rbw-attachment-proof';
const env={...process.env,RBW_PROFILE:'attachment-proof',HOME:path.join(root,'home'),
  XDG_CONFIG_HOME:path.join(root,'config'),XDG_CACHE_HOME:path.join(root,'cache'),
  XDG_DATA_HOME:path.join(root,'data'),XDG_RUNTIME_DIR:path.join(root,'run'),
  PATH:path.dirname(rbw)+path.delimiter+process.env.PATH};
for(const dir of ['home','config','cache','data','run']) await fs.mkdir(path.join(root,dir),{recursive:true,mode:0o700});
await fs.mkdir(path.join(env.XDG_CONFIG_HOME,profile),{recursive:true,mode:0o700});
await fs.mkdir(path.join(env.XDG_CACHE_HOME,profile),{recursive:true,mode:0o700});
const pinentry=path.join(root,'pinentry');
await fs.writeFile(pinentry,`#!/usr/bin/env python3
import sys
from pathlib import Path
p=Path(__file__).parent
print('OK synthetic pinentry',flush=True)
for line in sys.stdin:
 if line.startswith('GETPIN'):
  with (p/'pinentry-calls').open('a') as f:f.write('GETPIN\\n')
  mode=(p/'pinentry-mode').read_text().strip()
  if mode=='cancel':print('ERR 83886179 Operation cancelled',flush=True);continue
  print('D '+('${password}' if mode=='ok' else 'wrong synthetic password'),flush=True)
 print('OK',flush=True)
 if line.startswith('BYE'):break
`,{mode:0o700});
await fs.writeFile(path.join(root,'pinentry-mode'),'ok');
await fs.writeFile(path.join(env.XDG_CONFIG_HOME,profile,'config.json'),JSON.stringify({email,base_url:base,pinentry,lock_timeout:3600,sync_interval:0}));
const encodedServer=base.replace(/[\x00-\x1f\/:%]/g,c=>'%'+c.charCodeAt(0).toString(16).toUpperCase().padStart(2,'0'));
const dbPath=path.join(env.XDG_CACHE_HOME,profile,`${encodedServer}:${email}.json`);
function makeEntry({org=false,item=false,legacy=false,reprompt=0,bytes=Buffer.from([0,255,128,13,10,0]),duplicate=false}={}) {
  const vault=org?orgKey:userKey;
  const itemKey=item?crypto.randomBytes(64):vault;
  const fileKey=legacy?itemKey:crypto.randomBytes(64);
  const fileId=crypto.randomBytes(16).toString('hex');
  const attachment={id:fileId,fileName:encrypt(Buffer.from('fixture.bin'),itemKey).text,
    key:legacy?null:encrypt(fileKey,itemKey).text,size:String(bytes.length),url:`${base}/${legacy?'blob':'expired'}/${fileId}`};
  blobs=new Map([[fileId,encrypt(bytes,fileKey).binary]]);
  current={id:entryId,organizationId:org?orgId:null,name:encrypt(Buffer.from('Fictional attachment'),itemKey).text,
    secureNote:{},reprompt,key:item?encrypt(itemKey,vault).text:null,attachments:[attachment]};
  if(duplicate) {
    const second={...attachment,id:crypto.randomBytes(16).toString('hex')};
    current.attachments.push(second);blobs.set(second.id,blobs.get(fileId));
  }
  return {bytes,fileId};
}
function dbEntry() {return {id:entryId,org_id:current.organizationId,folder:null,folder_id:null,name:current.name,
  data:'SecureNote',fields:[],notes:null,history:[],key:current.key,master_password_reprompt:0,attachments:current.attachments};}
async function seed() {
  await fs.writeFile(dbPath,JSON.stringify({access_token:token,refresh_token:'synthetic-refresh',kdf:0,iterations,
    memory:null,parallelism:null,protected_key:protectedKey,protected_private_key:privateKey,
    protected_org_keys:{[orgId]:orgWrapped},entries:[dbEntry()]}));
}
const log=await fs.open(path.join(evidence,'agent.log'),'w');
let agentChild, agentDone;
const socketPath=path.join(env.XDG_RUNTIME_DIR,profile,'socket');
async function command(args,options={}) {
  const child=spawn(rbw,args,{env,stdio:['ignore','pipe','pipe'],...options});
  const stdout=[],stderr=[];
  child.stdout?.on('data',b=>stdout.push(b));child.stderr?.on('data',b=>stderr.push(b));
  const timer=setTimeout(()=>child.kill('SIGKILL'),15000);
  const [code]=await once(child,'close');clearTimeout(timer);
  return {code,stdout:Buffer.concat(stdout),stderr:Buffer.concat(stderr).toString()};
}
function rpc(action) {return new Promise((resolve,reject)=>{
  const socket=net.createConnection(socketPath);let data='';
  socket.setTimeout(12000,()=>socket.destroy(new Error('synthetic RPC timed out')));
  socket.on('error',reject);
  socket.on('connect',()=>socket.write(JSON.stringify({environment:{tty:null,env_vars:[]},action})+'\n'));
  socket.on('data',chunk=>{data+=chunk.toString();const newline=data.indexOf('\n');if(newline>=0){socket.destroy();try{resolve(JSON.parse(data.slice(0,newline)));}catch(e){reject(e);}}});
});}
const check=(name)=>{checks.push(name);console.log('PASS '+name);};
const pinCount=async()=>((await fs.readFile(path.join(root,'pinentry-calls'),'utf8').catch(()=>'' )).match(/GETPIN/g)||[]).length;
const exists=async file=>fs.access(file).then(()=>true,()=>false);
const get=(fileId,out)=>command(['get',entryId,'--attachment',fileId,'--output',out]);
let failure=null;
try {
  makeEntry();await seed();
  agentChild=spawn(agent,['--no-daemonize'],{env,stdio:['ignore',log.fd,log.fd]});
  agentDone=once(agentChild,'close');
  const deadline=Date.now()+10000;
  while(!await exists(socketPath)) {assert.equal(agentChild.exitCode,null);assert.ok(Date.now()<deadline,'agent socket startup timed out');await new Promise(r=>setTimeout(r,25));}
  assert.equal((await rpc({type:'Version'})).type,'Version');
  assert.equal((await command(['unlock'])).code,0);
  check('actual agent started and unlocked with fictional pinentry');

  for(const [label,options] of [
    ['personal',{}],['personal-item',{item:true}],['organization',{org:true}],
    ['organization-item',{org:true,item:true}],['legacy',{legacy:true}],
    ['empty',{bytes:Buffer.alloc(0)}],['large',{bytes:crypto.randomBytes(1024*1024+7)}]
  ]) {
    const fixture=makeEntry(options);await seed();mode=options.legacy?'legacy':'ok';
    const out=path.join(root,label+'.out');const result=await get(fixture.fileId,out);
    assert.equal(result.code,0,result.stderr);assert.deepEqual(await fs.readFile(out),fixture.bytes);
    assert.equal((await fs.stat(out)).mode&0o777,0o600);check(label+' exact binary download');
  }
  mode='ok';let fixture=makeEntry();await seed();
  let altered=JSON.parse(await fs.readFile(dbPath,'utf8'));
  altered.entries[0].org_id='not-the-actual-organization';
  altered.entries[0].key='not-the-actual-item-key';
  altered.entries[0].attachments[0].key='not-the-actual-attachment-key';
  await fs.writeFile(dbPath,JSON.stringify(altered));
  const freshBinding=path.join(root,'fresh-binding');assert.equal((await get(fixture.fileId,freshBinding)).code,0);
  assert.deepEqual(await fs.readFile(freshBinding),fixture.bytes);check('ID download ignores altered cached ownership and wrapped keys');
  await seed();
  const raw=await command(['get',entryId,'--raw']);assert.equal(raw.code,0,raw.stderr);
  assert.equal(JSON.parse(raw.stdout).attachments[0].file_name,'fixture.bin');
  const byName=path.join(root,'by-name');assert.equal((await get('fixture.bin',byName)).code,0);
  assert.deepEqual(await fs.readFile(byName),fixture.bytes);check('raw metadata and exact filename selection');
  const stdout=await get(fixture.fileId,'-');assert.equal(stdout.code,0,stdout.stderr);assert.deepEqual(stdout.stdout,fixture.bytes);
  check('binary stdout has no text conversion or extra newline');
  const keep=path.join(root,'keep');await fs.writeFile(keep,'unchanged');assert.notEqual((await get(fixture.fileId,keep)).code,0);
  assert.equal(await fs.readFile(keep,'utf8'),'unchanged');check('existing output never overwritten');
  fixture=makeEntry({duplicate:true});await seed();assert.notEqual((await get('fixture.bin',path.join(root,'ambiguous'))).code,0);
  assert.equal(await exists(path.join(root,'ambiguous')),false);assert.equal((await get(fixture.fileId,path.join(root,'by-id'))).code,0);
  check('duplicate filenames require a unique ID');

  for(const badMode of ['corrupt','unsupported','wrong-entry','forbidden-entry','forbidden-url']) {
    fixture=makeEntry();await seed();mode=badMode;const out=path.join(root,badMode);
    const result=await get(fixture.fileId,out);assert.notEqual(result.code,0,badMode);assert.equal(await exists(out),false);
    check(badMode+' rejects without publishing output');
  }
  mode='ok';fixture=makeEntry({reprompt:1});await seed();
  let before=await pinCount();assert.equal((await get(fixture.fileId,path.join(root,'reprompt-ok'))).code,0);
  assert.equal((await pinCount())-before,1);check('fresh protected entry reprompts despite unprotected cache');
  await fs.writeFile(path.join(root,'pinentry-mode'),'cancel');before=await pinCount();
  assert.notEqual((await get(fixture.fileId,path.join(root,'reprompt-cancel'))).code,0);
  assert.equal((await pinCount())-before,1);assert.equal(await exists(path.join(root,'reprompt-cancel')),false);
  check('cancelled reprompt releases no plaintext');
  await fs.writeFile(path.join(root,'pinentry-mode'),'wrong');before=await pinCount();
  assert.notEqual((await get(fixture.fileId,path.join(root,'reprompt-wrong'))).code,0);
  assert.equal((await pinCount())-before,3);assert.equal(await exists(path.join(root,'reprompt-wrong')),false);
  check('three wrong reprompt passwords release no plaintext');
  await fs.writeFile(path.join(root,'pinentry-mode'),'ok');

  fixture=makeEntry();await seed();token='server-new-token';
  let started,release;
  const startedPromise=new Promise(r=>started=r);const wait=new Promise(r=>release=r);
  refreshGate={started,wait};
  const refreshOut=path.join(root,'refreshed');const refreshing=get(fixture.fileId,refreshOut);
  await startedPromise;let latest=JSON.parse(await fs.readFile(dbPath,'utf8'));
  latest.entries.push({...dbEntry(),id:crypto.randomUUID(),name:'sentinel metadata update'});
  await fs.writeFile(dbPath,JSON.stringify(latest));release();
  const refreshed=await refreshing;refreshGate=null;assert.equal(refreshed.code,0,refreshed.stderr);
  latest=JSON.parse(await fs.readFile(dbPath,'utf8'));
  assert.equal(latest.access_token,'refreshed-synthetic-token');assert.equal(latest.entries.length,2);
  assert.deepEqual(await fs.readFile(refreshOut),fixture.bytes);
  check('expired token refresh preserves concurrent cache metadata');

  fixture=makeEntry();await seed();
  let blobStarted,blobRelease;
  const blobStart=new Promise(r=>blobStarted=r);const blobWait=new Promise(r=>blobRelease=r);
  blobGate={started:blobStarted,wait:blobWait};
  const lockOut=path.join(root,'locked-output');const inFlight=get(fixture.fileId,lockOut);
  await blobStart;assert.equal((await rpc({type:'Lock'})).type,'Ack');blobRelease();
  const locked=await inFlight;blobGate=null;assert.notEqual(locked.code,0);
  assert.match(locked.stderr,/locked/);assert.equal(await exists(lockOut),false);
  check('explicit lock during blob transfer wins before plaintext release');
  assert.equal(requests.filter(r=>r.path.startsWith('/blob/')&&r.bearer_present).length,0);
  check('no vault bearer token reaches any blob request');
} catch(error) {failure={message:error.message,stack:error.stack};console.error(error.stack);}
finally {
  if(agentChild) {if(agentChild.exitCode===null && agentChild.signalCode===null)agentChild.kill('SIGTERM');await agentDone.catch(()=>{});}
  await log.close();server.closeAllConnections();await new Promise(r=>server.close(r));
  await fs.writeFile(path.join(evidence,'agent-e2e-results.json'),JSON.stringify({checks,passed:checks.length,failure,synthetic_only:true,
    actual_cli_agent_socket:true,server:'independent loopback Bitwarden protocol fixture, not real Vaultwarden',
    requests,agent_exit:agentChild?.exitCode,agent_signal:agentChild?.signalCode,cleanup:true},null,2));
}
if(failure)process.exitCode=1;
