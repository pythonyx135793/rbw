// Real disposable Vaultwarden + official Bitwarden CLI oracle. No real account.
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as crypto from 'node:crypto';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {once} from 'node:events';

const [rbwArg, agentArg, bwArg, base, evidenceArg] = process.argv.slice(2);
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
  const child=spawn(exe,args,{env,stdio:['pipe','pipe','pipe']});const out=[],err=[];
  child.stdout.on('data',b=>out.push(b));child.stderr.on('data',b=>err.push(b));child.stdin.end(input);
  const timer=setTimeout(()=>child.kill('SIGKILL'),45000);
  const [code]=await once(child,'close');clearTimeout(timer);
  const stderr=Buffer.concat(err).toString();assert.equal(code,0,`${path.basename(exe)} ${args[0]}: ${stderr}`);
  return Buffer.concat(out);
}
const bwRun=(...args)=>command(process.execPath,[bw,...args]);
const rbwRun=(...args)=>command(rbw,args);
const pass=name=>{checks.push(name);console.log('PASS '+name);};
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
  const verify=await fetch(base+'/identity/accounts/register/send-verification-email',{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify({email,name:registration.name})});
  assert.equal(verify.status,200,await verify.clone().text());
  registration.emailVerificationToken=await verify.json();
  assert.equal(typeof registration.emailVerificationToken,'string');
  const response=await fetch(base+'/identity/accounts/register/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(registration)});
  assert.equal(response.status,200,await response.text());
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
  if(child){if(child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');await done.catch(()=>{});}
  await log.close();
  await fs.writeFile(path.join(evidence,'vaultwarden-e2e-results.json'),JSON.stringify({checks,passed:checks.length,failure,
    synthetic_only:true,real_server:true,official_cli:'2025.12.1',server_release:'1.37.4',
    entry_id:entryId,attachment_id:attachmentId,agent_exit:child?.exitCode,agent_signal:child?.signalCode,cleanup:true},null,2));
}
if(failure)process.exitCode=1;
