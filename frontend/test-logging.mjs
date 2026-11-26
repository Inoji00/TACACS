import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {build} from 'esbuild';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
const compiled=await build({stdin:{contents:"export * from './src/audit-time';export * from './src/audit-date-time';export * from './src/logging';export * from './src/operations';export * from './src/i18n';",resolveDir:process.cwd(),loader:'tsx'},bundle:true,write:false,platform:'node',format:'cjs',external:['react','react/jsx-runtime']});
const module={exports:{}};new Function('module','exports','require',compiled.outputFiles[0].text)(module,module.exports,createRequire(import.meta.url));
const {LogTable,Logging,csvCell,logCsv,LanguageProvider}=module.exports;
const render=(component,props,language)=>renderToStaticMarkup(createElement(LanguageProvider,{initialLanguage:language},createElement(component,props)));
const event={event_id:'event-id',sequence:1,timestamp:'2026-11-05T00:00:00Z',actor:'device',actor_name:null,attempted_username:'unknown-user<script>',source:'tacacs',action:'aaa.authentication',target:'<script>bad</script>',result:'fail',session:'42',policy_version:null};
for(const language of ['en','vi']){
  const html=render(LogTable,{items:[event]},language);assert.ok(!html.includes('<script>bad'));assert.match(html,/&lt;script&gt;bad&lt;\/script&gt;/);assert.match(html,/log-result bad/);assert.match(html,/ops-failed/);assert.ok(html.includes('unknown-user&lt;script&gt;'));
  assert.equal((html.match(/<th\b/g)||[]).length,7);
  assert.equal((html.match(/<td\b/g)||[]).length,7);
  assert.doesNotMatch(html,/<(?:details|dialog|button)\b/);
  const form=render(Logging,{kind:'aaa',load:async()=>({items:[]}),report:false},language);assert.equal((form.match(/type="date"/g)||[]).length,2);assert.match(form,/HH:mm/);assert.match(form,/role="combobox"/);assert.equal((form.match(/role="option"/g)||[]).length,21);assert.match(form,/maxLength="256"/i);assert.ok(!form.includes('Delete'));assert.doesNotMatch(form,/More filters|Actor ID/);
}
const overPage = render(LogTable,{items:Array.from({length:101},(_,index)=>({...event,event_id:String(index)}))},'en');
assert.equal((overPage.match(/<tr/g)||[]).length,101);
assert.match(overPage,/aria-current="page"/);
assert.match(overPage,/>2<\/button>/);
const element=(type,props)=>({type,...props});
const dateValues=[];
const controls=(value,endOfDay=false)=>module.exports.auditDateTimeControls({jsx:element,jsxs:element,label:'Date',t:value=>value,value,endOfDay,onChange:value=>dateValues.push(value)});
controls('',true).children[0].children[1].onChange({target:{value:'2026-11-11'}});
controls('2026-11-11T00:05').children[1].children[2].onChange({target:{value:'PM'}});
controls('2026-11-11T12:05').children[1].children[2].onChange({target:{value:'AM'}});
assert.deepEqual(dateValues,['2026-11-11T23:59','2026-11-11T12:05','2026-11-11T00:05']);
for(const value of ['=SUM(A1:A2)','+cmd','-1','@something',' \t=1'])assert.ok(csvCell(value).startsWith('"\''));
assert.equal(csvCell('a"b'),'"a""b"');assert.match(logCsv([event]),/TACACS session/);assert.ok(!logCsv([event]).includes('security_context'));
const webEvent={...event,source:'admin-web',action:'web.login',target:'192.0.2.5',source_ip:'192.0.2.10',destination_ip:'192.0.2.5'};
for (const language of ['en','vi']) {
  const html=render(LogTable,{items:[webEvent]},language);
  assert.match(html,/<td><code>192\.0\.2\.5<\/code><\/td><td><code>192\.0\.2\.10<\/code><\/td>/);
}
assert.match(logCsv([webEvent]),/"Source IP","Destination IP","Remote address"/);
assert.match(logCsv([webEvent]),/"192.0.2.10","192.0.2.5","192.0.2.10"/);
const sshEvent={...event,target:'192.0.2.2',target_name:'Switch-01',remote_address:'2001:db8::27'};
for (const [language,header] of [['en','Remote address'],['vi','IP truy cập']]) {
  const html=render(LogTable,{items:[sshEvent]},language);
  assert.ok(html.includes(header));
  assert.match(html,/<td><code>Switch-01<\/code><small><code>192\.0\.2\.2<\/code><\/small><\/td><td><code>2001:db8::27<\/code><\/td>/);
}
assert.match(logCsv([sshEvent]),/,"2001:db8::27"$/);
console.log('Logging bilingual filters, event escaping, readonly rows and spreadsheet-safe CSV verified.');

const account={id:'a',timestamp:'now',session:'123',username:'operator',device:'192.0.2.2',action:'stop',kind:'command',command:'show <script>bad</script>',redacted:false,task_id:'42',privilege:15};
for(const language of ['en','vi']){
 const html=render(module.exports.AccountingTable,{items:[account,{...account,id:'b',redacted:true,command:'NEVER-RENDER'}]},language);
 assert.ok(html.includes('&lt;script&gt;bad&lt;/script&gt;'));assert.ok(!html.includes('<script>'));assert.ok(!html.includes('NEVER-RENDER'));assert.ok(html.includes('42'));
 assert.doesNotMatch(html,/<(?:details|dialog|button)\b/);
 const form=render(module.exports.AccountingPanel,{load:async()=>({items:[],next_before:null,scope:'accounting-only'})},language);assert.match(form,/class="log-refresh-select"/);assert.equal((form.match(/<input/g)||[]).length,4);
}
assert.ok(!module.exports.accountingCsv([{...account,redacted:true,command:'NEVER-EXPORT'}]).includes('NEVER-EXPORT'));
assert.match(module.exports.accountingCsv([{...account,command:'=FORMULA'}]),/"'=FORMULA"/);
console.log('Accounting commands: bilingual redacted table, XSS escaping, live toggle and safe CSV passed.');

const oldTimezone=process.env.TZ;
try{
 for(const zone of ['UTC','America/Los_Angeles','Asia/Ho_Chi_Minh']){
  process.env.TZ=zone;
  assert.equal(module.exports.vietnamTime('2026-11-05T09:03:44Z'),'05/11/2026 16:03:44');
  assert.equal(module.exports.vietnamIso('2026-11-05T20:30:00Z'),'2026-11-06T03:30:00.000+07:00');
  assert.equal(module.exports.vietnamInputToIso('2026-11-05T16:03'),'2026-11-05T16:03:00.000+07:00');
 }
 assert.throws(()=>module.exports.vietnamInputToIso('2026-02-30T12:00'));
 assert.equal(module.exports.vietnamTime('invalid'),'—');
 assert.match(module.exports.accountingCsv([{...account,timestamp:'2026-11-05T09:03:44.123456+00:00'}]),/2026-11-05T16:03:44.123\+07:00/);
 assert.match(module.exports.accountingCsv([{...account,timestamp:'2026-11-05T09:03:44.123456+00:00'}]),/2026-11-05T09:03:44.123456\+00:00/);
}finally{if(oldTimezone===undefined)delete process.env.TZ;else process.env.TZ=oldTimezone;}
console.log('Vietnam audit time, midnight rollover, browser-zone-independent filters and original CSV precision passed.');
