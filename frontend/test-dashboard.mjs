import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import fs from 'node:fs';
import {build} from 'esbuild';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
const bundle=await build({stdin:{contents:"export * from './src/dashboard';export * from './src/i18n';",resolveDir:process.cwd(),loader:'tsx'},bundle:true,write:false,platform:'node',format:'cjs',external:['react','react/jsx-runtime']});
const module={exports:{}};new Function('module','exports','require',bundle.outputFiles[0].text)(module,module.exports,createRequire(import.meta.url));
const {DashboardView,LanguageProvider}=module.exports;
const now=new Date(),hour=new Date(now);hour.setUTCMinutes(0,0,0);
const data={observed_at:now.toISOString(),window:'24-hour-buckets',inventory:{users:12,usable_users:10,locked_users:1,groups:3,devices:6,enabled_devices:5,pending_devices:2},policies:{active:1,approval:2},activity:Array.from({length:15},(_,i)=>[{hour:new Date(hour.getTime()-(14-i)*3600000).toISOString(),action:'aaa.authentication',result:'pass',count:(i*7)%23+2},{hour:new Date(hour.getTime()-(14-i)*3600000).toISOString(),action:'aaa.authentication',result:'fail',count:i%4}]).flat(),failures:[{device:'192.0.2.12',count:8,last_at:now.toISOString()},{device:'192.0.2.25',count:3,last_at:now.toISOString()}],recent:[{timestamp:now.toISOString(),action:'device.update',target:'192.0.2.12',result:'success'},{timestamp:now.toISOString(),action:'identity.create',target:'<script>untrusted</script>',result:'success'}]};
data.totals=[99,7,2,3];data.hourly=[];data.denied_devices=[{label:'192.0.2.12',count:8}];data.latest=[{timestamp:now.toISOString(),device:'192.0.2.12',username:'<script>untrusted</script>',action:'aaa.authentication',result:'fail'}];
const props={data,deployment:{state:'snapshot',observed_at:now.toISOString(),endpoints:[],system:{uptime_seconds:86460,cpu_percent:17,memory_percent:53,disk_percent:62},tcp_probe:true,https_probe:true},error:false,busy:false,onRefresh:()=>{},navigate:()=>{}};
const render=(language,values=props)=>renderToStaticMarkup(createElement(LanguageProvider,{initialLanguage:language},createElement(DashboardView,values)));
const en=render('en'),vi=render('vi'),empty=render('en',{...props,data:null,deployment:null}),stale=render('en',{...props,error:true,deployment:{...props.deployment,state:'stale',observed_at:'2000-01-01T00:00:00Z'}});
const lanes=render('en',{...props,data:{...data,latest:[
  {timestamp:now.toISOString(),device:'192.0.2.50',action:'aaa.authorization',result:'deny'},
  {timestamp:now.toISOString(),device:'192.0.2.51',action:'aaa.authorization',result:'error'},
  {timestamp:now.toISOString(),device:'192.0.2.52',action:'aaa.accounting',result:'committed'},
]}});
const lane=(name)=>lanes.match(new RegExp(`ops-lane-${name}"[^>]*>(.*?)</section>`))?.[1]??'';
assert.match(lane('authorization'),/192\.0\.2\.50/);
assert.doesNotMatch(lane('authorization'),/192\.0\.2\.51/);
assert.match(lane('errors'),/192\.0\.2\.51/);
assert.match(lane('accounting'),/192\.0\.2\.52/);
assert.match(en,/AAA activity/);assert.match(vi,/Hoạt động AAA/);
assert.match(en,/192.0.2.12/);assert.ok(!en.includes('<script>untrusted</script>'));assert.match(en,/&lt;script&gt;/);
assert.match(empty,/Waiting for data/);assert.match(stale,/Data may be stale/);assert.match(stale,/Not currently verified/);
assert.equal((en.match(/class="ops-sparkline"/g)||[]).length,4);assert.match(en,/ops-chart-good/);assert.match(en,/ops-chart-bad/);
assert.ok(!en.includes('RADIUS'));assert.doesNotMatch(en,/17%/);
const failedProps={...props,data:{...data, failure_summary:{total:12,users:4,source_ips:3}, failures:[
  {username:'<script>untrusted</script>',device:'192.0.2.12',count:5,last_at:now.toISOString()},
  {username:'admin1',device:'192.0.2.12',count:1,last_at:now.toISOString()},
]}};
const failedCard=(markup)=>markup.match(/class="card dash-failures dash-auth-card"[^>]*>(.*?)<\/section>/)?.[1]??'';
const card=failedCard(render('en',failedProps));
assert.match(card,/<dt>Failures<\/dt><dd>12<\/dd>/);
assert.match(card,/<dt>Users<\/dt><dd>4<\/dd>/);
assert.match(card,/<dt>Source IPs<\/dt><dd>3<\/dd>/);
assert.match(card,/5 failures.*<progress value="5" max="5"/);
assert.match(card,/1 failure.*<progress value="1" max="5"/);
assert.match(card,/&lt;script&gt;untrusted&lt;\/script&gt;/);
assert.match(failedCard(render('vi',failedProps)),/5 lần lỗi/);
assert.match(failedCard(render('en',{...props,data:{...data, failures:[], failure_summary:{total:0,users:0,source_ips:0}}})),/No failed authentications/);
if(process.argv.includes('--preview')){
  const css=fs.readFileSync('../src/tacacs_appliance/console/console.css','utf8');
  fs.writeFileSync('../artifacts/dashboard-preview.html',`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Dashboard design preview</title><style>${css}body{background:#f4f7fa}main{max-width:1400px;margin:0 auto;padding:24px}.preview-label{font:12px system-ui;color:#687d8d;margin-bottom:22px}</style><main><p class="preview-label">DESIGN PREVIEW · SAMPLE DATA</p>${en}</main></html>`);
}
console.log('Dashboard bilingual, empty/stale state, hourly chart and escaping checks passed.');
