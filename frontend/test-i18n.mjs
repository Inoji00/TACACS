import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import fs from 'node:fs';
import ts from 'typescript';
import {build} from 'esbuild';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
const bundle=await build({stdin:{contents:`export * from './src/i18n';export * from './src/locales-vi';export * from './src/device-manager';export * from './src/identity-manager';export * from './src/rule-editor';export * from './src/case-editor';export * from './src/impact-view';export * from './src/evidence-view';export * from './src/workspace';export * from './src/operations';`,resolveDir:process.cwd(),loader:'tsx'},bundle:true,write:false,platform:'node',format:'cjs',external:['react','react/jsx-runtime']});
const module={exports:{}};new Function('module','exports','require',bundle.outputFiles[0].text)(module,module.exports,createRequire(import.meta.url));
const api=module.exports;
const render=(language,Component,props)=>renderToStaticMarkup(createElement(api.LanguageProvider,{initialLanguage:language},createElement(Component,props)));
const noop=()=>{};
const deviceProps={initialView:'create',busy:false,devices:{devices:[{address:'192.0.2.2',name:'English',enabled:true,shell_group:'operators',privilege:1,access_mappings:[{group:'operators',privilege:1,mode:'policy'}]}],truncated:false,application:'live',transport:'TCP/49'},onLoad:noop,onSave:noop};
const english=render('en',api.DeviceManager,deviceProps),vietnamese=render('vi',api.DeviceManager,deviceProps);
assert.match(english,/Add device/);assert.match(vietnamese,/Thêm thiết bị/);
assert.ok(!vietnamese.includes('Save device configuration'));
assert.match(vietnamese,/Thông tin: Khóa dùng chung/);
assert.ok(!vietnamese.includes('192.0.2.2'));assert.ok(!vietnamese.includes('>English<'));assert.ok(!vietnamese.includes('>operators<'));
assert.match(vietnamese,/name="secret"/);assert.match(vietnamese,/name="access_mappings"/);
assert.match(render('vi',api.IdentityManager,{busy:false,onCreate:noop,onState:noop}),/Tạo người dùng thiết bị/);
const rule={key:1,rule_id:'show',groups:'operators',device_ids:'192.0.2.2',command_prefix:'show version',decision:'deny'};
const rules=render('vi',api.RuleEditor,{rows:[rule],onChange:noop,disabled:false});
assert.match(rules,/Thêm quy tắc/);assert.match(rules,/show version/);assert.match(rules,/value="deny"/);
assert.match(render('vi',api.CaseEditor,{rows:[],onChange:noop,disabled:false}),/Ca kiểm thử chính sách/);
assert.match(render('vi',api.EvidenceView,{version:'candidate',page:null,record:null,busy:false,onRefresh:noop,onOlder:noop,onInspect:noop,onClear:noop}),/Bằng chứng mô phỏng đã lưu/);
const workspace=render('vi',api.Workspace,{children:null,inventory:null,onRefresh:noop,busy:false,mfaRequired:false,policyCount:0,onCreateIdentity:noop,onIdentityState:noop,devices:null,onLoadDevices:noop,onSaveDevice:noop});
assert.match(workspace,/Tài nguyên mạng/);assert.match(workspace,/Quản trị hệ thống/);assert.match(workspace,/Tổng quan/);
assert.ok(!workspace.includes('Bản đánh giá')&&!workspace.includes('Evaluation'));
assert.match(render('vi',api.DeploymentPanel,{load:async()=>({state:'unknown',endpoints:[]})}),/Trạng thái triển khai/);
assert.match(render('vi',api.AccountingPanel,{load:async()=>({items:[],next_before:null,scope:'accounting-only'})}),/Sự kiện accounting/);
assert.equal(api.translate('3 policy tests passed.','vi'),'3 kiểm thử chính sách đã đạt.');
assert.equal(api.translate('invalid credentials','vi'),'Thông tin đăng nhập không đúng');
assert.equal(api.translate('192.0.2.2','vi'),'192.0.2.2');
assert.equal(api.validationMessage({valueMissing:true},'vi'),'Vui lòng điền trường này.');
assert.equal(api.validationMessage({patternMismatch:true},'vi'),'Vui lòng nhập đúng định dạng yêu cầu.');
assert.equal(api.validationMessage({tooShort:true},'en'),'Input is too short.');
let count=0;
for(const file of fs.readdirSync('src').filter(file=>file.endsWith('.tsx')&&file!=='i18n.tsx')){
 const text=fs.readFileSync('src/'+file,'utf8'),tree=ts.createSourceFile(file,text,ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX);
 function visit(node){
  if(ts.isCallExpression(node)&&node.expression.getText(tree)==='t'&&node.arguments[0]&&ts.isStringLiteral(node.arguments[0])){
   const message=node.arguments[0].text;assert.ok(Object.hasOwn(api.vi,message),file+': missing translation '+message);count++;
  }
  if(ts.isJsxText(node)){const value=node.text.replace(/\s+/g,' ').trim();if(/[A-Za-z]/.test(value))assert.ok(['i','TACACS','HTTPS','TCP / 49','TCP/49'].includes(value),file+': unlocalized JSX '+value);}
  ts.forEachChild(node,visit);
 }visit(tree);
}
const python=fs.readFileSync('../src/tacacs_appliance/admin_api.py','utf8');
for(const match of python.matchAll(/["']error["']\s*:\s*["']([^"']+)["']/g))assert.ok(Object.hasOwn(api.vi,match[1]),'Untranslated API error: '+match[1]);
console.log(`Bilingual rendering, unchanged payload/data, API errors and ${count} static message uses verified.`);
