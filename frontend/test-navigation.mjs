import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {build} from 'esbuild';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
const compiled=await build({stdin:{contents:"export * from './src/navigation';export * from './src/workspace';export * from './src/i18n';export * from './src/locales-vi';",resolveDir:process.cwd(),loader:'tsx'},bundle:true,write:false,platform:'node',format:'cjs',external:['react','react/jsx-runtime']});
const module={exports:{}};new Function('module','exports','require',compiled.outputFiles[0].text)(module,module.exports,createRequire(import.meta.url));
const {sections,pages,resolvePage,defaultPage,Workspace,LanguageProvider,vi}=module.exports;
assert.equal(new Set(pages.map(page=>page.id)).size,pages.length);
assert.equal(resolvePage('#/not-a-page'),'overview');
assert.equal(resolvePage('#/aaa-logs'),'authentication-log');
const noop=()=>{};
for(const section of sections)assert.equal(defaultPage(section.id),section.pages[0][0]);
for(const {id,label} of pages){
  assert.equal(resolvePage('#/'+id),id);assert.ok(vi[label],`Missing translation: ${label}`);
  globalThis.window={location:{hash:'#/'+id}};
  const html=renderToStaticMarkup(createElement(LanguageProvider,{initialLanguage:'en'},createElement(Workspace,{children:pages.map(page=>createElement('section',{'data-page':page.id,key:page.id},page.id)),inventory:null,onRefresh:noop,busy:false,mfaRequired:false,policyCount:0,onCreateIdentity:noop,onIdentityState:noop,devices:null,onLoadDevices:noop,onSaveDevice:noop})));
  if(id==='accounting'){
    const group=html.match(/<div id="nav-aaa-logs"[^>]*>(.*?)<\/div>/)?.[1];
    assert.ok(group);
    for(const route of ['authentication-log','authorization-log','accounting'])assert.ok(group.includes('#/'+route));
    assert.match(group,/#\/accounting"[^>]*aria-current="page"/);
  }
  if(id==='overview')assert.doesNotMatch(html,/class="card quick-setup"/);
  assert.ok(html.includes(`<h1 tabindex="-1">${label.replaceAll('&','&amp;')}`));
  assert.ok(html.includes(`<div><section data-page="${id}">`),`Current page hidden: ${id}`);
  for(const other of pages.filter(page=>page.id!==id))assert.ok(html.includes(`<div hidden=""><section data-page="${other.id}">`),`Other page visible: ${other.id}`);
}
delete globalThis.window;
console.log('Independent page routes, bilingual labels, selected page isolation and invalid-link fallback verified.');
