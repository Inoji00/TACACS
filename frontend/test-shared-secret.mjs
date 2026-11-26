import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {webcrypto} from 'node:crypto';
import {build} from 'esbuild';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
const result=await build({entryPoints:['src/shared-secret-field.tsx'],bundle:true,write:false,platform:'node',format:'cjs',external:['react','react/jsx-runtime']});
const module={exports:{}};
new Function('module','exports','require',result.outputFiles[0].text)(module,module.exports,createRequire(import.meta.url));
const original=globalThis.crypto;
try{
  // All 256 input byte values must map equally to the 64-symbol alphabet.
  let offset=0;Object.defineProperty(globalThis,'crypto',{configurable:true,value:{getRandomValues(bytes){bytes.forEach((_,i)=>bytes[i]=(offset++)&255);return bytes;}}});
  const counts=new Map();for(let i=0;i<16;i++)for(const c of module.exports.generateSharedSecret(16))counts.set(c,(counts.get(c)||0)+1);
  assert.equal(counts.size,64);assert.ok([...counts.values()].every(n=>n===4));
  Object.defineProperty(globalThis,'crypto',{configurable:true,value:webcrypto});
  for(const length of [16,32,48,63,128]){const value=module.exports.generateSharedSecret(length);assert.equal(value.length,length);assert.match(value,/^[A-Za-z0-9_-]+$/);}
  assert.throws(()=>module.exports.generateSharedSecret(13));
  Object.defineProperty(globalThis,'crypto',{configurable:true,value:undefined});
  assert.throws(()=>module.exports.generateSharedSecret()); // No insecure fallback.
}finally{Object.defineProperty(globalThis,'crypto',{configurable:true,value:original});}
const html=renderToStaticMarkup(createElement(module.exports.SharedSecretField,{existing:false,busy:false}));
assert.match(html,/minLength="14"/);assert.match(html,/Generate secret/);assert.match(html,/type="range"[^>]*value="32"/);assert.match(html,/type="password"/);
assert.ok(!html.includes('value="Ab')); // Rendering never generates or embeds a secret.
console.log('Shared secret: unbiased CSPRNG mapping, length boundaries, fail-closed generation and masked UI passed.');
