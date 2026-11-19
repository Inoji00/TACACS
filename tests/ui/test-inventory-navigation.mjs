import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import ts from 'typescript';
import * as React from 'react';
import * as runtime from 'react/jsx-runtime';
import {renderToStaticMarkup} from 'react-dom/server';

const root = path.resolve(import.meta.dirname, '../..');
const bundle = fs.readFileSync(path.join(root, 'src/tacacs_appliance/console/console.js'), 'utf8');
const syntax = ts.createSourceFile('console.js', bundle, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
const functions = new Map();
function visit(node) {
  if (ts.isFunctionDeclaration(node) && node.name) functions.set(node.name.text, node.getText(syntax));
  ts.forEachChild(node, visit);
}
visit(syntax);
const helpers = {URLSearchParams};
vm.createContext(helpers);
for (const name of ['inventoryStatus', 'inventoryDeviceQuery', 'inventoryTileHint']) {
  assert.ok(functions.has(name), `Missing packaged helper: ${name}`);
  vm.runInContext(functions.get(name), helpers);
}
assert.equal(helpers.inventoryStatus('#/users?status=locked', 'users'), 'locked');
assert.equal(helpers.inventoryStatus('#/users?status=enabled', 'users'), 'all');
assert.equal(helpers.inventoryStatus('#/devices?status=enabled', 'devices'), 'enabled');
assert.equal(helpers.inventoryDeviceQuery('#/devices?status=enabled'), '?status=enabled');
assert.equal(helpers.inventoryDeviceQuery('#/devices'), undefined);
assert.equal(helpers.inventoryStatus('#/users', 'users'), 'all');
assert.equal(helpers.inventoryTileHint('locked', 'vi', ''), 'Xem tài khoản bị khóa');
assert.equal(helpers.inventoryTileHint('enabled', 'en', ''), 'View enabled switches');


const resolve = new Function('vu', `return (${functions.get('mr')})`)([{id:'users'}, {id:'devices'}, {id:'overview'}]);
assert.equal(resolve('#/users?status=locked'), 'users');
assert.equal(resolve('#/devices?status=enabled'), 'devices');
assert.equal(resolve('#/invalid?status=locked'), 'overview');

const users = [
  {id:'1', username:'locked-user', locked:true, enabled:true, editable:true, groups:[]},
  {id:'2', username:'active-user', locked:false, enabled:true, editable:true, groups:[]},
];
const hooks = {...React, useState(initial) {
  return React.useState(Array.isArray(initial) && initial.length === 0 ? users : initial);
}};
function renderUsers(hash) {
  const component = new Function('at','R','F','re','ob','window','inventoryStatus',
    `return (${functions.get('Hp')})`)(hooks, runtime, () => ({t:value=>value}), () => null,
    () => React.createElement('td'), {location:{hash}}, helpers.inventoryStatus);
  return renderToStaticMarkup(React.createElement(component, {actions:{list:async()=>({users,next_after:null})}}));
}
const locked = renderUsers('#/users?status=locked');
assert.match(locked, /locked-user/);
assert.match(locked, /active-user/);
assert.match(locked, /<h2>Local users/);
assert.doesNotMatch(locked, /<select|Search users|Command policy \(optional\)/);
const all = renderUsers('#/users');
assert.match(all, /locked-user/);
assert.match(all, /active-user/);
assert.doesNotMatch(bundle, /window\.location\.hash="\/users\?status=locked"/);
console.log('PASS: Users retains locked and enabled accounts from dashboard and legacy links; no filter controls');
