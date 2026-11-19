import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import * as React from 'react';
import {jsx, jsxs} from 'react/jsx-runtime';
import {renderToStaticMarkup} from 'react-dom/server';

const root = path.resolve(import.meta.dirname, '../..');
const source = fs.readFileSync(path.join(root, 'src/tacacs_appliance/console/console.js'), 'utf8');
const config = {enabled:false, name:'<script>sample</script>', events:['services','resources'],
  cpu_percent:90, memory_percent:90, disk_percent:85, resource_seconds:300,
  failure_threshold:10, repeat_seconds:1800, webhook_configured:true, pending:0};
const hooks = {...React, useState(initial) {return React.useState(initial === null ? config : initial);}};
const syntax = ts.createSourceFile('console.js', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
let dictionary, panelSource;
const translations = [];
function visit(node) {
  if (ts.isFunctionDeclaration(node) && node.name?.text === 'SlackAlertsPanel') panelSource = node.getText(syntax);
  if (ts.isObjectLiteralExpression(node) && node.properties.some(item => item.name?.getText(syntax) === '"Slack alerts"')) {
    dictionary = new Function(`return (${node.getText(syntax)})`)();
  }
  ts.forEachChild(node, visit);
}
visit(syntax);
assert.ok(dictionary);
assert.ok(panelSource, 'Packaged Slack panel exists');
const Panel = new Function(`return (${panelSource})`)();
const panelSyntax = ts.createSourceFile('panel.js', panelSource, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
function collectTranslations(node) {
  if (ts.isCallExpression(node) && node.expression.getText(panelSyntax) === 't' &&
      node.arguments[0] && ts.isStringLiteral(node.arguments[0])) translations.push(node.arguments[0].text);
  ts.forEachChild(node, collectTranslations);
}
collectTranslations(panelSyntax);
for (const label of translations) {
  assert.ok(dictionary[label] || ['Refresh','Loading…','None'].includes(label), `Missing translation: ${label}`);
}
const en = renderToStaticMarkup(React.createElement(Panel, {hooks,jsx,jsxs,t:value=>value}));
const vi = renderToStaticMarkup(React.createElement(Panel, {hooks,jsx,jsxs,t:value=>dictionary[value]??value}));
assert.match(en, /Slack alerts/);
assert.match(vi, /Cảnh báo Slack/);
assert.match(en, /type="password"/);
assert.match(en, /&lt;script&gt;sample&lt;\/script&gt;/);
assert.doesNotMatch(en, /value="https:\/\/hooks/);
assert.match(en, /Send test alert/);
assert.match(en, /Successful device authentication/);
assert.match(en, /Recorded device commands/);
assert.match(en, /Audited Web actions/);
assert.match(vi, /Lệnh thiết bị được ghi nhận/);
assert.match(en, /No recent monitor check/);
assert.match(vi, /Bật giám sát qua Slack/);
assert.match(source, /\["alerts","Alerts"\]/);
assert.match(source, /P==="alerts"&&\(0,X.jsx\)\(SlackAlertsPanel/);
console.log('PASS: actual bundled Slack panel renders English and Vietnamese, hides webhook, escapes input and exposes delivery status');
