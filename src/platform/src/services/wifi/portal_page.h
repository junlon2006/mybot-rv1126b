/* SPDX-License-Identifier: Apache-2.0 */
#ifndef RV1126B_PORTAL_PAGE_H
#define RV1126B_PORTAL_PAGE_H

namespace rv1126b_wifi {
/* Self-contained for captive browsers without an upstream Internet connection. */
static const char kPortalPage[] = R"HTML(<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MyBot Wi-Fi</title><style nonce="@TOKEN@">
:root{color-scheme:light;font:16px system-ui,sans-serif;color:#182434;background:#f2f5f9}*{box-sizing:border-box}
body{margin:0;padding:24px 16px}main{max-width:440px;margin:auto;background:white;border-radius:20px;padding:24px;box-shadow:0 8px 32px #18243412}
header{display:flex;justify-content:space-between;align-items:center}h1{font-size:26px;margin:10px 0}h2{font-size:17px;margin-top:28px}p{line-height:1.6;color:#526174}
label{display:block;margin:18px 0 6px}input,button,select{font:inherit;min-height:46px;border-radius:10px}input,select{width:100%;padding:10px;border:1px solid #c7d1de;background:white;color:inherit}
button{padding:9px 15px;border:0;background:#2563eb;color:white;cursor:pointer}button:disabled{opacity:.55;cursor:wait}.wide{width:100%;margin-top:22px}.quiet{background:#edf2f8;color:#34506c}
.row{display:flex;gap:8px;align-items:center;margin:8px 0}.row span{flex:1;overflow-wrap:anywhere}.row button{font-size:13px;min-height:38px;padding:7px 10px}#message{min-height:26px;overflow-wrap:anywhere}#message.error{color:#b42318}#success{display:none;text-align:center;padding:28px 0}#success b{display:block;font-size:44px;color:#169b62}small{color:#607087}#lang{font-size:13px;min-height:34px;padding:6px 10px}a{color:#2563eb}
</style></head><body><main><header><strong>MyBot</strong><button id="lang" class="quiet" type="button">English</button></header>
<section id="setup"><h1 data-text="title"></h1><p data-text="intro"></p>
<form id="form"><label for="networks" data-text="nearby"></label><div class="row"><select id="networks"><option value="" data-text="manual"></option></select><button id="scan" class="quiet" type="button" data-text="refresh"></button></div>
<label for="ssid" data-text="ssid"></label><input id="ssid" name="ssid" maxlength="32" autocomplete="off" required>
<label for="password" data-text="password"></label><input id="password" name="password" type="password" maxlength="64" autocomplete="new-password"><small data-text="open"></small>
<button id="connect" class="wide" type="submit" data-text="connect"></button></form><p id="message" role="status" aria-live="polite"></p>
<h2 data-text="saved"></h2><div id="saved"></div><p><small data-text="band"></small></p></section>
<section id="success"><b>✓</b><h1 data-text="success"></h1><p data-text="done"></p><button id="exit" class="wide" type="button" data-text="exit"></button></section>
</main><script nonce="@TOKEN@">
'use strict';
const token='@TOKEN@', $=id=>document.getElementById(id), texts={
'zh-CN':{title:'连接 Wi-Fi',intro:'选择网络并输入密码，让 MyBot 连接互联网。',nearby:'附近的网络',manual:'手动输入 / 隐藏网络',refresh:'刷新',ssid:'网络名称',password:'密码',open:'开放网络请留空。',connect:'连接',saved:'已保存的网络',band:'支持 2.4 GHz Wi-Fi。',scanning:'正在搜索网络…',failed:'连接失败，请检查密码后重试。',connecting:'正在连接，请稍候…',reconnect:'请保持手机连接 MyBot 热点，稍后重试。',success:'连接成功',done:'MyBot 已连接网络，即将关闭配网。',exit:'完成',default:'设为默认',remove:'删除',empty:'暂无已保存的网络',request:'操作失败，请重试。'},
'en-US':{title:'Connect to Wi-Fi',intro:'Choose a network and enter its password to connect MyBot.',nearby:'Nearby networks',manual:'Manual / hidden network',refresh:'Refresh',ssid:'Network name',password:'Password',open:'Leave empty for an open network.',connect:'Connect',saved:'Saved networks',band:'2.4 GHz Wi-Fi supported.',scanning:'Searching for networks…',failed:'Connection failed. Check the password and try again.',connecting:'Connecting, please wait…',reconnect:'Keep your phone connected to the MyBot hotspot and try again.',success:'Connected',done:'MyBot is online. Wi-Fi setup will close shortly.',exit:'Done',default:'Make default',remove:'Delete',empty:'No saved networks',request:'The request failed. Please try again.'}};
let lang=(navigator.language||'').startsWith('zh')?'zh-CN':'en-US',busy=false,finished=false,pollTimer,exitTimer,aps=[],saved=[];
function message(key,error=false){$('message').textContent=texts[lang][key];$('message').className=error?'error':''}
function render(){document.documentElement.lang=lang;document.querySelectorAll('[data-text]').forEach(e=>e.textContent=texts[lang][e.dataset.text]);$('lang').textContent=lang==='zh-CN'?'English':'中文';renderNetworks();renderSaved()}
function renderNetworks(){const select=$('networks'),current=select.value;select.replaceChildren();const manual=document.createElement('option');manual.value='';manual.textContent=texts[lang].manual;select.append(manual);aps.forEach(ap=>{const option=document.createElement('option');option.value=ap.ssid;option.textContent=ap.ssid+'  '+ap.rssi+' dBm'+(ap.authmode?' 🔒':'');select.append(option)});select.value=current}
function renderSaved(){const box=$('saved');box.replaceChildren();if(!saved.length){const e=document.createElement('small');e.textContent=texts[lang].empty;box.append(e)}saved.forEach((ssid,index)=>{const row=document.createElement('div');row.className='row';const name=document.createElement('span');name.textContent=(index===0?'★ ':'')+ssid;row.append(name);['set_default','delete'].forEach(action=>{const button=document.createElement('button');button.type='button';button.className='quiet';button.textContent=texts[lang][action==='delete'?'remove':'default'];button.disabled=busy;button.onclick=()=>mutateSaved(action,index,ssid);row.append(button)});box.append(row)})}
async function api(path,body,timeout=5000){const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),timeout);try{const options={cache:'no-store',signal:controller.signal};if(body!==undefined){options.method='POST';options.headers={'Content-Type':'application/json','X-CSRF-Token':token};options.body=JSON.stringify(body)}const response=await fetch(path,options);const data=await response.json();if(!response.ok)throw new Error('request');return data}finally{clearTimeout(timer)}}
async function scan(){if(busy)return;$('scan').disabled=true;message('scanning');try{const data=await api('/scan');aps=data.aps;renderNetworks();$('message').textContent=''}catch(e){message('request',true)}finally{$('scan').disabled=busy}}
async function loadSaved(){saved=await api('/saved/list');renderSaved()}
async function waitSaved(){const deadline=Date.now()+15000;while(Date.now()<deadline){const status=await api('/status',undefined,Math.min(5000,deadline-Date.now()));if(status.state==='error')throw new Error('request');if(status.busy===false)return;await new Promise(resolve=>setTimeout(resolve,Math.min(250,Math.max(0,deadline-Date.now()))))}throw new Error('timeout')}
async function mutateSaved(action,index,ssid){if(busy||finished)return;setBusy(true);$('message').textContent='';try{await api('/saved/'+action,{index,ssid});await waitSaved();await loadSaved()}catch(e){message('request',true)}finally{setBusy(false)}}
function setBusy(value){busy=value;['ssid','password','networks','scan','connect'].forEach(id=>$(id).disabled=value);renderSaved()}
async function leave(){clearTimeout(exitTimer);try{await api('/exit',{})}catch(e){/* The AP may already be closing. */}}
async function poll(){try{const data=await api('/status');if(data.state==='connected'){finished=true;setBusy(false);$('password').value='';$('setup').style.display='none';$('success').style.display='block';exitTimer=setTimeout(leave,1000);return}if(data.state==='error'){setBusy(false);message('failed',true);return}message('connecting')}catch(e){message('reconnect',true)}if(busy)pollTimer=setTimeout(poll,1000)}
$('form').onsubmit=async event=>{event.preventDefault();if(busy||finished)return;setBusy(true);message('connecting');try{await api('/submit',{ssid:$('ssid').value,password:$('password').value});$('password').value='';clearTimeout(pollTimer);poll()}catch(e){setBusy(false);message('request',true)}};
$('networks').onchange=()=>{if($('networks').value)$('ssid').value=$('networks').value};$('scan').onclick=scan;$('exit').onclick=leave;$('lang').onclick=()=>{lang=lang==='zh-CN'?'en-US':'zh-CN';render()};render();scan();loadSaved().catch(()=>message('request',true));
</script></body></html>)HTML";
} // namespace rv1126b_wifi
#endif
