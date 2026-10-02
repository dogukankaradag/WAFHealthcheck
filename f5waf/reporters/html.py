"""Tek dosyalık, filtrelenebilir HTML raporu (harici bağımlılık yok, çevrimdışı açılır)."""
from __future__ import annotations

import html
import json

TEMPLATE = r"""<!doctype html>
<html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WAF Healthcheck __SCAN__</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#1b1f24;--mute:#5d6673;--line:#e3e6ea;--accent:#1f5eff;
--crit:#b3132b;--high:#e0531f;--med:#c98a00;--low:#2f7fd1;--info:#6b7480;--ok:#1f8a4c}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--card:#1a1e24;--ink:#e7eaee;--mute:#9aa3ae;
--line:#2b313a;--accent:#6c95ff;--crit:#ff5a6e;--high:#ff8a4f;--med:#f0b73a;--low:#6aaeff;--info:#9aa3ae;--ok:#4cc68a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.45 "Segoe UI",system-ui,-apple-system,sans-serif}
header{padding:22px 28px;border-bottom:1px solid var(--line);background:var(--card)}
h1{margin:0;font-size:20px;font-weight:650}h2{font-size:15px;margin:28px 0 10px;font-weight:650}
.meta{color:var(--mute);font-size:12.5px;margin-top:4px}main{padding:8px 28px 60px;max-width:1500px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-top:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;cursor:pointer}
.card .n{font-size:26px;font-weight:700;font-variant-numeric:tabular-nums}.card .l{color:var(--mute);font-size:12px}
.card.sel{outline:2px solid var(--accent)}
.sev{display:inline-block;min-width:74px;text-align:center;border-radius:5px;padding:1px 6px;font-size:11px;
font-weight:700;color:#fff;letter-spacing:.3px}
.CRITICAL{background:var(--crit)}.HIGH{background:var(--high)}.MEDIUM{background:var(--med)}
.LOW{background:var(--low)}.INFO{background:var(--info)}
.c-CRITICAL{color:var(--crit)}.c-HIGH{color:var(--high)}.c-MEDIUM{color:var(--med)}.c-LOW{color:var(--low)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--mute);font-weight:600;background:var(--bg);position:sticky;top:0;cursor:pointer;user-select:none}
td.num{text-align:right;font-variant-numeric:tabular-nums}tr.f:hover{background:rgba(127,127,127,.06)}
.obj{font-family:Consolas,ui-monospace,monospace;font-size:12.5px;word-break:break-all}
.rec{color:var(--mute);font-size:12.5px;margin-top:3px}.tag{font-size:10.5px;font-weight:700;padding:1px 5px;border-radius:4px;
border:1px solid var(--accent);color:var(--accent);margin-left:4px}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0}
select,input{background:var(--card);color:var(--ink);border:1px solid var(--line);border-radius:7px;padding:6px 8px;font:inherit}
input{min-width:240px}.bar{height:8px;border-radius:4px;background:var(--line);overflow:hidden;display:flex;min-width:120px}
.bar span{display:block;height:100%}.dev-ok{color:var(--ok);font-weight:600}.dev-bad{color:var(--crit);font-weight:600}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px;margin-top:10px}
summary{cursor:pointer;font-weight:600}.muted{color:var(--mute)}.wrap{overflow-x:auto}
button{background:var(--accent);color:#fff;border:0;border-radius:7px;padding:6px 12px;font:inherit;cursor:pointer}
</style></head><body>
<header><h1>F5 WAF Healthcheck Raporu</h1>
<div class="meta" id="meta"></div></header>
<main>
<div class="cards" id="cards"></div>

<h2>Cihazlar</h2><div class="wrap"><table id="devices"></table></div>

<h2>Partition / Müşteri Risk Sıralaması</h2>
<div class="muted" style="font-size:12px;margin-bottom:6px">Skor = CRITICAL×40 + HIGH×15 + MEDIUM×5 + LOW×1. Satıra tıklayınca bulgular o partition'a filtrelenir.</div>
<div class="wrap"><table id="parts"></table></div>

<h2>Bulgular</h2>
<div class="filters">
<select id="fDev"><option value="">Tüm cihazlar</option></select>
<select id="fPart"><option value="">Tüm partition'lar</option></select>
<select id="fSev"><option value="">Tüm önem dereceleri</option></select>
<select id="fChk"><option value="">Tüm kontroller</option></select>
<select id="fSt"><option value="">Yeni + devam eden</option><option value="NEW">Yalnızca yeni</option><option value="PERSISTENT">Yalnızca devam eden</option></select>
<input id="fQ" placeholder="Nesne / detay ara…">
<button id="csv">Filtrelenmiş CSV</button>
</div>
<div class="muted" id="count" style="font-size:12px;margin-bottom:6px"></div>
<div class="wrap"><table id="finds"></table></div>

<details id="resolvedBox"><summary>Önceki taramadan bu yana kapanan bulgular (<span id="rc"></span>)</summary><div class="wrap" style="margin-top:8px"><table id="resolved"></table></div></details>
<details><summary>İstisna tanımlı (suppressed) bulgular (<span id="sc"></span>)</summary><div class="wrap" style="margin-top:8px"><table id="supp"></table></div></details>
<details><summary>Kontrol kataloğu</summary><div class="wrap" style="margin-top:8px"><table id="cat"></table></div></details>
</main>
<script>
const R = __DATA__;
const SEV=["CRITICAL","HIGH","MEDIUM","LOW","INFO"], W={CRITICAL:40,HIGH:15,MEDIUM:5,LOW:1,INFO:0};
const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const $=id=>document.getElementById(id);
const fmt=t=>t?new Date(t).toLocaleString("tr-TR"):"-";
const S=R.summary, active=R.findings.filter(f=>!f.suppressed), supp=R.findings.filter(f=>f.suppressed);
$("meta").textContent=`Tarama ${R.scan_id} · ${fmt(R.started_at)} → ${fmt(R.finished_at)} · durum: ${R.status} · ${S.devices_ok}/${S.devices_total} cihaz · ${S.partitions.length} partition`;
let sevSel="";
function cards(){
 const items=[["Toplam bulgu",S.total,""],...SEV.map(s=>[s,S.by_severity[s],s]),["Yeni",S.new,"NEW"],["Kapanan",S.resolved,"RES"]];
 $("cards").innerHTML=items.map(([l,n,k])=>`<div class="card ${k&&k===sevSel?"sel":""}" data-k="${k}"><div class="n ${SEV.includes(k)?"c-"+k:""}">${n}</div><div class="l">${l}</div></div>`).join("");
 document.querySelectorAll(".card").forEach(c=>c.onclick=()=>{const k=c.dataset.k;
  if(k==="RES"){$("resolvedBox").open=true;$("resolvedBox").scrollIntoView({behavior:"smooth"});return;}
  if(k==="NEW"){$("fSt").value=$("fSt").value==="NEW"?"":"NEW";}
  else if(SEV.includes(k)){sevSel=sevSel===k?"":k;$("fSev").value=sevSel;} else {sevSel="";$("fSev").value="";$("fSt").value="";}
  cards();render();});
}
$("devices").innerHTML="<tr><th>Cihaz</th><th>Host</th><th>Sürüm</th><th>Durum</th>"+["Partition","VS","Pool","WAF policy","Süre (sn)"].map(h=>`<th style="text-align:right">${h}</th>`).join("")+"</tr>"+
 R.devices.map(d=>`<tr><td><b>${esc(d.name)}</b></td><td class="obj">${esc(d.host)}</td><td>${esc(d.version)}</td>
 <td class="${d.ok?"dev-ok":"dev-bad"}">${d.ok?"Tarandı":"HATA: "+esc(d.error)}</td><td class="num">${d.partitions.length}</td>
 <td class="num">${d.stats.virtuals??"-"}</td><td class="num">${d.stats.pools??"-"}</td><td class="num">${d.stats.policies??"-"}</td><td class="num">${d.duration_sec}</td></tr>`).join("");
function parts(){
 const max=Math.max(1,...S.partitions.map(p=>p.score));
 $("parts").innerHTML="<tr><th>Cihaz</th><th>Partition</th><th>Müşteri</th><th style=\"text-align:right\">Skor</th><th></th>"+SEV.slice(0,4).map(s=>`<th style="text-align:right">${s}</th>`).join("")+"</tr>"+
 S.partitions.map(p=>{const bar=SEV.slice(0,4).map(s=>p[s]?`<span class="${s}" style="width:${p[s]*W[s]/max*100}%"></span>`:"").join("");
 return `<tr class="f" data-d="${esc(p.device)}" data-p="${esc(p.partition)}" style="cursor:pointer"><td>${esc(p.device)}</td><td class="obj">${esc(p.partition)}</td><td>${esc(p.customer)}</td>
 <td class="num"><b>${p.score}</b></td><td><div class="bar">${bar}</div></td>${SEV.slice(0,4).map(s=>`<td class="num ${p[s]?"c-"+s:"muted"}">${p[s]}</td>`).join("")}</tr>`}).join("");
 document.querySelectorAll("#parts tr.f").forEach(tr=>tr.onclick=()=>{$("fDev").value=tr.dataset.d;fillPart();$("fPart").value=tr.dataset.p;render();$("finds").scrollIntoView({behavior:"smooth"});});
}
const uniq=a=>[...new Set(a)].sort();
function opts(sel,vals,lab){sel.innerHTML=sel.options[0].outerHTML+vals.map(v=>`<option value="${esc(v)}">${esc(lab?lab(v):v)}</option>`).join("");}
opts($("fDev"),uniq(active.map(f=>f.device)));
function fillPart(){const d=$("fDev").value;opts($("fPart"),uniq(active.filter(f=>!d||f.device===d).map(f=>f.partition)),p=>{const f=active.find(x=>x.partition===p);return f&&f.customer!==p?`${p} — ${f.customer}`:p});}
fillPart();
opts($("fSev"),SEV);
const titles=Object.fromEntries(R.catalog.map(c=>[c.id,c.title]));
opts($("fChk"),uniq(active.map(f=>f.check_id)),c=>`${c} · ${titles[c]||""}`);
let sortKey=null,sortDir=1;
function filtered(){const d=$("fDev").value,p=$("fPart").value,s=$("fSev").value,c=$("fChk").value,st=$("fSt").value,q=$("fQ").value.toLowerCase();
 let r=active.filter(f=>(!d||f.device===d)&&(!p||f.partition===p)&&(!s||f.severity===s)&&(!c||f.check_id===c)&&(!st||f.status===st)&&
  (!q||(f.object_name+" "+f.detail+" "+f.customer).toLowerCase().includes(q)));
 if(sortKey){r=[...r].sort((a,b)=>{const x=sortKey==="severity"?SEV.indexOf(a.severity)-SEV.indexOf(b.severity):String(a[sortKey]).localeCompare(String(b[sortKey]),"tr");return x*sortDir;});}
 return r;}
const COLS=[["severity","Önem"],["check_id","Kontrol"],["device","Cihaz"],["partition","Partition"],["object_name","Nesne / Detay"],["status","Durum"]];
function row(f,withRec=true){return `<tr class="f"><td><span class="sev ${f.severity}">${f.severity}</span></td>
 <td><b>${esc(f.check_id)}</b><div class="muted" style="font-size:12px">${esc(f.title)}</div></td><td>${esc(f.device)}</td>
 <td class="obj">${esc(f.partition)}${f.customer&&f.customer!==f.partition?`<div class="muted" style="font-family:'Segoe UI',system-ui,sans-serif;font-size:12px">${esc(f.customer)}</div>`:""}</td>
 <td><div class="obj">${esc(f.object_name)}</div><div>${esc(f.detail)}</div>${withRec?`<div class="rec">➜ ${esc(f.recommendation)}</div>`:""}${f.suppress_reason?`<div class="rec">İstisna: ${esc(f.suppress_reason)}</div>`:""}</td>
 <td>${f.status==="RESOLVED"?'<span class="dev-ok">KAPANDI</span>':f.status==="NEW"?'<span class="tag">YENİ</span>':`<span class="muted" style="font-size:12px">ilk: ${fmt(f.first_seen)}</span>`}</td></tr>`;}
function render(){const r=filtered();$("count").textContent=`${r.length} / ${active.length} bulgu gösteriliyor`;
 $("finds").innerHTML="<tr>"+COLS.map(([k,l])=>`<th data-k="${k}">${l}${sortKey===k?(sortDir>0?" ▲":" ▼"):""}</th>`).join("")+"</tr>"+(r.map(f=>row(f)).join("")||'<tr><td colspan="6" class="muted">Filtreye uyan bulgu yok.</td></tr>');
 document.querySelectorAll("#finds th").forEach(th=>th.onclick=()=>{const k=th.dataset.k;sortDir=sortKey===k?-sortDir:1;sortKey=k;render();});}
["fDev","fPart","fSev","fChk","fSt"].forEach(i=>$(i).onchange=()=>{if(i==="fDev")fillPart();if(i==="fSev"){sevSel=$("fSev").value;cards();}render();});
$("fQ").oninput=render;
$("csv").onclick=()=>{const cols=["severity","status","check_id","title","device","partition","customer","object_name","detail","recommendation"];
 const lines=[cols.join(";"),...filtered().map(f=>cols.map(c=>'"'+String(f[c]??"").replace(/"/g,'""')+'"').join(";"))];
 const a=document.createElement("a");a.href=URL.createObjectURL(new Blob(["﻿"+lines.join("\n")],{type:"text/csv"}));a.download=`waf-bulgular-${R.scan_id}.csv`;a.click();};
const H6="<tr><th>Önem</th><th>Kontrol</th><th>Cihaz</th><th>Partition</th><th>Nesne / Detay</th><th>Durum</th></tr>";
$("rc").textContent=R.resolved.length;$("resolved").innerHTML=H6+(R.resolved.map(f=>row({...f,status:"RESOLVED"},false)).join("")||'<tr><td colspan="6" class="muted">Kapanan bulgu yok.</td></tr>');
$("sc").textContent=supp.length;$("supp").innerHTML=H6+(supp.map(f=>row(f,false)).join("")||'<tr><td colspan="6" class="muted">İstisna yok.</td></tr>');
$("cat").innerHTML="<tr><th>ID</th><th>Kontrol</th><th>Kategori</th><th>Açıklama</th><th>Öneri</th></tr>"+R.catalog.map(c=>`<tr><td><b>${c.id}</b></td><td>${esc(c.title)}</td><td>${esc(c.category)}</td><td>${esc(c.description)}</td><td class="muted">${esc(c.recommendation)}</td></tr>`).join("");
cards();parts();render();
</script></body></html>"""


def write_html(report: dict, path: str) -> str:
    data = json.dumps(report, ensure_ascii=False, default=str).replace("</", "<\\/")
    out = TEMPLATE.replace("__DATA__", data).replace("__SCAN__", html.escape(report["scan_id"]))
    with open(path, "w", encoding="utf-8") as f:
        f.write(out)
    return path
