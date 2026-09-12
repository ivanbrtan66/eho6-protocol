#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Upravljacka ploca dnkd-a — jedna HTML stranica, bez vanjskih zavisnosti.

Pravilo koje ova ploca postuje bez iznimke: korisnik u svakoj milisekundi zna
status svog zahtjeva. Svaki gumb se prije slanja onemoguci i mijenja tekst;
svaka greska (400/403/404/500, mrezni pad, timeout, neispravan JSON) ispisuje
se kao citljiva PREVEDENA poruka na ekranu; svaki uspjeh ima vidljivu potvrdu;
pad veze s demonom pokazuje trajnu crvenu vrpcu umjesto tihog zamrzavanja
brojki. Slijepa ulica ne postoji — i kad sve padne, na ekranu stoji sto je
palo i sto korisnik moze uciniti.

Bez CDN-a i bez fontova s interneta: ploca mora raditi na rubnom uredjaju bez
izlaza na internet, jer se upravo tada i gleda.
"""
from __future__ import annotations

_PLOCA = r"""<!doctype html>
<html lang="hr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dnkd — MASKA razrjesitelj</title>
<style>
  :root{
    --poz:#f7f7f5; --pov:#ffffff; --tekst:#16181d; --prigus:#5c6370; --rub:#dcdbd4;
    --ok:#1f7a44; --ok-poz:#e6f4ea; --alarm:#a3251c; --alarm-poz:#fbeae8;
    --nepoznato:#8a6410; --nepoznato-poz:#fbf3e0; --akcent:#0f5f8a; --sjena:0 1px 2px rgba(0,0,0,.06);
    color-scheme:light dark;
  }
  :root:not([data-tema="svijetlo"]) { }
  @media (prefers-color-scheme: dark){
    :root:not([data-tema="svijetlo"]){
      --poz:#0f1115; --pov:#171a21; --tekst:#e8e9ec; --prigus:#9aa1ad; --rub:#2a2f39;
      --ok:#5ed08b; --ok-poz:#12241a; --alarm:#ff8b7e; --alarm-poz:#2a1512;
      --nepoznato:#f0c469; --nepoznato-poz:#2a2110; --akcent:#6fc3f0; --sjena:none;
    }
  }
  :root[data-tema="tamno"]{
    --poz:#0f1115; --pov:#171a21; --tekst:#e8e9ec; --prigus:#9aa1ad; --rub:#2a2f39;
    --ok:#5ed08b; --ok-poz:#12241a; --alarm:#ff8b7e; --alarm-poz:#2a1512;
    --nepoznato:#f0c469; --nepoznato-poz:#2a2110; --akcent:#6fc3f0; --sjena:none;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--poz);color:var(--tekst);
       font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  .omot{max-width:1040px;margin:0 auto;padding:20px 16px 56px}
  header{display:flex;flex-wrap:wrap;gap:12px;align-items:baseline;justify-content:space-between;
         border-bottom:1px solid var(--rub);padding-bottom:14px;margin-bottom:18px}
  h1{font-size:17px;margin:0;letter-spacing:.06em;text-transform:uppercase}
  h1 span{color:var(--prigus);text-transform:none;letter-spacing:0;font-weight:400}
  h2{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--prigus);
     margin:26px 0 10px}
  .vrpca{display:none;margin:0 0 16px;padding:11px 13px;border-radius:8px;
         background:var(--alarm-poz);color:var(--alarm);border:1px solid currentColor}
  .vrpca[data-vidljivo="1"]{display:block}
  .traka{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:8px}
  button{font:inherit;cursor:pointer;padding:8px 13px;border-radius:7px;
         border:1px solid var(--rub);background:var(--pov);color:var(--tekst);
         box-shadow:var(--sjena);transition:opacity .15s}
  button:hover:not(:disabled){border-color:var(--akcent);color:var(--akcent)}
  button:disabled{opacity:.55;cursor:progress}
  button.glavni{background:var(--akcent);border-color:var(--akcent);color:#fff}
  button.glavni:hover:not(:disabled){color:#fff;filter:brightness(1.08)}
  .kartice{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px}
  .kartica{background:var(--pov);border:1px solid var(--rub);border-radius:10px;padding:12px 14px;
           box-shadow:var(--sjena)}
  .kartica .oznaka{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--prigus)}
  .kartica .vrijednost{font-size:19px;margin-top:5px;word-break:break-word}
  .pilula{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;
          letter-spacing:.08em;border:1px solid currentColor}
  .ok{color:var(--ok);background:var(--ok-poz)}
  .alarm{color:var(--alarm);background:var(--alarm-poz)}
  .nepoznato{color:var(--nepoznato);background:var(--nepoznato-poz)}
  .tablica-omot{overflow-x:auto;border:1px solid var(--rub);border-radius:10px;background:var(--pov)}
  table{border-collapse:collapse;width:100%;min-width:560px}
  th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--rub);vertical-align:top}
  th{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--prigus);font-weight:400}
  tr:last-child td{border-bottom:none}
  td.razlog{color:var(--prigus);max-width:340px;word-break:break-word}
  code{background:var(--poz);border:1px solid var(--rub);border-radius:5px;padding:1px 5px}
  .prigus{color:var(--prigus)}
  .toasti{position:fixed;right:14px;bottom:14px;display:flex;flex-direction:column;gap:8px;
          max-width:min(420px,calc(100vw - 28px));z-index:50}
  .toast{background:var(--pov);border:1px solid var(--rub);border-left:4px solid var(--akcent);
         border-radius:8px;padding:11px 13px;box-shadow:0 6px 18px rgba(0,0,0,.18);
         animation:ulaz .18s ease-out}
  .toast.uspjeh{border-left-color:var(--ok)} .toast.greska{border-left-color:var(--alarm)}
  .toast.rad{border-left-color:var(--nepoznato)}
  .toast b{display:block;margin-bottom:2px}
  @keyframes ulaz{from{transform:translateY(8px);opacity:0}to{transform:none;opacity:1}}
  .napomena{margin-top:22px;padding:12px 14px;border:1px dashed var(--rub);border-radius:10px;
            color:var(--prigus);background:var(--pov)}
  footer{margin-top:26px;color:var(--prigus);font-size:12px}
  @media (max-width:460px){ h1{font-size:15px} .kartica .vrijednost{font-size:17px} }
</style>
</head>
<body>
<div class="omot">
  <header>
    <h1>dnkd <span>— MASKA F2, lokalni razrjesitelj .dnk</span></h1>
    <div class="traka" style="margin:0">
      <span id="osvjezeno" class="prigus">ucitavanje…</span>
      <button id="tema" title="Prebaci temu">tema</button>
    </div>
  </header>

  <div id="vrpca" class="vrpca" role="alert"></div>

  <section>
    <div class="kartice">
      <div class="kartica"><div class="oznaka">Ukupno stanje</div>
        <div class="vrijednost"><span id="k-stanje" class="pilula nepoznato">—</span></div></div>
      <div class="kartica"><div class="oznaka">Imena</div>
        <div class="vrijednost" id="k-imena">—</div></div>
      <div class="kartica"><div class="oznaka">DNS upiti</div>
        <div class="vrijednost" id="k-upiti">—</div></div>
      <div class="kartica"><div class="oznaka">Godovi (mjerenja)</div>
        <div class="vrijednost" id="k-godovi">—</div></div>
      <div class="kartica"><div class="oznaka">Lanac godova</div>
        <div class="vrijednost"><span id="k-lanac" class="pilula nepoznato">—</span></div></div>
      <div class="kartica"><div class="oznaka">Radi</div>
        <div class="vrijednost" id="k-uptime">—</div></div>
    </div>
  </section>

  <h2>Akcije</h2>
  <div class="traka">
    <button id="b-osvjezi" class="glavni">Osvjezi PELUD (svi)</button>
    <button id="b-lanac">Provjeri lanac godova</button>
    <button id="b-stanje">Ponovno procitaj stanje</button>
    <label class="prigus" style="margin-left:4px">
      <input type="checkbox" id="auto" checked> automatski svakih <span id="odbrojavanje">10</span> s
    </label>
  </div>

  <h2>Imena</h2>
  <div class="tablica-omot">
    <table>
      <thead><tr><th>Ime</th><th>Stanje</th><th>Adresa</th><th>Visina</th><th>Rok</th>
                 <th>Suglasnost</th><th>Razlog / lokatori</th><th></th></tr></thead>
      <tbody id="t-imena"><tr><td colspan="8" class="prigus">ucitavanje…</td></tr></tbody>
    </table>
  </div>

  <h2>Vatre</h2>
  <div id="vatre" class="prigus">—</div>

  <h2>Zadnja mjerenja (godovi)</h2>
  <div class="tablica-omot">
    <table>
      <thead><tr><th>#</th><th>Vrijeme</th><th>Ime</th><th>Ishod</th><th>ms</th><th>Razlog</th></tr></thead>
      <tbody id="t-godovi"><tr><td colspan="6" class="prigus">ucitavanje…</td></tr></tbody>
    </table>
  </div>

  <div class="napomena">
    <b>Certifikati:</b> nijedan javni CA ne izdaje certifikat za <code>.dnk</code>. dnkd NE dira
    sistemski trust store i ne instalira vlastiti CA — takav CA bio bi kljuc za sve stranice na
    ovom uredjaju, dakle stvarna steta za tebe, a ne zastita. TLS za <code>.dnk</code> terminira
    aplikacija na loopbacku. Detalji: <code>docs/MASKA-FAZE.md</code>.
  </div>

  <footer>
    dnkd na <code id="adresa-ploce"></code> · PELUD potpis: Ed25519 (ML-DSA-65 nije implementiran u
    ovom stacku i zapis s njim se odbija) · sva mjerenja idu u godovi dnevnik, i uspjesna i pala.
  </footer>
</div>

<div class="toasti" id="toasti" aria-live="polite"></div>

<script>
"use strict";
const PORT = "__PORT__";
const BAZA = "";
const VRIJEME_CEKANJA_MS = 12000;
let automatski = true, odbrojavanje = 10, ciklus = null, zadnjiUspjeh = null;

/* ---------- povratne informacije ---------------------------------------- */
function toast(vrsta, naslov, tekst, trajanje) {
  const el = document.createElement("div");
  el.className = "toast " + vrsta;
  const b = document.createElement("b"); b.textContent = naslov; el.appendChild(b);
  if (tekst) { const s = document.createElement("span"); s.textContent = tekst; el.appendChild(s); }
  document.getElementById("toasti").appendChild(el);
  const ms = trajanje === undefined ? (vrsta === "greska" ? 12000 : 5000) : trajanje;
  if (ms > 0) setTimeout(() => el.remove(), ms);
  return el;
}
function vrpca(tekst) {
  const v = document.getElementById("vrpca");
  if (tekst) { v.textContent = tekst; v.dataset.vidljivo = "1"; }
  else { v.dataset.vidljivo = "0"; v.textContent = ""; }
}
function zauzmi(gumb, tekstTijekom) {
  const izvorni = gumb.dataset.izvorni || gumb.textContent;
  gumb.dataset.izvorni = izvorni;
  gumb.disabled = true;
  gumb.textContent = tekstTijekom;
  return () => { gumb.disabled = false; gumb.textContent = izvorni; };
}
/* Prevedena poruka za SVAKI moguci ishod — nikad samo console.log. */
function porukaGreske(status, tijelo) {
  const detalj = (tijelo && (tijelo.greska || tijelo.razlog)) ? String(tijelo.greska || tijelo.razlog) : "";
  const tablica = {
    400: "Zahtjev je neispravan (400). Demon je odbio tijelo zahtjeva.",
    403: "Zahtjev odbijen (403). Ploca se mora otvoriti kao http://127.0.0.1:" + PORT + "/ — otvaranje s druge adrese dnkd namjerno odbija.",
    404: "Ruta ne postoji (404). Vjerojatno je pokrenuta starija verzija dnkd-a.",
    500: "Demon je javio internu gresku (500). Pogledaj njegov ispis: journalctl -u dnkd -n 50.",
    502: "Sidro nije odgovorilo (502).",
    503: "Demon je privremeno nedostupan (503)."
  };
  return (tablica[status] || ("Neocekivan odgovor demona (HTTP " + status + ").")) +
         (detalj ? " Detalj: " + detalj : "");
}
async function zovi(put, opcije) {
  const kontrola = new AbortController();
  const sat = setTimeout(() => kontrola.abort("timeout"), VRIJEME_CEKANJA_MS);
  try {
    const odg = await fetch(BAZA + put, Object.assign({
      signal: kontrola.signal, cache: "no-store",
      headers: { "Content-Type": "application/json" }
    }, opcije || {}));
    const sirovo = await odg.text();
    let tijelo = null;
    if (sirovo) { try { tijelo = JSON.parse(sirovo); } catch (e) { tijelo = null; } }
    if (!odg.ok) { const g = new Error(porukaGreske(odg.status, tijelo)); g.status = odg.status; throw g; }
    if (tijelo === null) throw new Error("Demon je vratio odgovor koji nije JSON — vjerojatno nije dnkd na tom portu.");
    return tijelo;
  } catch (e) {
    if (e.name === "AbortError") {
      throw new Error("Demon nije odgovorio u " + (VRIJEME_CEKANJA_MS / 1000) + " s. Radi li dnkd? (systemctl --user status dnkd)");
    }
    if (e instanceof TypeError) {
      throw new Error("Nema veze s demonom na 127.0.0.1:" + PORT + ". Provjeri je li dnkd pokrenut.");
    }
    throw e;
  } finally { clearTimeout(sat); }
}

/* ---------- prikaz ------------------------------------------------------ */
function razred(stanje) {
  const s = String(stanje || "").toUpperCase();
  if (s === "OK") return "ok";
  if (s === "ALARM") return "alarm";
  return "nepoznato";
}
function pilula(stanje) {
  const sp = document.createElement("span");
  sp.className = "pilula " + razred(stanje);
  sp.textContent = String(stanje || "—").toUpperCase();
  return sp;
}
function txt(td, tekst) { td.textContent = (tekst === null || tekst === undefined || tekst === "") ? "—" : String(tekst); return td; }
function red(vrijednosti) {
  const tr = document.createElement("tr");
  for (const v of vrijednosti) {
    const td = document.createElement("td");
    if (v instanceof Node) td.appendChild(v); else txt(td, v);
    tr.appendChild(td);
  }
  return tr;
}
function sekundeLjudski(s) {
  if (s === null || s === undefined) return "—";
  s = Math.round(s);
  if (s < 0) return "istekao " + Math.abs(s) + " s";
  if (s < 90) return s + " s";
  if (s < 5400) return Math.round(s / 60) + " min";
  return Math.round(s / 3600) + " h";
}

function nacrtajZdravlje(z) {
  document.getElementById("k-stanje").replaceWith(Object.assign(pilula(z.stanje), { id: "k-stanje" }));
  document.getElementById("k-imena").textContent = (z.imena || []).length;
  document.getElementById("k-upiti").textContent = z.upita;
  document.getElementById("k-godovi").textContent = z.dok_count;
  document.getElementById("k-lanac").replaceWith(Object.assign(pilula(z.godovi_lanac === "CIJEL" ? "OK" : "ALARM"), { id: "k-lanac", textContent: z.godovi_lanac }));
  document.getElementById("k-uptime").textContent = sekundeLjudski(z.uptime_s);

  const tb = document.getElementById("t-imena");
  tb.textContent = "";
  for (const u of (z.imena || [])) {
    const lok = document.createElement("div");
    if (u.razlog) { const d = document.createElement("div"); d.textContent = u.razlog; lok.appendChild(d); }
    for (const l of (u.lokatori || [])) {
      const c = document.createElement("code"); c.textContent = l;
      const w = document.createElement("div"); w.appendChild(c); lok.appendChild(w);
    }
    if (!lok.childNodes.length) lok.textContent = "—";
    const gumb = document.createElement("button");
    gumb.textContent = "osvjezi";
    gumb.addEventListener("click", () => osvjezi(u.ime, gumb));
    const trR = red([u.ime, pilula(u.stanje), u.adresa, u.visina,
                     sekundeLjudski(u.preostalo_s), pilula(((u.suglasnost || {}).stanje) || "NEPOZNATO"),
                     lok, gumb]);
    trR.children[6].className = "razlog";
    if (u.posluzuje_se === false) {
      const nap = document.createElement("div");
      nap.className = "prigus"; nap.textContent = "(DNS odgovor se NE posluzuje — SERVFAIL)";
      trR.children[6].appendChild(nap);
    }
    tb.appendChild(trR);
  }
  if (!(z.imena || []).length) tb.appendChild(red(["nema konfiguriranih imena u dnkd.json", "", "", "", "", "", "", ""]));

  const v = document.getElementById("vatre");
  v.textContent = "";
  if (!(z.vatre || []).length) { v.className = "prigus"; v.textContent = "nijedna — svi putevi mjereni i zeleni"; }
  else {
    v.className = "";
    for (const f of z.vatre) {
      const d = document.createElement("div");
      d.style.marginBottom = "6px";
      d.appendChild(pilula(f.ozbiljnost === "critical" ? "ALARM" : "NEPOZNATO"));
      const s = document.createElement("span"); s.textContent = " " + f.razlog;
      d.appendChild(s); v.appendChild(d);
    }
  }
}

function nacrtajGodove(p) {
  const tb = document.getElementById("t-godovi");
  tb.textContent = "";
  const zapisi = (p.zapisi || []).slice().reverse();
  if (!zapisi.length) { tb.appendChild(red(["—", "jos nema mjerenja", "", "", "", ""])); return; }
  for (const r of zapisi) {
    const t = r.t ? new Date(r.t * 1000).toLocaleTimeString("hr-HR") : "—";
    tb.appendChild(red([r.i, t, r.ime, pilula(r.ishod), r.ms, r.razlog || ""]));
  }
  if (p.lanac !== "CIJEL") {
    vrpca("Lanac godova je RAZBIJEN: " + ((p.greske || [])[0] || "nepoznat razlog") +
          ". Dnevnik mjerenja je naknadno mijenjan — ne vjeruj brojkama dok se ne razrijesi.");
  }
}

/* ---------- akcije ------------------------------------------------------ */
async function ucitajStanje(tiho) {
  try {
    const [z, g] = await Promise.all([zovi("/borg/health.json"), zovi("/dnkd/godovi?n=40")]);
    nacrtajZdravlje(z); nacrtajGodove(g);
    zadnjiUspjeh = new Date();
    document.getElementById("osvjezeno").textContent = "stanje procitano " + zadnjiUspjeh.toLocaleTimeString("hr-HR");
    if (z.godovi_lanac === "CIJEL") vrpca("");
    return true;
  } catch (e) {
    const kada = zadnjiUspjeh ? (" Zadnje uspjesno citanje: " + zadnjiUspjeh.toLocaleTimeString("hr-HR") + " — brojke ispod su od tada i mogu biti zastarjele.") : "";
    vrpca(e.message + kada);
    document.getElementById("osvjezeno").textContent = "veza s demonom prekinuta";
    if (!tiho) toast("greska", "Citanje stanja nije uspjelo", e.message);
    return false;
  }
}

async function osvjezi(ime, gumb) {
  const vrati = zauzmi(gumb, ime ? "Obrada…" : "Povlacim PELUD…");
  const radi = toast("rad", ime ? ("Povlacim PELUD za " + ime) : "Povlacim PELUD sa svih sidara",
                     "PULL + provjera potpisa + provjera suglasnosti s javnim DNS-om…", 0);
  try {
    const p = await zovi("/dnkd/osvjezi", { method: "POST", body: JSON.stringify(ime ? { ime } : {}) });
    const r = p.osvjezeno || [];
    const ok = r.filter(x => x.stanje === "OK").length;
    const alarm = r.filter(x => x.stanje === "ALARM");
    const nepoznato = r.filter(x => x.stanje === "NEPOZNATO");
    radi.remove();
    if (alarm.length) toast("greska", "ALARM na " + alarm.length + " imena", alarm.map(x => x.ime + ": " + (x.razlog || "")).join(" · "));
    if (nepoznato.length) toast("rad", "NEPOZNATO na " + nepoznato.length + " imena", nepoznato.map(x => x.ime + ": " + (x.razlog || "")).join(" · "));
    if (ok) toast("uspjeh", ok + " " + (ok === 1 ? "ime osvjezeno" : "imena osvjezena"),
                  r.filter(x => x.stanje === "OK").map(x => x.ime + " → " + x.adresa + " (visina " + x.visina + ", rok " + sekundeLjudski(x.preostalo_s) + ")").join(" · "));
    if (!r.length) toast("greska", "Nista nije osvjezeno", "Demon nije vratio ni jedan rezultat.");
    await ucitajStanje(true);
  } catch (e) {
    radi.remove();
    toast("greska", "Osvjezavanje nije uspjelo", e.message);
    vrpca(e.message);
  } finally { vrati(); }
}

async function provjeriLanac(gumb) {
  const vrati = zauzmi(gumb, "Provjeravam…");
  try {
    const p = await zovi("/dnkd/godovi/provjeri", { method: "POST", body: "{}" });
    if (p.lanac === "CIJEL") { toast("uspjeh", "Lanac godova je CIJEL", p.ukupno + " mjerenja, svi hashevi se poklapaju."); vrpca(""); }
    else { toast("greska", "Lanac godova je RAZBIJEN", (p.greske || []).join(" · ")); vrpca("Lanac godova je RAZBIJEN: " + ((p.greske || [])[0] || "")); }
    await ucitajStanje(true);
  } catch (e) { toast("greska", "Provjera lanca nije uspjela", e.message); vrpca(e.message); }
  finally { vrati(); }
}

/* ---------- pokretanje -------------------------------------------------- */
document.getElementById("adresa-ploce").textContent = "127.0.0.1:" + PORT;
document.getElementById("b-osvjezi").addEventListener("click", (e) => osvjezi(null, e.currentTarget));
document.getElementById("b-lanac").addEventListener("click", (e) => provjeriLanac(e.currentTarget));
document.getElementById("b-stanje").addEventListener("click", async (e) => {
  const vrati = zauzmi(e.currentTarget, "Citam…");
  const uspjelo = await ucitajStanje(false);
  if (uspjelo) toast("uspjeh", "Stanje procitano", "Svi pokazatelji su osvjezeni.");
  vrati();
});
document.getElementById("auto").addEventListener("change", (e) => {
  automatski = e.currentTarget.checked;
  toast("rad", automatski ? "Automatsko citanje uključeno" : "Automatsko citanje isključeno",
        automatski ? "Stanje se cita svakih 10 s." : "Stanje se cita samo na tvoj zahtjev.", 3500);
});
document.getElementById("tema").addEventListener("click", () => {
  const sada = document.documentElement.dataset.tema;
  const novo = sada === "tamno" ? "svijetlo" : (sada === "svijetlo" ? "" : "tamno");
  if (novo) document.documentElement.dataset.tema = novo; else delete document.documentElement.dataset.tema;
  try { localStorage.setItem("maska-tema", novo); } catch (e) { /* privatni prozor — tema se ne pamti, ploca radi */ }
});
try { const t = localStorage.getItem("maska-tema"); if (t) document.documentElement.dataset.tema = t; } catch (e) {}

ucitajStanje(false);
ciklus = setInterval(() => {
  if (!automatski) { document.getElementById("odbrojavanje").textContent = "—"; return; }
  odbrojavanje -= 1;
  if (odbrojavanje <= 0) { odbrojavanje = 10; ucitajStanje(true); }
  document.getElementById("odbrojavanje").textContent = odbrojavanje;
}, 1000);
</script>
</body>
</html>
"""


def ploca(port: int) -> str:
    """HTML upravljacke ploce za dnkd koji slusa na danom portu."""
    return _PLOCA.replace("__PORT__", str(int(port)))
