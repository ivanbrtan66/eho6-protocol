#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hrvatska verzija EHO6 stranice — prijevod po BLOKOVIMA, s assertom na svaki.

Zasto par stranica a ne prijevod postojece: SEO doseg je stvaran zahtjev zbog
kojeg DNS uopce ostaje u MASKI (c1570). Prevesti jedinu stranicu na hrvatski
znaci izgubiti globalnu publiku; par /quantum/eho6/ (en) + /quantum/eho6/hr/ (hr)
povezan hreflang-om je dobiva obje — trazilica indeksira svaku i svakoj salje
njezinu publiku.

Zasto blokovi a ne tekstualni cvorovi: rijeci su isprekidane inline oznakama
(<strong>, <code>, <em>). Prijevod po cvorovima razbio bi ih. Prijevod po
blokovima zadrzava oznake i ostaje citljiv u diffu.

Zasto assert na svaki blok: ako se engleska stranica promijeni, ovo mora PASTI i
imenovati blok koji vise ne postoji — polu-prevedena stranica je gora od
neprevedene, jer izgleda kao greska a ne kao odluka.

  python3 www/hrvatska_verzija.py --izvor www/eho6/index.html --izlaz www/eho6/hr/index.html
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# (engleski blok, hrvatski blok) — redoslijed kao na stranici.
# Tehnicki nazivi ostaju u izvorniku (Ed25519, WireGuard, NAT, STUN, PELUD, dnkd):
# prevoditi ih znacilo bi izmisljati pojmove kojih u struci nema.
PRIJEVOD: list[tuple[str, str]] = [
    # --- <head> i navigacija ---
    ('<html lang="en">', '<html lang="hr">'),
    ("<title>EHO6 — Decentralized Verification Protocol</title>",
     "<title>EHO6 — Protokol decentralizirane provjere</title>"),
    ('<a class="jezik-aktivan" href="/quantum/eho6/" hreflang="en">EN</a><a href="/quantum/eho6/hr/" hreflang="hr">HR</a>',
     '<a href="/quantum/eho6/" hreflang="en">EN</a><a class="jezik-aktivan" href="/quantum/eho6/hr/" hreflang="hr">HR</a>'),
    ('<a href="#install">Install</a>', '<a href="#install">Instalacija</a>'),
    ('<a href="#steps">How It Works</a>', '<a href="#steps">Kako radi</a>'),
    ('<a href="#features">Features</a>', '<a href="#features">Temelji</a>'),
    ('<a href="#anchors">Anchors</a>', '<a href="#anchors">Sidra</a>'),
    ('title="Toggle theme"', 'title="Promijeni temu"'),

    # --- hero ---
    ('<div class="hero-badge">Protocol v6 &middot; Live</div>',
     '<div class="hero-badge">Protokol v6 &middot; Zivo</div>'),
    ('<p class="hero-sub">Decentralized Verification Protocol</p>',
     '<p class="hero-sub">Protokol decentralizirane provjere</p>'),
    ("&ldquo;Truth is proven, not claimed.&rdquo;", "&bdquo;Istina se dokazuje, ne tvrdi.&ldquo;"),
    ("&#9654; Quick Install", "&#9654; Brza instalacija"),
    (">&#128196; Whitepaper</a>", ">&#128196; Rad (PDF)</a>"),
    ('''<a class="hero-new" href="#maska">New &#183; MASKA address indirection
    <span>&mdash; signed, expiring location &rarr;</span></a>''',
     '''<a class="hero-new" href="#maska">Novo &#183; MASKA adresna indirekcija
    <span>&mdash; potpisana lokacija s rokom &rarr;</span></a>'''),

    # --- instalacija ---
    ('<p class="section-label">// one-command install</p>',
     '<p class="section-label">// instalacija jednom naredbom</p>'),
    ("<h2>Get Running in 30 Seconds</h2>", "<h2>Pokreni u 30 sekundi</h2>"),
    ('<span class="install-title">bash &mdash; eho6 bootstrap</span>',
     '<span class="install-title">bash &mdash; eho6 pokretanje</span>'),
    ('onclick="copyInstall()">Copy<', 'onclick="copyInstall()">Kopiraj<'),
    ("""    Requires: Linux/macOS &middot; Python 3.11+ &middot; stdlib only &mdash; no pip install needed.""",
     """    Trazi: Linux/macOS &middot; Python 3.11+ &middot; samo standardna biblioteka &mdash; bez pip instalacije."""),
    ("View source before running &rarr;", "Pogledaj izvorni kod prije pokretanja &rarr;"),

    # --- tri koraka ---
    ('<p class="section-label">// admission flow</p>',
     '<p class="section-label">// postupak primanja</p>'),
    ("<h2>Three Steps to Join the Mesh</h2>", "<h2>Tri koraka do mreze</h2>"),
    ("<h3>Request Admission</h3>", "<h3>Zatrazi primanje</h3>"),
    ("""          Run the installer. It generates a local <code>Ed25519</code> keypair, builds your
          <code>rendezvous seed</code>, and sends a signed admission request to both anchor nodes
          (Frankfurt + Berlin). Your public key becomes your identity &mdash; no account, no email.""",
     """          Pokreni instalaciju. Ona lokalno generira <code>Ed25519</code> par kljuceva, izgradi tvoje
          <code>sjeme za susret</code> i posalje potpisan zahtjev za primanje na oba sidra
          (Frankfurt + Berlin). Tvoj javni kljuc postaje tvoj identitet &mdash; bez racuna, bez e-poste."""),
    ("<h3>Send 0.001 XMR</h3>", "<h3>Posalji 0,001 XMR</h3>"),
    ("""          A one-time Monero micro-payment proves liveness and prevents Sybil attacks.
          The installer prints your unique <code>XMR subaddress</code>. Payment is detected
          on-chain &mdash; no centralized gateway, no KYC. Confirmation takes ~2 minutes.""",
     """          Jednokratna Monero mikro-uplata dokazuje da cvor zivi i sprjecava Sybil napade.
          Instalacija ispise tvoju jedinstvenu <code>XMR podadresu</code>. Uplata se ocitava
          u lancu &mdash; bez posrednika i bez KYC-a. Potvrda traje oko 2 minute."""),
    ("<h3>Node Admitted + Running</h3>", "<h3>Cvor primljen i radi</h3>"),
    ("""          Both anchors co-sign your <code>phi_t admission token</code>. Your node starts publishing
          <code>/borg/health.json</code> every 30 s (BORG format). The mesh pulls your
          health &mdash; you never push to peers. You are now a verified EHO6 node.""",
     """          Oba sidra supotpisuju tvoj <code>phi_t token primanja</code>. Cvor pocinje objavljivati
          <code>/borg/health.json</code> svakih 30 s (BORG format). Mreza tvoje zdravlje
          POVLACI &mdash; ti nikad ne guras prema susjedima. Od sada si provjeren EHO6 cvor."""),

    # --- temelji ---
    ('<p class="section-label">// protocol primitives</p>',
     '<p class="section-label">// gradivni elementi protokola</p>'),
    ("<h2>Built on Solid Foundations</h2>", "<h2>Temelji koji drze</h2>"),
    ("<h3>Ed25519 2-Anchor</h3>", "<h3>Ed25519, dva sidra</h3>"),
    ("<p>Every admission token requires co-signatures from two geographically independent anchor nodes. One anchor down = protocol continues uninterrupted.</p>",
     "<p>Svaki token primanja trazi supotpis dvaju zemljopisno neovisnih sidara. Pad jednog sidra ne prekida protokol.</p>"),
    ("<h3>Monero Payment</h3>", "<h3>Monero uplata</h3>"),
    ("<p>0.001 XMR micro-payment as Sybil resistance. Privacy-preserving, non-custodial. No exchange account required &mdash; any XMR wallet works.</p>",
     "<p>Mikro-uplata od 0,001 XMR kao obrana od Sybil napada. Cuva privatnost, bez skrbnika. Ne treba racun na mjenjacnici &mdash; radi svaki XMR novcanik.</p>"),
    ("<h3>stdlib-only</h3>", "<h3>Samo standardna biblioteka</h3>"),
    ("<p>Zero external dependencies. Ships as a single Python file using only the standard library. Auditable in minutes, deployable on any Python 3.9+ system.</p>",
     "<p>Nijedna vanjska zavisnost. Isporucuje se kao jedna Python datoteka koja koristi samo standardnu biblioteku. Procita se u nekoliko minuta i radi na svakom sustavu s Pythonom 3.11+.</p>"),
    ("<h3>BORG Health Format</h3>", "<h3>BORG format zdravlja</h3>"),
    ("<p>Standard <code>/borg/health.json</code> published every 30 s. Includes <code>dok_count</code>, <code>last_block_hash</code>, disk, memory, and load metrics.</p>",
     "<p>Standardni <code>/borg/health.json</code> objavljen svakih 30 s. Sadrzi <code>dok_count</code>, <code>last_block_hash</code>, disk, memoriju i opterecenje.</p>"),
    ("<h3>Deterministic Rendezvous</h3>", "<h3>Deterministicki susret</h3>"),
    ("<p>Seed-based peer discovery with bit-identical output across architectures (x86/ARM proven). No central directory server required.</p>",
     "<p>Pronalazenje susjeda iz sjemena, s bit-identicnim ishodom na razlicitim arhitekturama (dokazano x86/ARM). Bez sredisnjeg imenika.</p>"),
    ("<h3>Pull-only Mesh</h3>", "<h3>Mreza koja samo povlaci</h3>"),
    ("<p>Nodes never push to peers. Health data is pulled every 30 s. No WebSockets, no long-polling &mdash; NAT-friendly, works behind any firewall.</p>",
     "<p>Cvorovi nikad ne guraju prema susjedima. Zdravlje se povlaci svakih 30 s. Bez WebSocketa i dugog cekanja &mdash; prolazi kroz NAT i radi iza svakog vatrozida.</p>"),

    # --- sidra ---
    ('<p class="section-label">// anchor nodes</p>', '<p class="section-label">// sidra</p>'),
    ("<h2>Active Anchor Network</h2>", "<h2>Ziva mreza sidara</h2>"),
    ("          <th>Node</th>", "          <th>Cvor</th>"),
    ("          <th>Location</th>", "          <th>Lokacija</th>"),
    ("          <th>Endpoint</th>", "          <th>Adresa</th>"),
    ("          <th>Status</th>", "          <th>Stanje</th>"),
    ("          <th>Role</th>", "          <th>Uloga</th>"),
    ("<td>Frankfurt, DE</td>", "<td>Frankfurt, Njemacka</td>"),
    ("<td>Berlin, DE</td>", "<td>Berlin, Njemacka</td>"),
    ('<span class="status-dot status-live">Live</span></td>\n          <td><span class="mono">Anchor A &middot; Primary</span>',
     '<span class="status-dot status-live">Zivo</span></td>\n          <td><span class="mono">Sidro A &middot; primarno</span>'),
    ('<span class="status-dot status-live">Live</span></td>\n          <td><span class="mono">Anchor B &middot; Secondary</span>',
     '<span class="status-dot status-live">Zivo</span></td>\n          <td><span class="mono">Sidro B &middot; pricuvno</span>'),
    ("    Anchor health endpoints:", "    Zdravlje sidara:"),

    # --- resursi i podnozje ---
    ('<p class="section-label">// resources</p>', '<p class="section-label">// materijali</p>'),
    ("<h2>Documentation &amp; Source</h2>", "<h2>Dokumentacija i izvorni kod</h2>"),
    ("&#128279; GitHub Repository", "&#128279; GitHub repozitorij"),
    ("&#128196; Whitepaper PDF", "&#128196; Rad (PDF)"),
    ("&#128220; install.sh source", "&#128220; izvorni kod install.sh"),
    ("&#129658; Anchor Health JSON", "&#129658; Zdravlje sidara (JSON)"),
    ("&#129517; MASKA phases (F1&ndash;F5)", "&#129517; MASKA faze (F1&ndash;F5)"),
    ("  MIT License &middot;", "  MIT licenca &middot;"),
    ('target="_blank">Whitepaper</a> &middot;', 'target="_blank">Rad</a> &middot;'),
    ("  EHO6 Research Collective 2026 &middot;", "  EHO6 istrazivacki kolektiv 2026. &middot;"),
    ('<span style="font-family:var(--mono); font-size:0.78rem; color:var(--text2);">Truth is proven, not claimed.</span>',
     '<span style="font-family:var(--mono); font-size:0.78rem; color:var(--text2);">Istina se dokazuje, ne tvrdi.</span>'),
]

# --- MASKA sekcija ----------------------------------------------------------
PRIJEVOD += [
    ('<p class="section-label">// address indirection layer</p>',
     '<p class="section-label">// sloj adresne indirekcije</p>'),
    ("<h2>Where You Are Found Is Not Where You Live</h2>",
     "<h2>Gdje te nalaze nije gdje zivis</h2>"),
    ("""    EHO6 proves <strong>who</strong> a node is. MASKA decides <strong>where</strong> it can be
    reached &mdash; and keeps that answer out of DNS. A static <code>A</code> record is a fact
    with no author and no expiry: whoever changes it has changed the truth. MASKA replaces it
    with a <strong>signed claim that expires</strong>, and moves the real location out of the
    public record entirely. The DNS name stays exactly where it is, because search reach is a
    real requirement &mdash; it is the <em>content</em> of the answer that changes.""",
     """    EHO6 dokazuje <strong>tko</strong> je cvor. MASKA odlucuje <strong>gdje</strong> je dosezljiv
    &mdash; i taj odgovor drzi izvan DNS-a. Staticni <code>A</code> zapis je cinjenica bez autora
    i bez roka: tko ga promijeni, promijenio je istinu. MASKA ga zamjenjuje
    <strong>potpisanom tvrdnjom koja istice</strong> i stvarnu lokaciju u potpunosti mice iz
    javnog zapisa. DNS ime ostaje tocno gdje jest, jer je doseg u trazilicama stvaran zahtjev
    &mdash; mijenja se <em>sadrzaj</em> odgovora, ne mjesto."""),
    ("""    One PELUD record. It extends the GENESIS1 DNS TXT format already in use rather than
    inventing a new one. Unknown fields, non-canonical spelling, an expired claim, a missing
    pinned key, or a reserved-but-unimplemented <code>alg</code> (e.g. <code>ml-dsa-65</code>)
    are all <em>rejected</em> &mdash; never silently accepted. A signature checked with the key from the same record proves
    nothing, so verification without a pinned key fails by design.""",
     """    Jedan PELUD zapis. Prosiruje postojeci GENESIS1 DNS TXT format umjesto da izmislja novi.
    Nepoznata polja, nekanonski oblik, istekla tvrdnja, nedostatak pinovanog kljuca i rezervirani
    ali neimplementirani <code>alg</code> (npr. <code>ml-dsa-65</code>) &mdash; sve se
    <em>odbija</em>, nikad tiho ne prihvaca. Potpis provjeren kljucem <em>iz istog zapisa</em> ne
    dokazuje nista, pa provjera bez pinovanog kljuca namjerno pada."""),

    ("<h3>Signed, expiring locator record</h3>", "<h3>Potpisani zapis lokacije s rokom</h3>"),
    ("""        <p>Ed25519 over a fixed canonical field order, one-hour maximum lifetime, verified
           against a pinned key. The address stops being a fact and becomes a claim with a
           deadline.</p>""",
     """        <p>Ed25519 preko fiksnog kanonskog redoslijeda polja, najvise sat vremena trajanja,
           provjereno protiv pinovanog kljuca. Adresa prestaje biti cinjenica i postaje tvrdnja
           s rokom.</p>"""),
    ('<span class="maska-pill built">Built</span>\n    </div>\n    <div class="maska-phase">\n      <span class="maska-phase-code">F2 dnkd</span>',
     '<span class="maska-pill built">Izgradjeno</span>\n    </div>\n    <div class="maska-phase">\n      <span class="maska-phase-code">F2 dnkd</span>'),
    ("<h3>Local resolver for <code>.dnk</code></h3>", "<h3>Lokalni razrjesitelj za <code>.dnk</code></h3>"),
    ("""        <p>Name resolution becomes a local function of the host again, the way ARPANET's
           <code>HOSTS.TXT</code> worked before DNS existed &mdash; but pulled, signed, and
           expiring. Everything outside <code>.dnk</code> gets <code>REFUSED</code>: a resolver
           that forwards becomes a proxy for all of your traffic. It installs no CA into the
           system trust store, ever.</p>""",
     """        <p>Razrjesenje imena opet postaje lokalna funkcija hosta, onako kako je radio ARPANET-ov
           <code>HOSTS.TXT</code> prije nego je DNS postojao &mdash; ali povuceno, potpisano i s
           rokom. Sve izvan <code>.dnk</code> dobiva <code>REFUSED</code>: razrjesitelj koji
           prosljedjuje postaje posrednik kroz koji ide sav tvoj promet. U sistemski trust store
           ne instalira nikakav CA, nikada.</p>"""),
    ('<span class="maska-pill built">Built</span>\n    </div>\n    <div class="maska-phase">\n      <span class="maska-phase-code">F3 RIZOM</span>',
     '<span class="maska-pill built">Izgradjeno</span>\n    </div>\n    <div class="maska-phase">\n      <span class="maska-phase-code">F3 RIZOM</span>'),
    ("<h3>Dual-anchor WireGuard</h3>", "<h3>Dvo-sidreni WireGuard</h3>"),
    ("""        <p>Replaces a single <code>ssh -R</code> reverse tunnel, which is a user-space TCP
           session that goes half-open when ISP NAT forgets the mapping &mdash; device alive,
           tunnel dead, neither side aware. Two anchors, kernel WireGuard, stateless handshake,
           <code>AllowedIPs</code> restricted to the anchor's <code>/32</code> so ordinary
           traffic is untouched.</p>""",
     """        <p>Zamjenjuje jedan <code>ssh -R</code> obrnuti tunel, koji je TCP sjednica u
           korisnickom prostoru i ostane poluotvorena kad ISP-ov NAT zaboravi mapiranje &mdash;
           uredjaj ziv, tunel mrtav, nijedna strana to ne zna. Dva sidra, WireGuard u kernelu,
           handshake bez stanja, <code>AllowedIPs</code> ogranicen na <code>/32</code> sidra pa
           obican promet ostaje netaknut.</p>"""),
    ('<span class="maska-pill partial">Tooling built &#183; pilot pending</span>',
     '<span class="maska-pill partial">Alat izgradjen &#183; pilot ceka</span>'),
    ("<h3>Direct punch through NAT</h3>", "<h3>Izravan probod kroz NAT</h3>"),
    ("""        <p>The anchor runs its own STUN and a signed rendezvous board; peers measure their NAT,
           exchange signed candidates, punch simultaneously, and hand the winning path to
           WireGuard only after a handshake actually moves. This is the phase that removes the
           single point of failure rather than relocating it. The rendezvous service has no
           route that carries payload &mdash; a test fails if one ever appears.</p>""",
     """        <p>Sidro vozi vlastiti STUN i potpisanu oglasnu plocu; strane izmjere svoj NAT, razmijene
           potpisane kandidate, probijaju istovremeno i pobjednicki put predaju WireGuardu tek
           kad se handshake stvarno pomakne. Ovo je faza koja jedinstvenu tocku kvara UKIDA, a ne
           premjesta. Sluzba susreta nema rutu koja prenosi teret &mdash; test pada ako se ikad
           pojavi.</p>"""),
    ('<span class="maska-pill partial">Built &#183; field pilot pending</span>',
     '<span class="maska-pill partial">Izgradjeno &#183; pilot na terenu ceka</span>'),
    ("<h3>K-of-N announcement boards</h3>", "<h3>K-od-N oglasne ploce</h3>"),
    ("""        <p>N registrars, TLDs and jurisdictions with K-of-N consensus before any redirect. The
           only phase that costs search reach, because it splits one signal across three
           domains &mdash; so it is conditional, not merely deferred.</p>""",
     """        <p>N registrara, TLD-ova i jurisdikcija, uz K-od-N konsenzus prije svakog preusmjeravanja.
           Jedina faza koja placa dosegom u trazilicama, jer dijeli jedan signal na tri domene
           &mdash; zato je uvjetna, a ne samo odgodjena.</p>"""),
    ('<span class="maska-pill none">Not built</span>', '<span class="maska-pill none">Nije izgradjeno</span>'),

    # dijagram
    ('fill="currentColor" opacity="0.55">F3 &#183; RIZOM (today)</text>',
     'fill="currentColor" opacity="0.55">F3 &#183; RIZOM (danas)</text>'),
    ('<text x="68" y="137" font-size="12" text-anchor="middle" fill="currentColor">edge X96</text>',
     '<text x="68" y="137" font-size="12" text-anchor="middle" fill="currentColor">rub X96</text>'),
    ('<text x="220" y="137" font-size="12" text-anchor="middle" fill="currentColor">anchor</text>',
     '<text x="220" y="137" font-size="12" text-anchor="middle" fill="currentColor">sidro</text>'),
    ('<text x="364" y="137" font-size="12" text-anchor="middle" fill="currentColor">peer</text>',
     '<text x="364" y="137" font-size="12" text-anchor="middle" fill="currentColor">peer</text>'),
    ('opacity="0.75">all traffic</text>', 'opacity="0.75">sav promet</text>'),
    ('opacity="0.55">sees everything</text>', 'opacity="0.55">vidi sve</text>'),
    ('opacity="0.55">anchor down = path down</text>', 'opacity="0.55">pad sidra = pad puta</text>'),
    ('opacity="0.75">signed candidates only</text>',
     'opacity="0.75">samo potpisani kandidati</text>'),
    ('<text x="522" y="177" font-size="12" text-anchor="middle" fill="currentColor">edge X96</text>',
     '<text x="522" y="177" font-size="12" text-anchor="middle" fill="currentColor">rub X96</text>'),
    ('<text x="616" y="77" font-size="12" text-anchor="middle" fill="currentColor">anchor</text>',
     '<text x="616" y="77" font-size="12" text-anchor="middle" fill="currentColor">sidro</text>'),
    ('fill="var(--accent2)">direct UDP after punch</text>',
     'fill="var(--accent2)">izravan UDP nakon proboda</text>'),
    ('opacity="0.55">anchor down = path survives</text>',
     'opacity="0.55">pad sidra = put prezivi</text>'),
    ('aria-label="Before F4 all traffic passes through the anchor, which is a single point of failure. After F4 the anchor only exchanges signed candidates and traffic goes directly between peers."',
     'aria-label="Prije F4 sav promet ide kroz sidro, koje je jedinstvena tocka kvara. Nakon F4 sidro samo razmjenjuje potpisane kandidate, a promet ide izravno izmedju strana."'),
    ("""      What F4 changes. Until the punch, the anchor carries the traffic and is both the
      single point of failure and the only place the traffic can be read. After the punch it
      exchanges signed candidates and nothing else &mdash; and its failure no longer drops an
      established path. Symmetric NAT (EDM) is the case where the punch cannot work; there the
      anchor stays a relay, and MASKA reports that instead of claiming success.""",
     """      Sto F4 mijenja. Do proboda sidro nosi promet i ujedno je jedinstvena tocka kvara i jedino
      mjesto s kojeg se promet moze citati. Nakon proboda razmjenjuje samo potpisane kandidate
      &mdash; i njegov pad vise ne rusi uspostavljen put. Simetricni NAT (EDM) je slucaj u kojem
      probod ne moze uspjeti; ondje sidro ostaje relej, a MASKA to JAVI umjesto da tvrdi uspjeh."""),

    # dvije kutije
    ("<h3>What the network decides, not the code</h3>", "<h3>O cemu odlucuje mreza, ne kod</h3>"),
    ("""        <li><b>EIM</b> &mdash; the NAT hands out the same external address regardless of
            destination, so the address one anchor sees is usable by a third party.
            <code>Punch possible.</code></li>""",
     """        <li><b>EIM</b> &mdash; NAT daje istu vanjsku adresu bez obzira na odrediste, pa adresa
            koju vidi jedno sidro vrijedi i za trecu stranu.
            <code>Probod je moguc.</code></li>"""),
    ("""        <li><b>EDM (symmetric)</b> &mdash; a new port per destination. The address the EU anchor
            sees is valid for nobody else. <code>Relay stays.</code> Reported as EDM, not
            attempted and quietly downgraded.</li>""",
     """        <li><b>EDM (simetricni)</b> &mdash; novi port po odredistu. Adresa koju vidi sidro EU ne
            vrijedi ni za koga drugog. <code>Relej ostaje.</code> Prijavljuje se kao EDM, a ne
            pokusava pa tiho spusta na nizu razinu.</li>"""),
    ("""        <li><b>Unknown</b> &mdash; measuring this needs two vantage points on different IP
            addresses. With one anchor the answer is <code>NEPOZNATO</code>; &ldquo;probably
            fine&rdquo; is not a measurement.</li>""",
     """        <li><b>Nepoznato</b> &mdash; za ovo mjerenje trebaju dvije tocke gledanja na razlicitim IP
            adresama. S jednim sidrom odgovor je <code>NEPOZNATO</code>; &bdquo;vjerojatno je u
            redu&ldquo; nije mjerenje.</li>"""),
    ("<h3>What MASKA does not do</h3>", "<h3>Sto MASKA ne radi</h3>"),
    ("""        <li>It does not remove the <code>A</code> record. No unmodified browser can reach you
            without DNS, an IP and a route; every alternative trades away reach.</li>""",
     """        <li>Ne uklanja <code>A</code> zapis. Nijedan nepromijenjen preglednik ne moze doci do tebe
            bez DNS-a, IP adrese i rute; svaka alternativa placa dosegom.</li>"""),
    ("""        <li>It does not install a certificate authority. A local CA would be a key for
            <em>every</em> site on that device &mdash; real damage, not protection.</li>""",
     """        <li>Ne instalira vlastiti CA. Lokalni CA bio bi kljuc za <em>svaku</em> stranicu na tom
            uredjaju &mdash; stvarna steta, ne zastita.</li>"""),
    ("""        <li>The chain height in a record is carried, <b>not verified</b> against the chain.</li>""",
     """        <li>Visina lanca u zapisu se <b>prenosi, ali ne provjerava</b> protiv samog lanca.</li>"""),
    ("""        <li>There is <b>no key revocation</b> yet; a short expiry limits how long a compromise
            lasts, not that it happened.</li>""",
     """        <li>Jos <b>nema opoziva kljuca</b>; kratak rok ogranicava koliko kompromitacija traje, ne
            i to sto se dogodila.</li>"""),
    ("""        <li>The measurement ledger is hash-chained locally but <b>not anchored</b> in the
            chain, so whoever holds the file could rewrite all of it.</li>""",
     """        <li>Dnevnik mjerenja lokalno je lancan hashevima, ali <b>nije usidren</b> u lanac, pa ga
            onaj tko drzi datoteku moze prepisati u cijelosti.</li>"""),
    ("""    Measured on the build host, not estimated: signature <b>4 ms</b> &#183; verification
    <b>4 ms</b> &#183; full name resolution including PULL <b>14 ms</b> &#183; <b>215 tests</b>,
    standard library only, no network egress. Ed25519 is checked against RFC&nbsp;8032 &sect;7.1
    vectors, X25519 against RFC&nbsp;7748 &sect;5.2 plus a cross-check against OpenSSL, and the
    NAT simulator models RFC&nbsp;4787 mapping and filtering classes &mdash; including the
    <em>failure</em> cases: a punch through a symmetric NAT fails even when the code is told the
    NAT is EIM. What is still open is the field pilot on real CGNAT hardware; the pass criterion
    was set before the measurement: seven days with both paths measured in parallel and no
    watchdog alarm.""",
     """    Izmjereno na stroju na kojem je gradjeno, ne procijenjeno: potpis <b>4 ms</b> &#183;
    provjera <b>4 ms</b> &#183; cijelo razrjesenje imena s PULL-om <b>14 ms</b> &#183;
    <b>215 testova</b>, samo standardna biblioteka, bez izlaza na internet. Ed25519 je provjeren
    protiv vektora iz RFC&nbsp;8032 &sect;7.1, X25519 protiv RFC&nbsp;7748 &sect;5.2 uz kriznu
    provjeru s OpenSSL-om, a NAT simulator modelira razrede mapiranja i filtriranja iz
    RFC&nbsp;4787 &mdash; ukljucujuci <em>neuspjele</em> slucajeve: probod kroz simetricni NAT
    pada i kad se kodu kaze da je NAT tipa EIM. Otvoren ostaje pilot na stvarnom CGNAT-u;
    kriterij prolaza postavljen je prije mjerenja: sedam dana s oba puta mjerena paralelno i bez
    ijednog alarma nadzora."""),
]


# Dijakritici se dodaju kao ZASEBAN korak, a ne rucno u tablici iznad.
# Razlog: tablica ostaje ASCII kao i ostatak koda (komentari, commit poruke), a
# stranica dobiva ispravnu hrvatsku ortografiju. Bez ovoga stranica izgleda kao
# poruka iz 2003., sto je na javnom proizvodu nemar, ne stil.
# Zamjena ide po granici rijeci, pa ne dira kod, URL-ove ni engleski tekst.
DIJAKRITICI: dict[str, str] = {
    "cvor": "\u010dvor", "cvora": "\u010dvora", "cvorovi": "\u010dvorovi", "cvorova": "\u010dvorova",
    "cemu": "\u010demu", "sto": "\u0161to", "tocka": "to\u010dka", "tocke": "to\u010dke",
    "tocku": "to\u010dku", "tocno": "to\u010dno", "jos": "jo\u0161", "nista": "ni\u0161ta",
    "moze": "mo\u017ee", "kljuc": "klju\u010d", "kljuca": "klju\u010da", "kljucem": "klju\u010dem",
    "kljuceva": "klju\u010deva", "znaci": "zna\u010di", "pocinje": "po\u010dinje",
    "racun": "ra\u010dun", "racuna": "ra\u010duna", "trazi": "tra\u017ei",
    "trazilica": "tra\u017eilica", "trazilicama": "tra\u017eilicama", "istice": "isti\u010de",
    "povlaci": "povla\u010di", "POVLACI": "POVLA\u010cI", "guras": "gura\u0161",
    "procita": "pro\u010dita", "procitati": "pro\u010ditati", "isporucuje": "isporu\u010duje",
    "pronalazenje": "pronala\u017eenje", "razlicitim": "razli\u010ditim",
    "sredisnjeg": "sredi\u0161njeg", "ogranicen": "ograni\u010den", "ogranicava": "ograni\u010dava",
    "korisnickom": "korisni\u010dkom", "uredjaj": "ure\u0111aj", "uredjaju": "ure\u0111aju",
    "izmedju": "izme\u0111u", "odgodjena": "odgo\u0111ena", "izgradjeno": "izgra\u0111eno", "izgradjen": "izgra\u0111en",
    "vise": "vi\u0161e",
    "gradjeno": "gra\u0111eno", "prosljedjuje": "proslje\u0111uje",
    "razrjesitelj": "razrje\u0161itelj", "razrjesenje": "razrje\u0161enje",
    "placa": "pla\u0107a", "plocu": "plo\u010du", "ploce": "plo\u010de",
    "pobjednicki": "pobjedni\u010dki", "sluzba": "slu\u017eba", "Sluzba": "Slu\u017eba",
    "simetricni": "simetri\u010dni", "ukljucujuci": "uklju\u010duju\u0107i",
    "kriznu": "kri\u017enu", "citati": "\u010ditati", "poste": "po\u0161te",
    "e-poste": "e-po\u0161te", "ceka": "\u010deka", "pricuvno": "pri\u010duvno",
    "zivo": "\u017eivo", "ziva": "\u017eiva", "ziv": "\u017eiv", "zivi": "\u017eivi",
    "zivis": "\u017eivi\u0161", "lancan": "lan\u010dan", "drzi": "dr\u017ei",
    "cinjenica": "\u010dinjenica", "sprjecava": "sprje\u010dava", "ocitava": "o\u010ditava",
    "moguc": "mogu\u0107", "moguce": "mogu\u0107e", "spusta": "spu\u0161ta",
    "rusi": "ru\u0161i", "citljiv": "\u010ditljiv", "salje": "\u0161alje",
    "greska": "gre\u0161ka", "sadrzaj": "sadr\u017eaj", "sadrzi": "sadr\u017ei",
    "opterecenje": "optere\u0107enje", "cekanja": "\u010dekanja",
    "istrazivacki": "istra\u017eiva\u010dki", "drze": "dr\u017ee", "cuva": "\u010duva",
    "mjenjacnici": "mjenja\u010dnici", "novcanik": "nov\u010danik",
    "deterministicki": "deterministi\u010dki", "bit-identicnim": "bit-identi\u010dnim",
    "mreza": "mre\u017ea", "mreze": "mre\u017ee", "mrezi": "mre\u017ei", "mrezu": "mre\u017eu",
    "Njemacka": "Njema\u010dka", "odlucuje": "odlu\u010duje", "dosezljiv": "dose\u017eljiv",
    "staticni": "stati\u010dni", "mice": "mi\u010de", "prosiruje": "pro\u0161iruje",
    "izmislja": "izmi\u0161lja", "prihvaca": "prihva\u0107a", "najvise": "najvi\u0161e",
    "povuceno": "povu\u010deno", "obican": "obi\u010dan", "premjesta": "premje\u0161ta",
    "prezivi": "pre\u017eivi", "slucaj": "slu\u010daj", "slucajeve": "slu\u010dajeve",
    "odrediste": "odredi\u0161te", "odredistu": "odredi\u0161tu", "trecu": "tre\u0107u",
    "pokusava": "poku\u0161ava", "doci": "do\u0107i", "kaze": "ka\u017ee",
    "zastita": "za\u0161tita", "steta": "\u0161teta", "zatrazi": "zatra\u017ei",
    "posalji": "po\u0161alji", "temelji": "temelji", "susjedima": "susjedima",
}


def s_dijakriticima(tekst: str) -> tuple[str, int]:
    """Vrati (tekst, broj zamjena). Granica rijeci cuva kod, URL-ove i engleski."""
    ukupno = 0
    for ascii_oblik, tocan in DIJAKRITICI.items():
        for izvor, cilj in ((ascii_oblik, tocan),
                            (ascii_oblik.capitalize(), tocan.capitalize())):
            uzorak = re.compile(rf"(?<![\w-]){re.escape(izvor)}(?![\w-])")
            tekst, n = uzorak.subn(cilj, tekst)
            ukupno += n
    return tekst, ukupno


# Tragovi po kojima se prepoznaje da je nesto ostalo neprevedeno. Nisu potpuni
# (ne moze biti), ali hvataju upravo one blokove koje je lako previdjeti.
KONTROLNE_RIJECI = ("Get Running", "Three Steps", "Built on Solid", "Active Anchor",
                    "Where You Are Found", "What MASKA does not do", "Not built",
                    "Documentation &amp; Source", "Truth is proven")


def prevedi(html: str) -> tuple[str, list[str]]:
    """Vrati (hrvatska_stranica, upozorenja). Pada na prvom bloku koji ne postoji."""
    upozorenja: list[str] = []
    for engleski, hrvatski in PRIJEVOD:
        broj = html.count(engleski)
        if broj != 1:
            isjecak = " ".join(engleski.split())[:90]
            raise SystemExit(
                f"GRESKA: blok nadjen {broj} puta (ocekivano 1): {isjecak!r}\n"
                f"        Engleska stranica se promijenila — uskladi PRIJEVOD u ovom alatu.\n"
                f"        Polu-prevedena stranica je gora od neprevedene.")
        html = html.replace(engleski, hrvatski, 1)

    html, zamjena = s_dijakriticima(html)
    upozorenja.append(f"__dijakritici__{zamjena}")

    for rijec in KONTROLNE_RIJECI:
        if rijec in html:
            upozorenja.append(f"neprevedeno: {rijec!r} jos je na stranici")
    return html, upozorenja


def _cli(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="python3 www/hrvatska_verzija.py",
        description="Prevedi nadopunjenu EHO6 stranicu na hrvatski (par s hreflang-om)")
    ap.add_argument("--izvor", default="www/eho6/index.html",
                    help="engleska stranica (izlaz iz nadopuni_stranicu.py)")
    ap.add_argument("--izlaz", default="www/eho6/hr/index.html")
    a = ap.parse_args(argv)

    izvor = Path(a.izvor)
    if not izvor.exists():
        print(f"GRESKA: nema {izvor} — pokreni prvo www/nadopuni_stranicu.py")
        return 2
    html = izvor.read_text(encoding="utf-8")
    if 'hreflang="hr"' not in html:
        print("GRESKA: engleska stranica nema hreflang par — nadopuni je prvo")
        return 2

    hrvatski, upozorenja = prevedi(html)

    izlaz = Path(a.izlaz)
    izlaz.parent.mkdir(parents=True, exist_ok=True)
    if izlaz.exists():
        kopija = izlaz.with_suffix(izlaz.suffix + ".bak")
        kopija.write_bytes(izlaz.read_bytes())
        print(f"[OK]  backup: {kopija}")
    izlaz.write_text(hrvatski, encoding="utf-8")

    dijakritika = [u for u in upozorenja if u.startswith("__dijakritici__")]
    upozorenja = [u for u in upozorenja if not u.startswith("__dijakritici__")]
    print(f"[OK]  prevedeno {len(PRIJEVOD)} blokova")
    if dijakritika:
        print(f"[OK]  dijakriticke zamjene: {dijakritika[0].split('__')[-1]}")
    print(f"[OK]  zapisano {izlaz} ({len(hrvatski)} B)")
    for u in upozorenja:
        print(f"[!!]  {u}")
    if not upozorenja:
        print("[OK]  kontrolne rijeci: nijedna engleska nije ostala")
    print(f"[..]  pustanje: sudo www/deploy_stranica.sh --cilj <docroot>/hr/index.html "
          f"--izvor {izlaz} --url https://genesis.limit-connect.com/quantum/eho6/hr/")
    return 1 if upozorenja else 0


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
