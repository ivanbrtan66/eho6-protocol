#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nadopuni ZIVU prezentacijsku stranicu EHO6 MASKA slojem — injekcijom, ne prepisom.

Zasto generator a ne nova stranica: stranica na
https://genesis.limit-connect.com/quantum/eho6/ vec postoji i ima svoj vizualni
jezik (tokeni --bg/--accent, JetBrains Mono + Inter, sekcije s // oznakama).
Nova stranica bacila bi to. Ovaj alat umece MASKA blok u postojeci dokument i
nad svakom tockom umetanja ima assert: ako se ziva stranica promijeni tako da
tocka nestane, alat PADNE i kaze gdje, umjesto da tiho proizvede pola stranice.

Idempotentno: ako je MASKA blok vec unutra, izlazi bez izmjene.

  python3 www/nadopuni_stranicu.py --izvor <preuzeta.html> --izlaz www/eho6/index.html
  python3 www/nadopuni_stranicu.py --preuzmi --izlaz www/eho6/index.html
"""
from __future__ import annotations

import argparse
import sys
import urllib.request
from pathlib import Path

ZIVI_URL = "https://genesis.limit-connect.com/quantum/eho6/"
OZNAKA = "<!-- MASKA (F1-F5) -->"

# =============================================================================
# CSS — u JEZIKU postojece stranice (njezini tokeni), imenovan maska-* da ne
# moze udariti u .feature/.step/.status-dot iz izvorne kaskade.
# =============================================================================
CSS = """
  /* ===== MASKA sloj (F1-F5) — dodano uz postojeci sustav tokena ===== */
  .maska-intro { max-width: 68ch; color: var(--text2); font-size: 1rem; }
  .maska-intro strong { color: var(--text); font-weight: 600; }
  .maska-record {
    margin: 1.6rem 0 0.5rem;
    background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 1rem 1.1rem; overflow-x: auto;
  }
  .maska-record code {
    font-family: var(--mono); font-size: 0.82rem; line-height: 1.9;
    white-space: pre; display: block; color: var(--text2);
  }
  .maska-record .k { color: var(--accent2); }
  .maska-record .v { color: var(--text); }
  .maska-caption { color: var(--text2); font-size: 0.84rem; margin-top: 0.6rem; }

  .maska-ladder { display: flex; flex-direction: column; gap: 0; margin-top: 1.8rem;
                  border: 1px solid var(--border); border-radius: var(--radius);
                  background: var(--bg2); overflow: hidden; }
  .maska-phase {
    display: grid; grid-template-columns: 7rem 1fr auto; gap: 1rem;
    align-items: baseline; padding: 1rem 1.2rem;
    border-top: 1px solid var(--border);
  }
  .maska-phase:first-child { border-top: none; }
  .maska-phase-code {
    font-family: var(--mono); font-size: 0.8rem; font-weight: 700;
    letter-spacing: 0.06em; color: var(--accent2);
  }
  .maska-phase h3 { font-size: 1rem; font-weight: 600; margin-bottom: 0.2rem; }
  .maska-phase p { color: var(--text2); font-size: 0.89rem; max-width: 62ch; }
  .maska-phase code { font-family: var(--mono); font-size: 0.83rem; color: var(--text); }
  .maska-pill {
    font-family: var(--mono); font-size: 0.68rem; letter-spacing: 0.08em;
    text-transform: uppercase; white-space: nowrap;
    border: 1px solid currentColor; border-radius: 99px; padding: 0.18rem 0.6rem;
  }
  .maska-pill.built { color: var(--green); }
  .maska-pill.partial { color: var(--orange); }
  .maska-pill.none { color: var(--text2); }

  .maska-figure { margin: 2rem 0 0; }
  .maska-figure svg { width: 100%; max-width: 100%; height: auto; display: block; }
  .maska-figure figcaption { color: var(--text2); font-size: 0.84rem; margin-top: 0.7rem;
                             max-width: 68ch; }
  .maska-two { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
               gap: 1rem; margin-top: 2rem; }
  .maska-box { background: var(--bg2); border: 1px solid var(--border);
               border-radius: var(--radius); padding: 1.1rem 1.2rem; }
  .maska-box.limits { border-left: 3px solid var(--orange); }
  .maska-box h3 { font-size: 0.95rem; font-weight: 600; margin-bottom: 0.7rem; }
  .maska-box ul { list-style: none; display: flex; flex-direction: column; gap: 0.55rem; }
  .maska-box li { color: var(--text2); font-size: 0.88rem; padding-left: 1.1rem;
                  position: relative; }
  .maska-box li::before { content: '\\2014'; position: absolute; left: 0;
                          color: var(--border); }
  .maska-box li b { color: var(--text); font-weight: 600; }
  .maska-box code { font-family: var(--mono); font-size: 0.82rem; color: var(--text); }
  .maska-measured { margin-top: 1.6rem; font-family: var(--mono); font-size: 0.8rem;
                    color: var(--text2); }
  .maska-measured b { color: var(--green); font-weight: 700; }
  .hero-new {
    display: inline-flex; align-items: center; gap: 0.5rem; margin-top: 1.6rem;
    font-family: var(--mono); font-size: 0.78rem; text-decoration: none;
    color: var(--accent2); border: 1px solid var(--border); border-radius: 99px;
    padding: 0.35rem 0.9rem; transition: border-color var(--transition);
  }
  .hero-new:hover { border-color: var(--accent2); }
  .hero-new span { color: var(--text2); }
  @media (max-width: 640px) {
    .maska-phase { grid-template-columns: 1fr; gap: 0.35rem; }
    .maska-phase-code { order: -1; }
  }
"""

# =============================================================================
# Dijagram — jedna tvrdnja: sto se tocno mijenja u F4.
# Boje: struktura u currentColor (radi u oba teme), jedan znacenjski element
# (neposredan put) u var(--accent2).
# =============================================================================
DIJAGRAM = """
  <figure class="maska-figure">
    <svg viewBox="0 0 860 260" role="img"
         aria-label="Before F4 all traffic passes through the anchor, which is a single point of failure. After F4 the anchor only exchanges signed candidates and traffic goes directly between peers.">
      <defs>
        <marker id="mk-arrow" viewBox="0 0 10 10" refX="9" refY="5"
                markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor"></path>
        </marker>
        <marker id="mk-arrow-direct" viewBox="0 0 10 10" refX="9" refY="5"
                markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--accent2)"></path>
        </marker>
      </defs>

      <!-- lijevo: F3 -->
      <text x="16" y="24" font-size="12" font-family="var(--mono)"
            fill="currentColor" opacity="0.55">F3 &#183; RIZOM (today)</text>
      <rect x="16" y="112" width="104" height="40" rx="8" fill="none"
            stroke="currentColor" stroke-width="1.5"></rect>
      <text x="68" y="137" font-size="12" text-anchor="middle" fill="currentColor">edge X96</text>
      <rect x="168" y="112" width="104" height="40" rx="8" fill="none"
            stroke="currentColor" stroke-width="1.5"></rect>
      <text x="220" y="137" font-size="12" text-anchor="middle" fill="currentColor">anchor</text>
      <rect x="320" y="112" width="88" height="40" rx="8" fill="none"
            stroke="currentColor" stroke-width="1.5"></rect>
      <text x="364" y="137" font-size="12" text-anchor="middle" fill="currentColor">peer</text>
      <line x1="120" y1="132" x2="164" y2="132" stroke="currentColor" stroke-width="1.5"
            marker-end="url(#mk-arrow)"></line>
      <line x1="272" y1="132" x2="316" y2="132" stroke="currentColor" stroke-width="1.5"
            marker-end="url(#mk-arrow)"></line>
      <text x="220" y="96" font-size="11" text-anchor="middle" fill="currentColor"
            opacity="0.75">all traffic</text>
      <text x="220" y="174" font-size="11" text-anchor="middle" fill="currentColor"
            opacity="0.55">sees everything</text>
      <text x="220" y="190" font-size="11" text-anchor="middle" fill="currentColor"
            opacity="0.55">anchor down = path down</text>

      <line x1="440" y1="40" x2="440" y2="230" stroke="currentColor" stroke-width="1"
            opacity="0.25"></line>

      <!-- desno: F4 -->
      <text x="470" y="24" font-size="12" font-family="var(--mono)"
            fill="var(--accent2)">F4 &#183; PROBOD</text>
      <rect x="470" y="152" width="104" height="40" rx="8" fill="none"
            stroke="currentColor" stroke-width="1.5"></rect>
      <text x="522" y="177" font-size="12" text-anchor="middle" fill="currentColor">edge X96</text>
      <rect x="672" y="152" width="88" height="40" rx="8" fill="none"
            stroke="currentColor" stroke-width="1.5"></rect>
      <text x="716" y="177" font-size="12" text-anchor="middle" fill="currentColor">peer</text>
      <rect x="560" y="52" width="112" height="40" rx="8" fill="none"
            stroke="currentColor" stroke-width="1.5" stroke-dasharray="4 3"></rect>
      <text x="616" y="77" font-size="12" text-anchor="middle" fill="currentColor">anchor</text>
      <line x1="540" y1="148" x2="580" y2="96" stroke="currentColor" stroke-width="1.2"
            stroke-dasharray="4 3" marker-end="url(#mk-arrow)"></line>
      <line x1="700" y1="148" x2="656" y2="96" stroke="currentColor" stroke-width="1.2"
            stroke-dasharray="4 3" marker-end="url(#mk-arrow)"></line>

      <line x1="578" y1="172" x2="666" y2="172" stroke="var(--accent2)" stroke-width="2.5"
            marker-end="url(#mk-arrow-direct)" marker-start="url(#mk-arrow-direct)"></line>
      <text x="622" y="206" font-size="11" text-anchor="middle" fill="var(--accent2)">direct UDP after punch</text>
      <text x="616" y="40" font-size="11" text-anchor="middle" fill="currentColor"
            opacity="0.75">signed candidates only</text>
      <text x="622" y="228" font-size="11" text-anchor="middle" fill="currentColor"
            opacity="0.55">anchor down = path survives</text>
    </svg>
    <figcaption>
      What F4 changes. Until the punch, the anchor carries the traffic and is both the
      single point of failure and the only place the traffic can be read. After the punch it
      exchanges signed candidates and nothing else &mdash; and its failure no longer drops an
      established path. Symmetric NAT (EDM) is the case where the punch cannot work; there the
      anchor stays a relay, and MASKA reports that instead of claiming success.
    </figcaption>
  </figure>
"""

SEKCIJA = OZNAKA + """
<div class="divider"></div>

<section id="maska">
  <p class="section-label">// address indirection layer</p>
  <h2>Where You Are Found Is Not Where You Live</h2>

  <p class="maska-intro">
    EHO6 proves <strong>who</strong> a node is. MASKA decides <strong>where</strong> it can be
    reached &mdash; and keeps that answer out of DNS. A static <code>A</code> record is a fact
    with no author and no expiry: whoever changes it has changed the truth. MASKA replaces it
    with a <strong>signed claim that expires</strong>, and moves the real location out of the
    public record entirely. The DNS name stays exactly where it is, because search reach is a
    real requirement &mdash; it is the <em>content</em> of the answer that changes.
  </p>

  <div class="maska-record">
    <code><span class="k">v</span>=<span class="v">PELUD1</span> <span class="k">ime</span>=<span class="v">medijapos.dnk</span> <span class="k">alg</span>=<span class="v">ed25519</span> <span class="k">pk</span>=<span class="v">&lt;64 hex&gt;</span> <span class="k">h</span>=<span class="v">4287</span> <span class="k">exp</span>=<span class="v">&lt;epoch&gt;</span>
<span class="k">loc</span>=<span class="v">wg://217.160.71.124:51820/&lt;key&gt;|https://mirror.example</span> <span class="k">sig</span>=<span class="v">&lt;base64url&gt;</span></code>
  </div>
  <p class="maska-caption">
    One PELUD record. It extends the GENESIS1 DNS TXT format already in use rather than
    inventing a new one. Unknown fields, non-canonical spelling, an expired claim, a missing
    pinned key, or a reserved-but-unimplemented <code>alg</code> (e.g. <code>ml-dsa-65</code>)
    are all <em>rejected</em> &mdash; never silently accepted. A signature checked with the key from the same record proves
    nothing, so verification without a pinned key fails by design.
  </p>

  <div class="maska-ladder">
    <div class="maska-phase">
      <span class="maska-phase-code">F1 PELUD</span>
      <div>
        <h3>Signed, expiring locator record</h3>
        <p>Ed25519 over a fixed canonical field order, one-hour maximum lifetime, verified
           against a pinned key. The address stops being a fact and becomes a claim with a
           deadline.</p>
      </div>
      <span class="maska-pill built">Built</span>
    </div>
    <div class="maska-phase">
      <span class="maska-phase-code">F2 dnkd</span>
      <div>
        <h3>Local resolver for <code>.dnk</code></h3>
        <p>Name resolution becomes a local function of the host again, the way ARPANET's
           <code>HOSTS.TXT</code> worked before DNS existed &mdash; but pulled, signed, and
           expiring. Everything outside <code>.dnk</code> gets <code>REFUSED</code>: a resolver
           that forwards becomes a proxy for all of your traffic. It installs no CA into the
           system trust store, ever.</p>
      </div>
      <span class="maska-pill built">Built</span>
    </div>
    <div class="maska-phase">
      <span class="maska-phase-code">F3 RIZOM</span>
      <div>
        <h3>Dual-anchor WireGuard</h3>
        <p>Replaces a single <code>ssh -R</code> reverse tunnel, which is a user-space TCP
           session that goes half-open when ISP NAT forgets the mapping &mdash; device alive,
           tunnel dead, neither side aware. Two anchors, kernel WireGuard, stateless handshake,
           <code>AllowedIPs</code> restricted to the anchor's <code>/32</code> so ordinary
           traffic is untouched.</p>
      </div>
      <span class="maska-pill partial">Tooling built &#183; pilot pending</span>
    </div>
    <div class="maska-phase">
      <span class="maska-phase-code">F4 PROBOD</span>
      <div>
        <h3>Direct punch through NAT</h3>
        <p>The anchor runs its own STUN and a signed rendezvous board; peers measure their NAT,
           exchange signed candidates, punch simultaneously, and hand the winning path to
           WireGuard only after a handshake actually moves. This is the phase that removes the
           single point of failure rather than relocating it. The rendezvous service has no
           route that carries payload &mdash; a test fails if one ever appears.</p>
      </div>
      <span class="maska-pill partial">Built &#183; field pilot pending</span>
    </div>
    <div class="maska-phase">
      <span class="maska-phase-code">F5 OGLASNIK</span>
      <div>
        <h3>K-of-N announcement boards</h3>
        <p>N registrars, TLDs and jurisdictions with K-of-N consensus before any redirect:
           a board redirects only when K independent boards hold the same signed claim, so
           seizing one domain changes nothing. The config refuses a K that is not a strict
           majority. An earlier version of this project said this phase costs search reach
           &mdash; it does not, as long as the boards are <code>noindex</code> redirectors
           with <code>rel=canonical</code> rather than copies of the site.</p>
      </div>
      <span class="maska-pill partial">Built &#183; domains not bought</span>
    </div>
  </div>
""" + DIJAGRAM + """
  <div class="maska-two">
    <div class="maska-box">
      <h3>What the network decides, not the code</h3>
      <ul>
        <li><b>EIM</b> &mdash; the NAT hands out the same external address regardless of
            destination, so the address one anchor sees is usable by a third party.
            <code>Punch possible.</code></li>
        <li><b>EDM (symmetric)</b> &mdash; a new port per destination. The address the EU anchor
            sees is valid for nobody else. <code>Relay stays.</code> Reported as EDM, not
            attempted and quietly downgraded.</li>
        <li><b>Unknown</b> &mdash; measuring this needs two vantage points on different IP
            addresses. With one anchor the answer is <code>NEPOZNATO</code>; &ldquo;probably
            fine&rdquo; is not a measurement.</li>
      </ul>
    </div>
    <div class="maska-box limits">
      <h3>What MASKA does not do</h3>
      <ul>
        <li>It does not remove the <code>A</code> record. No unmodified browser can reach you
            without DNS, an IP and a route; every alternative trades away reach.</li>
        <li>It does not install a certificate authority. A local CA would be a key for
            <em>every</em> site on that device &mdash; real damage, not protection.</li>
        <li>The chain height in a record is carried, <b>not verified</b> against the chain.</li>
        <li>There is <b>no key revocation</b> yet; a short expiry limits how long a compromise
            lasts, not that it happened.</li>
        <li>The measurement ledger is hash-chained locally but <b>not anchored</b> in the
            chain, so whoever holds the file could rewrite all of it.</li>
      </ul>
    </div>
  </div>

  <p class="maska-measured">
    Measured on the build host, not estimated: signature <b>4 ms</b> &#183; verification
    <b>4 ms</b> &#183; full name resolution including PULL <b>14 ms</b> &#183; <b>242 tests</b>,
    standard library only, no network egress. Ed25519 is checked against RFC&nbsp;8032 &sect;7.1
    vectors, X25519 against RFC&nbsp;7748 &sect;5.2 plus a cross-check against OpenSSL, and the
    NAT simulator models RFC&nbsp;4787 mapping and filtering classes &mdash; including the
    <em>failure</em> cases: a punch through a symmetric NAT fails even when the code is told the
    NAT is EIM. What is still open is the field pilot on real CGNAT hardware; the pass criterion
    was set before the measurement: seven days with both paths measured in parallel and no
    watchdog alarm.
  </p>
</section>
"""

# =============================================================================
# Injekcije: (opis, sidro, sto_umetnuti, prije_ili_poslije)
# =============================================================================
NAV_SIDRO = '    <a href="#anchors">Anchors</a>\n'
NAV_NOVO = '    <a href="#maska">MASKA</a>\n'

HERO_SIDRO = '''    <a class="btn btn-outline" href="https://github.com/ivanbrtan66/eho6-protocol" target="_blank" rel="noopener">&#128279; GitHub</a>
  </div>
'''
HERO_NOVO = '''    <a class="btn btn-outline" href="https://github.com/ivanbrtan66/eho6-protocol" target="_blank" rel="noopener">&#128279; GitHub</a>
  </div>
  <a class="hero-new" href="#maska">New &#183; MASKA address indirection
    <span>&mdash; signed, expiring location &rarr;</span></a>
'''

SEKCIJA_SIDRO = "<!-- ANCHOR STATUS -->"

RESURSI_SIDRO = '''    <a class="btn btn-outline" href="https://genesis.limit-connect.com/borg/health.json" target="_blank">
      &#129658; Anchor Health JSON
    </a>
'''
RESURSI_NOVO = RESURSI_SIDRO + '''    <a class="btn btn-outline" href="https://github.com/ivanbrtan66/eho6-protocol/blob/main/docs/MASKA-FAZE.md" target="_blank" rel="noopener">
      &#129517; MASKA phases (F1&ndash;F5)
    </a>
'''

# Ispravak stvarne netocnosti na zivoj stranici: install.sh trazi Python 3.11+
# ("Python 3.11+ required. Found none."), a stranica obecava 3.9+. Korisnik bi
# pokrenuo instalaciju i dobio gresku koju stranica nije najavila.
PYTHON_STARO = "Requires: Linux/macOS &middot; Python 3.9+ &middot; stdlib only"
PYTHON_NOVO = "Requires: Linux/macOS &middot; Python 3.11+ &middot; stdlib only"



# Dvojezicna postava: hreflang par umjesto prijevoda preko postojece stranice.
# Razlog je c1570: SEO doseg je STVARAN zahtjev zbog kojeg DNS uopce ostaje.
# Prijevod jedne stranice gubi globalni doseg; par /quantum/eho6/ + /hr/ ga
# povecava, jer trazilica indeksira obje i svakoj salje njezinu publiku.
HREFLANG = """<link rel="alternate" hreflang="en" href="https://genesis.limit-connect.com/quantum/eho6/">
<link rel="alternate" hreflang="hr" href="https://genesis.limit-connect.com/quantum/eho6/hr/">
<link rel="alternate" hreflang="x-default" href="https://genesis.limit-connect.com/quantum/eho6/">
"""

PREKIDAC_JEZIKA = """    <span class="jezik"><a class="jezik-aktivan" href="/quantum/eho6/" hreflang="en">EN</a><a href="/quantum/eho6/hr/" hreflang="hr">HR</a></span>
"""

CSS_JEZIK = """
  /* prekidac jezika */
  .jezik { display: inline-flex; border: 1px solid var(--border); border-radius: 6px;
           overflow: hidden; font-family: var(--mono); font-size: 0.72rem; }
  .jezik a { padding: 0.25rem 0.5rem; color: var(--text2); text-decoration: none;
             transition: color var(--transition), background var(--transition); }
  .jezik a:hover { color: var(--text); }
  .jezik a.jezik-aktivan { background: var(--bg3); color: var(--accent); }
"""

JS_STARO = """    var stored = localStorage.getItem('eho6-theme') || 'dark';"""
JS_NOVO = """    var stored = 'dark';
    try { stored = localStorage.getItem('eho6-theme') || 'dark'; } catch (e) { /* privatni prozor: tema se ne pamti, prekidac i dalje radi */ }"""

JS_STARO2 = """      localStorage.setItem('eho6-theme', next);"""
JS_NOVO2 = """      try { localStorage.setItem('eho6-theme', next); } catch (e) {}"""


def nadopuni(html: str) -> tuple[str, list[str]]:
    """Vrati (nova_stranica, popis_izmjena). Pada ako sidro nestane."""
    if OZNAKA in html:
        return html, []
    izmjene: list[str] = []

    def zamijeni(sidro: str, novo: str, opis: str, obavezno: bool = True) -> None:
        nonlocal html
        broj = html.count(sidro)
        if broj != 1:
            if obavezno:
                raise SystemExit(
                    f"GRESKA: sidro za '{opis}' nadjeno {broj} puta (ocekivano 1). "
                    f"Ziva stranica se promijenila — ispravi sidro u ovom alatu, "
                    f"ne diraj stranicu na slijepo.")
            izmjene.append(f"PRESKOCENO: {opis} (sidro nije nadjeno {broj}x)")
            return
        html = html.replace(sidro, novo, 1)
        izmjene.append(opis)

    zamijeni("</style>", CSS + CSS_JEZIK + "</style>", "CSS za MASKA blok i prekidac jezika")
    zamijeni('<link rel="preconnect" href="https://fonts.googleapis.com">',
             HREFLANG + '<link rel="preconnect" href="https://fonts.googleapis.com">',
             "hreflang par (en / hr / x-default)")
    zamijeni(NAV_SIDRO, NAV_SIDRO + PREKIDAC_JEZIKA, "navigacija: prekidac jezika EN/HR")
    zamijeni(NAV_SIDRO, NAV_NOVO + NAV_SIDRO, "navigacija: link MASKA")
    zamijeni(HERO_SIDRO, HERO_NOVO, "hero: pilula 'New — MASKA'")
    zamijeni(SEKCIJA_SIDRO, SEKCIJA + "\n" + SEKCIJA_SIDRO, "sekcija #maska (F1-F5 + dijagram)")
    zamijeni(RESURSI_SIDRO, RESURSI_NOVO, "resursi: link na docs/MASKA-FAZE.md")
    zamijeni(PYTHON_STARO, PYTHON_NOVO,
             "ispravak: Python 3.9+ -> 3.11+ (install.sh stvarno trazi 3.11+)", obavezno=False)
    zamijeni(JS_STARO, JS_NOVO,
             "ispravak: citanje teme iz localStorage u try/catch (privatni prozor)",
             obavezno=False)
    zamijeni(JS_STARO2, JS_NOVO2,
             "ispravak: pisanje teme u localStorage u try/catch", obavezno=False)
    return html, izmjene


def _cli(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="python3 www/nadopuni_stranicu.py",
                                 description="Umetni MASKA blok u postojecu EHO6 stranicu")
    ap.add_argument("--izvor", help="lokalna kopija zive stranice (HTML)")
    ap.add_argument("--preuzmi", action="store_true", help=f"preuzmi s {ZIVI_URL}")
    ap.add_argument("--izlaz", required=True, help="gdje zapisati nadopunjenu stranicu")
    a = ap.parse_args(argv)

    if a.preuzmi:
        with urllib.request.urlopen(ZIVI_URL, timeout=20) as odgovor:
            if odgovor.status != 200:
                print(f"GRESKA: {ZIVI_URL} vraca HTTP {odgovor.status}")
                return 1
            html = odgovor.read().decode("utf-8")
        print(f"[OK]  preuzeto {len(html)} B s {ZIVI_URL}")
    elif a.izvor:
        html = Path(a.izvor).read_text(encoding="utf-8")
        print(f"[OK]  procitano {len(html)} B iz {a.izvor}")
    else:
        print("GRESKA: daj --izvor <datoteka> ili --preuzmi")
        return 2

    prije = len(html)
    novo, izmjene = nadopuni(html)
    if not izmjene:
        print("[--]  MASKA blok je vec u stranici — nista se ne mijenja (idempotentno)")
    izlaz = Path(a.izlaz)
    izlaz.parent.mkdir(parents=True, exist_ok=True)
    if izlaz.exists():
        kopija = izlaz.with_suffix(izlaz.suffix + ".bak")
        kopija.write_bytes(izlaz.read_bytes())
        print(f"[OK]  backup: {kopija}")
    izlaz.write_text(novo, encoding="utf-8")
    for opis in izmjene:
        print(f"[OK]  {opis}")
    print(f"[OK]  zapisano {izlaz} ({prije} -> {len(novo)} B, +{len(novo) - prije})")
    print(f"[..]  pustanje na sidro: sudo www/deploy_stranica.sh --cilj <putanja/index.html> "
          f"--izvor {izlaz}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
