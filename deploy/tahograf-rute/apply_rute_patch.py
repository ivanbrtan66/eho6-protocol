#!/usr/bin/env python3
"""
apply_rute_patch.py — dispecerski tab "Rute" + OSRM auto-routing (tahograf-mvp)

Pokrece se NA EU NODE-u, kao root:

    cd /var/www/genesis/tahograf-mvp
    python3 apply_rute_patch.py --dry-run     # prikaz bez pisanja
    python3 apply_rute_patch.py               # primjena + backup + chown

Mijenja tri fajla:
  api/tahograf_features.py   +  POST /api/v1/geo/route (OSRM Trip proxy)
                             +  /api/v1/geo/search vraca city/plz/country/admin
  pwa/dispatcher.html        +  tab gumb, panel, CSS
  pwa/dispatcher.js          +  RuteModule (append na kraj, bez diranja postojeceg)

Svaka izmjena je anchor-provjerena: ako se anchor ne nade TOCNO jednom, skripta
staje i ne pise nista. Idempotentna je — drugi pokret preskace vec primijenjene
dijelove. Prije pisanja radi .bak_<timestamp> kopiju svakog dirnutog fajla.
"""
import argparse
import os
import shutil
import subprocess
import sys
import time

ROOT = "/var/www/genesis/tahograf-mvp"
OWNER = "www-data:www-data"

FEATURES = "api/tahograf_features.py"
DISP_HTML = "pwa/dispatcher.html"
DISP_JS = "pwa/dispatcher.js"


# ══════════════════════════════════════════════════════════════════════════
# 1) BACKEND — anchor: kraj geo_reverse()
# ══════════════════════════════════════════════════════════════════════════
A_GEO_REVERSE_END = '''    except Exception as exc:
        logger.warning("geo/reverse pao: %s", exc)
        return jsonify(None), 200
'''

P_GEO_ROUTE = '''    except Exception as exc:
        logger.warning("geo/reverse pao: %s", exc)
        return jsonify(None), 200


# ── GEO — obogaceni zapis mjesta ───────────────────────────────────────────
# pwa/geocode.js crta dropdown iz polja city/plz/country/admin. Nominatim ih
# vraca ugnijezdena u "address", pa ih ovdje podizemo na razinu zapisa; stara
# polja (display_name/lat/lon/lng/tip/adresa) ostaju netaknuta.
def _geo_item(x: dict) -> dict:
    a = x.get("address", {}) or {}
    city = (a.get("city") or a.get("town") or a.get("village")
            or a.get("municipality") or a.get("hamlet") or a.get("suburb")
            or a.get("county") or (x.get("display_name") or "").split(",")[0].strip())
    return {"display_name": x.get("display_name"),
            "lat": float(x["lat"]), "lon": float(x["lon"]), "lng": float(x["lon"]),
            "tip": x.get("type"), "adresa": a,
            "city": city,
            "plz": a.get("postcode", ""),
            "country": (a.get("country_code") or "").upper(),
            "admin": a.get("state") or a.get("county") or ""}


# ── GEO ROUTE — OSRM Trip API proxy (optimalan redoslijed stopova) ─────────
@feat_bp.route("/api/v1/geo/route", methods=["POST"])
@verify_token
def geo_route():
    """
    body: {tocke: [{lat, lon}, ...]}  (2-12 tocaka)
    Prva tocka = fiksni start, zadnja = fiksno odrediste; OSRM Trip optimizira
    redoslijed tocaka IZMEDU njih. Fail-soft: ako OSRM padne, vraca ok:false s
    razumljivom porukom (frontend nastavlja rucnim redom — auto-izracun je
    pomoc, ne uvjet za kreiranje rute).
    """
    body = request.get_json(silent=True) or {}
    tocke = body.get("tocke") or []
    if not isinstance(tocke, list) or len(tocke) < 2:
        return jsonify({"ok": False, "detail": "Treba minimalno 2 tocke s koordinatama"}), 400
    if len(tocke) > 12:
        return jsonify({"ok": False, "detail": "Maksimalno 12 destinacija po ruti"}), 400
    try:
        coords = ";".join("%f,%f" % (float(t["lon"]), float(t["lat"])) for t in tocke)
    except (KeyError, TypeError, ValueError):
        return jsonify({"ok": False, "detail": "Svaka tocka mora imati lat i lon"}), 400
    url = "https://router.project-osrm.org/trip/v1/driving/" + coords
    params = {"source": "first", "destination": "last", "roundtrip": "false",
              "overview": "full", "geometries": "geojson"}
    try:
        r = requests.get(url, params=params, headers=_UA, timeout=15)
        if not r.ok:
            return jsonify({"ok": False, "detail": "OSRM vratio %s" % r.status_code}), 200
        d = r.json()
        if d.get("code") != "Ok" or not d.get("trips"):
            return jsonify({"ok": False,
                            "detail": d.get("message", "OSRM nije pronasao rutu")}), 200
        trip = d["trips"][0]
        wps = d.get("waypoints") or []
        if len(wps) != len(tocke):
            return jsonify({"ok": False, "detail": "OSRM vratio neocekivan broj tocaka"}), 200
        try:
            # waypoints[i].waypoint_index = pozicija ulazne tocke i u optimiziranom nizu,
            # pa sortiranje ulaznih indeksa po njemu daje redoslijed obilaska.
            redoslijed = sorted(range(len(tocke)),
                                key=lambda i: wps[i]["waypoint_index"])
        except (KeyError, TypeError):
            return jsonify({"ok": False, "detail": "OSRM odgovor bez waypoint_index"}), 200
        return jsonify({
            "ok": True,
            "redoslijed": redoslijed,
            "distanca_km": round(trip["distance"] / 1000, 1),
            "trajanje_min": round(trip["duration"] / 60),
            "geometry": trip.get("geometry"),
        }), 200
    except Exception as exc:
        logger.warning("geo/route (OSRM) pao: %s", exc)
        return jsonify({"ok": False, "detail": "Routing servis nedostupan: %s" % exc}), 200
'''

# ── BACKEND — geo_search koristi _geo_item ────────────────────────────────
A_GEO_SEARCH_OUT = '''        out = [{"display_name": x.get("display_name"),
                "lat": float(x["lat"]), "lon": float(x["lon"]), "lng": float(x["lon"]),
                "tip": x.get("type"), "adresa": x.get("address", {})}
               for x in r.json() if x.get("lat") and x.get("lon")]
'''

P_GEO_SEARCH_OUT = '''        out = [_geo_item(x) for x in r.json() if x.get("lat") and x.get("lon")]
'''


# ══════════════════════════════════════════════════════════════════════════
# 2) HTML — tab gumb
# ══════════════════════════════════════════════════════════════════════════
A_TAB_BTN = ('          <button class="dtab" id="tab-burza" data-action="switch-tab"'
             ' data-tab="burza">&#x1F9E7; Burza</button>\n')

P_TAB_BTN = A_TAB_BTN + ('          <button class="dtab" id="tab-rute" data-action="switch-tab"'
                         ' data-tab="rute">&#x1F4CD; Rute</button>\n')

# ── HTML — CSS (svaki panel ima VLASTITO id-pravilo; generickog nema) ─────
A_CSS = '''    #tab-burza-panel.on{display:block}
'''

P_CSS = '''    #tab-burza-panel.on{display:block}

    /* Rute tab — dispecerska multi-stop ruta vozacu */
    #tab-rute-panel{flex:1;overflow-y:auto;display:none}
    #tab-rute-panel.on{display:block}
    #rute-stops-container{display:flex;flex-direction:column;gap:.5rem;margin-top:.5rem}
    .rute-stop-row{display:flex;gap:.5rem;align-items:center}
    .rute-stop-lbl{font-size:.78rem;color:var(--text3);width:1.4rem;flex-shrink:0}
    .rute-banner{display:none;font-size:.8rem;line-height:1.5;border-radius:8px;padding:.5rem .75rem;margin-top:.5rem}
    .rute-banner-ok{color:#2ecc71;background:rgba(46,204,113,.08);border:1px solid rgba(46,204,113,.2)}
    .rute-banner-err{color:#e74c3c;background:rgba(231,76,60,.08);border:1px solid rgba(231,76,60,.2)}
'''

# ── HTML — panel (ide odmah iza zatvaranja burza panela) ─────────────────
A_PANEL = '''          <div class="burza-list" id="burza-list">
            <div class="burza-empty">U\u010ditavanje ponuda&#x2026;</div>
          </div>
        </div>
'''

P_PANEL = A_PANEL + '''
        <!-- RUTE — dispe\u010derska multi-stop ruta voza\u010du -->
        <div id="tab-rute-panel">
          <div style="padding:1rem">
            <div class="dispo-create-form">
              <div class="dispo-form-title">&#x1F4CD; Nova ruta voza\u010du</div>
              <div class="dispo-form-grid">
                <select class="dispo-inp dispo-form-full" id="rute-vozac-sel">
                  <option value="">\u2014 odaberi voza\u010da \u2014</option>
                </select>
                <input class="dispo-inp" id="rute-datum" type="date" title="Datum rute">
                <input class="dispo-inp" id="rute-napomena" placeholder="Napomena (opcionalno)" autocomplete="off">
              </div>
              <div id="rute-stops-container">
                <div class="rute-stop-row" data-idx="0">
                  <span class="rute-stop-lbl">1.</span>
                  <input class="dispo-inp rute-stop-naziv" placeholder="Naziv (npr. Skladi\u0161te Zagreb)" style="max-width:11rem">
                  <input class="dispo-inp rute-stop-adresa" placeholder="Adresa ili grad&#x2026;" autocomplete="off">
                </div>
                <div class="rute-stop-row" data-idx="1">
                  <span class="rute-stop-lbl">2.</span>
                  <input class="dispo-inp rute-stop-naziv" placeholder="Naziv" style="max-width:11rem">
                  <input class="dispo-inp rute-stop-adresa" placeholder="Adresa ili grad&#x2026;" autocomplete="off">
                </div>
              </div>
              <button type="button" class="btn-sm" data-action="rute-add-stop" style="margin-top:.5rem">+ Dodaj destinaciju</button>
              <div id="rute-calc-result" class="rute-banner rute-banner-ok"></div>
              <button class="dispo-create-btn" id="rute-calc-btn" data-action="rute-calc" style="background:rgba(52,152,219,.12);border-color:rgba(52,152,219,.3);color:#3498db">&#x1F9ED; Izra\u010dunaj optimalnu rutu</button>
              <button class="dispo-create-btn" id="rute-create-btn" data-action="rute-create">&#x2705; Kreiraj rutu</button>
              <div id="rute-create-ok" class="rute-banner rute-banner-ok"></div>
              <div id="rute-create-err" class="rute-banner rute-banner-err"></div>
            </div>
          </div>
        </div>
'''


# ══════════════════════════════════════════════════════════════════════════
# 3) JS — append na kraj dispatcher.js (nijedan postojeci redak se ne dira)
# ══════════════════════════════════════════════════════════════════════════
P_JS = '''

/* ═══════════════════════════════════════════════════════════════════════════
   RUTE — dispecerska multi-stop ruta vozacu (tab "Rute")
     POST /api/v1/geo/route      -> OSRM Trip: optimalan redoslijed + km/min
     POST /api/v1/tahograf/rute  -> {driver_weise3, destinacije[], napomena, datum}
   Vozacka strana (pwa/routes.js) cita destinaciju kao {naziv, adresa, lat, lon}.
   Cist append: fleet_id se cita iz localStorage, vozaci iz vec popunjenog
   #chat-vozac-sel — nijedna postojeca varijabla/funkcija se ne mijenja.
   ES2017 (bez ?. i ??) jer build.js transpilira pwa/*.js na chrome60.
   ═════════════════════════════════════════════════════════════════════════ */
window.RuteModule = (function() {
  "use strict";
  const MAX_STOPS = 12;
  const STORAGE_FLEET = "tg_disp_fleet_v2";

  function _hdr() {
    const tok = window.GenesisAuth && window.GenesisAuth.getToken
      ? window.GenesisAuth.getToken()
      : localStorage.getItem("tg_session_token");
    return { "Content-Type": "application/json", "Authorization": "Bearer " + (tok || "") };
  }
  function _esc(s) {
    return String(s === null || s === undefined ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function _el(id) { return document.getElementById(id); }
  function _show(el, text) { if (el) { el.textContent = text; el.style.display = "block"; } }
  function _hide(el) { if (el) el.style.display = "none"; }

  // Vozaci: #chat-vozac-sel puni loadStatus2() svakih 30s istim popisom, pa ga
  // preslikamo. Ako jos nije popunjen (tab otvoren prije prvog refresha),
  // povucemo fleet status sami.
  function _populateVozaci() {
    const sel = _el("rute-vozac-sel");
    if (!sel) return;
    const chatSel = _el("chat-vozac-sel");
    if (chatSel && chatSel.options.length > 1) {
      const cur = sel.value;
      sel.innerHTML = chatSel.innerHTML;
      if (cur) sel.value = cur;
      return;
    }
    const fleetId = localStorage.getItem(STORAGE_FLEET);
    if (!fleetId) return;
    fetch("/api/v1/tahograf/fleet/" + fleetId + "/status", { headers: _hdr() })
      .then(function(r) { return r.ok ? r.json() : null; })
      .then(function(d) {
        if (!d) return;
        const cur = sel.value;
        sel.innerHTML = '<option value="">\\u2014 odaberi voza\\u010da \\u2014</option>' +
          (d.vozaci || []).map(function(v) {
            return '<option value="' + _esc(v.weise3_id) + '">' + _esc(v.display_name) + "</option>";
          }).join("");
        if (cur) sel.value = cur;
      })
      .catch(function() { /* fail-soft: prazan select, greska se vidi pri submitu */ });
  }

  // geocode.js zapis: {city, plz, country, admin, lat, lng}. Fallback na
  // display_name da polje nikad ne ostane prazno ni ako backend vrati manje.
  function _label(item) {
    const city = item.city || item.display_name || "";
    return item.plz ? city + " (" + item.plz + ")" : city;
  }
  function _wireAutocomplete(row) {
    const input = row.querySelector(".rute-stop-adresa");
    if (!input || input.dataset.geoWired) return;
    if (!window.DgGeocode || !window.DgGeocode.attachAutocomplete) return;
    input.dataset.geoWired = "1";
    window.DgGeocode.attachAutocomplete(input, {
      onSelect: function(item) {
        input.value = _label(item);
        input.dataset.lat = item.lat;
        input.dataset.lon = (item.lng !== undefined && item.lng !== null) ? item.lng : item.lon;
      }
    });
  }
  function _wireAllRows() {
    const rows = document.querySelectorAll("#rute-stops-container .rute-stop-row");
    Array.prototype.forEach.call(rows, _wireAutocomplete);
  }

  function _rowHtml(i, naziv, adresa) {
    return '<span class="rute-stop-lbl">' + (i + 1) + '.</span>' +
      '<input class="dispo-inp rute-stop-naziv" placeholder="Naziv" style="max-width:11rem" value="' + _esc(naziv) + '">' +
      '<input class="dispo-inp rute-stop-adresa" placeholder="Adresa ili grad\\u2026" autocomplete="off" value="' + _esc(adresa) + '">';
  }
  function _renderStops(stops) {
    const c = _el("rute-stops-container");
    if (!c) return;
    c.innerHTML = "";
    stops.forEach(function(s, i) {
      const row = document.createElement("div");
      row.className = "rute-stop-row";
      row.dataset.idx = i;
      row.innerHTML = _rowHtml(i, s.naziv || "", s.adresa || "");
      c.appendChild(row);
      const inp = row.querySelector(".rute-stop-adresa");
      if (s.lat !== null && s.lat !== undefined && s.lon !== null && s.lon !== undefined) {
        inp.dataset.lat = s.lat;
        inp.dataset.lon = s.lon;
      }
      _wireAutocomplete(row);
    });
  }
  function _collectStops() {
    const rows = document.querySelectorAll("#rute-stops-container .rute-stop-row");
    const out = [];
    Array.prototype.forEach.call(rows, function(row) {
      const nazivInp = row.querySelector(".rute-stop-naziv");
      const adresaInp = row.querySelector(".rute-stop-adresa");
      if (!adresaInp) return;
      const naziv = nazivInp ? nazivInp.value.trim() : "";
      const adresa = adresaInp.value.trim();
      if (!adresa) return;
      // attachAutocomplete usput puni geoLat/geoLng — citamo oba izvora.
      const lat = parseFloat(adresaInp.dataset.lat || adresaInp.dataset.geoLat);
      const lon = parseFloat(adresaInp.dataset.lon || adresaInp.dataset.geoLng);
      out.push({
        naziv: naziv || adresa,
        adresa: adresa,
        lat: isNaN(lat) ? null : lat,
        lon: isNaN(lon) ? null : lon
      });
    });
    return out;
  }

  function addStop() {
    const c = _el("rute-stops-container");
    if (!c) return;
    const idx = c.querySelectorAll(".rute-stop-row").length;
    if (idx >= MAX_STOPS) {
      _show(_el("rute-create-err"), "Maksimalno " + MAX_STOPS + " destinacija po ruti.");
      return;
    }
    const row = document.createElement("div");
    row.className = "rute-stop-row";
    row.dataset.idx = idx;
    row.innerHTML = _rowHtml(idx, "", "");
    c.appendChild(row);
    _wireAutocomplete(row);
  }

  async function calc() {
    const btn = _el("rute-calc-btn");
    const okEl = _el("rute-calc-result");
    const errEl = _el("rute-create-err");
    _hide(errEl);
    _hide(_el("rute-create-ok"));
    _hide(okEl);
    const stops = _collectStops();
    const sGeo = stops.filter(function(s) { return s.lat !== null && s.lon !== null; });
    const sPlain = stops.filter(function(s) { return s.lat === null || s.lon === null; });
    if (sGeo.length < 2) {
      _show(errEl, "Za izra\\u010dun treba najmanje 2 destinacije odabrane iz padaju\\u0107e liste (samo one nose koordinate).");
      return;
    }
    btn.disabled = true;
    btn.textContent = "\\u23f3 Ra\\u010dunam rutu\\u2026";
    try {
      const r = await fetch("/api/v1/geo/route", {
        method: "POST",
        headers: _hdr(),
        body: JSON.stringify({
          tocke: sGeo.map(function(s) { return { lat: s.lat, lon: s.lon }; })
        })
      });
      const d = await r.json();
      if (!d || !d.ok) throw new Error((d && d.detail) || "Izra\\u010dun nije uspio");
      const order = d.redoslijed || [];
      const reordered = order.map(function(i) { return sGeo[i]; })
                             .filter(function(s) { return !!s; });
      // Destinacije bez koordinata se NE gube — ostaju na kraju popisa.
      _renderStops(reordered.concat(sPlain));
      _show(okEl, "\\u2713 Optimalna ruta: " + d.distanca_km + " km \\u00b7 ~" + d.trajanje_min +
        " min. Redoslijed je preure\\u0111en ispod." +
        (sPlain.length ? " (" + sPlain.length + " bez koordinata \\u2014 ostavljeno na kraju)" : ""));
    } catch (e) {
      _show(errEl, "Izra\\u010dun rute nije uspio: " + e.message +
        " \\u2014 rutu mo\\u017ee\\u0161 kreirati i bez izra\\u010duna, redoslijed ostaje kako si unio.");
    } finally {
      btn.disabled = false;
      btn.textContent = "\\ud83e\\udded Izra\\u010dunaj optimalnu rutu";
    }
  }

  async function create() {
    const btn = _el("rute-create-btn");
    const errEl = _el("rute-create-err");
    const okEl = _el("rute-create-ok");
    _hide(errEl);
    _hide(okEl);
    const vozacSel = _el("rute-vozac-sel");
    const vozac = vozacSel ? vozacSel.value : "";
    const datumEl = _el("rute-datum");
    const datum = datumEl ? datumEl.value : "";
    const napomenaEl = _el("rute-napomena");
    const napomena = napomenaEl ? napomenaEl.value : "";
    const stops = _collectStops();
    if (!vozac) { _show(errEl, "Odaberi voza\\u010da."); return; }
    if (!stops.length) { _show(errEl, "Unesi barem jednu destinaciju."); return; }
    const body = { driver_weise3: vozac, destinacije: stops, napomena: napomena };
    if (datum) body.datum = datum;
    btn.disabled = true;
    btn.textContent = "\\u23f3 Kreiranje\\u2026";
    try {
      const r = await fetch("/api/v1/tahograf/rute", {
        method: "POST", headers: _hdr(), body: JSON.stringify(body)
      });
      const d = await r.json();
      if (!r.ok || !d.ok) throw new Error((d && d.detail) || "Kreiranje rute nije uspjelo");
      _renderStops([{ naziv: "", adresa: "" }, { naziv: "", adresa: "" }]);
      if (napomenaEl) napomenaEl.value = "";
      _hide(_el("rute-calc-result"));
      _show(okEl, "\\u2713 Ruta kreirana i dodijeljena voza\\u010du (" + String(d.ruta_id || "").slice(0, 12) + "\\u2026).");
    } catch (e) {
      _show(errEl, "Gre\\u0161ka: " + e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "\\u2705 Kreiraj rutu";
    }
  }

  function init() {
    _populateVozaci();
    const datum = _el("rute-datum");
    if (datum && !datum.value) datum.value = new Date().toISOString().slice(0, 10);
    _wireAllRows();
  }

  return { init: init, addStop: addStop, calc: calc, create: create };
})();

/* switchTab wrapper — isti obrazac kao postojeci dispo/burza wrapper gore.
   Unutarnji wrapper gasi svih 6 postojecih panela, ovaj dodaje sedmi. */
(function() {
  const _prevSwitch = window.switchTab;
  window.switchTab = function(name) {
    if (typeof _prevSwitch === "function") _prevSwitch(name);
    const btn = document.getElementById("tab-rute");
    const panel = document.getElementById("tab-rute-panel");
    if (btn) btn.classList.toggle("on", name === "rute");
    if (panel) panel.classList.toggle("on", name === "rute");
    if (name === "rute" && window.RuteModule) window.RuteModule.init();
  };
})();

/* data-action delegacija (dispatcher-events.js ne zna za rute-* akcije) */
document.addEventListener("click", function(e) {
  const t = e.target.closest("[data-action]");
  if (!t) return;
  const a = t.dataset.action;
  if (a === "rute-add-stop") { e.preventDefault(); window.RuteModule.addStop(); }
  else if (a === "rute-calc") { e.preventDefault(); window.RuteModule.calc(); }
  else if (a === "rute-create") { e.preventDefault(); window.RuteModule.create(); }
}, true);
'''


# ══════════════════════════════════════════════════════════════════════════
# Hunk definicije: (fajl, opis, anchor, zamjena, marker-za-idempotenciju)
# anchor=None znaci append na kraj fajla.
# ══════════════════════════════════════════════════════════════════════════
HUNKS = [
    (FEATURES, "POST /api/v1/geo/route (OSRM Trip proxy) + _geo_item",
     A_GEO_REVERSE_END, P_GEO_ROUTE, "/api/v1/geo/route"),
    (FEATURES, "geo/search vraca city/plz/country/admin",
     A_GEO_SEARCH_OUT, P_GEO_SEARCH_OUT, "out = [_geo_item(x)"),
    (DISP_HTML, "tab gumb 'Rute'",
     A_TAB_BTN, P_TAB_BTN, 'id="tab-rute"'),
    (DISP_HTML, "CSS za #tab-rute-panel",
     A_CSS, P_CSS, "#tab-rute-panel.on{display:block}"),
    (DISP_HTML, "panel #tab-rute-panel",
     A_PANEL, P_PANEL, 'id="tab-rute-panel"'),
    (DISP_JS, "RuteModule + switchTab wrapper + delegacija",
     None, P_JS, "window.RuteModule"),
]


def _read(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=ROOT, help="korijen projekta (default %s)" % ROOT)
    ap.add_argument("--dry-run", action="store_true", help="samo provjeri, ne pisi")
    ap.add_argument("--no-chown", action="store_true", help="preskoci chown")
    args = ap.parse_args()

    root = args.root
    stamp = time.strftime("%Y%m%d_%H%M%S")

    # ── faza 1: ucitaj i provjeri SVE anchore prije ijednog pisanja ────────
    originals, planned, skipped = {}, [], []
    for rel, opis, anchor, payload, marker in HUNKS:
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            sys.exit("STOP: nema fajla %s" % path)
        if path not in originals:
            originals[path] = _read(path)
        text = originals[path]
        if marker in text:
            skipped.append("%s: %s (marker vec prisutan)" % (rel, opis))
            continue
        if anchor is None:
            planned.append((path, rel, opis, None, payload))
            continue
        n = text.count(anchor)
        if n != 1:
            sys.exit("STOP: anchor za '%s' u %s nadjen %d puta (ocekivano 1).\n"
                     "Fajl je izmijenjen u odnosu na verziju za koju je patch pisan — "
                     "nista nije zapisano." % (opis, rel, n))
        planned.append((path, rel, opis, anchor, payload))

    for s in skipped:
        print("  = preskacem  %s" % s)
    if not planned:
        print("\nSve je vec primijenjeno — nema promjena.")
        return
    for _p, rel, opis, anchor, _pl in planned:
        print("  + %s  %s%s" % (rel, opis, "" if anchor else "  (append na kraj)"))

    if args.dry_run:
        print("\n--dry-run: svi anchori nadjeni tocno jednom, nista nije zapisano.")
        return

    # ── faza 2: primijeni u memoriji ──────────────────────────────────────
    updated = dict(originals)
    for path, _rel, _opis, anchor, payload in planned:
        if anchor is None:
            updated[path] = updated[path].rstrip("\n") + "\n" + payload
        else:
            updated[path] = updated[path].replace(anchor, payload, 1)

    # ── faza 3: sintaksa Pythona prije ijednog pisanja ────────────────────
    for path, text in updated.items():
        if path.endswith(".py") and text != originals[path]:
            try:
                compile(text, path, "exec")
            except SyntaxError as exc:
                sys.exit("STOP: patchani %s ne prolazi compile(): %s\n"
                         "Nista nije zapisano." % (path, exc))

    # ── faza 4: backup + zapis ────────────────────────────────────────────
    print("")
    for path, text in updated.items():
        if text == originals[path]:
            continue
        bak = "%s.bak_%s" % (path, stamp)
        shutil.copy2(path, bak)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("  zapisano %s  (backup: %s)" % (path, os.path.basename(bak)))
        if not args.no_chown:
            try:
                subprocess.run(["chown", OWNER, path], check=True)
            except Exception as exc:
                print("  ! chown %s pao: %s (napravi rucno)" % (path, exc))

    print("\nGotovo. Sljedeci korak — restart backenda:")
    print("  systemctl list-units --type=service | grep -i tahograf")
    print("  systemctl restart <ime-servisa>")
    print("  curl -s -o /dev/null -w '%{http_code}\\n' https://digigraf.online/health")
    print("Frontend je staticki, a sw.js je network-first za .js/.html — dovoljan je reload.")


if __name__ == "__main__":
    main()
