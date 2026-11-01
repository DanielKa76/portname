# Discovery-Benchmark (lokal, handgeführt)

`scripts/bench-discovery.js` misst eine Discovery-Runde unter synthetischer
Listener-Last (0, 10, 50, 200). Kein CI-Job, keine Dependencies; die Werte
sind **lokale Einzelmessungen auf einem Entwicklungs-Mac** (Median über 3
Pässe je Größe, beide Messreihen am selben Tag, gleiche Maschine) — keine
statistisch gesicherten Benchmarks.

```bash
node scripts/bench-discovery.js --sizes 0,10,50,200 --passes 3 --json out.json
```

## Umgebung (beide Messreihen identisch)

- Apple M5, 10 Kerne, macOS (Darwin 27.0.0, arm64), Node v26.8.2
- `ps`/`lsof` laufen zur Zählung durch `/bin/sh`-Shims (identischer
  Shell-Overhead auf beiden Seiten des Vergleichs; absolute Durations
  sind dadurch gegenüber produktiv leicht erhöht)
- Proxy-/Control-Latenz: Host-Lookup absichtlich auf 127.0.0.1 gepinnt
  (macOS-getaddrinfo-/Threadpool-RAUSCHEN soll die Gateway-Messung nicht
  verzerren); nur HTTP-200 zählt als Sample. 20 Requests pro Messung.

## Ebenen: was gemockt ist, was echt ist

- **pipeline** (synthetische Listener, echte Subprozesse): `enrichAsync` +
  `detectInspectors` + `resolveRoutes` direkt aufgerufen, Kälte-Caches je
  Pass, `lsof`/`ps`-Aufrufe laufen echt (per Shim gezählt). Das ist ein
  Worst-Case: im Daemon fällt diese Arbeit nur für neue Prozesse an
  (siehe „Dauerzustand" unten), und cwd-Lookups entfallen bei
  voreingestelltem cwd.
- **daemon** (produktrelevant): voller `Daemon` mit echtem
  Loopback-Gateway, echtem Control-Socket (Unix-Socket wie die App) und
  echtem lokalen Upstream-Server; Listener sind synthetisch mit
  voreingestelltem `cwd`/`root` (wie in den Daemon-Tests), Startzeit-
  Lookups laufen echt pro PID. Gemessen wird ein `refresh()` mit
  gleichzeitigen Proxy-/Control-Request-Bursts.

## Vorher/Nachher

„Vorher" = Stand ohne gebündelte Subprozess-Lookups, „Nachher" = mit
Bündelung, gemessen mit demselben Skript. Subprozess-
anzahl ist unverändert (gleiche Arbeit, nur gebündelt gestartet).

### daemon-Ebene (produktrelevant; Median/Max in ms)

| Größe | Scan-Dauer vor→nach | Proxy während Scan p50/max vor→nach | Control während Scan p50/max vor→nach |
| ----: | ------------------- | ----------------------------------- | ------------------------------------- |
| 0     | 0.6 → 0.7           | 0.0/0.0 → 0.0/0.0                   | 2.0/3.1 → 3.4/4.7                     |
| 10    | 12.0 → 19.3         | 11.8/17.1 → 10.0/11.6               | 11.7/17.1 → 9.3/11.5                  |
| 50    | 59.6 → 64.1         | 60.6/132.8 → 4.8/17.7               | 62.1/132.9 → 8.1/18.5                 |
| 200   | 252.7 → 249.7       | 255.7/277.8 → 9.5/22.3              | 262.3/282.3 → 22.2/28.9               |

Eventloop-Delay (`perf_hooks.monitorEventLoopDelay`, p99/max): vorher
0.0/0.0–24.3 ms, nachher 0.0/0.0–21.4 ms. Beide Varianten zeigen
einzelne ~20 ms-Spitzen (GC-/State-Schreib-Typ, z. B. 24.3 ms auf
„vorher" bei Größe 50). Auffällig ist die Diskrepanz bei „vorher": das
Histogramm zeigt kaum In-Process-Delay, während gleichzeitige Requests
erst nach Scanende bedient werden. Eine vollständige Mechanismus-Analyse
(libuv-Ereignisverteilung, Scheduler-Kontention durch die ungebündelten
Kindprozess-Stürme) ist nicht Teil dieser Messung; reproduzierbar gemessen
ist der Effekt auf die Request-Latenz in beiden Messreihen.

### pipeline-Ebene (Kälte-Cache-Worst-Case; Median in ms)

| Größe | Scan-Dauer vor→nach | max. Startzeit-Parallelität vor→nach | Eventloop-Delay max vor→nach |
| ----: | ------------------ | ------------------------------------ | ---------------------------- |
| 10    | 47.5 → 59.3        | 10 → 4                               | 19.8 → 21.1                  |
| 50    | 199.5 → 216.6      | 50 → 4                               | 106.9 → 109.2                |
| 200   | 1233.1 → 1117.2    | 200 → 4                              | 906.5 → 658.0                |

Subprozesse je Pass (vor = nach): 15 ps + 10 lsof bei Größe 10,
75 ps + 50 lsof bei 50, 300 ps + 200 lsof bei 200.

Anmerkung zur Bündelung: die Messreihen entstanden auf einem Stand, in dem
nur die Startzeit-ps-Lookups auf 4 parallel gebündelt waren; die
cwd-Lookups wurden erst danach in dieselbe 4er-Bindung gezogen (lazy Start
in den boundeten Workern). Diese Bindung ist in
`test/discover-bounds.test.js` abgesichert, nicht über diese Bench-Zahlen.
Für die daemon-Ebene (voreingestelltes cwd, keine cwd-Lookups in der
Messstrecke) ändert das nichts an den Werten; die pipeline-Werte
(Kälte-Caches mit echten cwd-Lookups) können sich dadurch geringfügig
verschieben.

## Interpretation (ehrlich, ohne Prozentangaben)

- Der Gewinn liegt in der **Latenz unter gleichzeitigem Scan**, nicht in
  der reinen Scan-Dauer: die gebündelte Ausführung (max. 4 parallele
  Subprozess-Lookups je Pass — Startzeit-ps- und cwd-Lookups teilen sich
  ein Limit; 8 Inspector-Probes) macht die Daemon-Ebene während des Scans
  anfragefähig — Proxy-/Control-Requests werden in einstelligen bis
  niedrigen zweistelligen Millisekunden bedient, statt erst nach
  Scanende. Bei kleinen Listener-Zahlen kostet die Bündelung etwas
  Scan-Wandzeit (Staggering), bei 200 Listenern ist sie sogar schneller.
- Die verbleibenden ~20-ms-Spitzen treten in beiden Varianten auf und
  sind einzeln (GC bzw. persistenter State-Schreib mit fsync), nicht
  scan-systematisch.
- Die pipeline-Werte sind Kälte-Cache-Worst-Cases mit scheiternden
  Lookups für teils synthetische PIDs; produktiv tragen Caches und das
  Scan-Budget (gebundene Gesamtdauer, danach degradierter Scan) die
  verbleibenden Fälle.

## Dauerzustand im Daemon

Nicht gemessen, sondern aus der Cache-Semantik in `lib/discover.js`
(`enrichAsync`, `detectInspectors`) abgeleitet:

- pro Pass genau ein `lsof`-Listener-Scan;
- ein gebündelter `ps`-Aufruf pro Pass für die Startzeiten aller PIDs
  (die Prozessgeneration wird in jedem Pass geprüft, weil Freigaben an sie
  gebunden sind); für stabile Prozesse kein cwd-`lsof`, das cwd ist an die
  Prozessgeneration gebunden;
- je neuer Prozessgeneration ein cwd-`lsof` und, wenn sie eine
  Projektwurzel hat, ein `ps -o args`;
- das Debug-Endpunkt-Urteil einmal pro Prozessgeneration und Port (ein
  `GET /json/version`, 200 ms); ein Listener ohne Antwort wird mit Backoff
  von 5 s bis 5 min erneut geprüft. Listener ohne Projektwurzel (Apps mit
  cwd `/` oder `~`) werden nie zur Route und deshalb gar nicht geprüft.

Die Messreihen oben stammen von einem Stand, in dem nur `node`-Prozesse
auf Debug-Endpunkte geprüft wurden; der aktuelle Stand (jede Laufzeit, nur
Listener mit Projektwurzel, ein gebündelter `ps` pro Pass) ist nicht neu
gemessen.

## Grenzen

- Einzelmessung, eine Maschine, ein Tag. Keine Wiederholung über
  Last-Spitzen im System hinweg; die Absolutewerte schwanken zwischen
  Läufen um zweistellige Millisekunden.
- Die GUI wird nicht verlangsamt, um Zielverifikation zu ersetzen: die
  hier dokumentierten Grenzen liegen vollständig im Daemon
  (Parallelitäts- und Zeitbudgets, Fehlersemantik), nicht beim Client.
- Bench-Artefakte sind bewusst dokumentiert: Shim-Shell-Overhead,
  gepinnter Host-Lookup, vorgebaute Listener-Pools (kein FS in der
  Messstrecke).
