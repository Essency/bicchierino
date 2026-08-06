# CLAUDE.md — bicchierino

Documento di processo. **Da leggere insieme ad `ARCHITECTURE.md` e `WIRE.md`
prima di scrivere codice** — questo file orienta, quelli contengono il
dettaglio tecnico e non vanno duplicati qui.

Le sezioni **TBD** sono decisioni aperte: non improvvisare, fermarsi e chiedere.

---

## 0. Autorità e processo

Il maintainer è l'unica autorità sulle decisioni di architettura. `ARCHITECTURE.md`
e `WIRE.md` sono la sua voce — dove parlano, hanno ragione loro. Un'idea migliore
non è una licenza, è un'escalation: si segnala, non si aggira in silenzio.

**Cosa richiede fermarsi e chiedere:** qualunque TBD di §5, deviare da una
decisione già scritta in `ARCHITECTURE.md`/`WIRE.md`, aggiungere una dipendenza
non elencata in §2, qualunque cosa tocchi l'autenticazione o la sessione grappa.

**Cosa decide chi implementa senza chiedere:** nomi di funzioni/tipi interni,
struttura dei file dentro il binario, testo dei messaggi di errore/log,
refactor a comportamento osservabile identico.

---

## 1. Cosa stiamo costruendo

Un traduttore JSON⇄IRC stateless verso grappa. Un client IRC normale (irssi,
weechat, hexchat...) si connette, manda `USER <account> * * :<gecos>` e
`PASS <network>:<password>`, e bicchierino fa login REST su grappa **con quelle
credenziali, per quella connessione** — non un'identità fissata all'avvio del
processo come shottino `--ircd`. Nessuna GUI, nessun LLM, nessun rendering
media: solo il filo. Motivazione completa e alternative scartate in
`ARCHITECTURE.md`.

---

## 2. Stack

| Cosa | Scelta | Perché (dettaglio in ARCHITECTURE.md) |
|---|---|---|
| Linguaggio | C11 | coerenza con l'ecosistema (shottino, scbnc) |
| Event loop | `poll()`, **nessuna libreria** | `epoll` è Linux-only, vjt sviluppa su BSD; libevent non aggiunge nulla che non si scriva da sé in poche righe |
| TLS | OpenSSL diretto, **due ruoli distinti** | client verso grappa (verifica il loro cert) e server verso i client IRC a valle (presenta un cert nostro) — non sono la stessa cosa |
| WebSocket framing | `ws.c`/`ws.h` **vendorizzati da shottino** | MIT, autonomi, già testati (ASan/UBSan) — non riscriverli |
| JSON | `json.c`/`json.h` **vendorizzati da shottino** | idem, reader **e** writer |

**Attribuzione obbligatoria**: `THIRD_PARTY_LICENSES` accanto ai file
vendorizzati, credito a Marcello Barnaba / `vjt/grappa-irc`, MIT.

**Nessun'altra dipendenza senza passare da qui (§0).**

---

## 3. Decisioni architetturali chiuse — non riaprire senza motivo

Dettaglio completo in `ARCHITECTURE.md`. Digest:

- **Stateless per costruzione.** Zero stato tra una disconnessione e l'altra:
  ogni riconnessione è login REST fresco + join fresco + replay
  `CHATHISTORY` fresco. L'unico stato è uno specchio in-memory
  per-connessione (membri/topic/mode) per rispondere a `WHOIS`/`NAMES`/`WHO`
  senza round-trip — sottoprodotto gratuito dell'inoltro eventi che si fa
  comunque, non stato aggiuntivo da progettare.
- **Identità su tre fronti**: account da `USER`, `network:password` da `PASS`
  (convenzione già nota da shottino, riusata identica).
- **URL grappa è config di processo**, non per-connessione: un binario →
  un deployment grappa, passato via CLI all'avvio.
- **Scalabilità orizzontale gratuita**: zero stato condiviso tra connessioni
  → zero stato condiviso tra istanze → N processi dietro un load balancer TCP
  puro, senza sticky session né coordinamento.
- **Un thread per connessione** (chiude il TBD §5.1 di prima). Motivo
  decisivo: dopo il login REST (l'unica POST della sessione — vedi §4, ogni
  altra azione è push sulla websocket già aperta), quel thread passa in
  `poll()` su **due soli fd** per tutta la vita della connessione. Il login
  bloccante blocca solo se stesso, nessun altro client se ne accorge.
  Nessun lock necessario: le connessioni non condividono mai memoria (è la
  premessa "stateless" qui sopra), quindi non c'è niente da sincronizzare
  tra thread. Un unico loop `poll()` condiviso da tutte le connessioni
  avrebbe richiesto un client HTTP non bloccante scritto a mano solo per
  evitare che un login fermi tutti gli altri — complessità reale per un
  problema che il modello a thread elimina gratis. shottino usa un loop
  singolo perché il suo login avviene una volta sola *prima* che il loop
  parta (mono-utente per costruzione); bicchierino fa login per ogni nuova
  connessione mentre altre sono già vive, quindi non è lo stesso caso.

---

## 4. Wire protocol grappa — leggi `WIRE.md`, non indovinare

`WIRE.md` copre il ciclo di vita connessione (login REST, handshake WS, join
dei topic) letto **dal sorgente reale** di grappa, non dedotto dal
comportamento di shottino. Due cose che rompono tutto silenziosamente se
sbagliate, ripetute qui perché costano care da dimenticare:

1. **Dopo il login, niente più HTTP.** L'unica POST della sessione è
   `/auth/login`; ogni azione successiva (`PRIVMSG`, `JOIN`, `MODE`, ...) è
   un push sulla websocket già aperta, mai una nuova richiesta HTTP. Nessun
   keep-alive da gestire, nessun round-trip da ottimizzare — semplicemente
   non esiste traffico HTTP ripetuto.
2. **Ogni push su un topic deve portare il `join_ref` di QUEL join.** Phoenix
   scarta silenziosamente un frame con `join_ref` sbagliato — nessun errore,
   il messaggio semplicemente sparisce.
3. **Le DM in arrivo si ricevono solo iscrivendosi al topic del proprio nick**
   (`grappa:user:{subject}/network:{net}/channel:{ownNick}`), non a quello
   del interlocutore — altrimenti si vede solo la propria metà della
   conversazione. Bug reale, già preso una volta da shottino.

Il catalogo completo verbo-per-verbo (`op`, `kick`, `mode`, `whois`, ...) **non**
è duplicato né qui né in `WIRE.md`: si legge da `grappa_channel.ex` nel repo
`grappa-irc` quando si implementa quel verbo specifico.

---

## 5. TBD — decisioni aperte, non improvvisare

~~Modello di concorrenza.~~ **Risolto** — vedi §3, thread per connessione.

### 5.1 Configurazione e logging

Solo "URL grappa è config di processo" è deciso (§3). Non deciso: forma
esatta (argv posizionale come shottino, env var, file?), se bicchierino
logga qualcosa a runtime e dove (stderr? file? niente affatto, coerente con
"stupido"?).

### 5.2 Cosa succede se la websocket verso grappa cade a metà sessione

Mai discusso. Coerente con la sezione "stateless" di `ARCHITECTURE.md` la
risposta ovvia sarebbe: si chiude anche la connessione IRC a valle (niente
riconnessione silenziosa, niente stato da preservare), ma non è stato scritto
da nessuna parte come decisione — va confermato, non assunto.

---

## 6. Anti-pattern — già valutati e scartati, non riproporre

| Anti-pattern | Perché no |
|---|---|
| libevent | unico vantaggio reale è `bufferevent_openssl`, non vale la dipendenza in più (§2, ARCHITECTURE.md) |
| `epoll` diretto | Linux-only, rompe la portabilità BSD che `poll()` garantisce gratis |
| Riscrivere framing WS o parsing JSON a mano | già scritti, testati e vendorizzabili da shottino (MIT) — vedi §2 |
| Persistenza di sessione tra riconnessioni | contraddice la filosofia "stupido": ogni riconnessione è login fresco, punto |
| Login/URL grappa per-connessione | l'account varia per connessione, il deployment no — sono domande diverse |
| Rispondere a `WHOIS`/`NAMES`/`WHO` con una chiamata REST dedicata invece dello specchio in-memory | round-trip HTTP inutile per dati che si hanno già dall'inoltro eventi |
| Copiare da shottino la logica GUI/LLM/media | fuori scope per definizione (§1) |
| Un unico loop `poll()` condiviso da tutte le connessioni | richiederebbe un client HTTP non bloccante scritto a mano solo per non bloccare tutti durante un login altrui — complessità reale per un problema che il modello a thread elimina gratis (§3) |
| Ottimizzare/tenere vivo un client HTTP tra le richieste | non esiste traffico HTTP ripetuto da ottimizzare: dopo il login è tutto push sulla websocket già aperta (§4) |

---

## 7. Prossimo passo

Il modello di concorrenza (la decisione che contava di più) è chiuso. I due
TBD rimasti (§5.1, §5.2) non bloccano l'inizio della scrittura ma vanno
chiusi prima del primo commit di codice funzionante. Si può iniziare lo
scheletro: accept loop → thread per connessione → parsing registrazione IRC
→ login REST → join WS (§4, `WIRE.md`).
