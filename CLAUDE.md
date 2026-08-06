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

---

## 4. Wire protocol grappa — leggi `WIRE.md`, non indovinare

`WIRE.md` copre il ciclo di vita connessione (login REST, handshake WS, join
dei topic) letto **dal sorgente reale** di grappa, non dedotto dal
comportamento di shottino. Due cose che rompono tutto silenziosamente se
sbagliate, ripetute qui perché costano care da dimenticare:

1. **Ogni push su un topic deve portare il `join_ref` di QUEL join.** Phoenix
   scarta silenziosamente un frame con `join_ref` sbagliato — nessun errore,
   il messaggio semplicemente sparisce.
2. **Le DM in arrivo si ricevono solo iscrivendosi al topic del proprio nick**
   (`grappa:user:{subject}/network:{net}/channel:{ownNick}`), non a quello
   del interlocutore — altrimenti si vede solo la propria metà della
   conversazione. Bug reale, già preso una volta da shottino.

Il catalogo completo verbo-per-verbo (`op`, `kick`, `mode`, `whois`, ...) **non**
è duplicato né qui né in `WIRE.md`: si legge da `grappa_channel.ex` nel repo
`grappa-irc` quando si implementa quel verbo specifico.

---

## 5. TBD — decisioni aperte, non improvvisare

### 5.1 Modello di concorrenza — **il più importante, blocca lo scheletro**

Non deciso: un unico loop `poll()` che multiplexa i fd di **tutte** le
connessioni in un thread solo (coerente con "stupido", ma il login REST è
bloccante — fermerebbe ogni altra connessione mentre una fa login), oppure
**un thread per connessione** (il login bloccante blocca solo se stesso, e il
`poll()` di quel thread ha solo 2 fd — il socket IRC a valle e la websocket
verso grappa). shottino fa il primo perché è mono-utente per costruzione;
bicchierino è multi-tenant per definizione, quindi non è la stessa domanda.
Propendo per **thread per connessione** — più semplice da ragionare, il
costo di N thread bloccati su I/O è irrilevante alla scala di un bouncer
personale/di piccolo gruppo — ma è una proposta, non ancora deciso.

### 5.2 Configurazione e logging

Solo "URL grappa è config di processo" è deciso (§3). Non deciso: forma
esatta (argv posizionale come shottino, env var, file?), se bicchierino
logga qualcosa a runtime e dove (stderr? file? niente affatto, coerente con
"stupido"?).

### 5.3 Cosa succede se la websocket verso grappa cade a metà sessione

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

---

## 7. Prossimo passo

Risolvere §5.1 (modello di concorrenza) — è quello che decide la forma dello
scheletro. Gli altri due TBD (§5.2, §5.3) non bloccano l'inizio della
scrittura ma vanno chiusi prima del primo commit di codice funzionante.
