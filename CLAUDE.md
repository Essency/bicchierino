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

**Non ora, ma tenerlo a mente**: comandi di amministrazione **lato IRC** (un
po' come un servizio NickServ-style, digitati al bot), non solo via web —
così bicchierino resta configurabile anche senza passare da un pannello.
Non specificato oltre questo — cosa esattamente si configuri così, e con
quali permessi, è una decisione da prendere quando ci si arriva, non da
improvvisare ora. Annotato qui perché non vada perso, non perché blocchi
lo scheletro iniziale.

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

### 2.1 Convenzioni di codice

**Tutto in inglese**: identificatori, commenti nel codice, messaggi verso
l'utente (le righe `ERROR :...` di §3.3 incluse, i log di §3.2). Stessa
regola che KeelBot applica al proprio codice — coerenza tra i progetti
dell'ecosistema, e i messaggi `ERROR` finiscono nel client IRC di chiunque,
non solo nostro.

**I messaggi `ERROR` verso il client non portano un prefisso interno**
(niente `bicchierino: ` davanti). Sono testo per un umano che deve capire
cosa è successo ed eventualmente agire (`"...please contact the admin"`),
non un log — il prefisso di debug ha senso in `fprintf(stderr, ...)` (§3.2,
quello sì può restare `bicchierino: ...`), non su un socket IRC. Deciso
esplicitamente dopo aver scritto i primi messaggi con il prefisso ovunque
per abitudine e averli poi tolti tutti insieme per coerenza — un solo
messaggio "pulito" in mezzo ad altri con prefisso sarebbe stato peggio di
nessuno.

Questo documento (`CLAUDE.md`) resta in italiano, come il `CLAUDE.md` di
KeelBot — è un documento di processo per chi lavora al progetto, non
superficie che l'utente finale vede. `ARCHITECTURE.md` e `WIRE.md` sono già
in inglese e restano così.

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

  **Precisazione**: "un thread per connessione" non dice come si scoprono le
  connessioni nuove quando i listener sono più di uno (§3.1). Un thread (o
  il main) fa `poll()` sui socket in ascolto — pochi, fissi, uno per bind
  configurato — e a ogni `accept()` lancia il thread dedicato a quel client.

### 3.1 Configurazione: file a direttive, un bind è una tupla

Formato: **una direttiva per riga**, stile `sshd_config`/nginx — non JSON,
non libconfig (scartati: vedi `example.config` in radice per lo schema
completo e commentato, non duplicato qui). Path di default
`./bicchierino.config` (CWD), override con `--config <path>`.

Tre direttive, non di più:

- `grappa-url <url>` — obbligatoria, una sola. Config di processo (§3 sopra).
- `bind <ip> <porta> plain` / `bind <ip> <porta> tls <cert> <key>` —
  **ripetibile**: un processo può ascoltare su più `(ip, porta, tls)`
  indipendenti insieme (es. loopback in chiaro per test + pubblico TLS).
- `log-file <path>` — opzionale, vedi §3.2.

**Un bind non-loopback con `plain` rifiuta l'avvio per default.** Ogni
connessione a valle manda la password grappa dentro `PASS`: in chiaro fuori
da loopback è un secret vero esposto in rete. Non è un errore silenzioso né
un warning — il processo non parte. Si scavalca **solo** con `--insecure`
sulla riga di comando: scelta consapevole di chi lancia il processo, mai
nel file di config (dove qualcuno potrebbe lasciarla dimenticata).

### 3.2 Logging: un sink, N writer — l'unica eccezione a "zero lock"

- **Traffico IRC/JSON**: mai loggato in una build di release. Il codice che
  lo farebbe **non esiste nel binario** — dietro un `#ifdef` di build
  attivo solo in una variante di debug, non un flag runtime disattivabile.
  È privato, non è un livello di verbosità da poter accendere per sbaglio.
- **Tutto il resto** (connect/disconnect/errori): un solo file configurato
  (`log-file`, §3.1). Assente → solo stderr. Gli errori vanno **sempre**
  anche su stderr, file configurato o meno.
- **Il file di log è l'unico stato condiviso tra thread di connessioni
  diverse in tutto bicchierino.** Ogni altra parte del disegno vale "zero
  lock perché zero stato condiviso" (§3) — qui no: N thread scrivono sullo
  stesso file, serve un mutex minimo attorno alla scrittura o le righe si
  intrecciano a metà. Costo trascurabile (logging non è hot-path), ma
  un'eccezione reale da non dimenticare, non un'estensione della regola.
- Nessuna rotazione gestita da bicchierino — è compito di `logrotate(8)`
  esterno; riapertura del file su `SIGHUP` se serve supportarlo (stesso
  pattern del logger diagnostico di KeelBot).

### 3.3 Non si raggiunge grappa — una regola sola, due momenti in cui si applica

**Qualunque impossibilità di raggiungere grappa produce lo stesso
trattamento: `ERROR :<motivo>` sul socket IRC a valle, poi si chiude.
Nessun retry interno — è il client IRC vero a riconnettersi con la propria
logica**, esattamente come già deciso per §1 sopra (websocket caduta a metà
sessione). Non sono due decisioni, sono la stessa applicata in due punti del
ciclo di vita:

- **Al connect, prima della registrazione**: la POST di login fallisce per
  irraggiungibilità (non per credenziali sbagliate — quello resta un caso
  diverso, già coperto: bare `ERROR` prima del 464/simile, come fa già
  `ircd_register` di shottino per gli altri fallimenti pre-registrazione),
  oppure la websocket non si apre/non completa il join dopo un login
  riuscito. In nessuno di questi casi il client a valle ha mai ricevuto
  `001`: `ERROR :grappa non raggiungibile` (testo esatto da rifinire in
  implementazione) e chiusura, senza numerici — stesso pattern già
  osservato in `ircd_register` per `ERROR :bad password` e simili.
- **A metà sessione, dopo la registrazione**: la websocket cade.
  `ERROR :lost grappa connection` e chiusura.

**Non c'è distinzione di codice tra i due casi**: entrambi finiscono nella
stessa funzione — "questa connessione non può continuare, dillo e chiudi" —
cambia solo il messaggio e se `001` era già stato mandato. Non serve un
meccanismo di retry, non serve uno stato "sto ritentando": semplicemente
quella connessione muore e il client vero, se vuole, ne apre una nuova.

---

## 4. Wire protocol grappa — leggi `WIRE.md`, non indovinare

`WIRE.md` copre il ciclo di vita connessione (login REST, handshake WS, join
dei topic) letto **dal sorgente reale** di grappa, non dedotto dal
comportamento di shottino. Le cose che rompono tutto silenziosamente se
sbagliate, ripetute qui perché costano care da dimenticare:

1. **Corretto due volte (era sbagliato): la regola vera è "REST muta
   stato tracciato, WS inoltra verbi live".** Non "REST solo al
   bootstrap" — quattro azioni sono REST per TUTTA la vita della
   connessione: invio messaggio (`POST .../messages`,
   `Session.send_privmsg/4`), JOIN (`POST .../channels`,
   `Session.send_join/4`), PART (`DELETE .../channels/:chan`,
   `Session.send_part/4` — non accetta un reason, non lo inoltra a
   monte), TOPIC-set (`POST .../channels/:chan/topic`,
   `Session.send_topic/4` — ma `grappa_channel.ex` ha ANCHE un verbo WS
   `"topic_set"`, i due path non sono stati confrontati, non assumere
   quale usi cicchetto senza leggere entrambi). Nessuna delle prime tre
   ha un verbo WS gemello — REST non è un fallback, per queste è l'unica
   via. `MODE`, `KICK`, `WHOIS` e il resto dei verbi ops/info restano
   push WS come descritto qui sotto. Dettaglio completo: `WIRE.md` §2.5.
2. **Ogni push su un topic deve portare il `join_ref` di QUEL join.** Phoenix
   scarta silenziosamente un frame con `join_ref` sbagliato — nessun errore,
   il messaggio semplicemente sparisce.
3. **Le DM in arrivo si ricevono solo iscrivendosi al topic del proprio nick**
   (`grappa:user:{subject}/network:{net}/channel:{ownNick}`), non a quello
   del interlocutore — altrimenti si vede solo la propria metà della
   conversazione. Bug reale, già preso una volta da shottino.
4. **Il segmento `channel:` di un topic (nome canale reale O `{ownNick}`)
   va ASCII-folded (`A-Z`→`a-z`) PRIMA di costruire la stringa del
   `phx_join`.** `Grappa.PubSub.Topic.channel/3` — la funzione che OGNI
   broadcaster usa per la propria stringa — folda sempre, incondizionatamente.
   Un join con segmento non foldato ha successo (`status: "ok"`, `join_ref`
   vero) ma non riceve MAI un broadcast — nessun errore, il topic
   sottoscritto e quello del broadcaster sono semplicemente due stringhe
   diverse per Phoenix.PubSub (match esatto). Bug reale, trovato live: la
   DM-listener topic joinava con successo, `visibility` veniva pushato,
   ma ogni DM in arrivo spariva silenziosamente per un'intera sessione di
   debug prima di questo fix. Stessa cautela per il confronto lato
   ricezione (`channel == ownNick` per il re-key §5, `sender == ownNick`
   per il self-echo): il campo `channel` di un evento DM arriva GIÀ
   foldato dal wire (grappa fold-a-scrittura sulle channel KEY), `sender`
   NO (resta display-case) — confrontare un `ownNick` non foldato contro
   un valore wire foldato fallisce silenziosamente allo stesso modo.
   Dettaglio completo: `WIRE.md` §5.5.

Il catalogo completo verbo-per-verbo (`op`, `kick`, `mode`, `whois`, ...) **non**
è duplicato né qui né in `WIRE.md`: si legge da `grappa_channel.ex` nel repo
`grappa-irc` quando si implementa quel verbo specifico.

---

## 5. TBD — nessuna. Tutte le domande aperte sono chiuse (vedi §3.3)

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
| JSON o libconfig per la configurazione | JSON è più verboso di righe ripetute per i bind multipli; libconfig è una dipendenza nuova non vendorizzabile. Il formato a direttive costa meno codice di entrambi (§3.1) |
| Un flag runtime per disattivare il rifiuto di bind non-loopback in chiaro | dev'essere una scelta cosciente per-avvio (`--insecure`), mai qualcosa che sopravvive in un file di config dimenticato (§3.1) |
| Log del traffico dietro un flag runtime | deve sparire dal binario di release, non solo essere disattivabile — un flag si accende per sbaglio, un `#ifdef` no (§3.2) |
| Retry interno (login o websocket) quando grappa non si raggiunge | reintroduce esattamente lo stato che "stateless" vuole evitare; il client IRC vero sa già riconnettersi (§3.3) |
| Un percorso di codice diverso per "grappa irraggiungibile al connect" vs "caduta a metà sessione" | stesso fallimento, stesso trattamento (`ERROR` + close) — differenziarlo raddoppia la logica per zero guadagno (§3.3) |

---

## 7. Prossimo passo

Nessun TBD residuo.

**Stato attuale (verificato live contro cicchetto.sonic88.org, account
SonicTest):** accept loop → thread per connessione → parsing registrazione
IRC → login REST → `GET /networks` + `GET /networks/:slug/channels` →
handshake WS (`?vsn=2.0.0` — senza, Phoenix sceglie il serializer V1 e il
primo frame manda in crash il channel process lato server, visto
direttamente nello stack trace di produzione) → join sequence completa
nell'ordine di `ws_join_topics` di shottino: topic utente, un topic per
ogni canale già joinato, topic DM-listener (proprio nick di rete), push
`visibility:true`. Tutto provato live e funzionante.

**Gotcha reale trovato e corretto**: `bridge_join` leggeva un solo frame
dopo l'invio del `phx_join` e lo trattava come LA risposta. grappa spinge
eventi "after-join snapshot" non richiesti sullo stesso topic subito dopo
un join riuscito (bundle hash, server settings, query_windows_list, ...) —
con più di un topic joinato sullo stesso socket, i push residui di un join
precedente arrivano prima della vera risposta al join successivo.
`bridge_join` ora scarta ogni frame che non sia esattamente un
`phx_reply` con il proprio `ref`, con un tetto di tentativi. Questi push
scartati restano il motivo per cui serve il prossimo passo qui sotto.

**Restructure `poll()`-su-due-fd (§3): fatto, provato live.** Fase 2 ora
fa `poll()` su fd IRC + fd WS (il secondo armato solo se `br_connected`,
altrimenti `-1` — poll() lo ignora, Case B degrada correttamente a un solo
fd). Drena ogni riga IRC già bufferizzata da un singolo `recv()` (peek puro
via `line_buffered`, mai un secondo `recv()` non promesso da poll()) prima
di tornare a `poll()`; consuma ogni evento WS ricevuto (per ora solo
loggato, non ancora tradotto — TODO(next) sotto); implementa §3.3 per la
websocket che cade a metà sessione (`ERROR :lost grappa connection` +
chiusura, stesso trattamento di ogni altra perdita di grappa).

**Secondo gotcha reale trovato e corretto, stavolta nel drain loop WS**: la
prima versione riusava lo stesso pattern di `bridge_join` — un `for(;;)`
che richiama `ws_client_recv` finché non torna `WS_NEED_MORE`. Dentro
`poll()` questo è sbagliato: dopo aver estratto UN frame già bufferizzato,
una seconda chiamata a `ws_client_recv` può innescare una `SSL_read`
bloccante che `poll()` non ha promesso — grappa non manda sempre tutti gli
after-join snapshot push nello stesso segmento TCP. Visto live: il thread
di connessione si bloccava in silenzio, senza servire NESSUNO dei due fd,
finché grappa non chiudeva la websocket per inattività. Fix: solo la
PRIMA estrazione per risveglio di `poll()` può toccare la rete
(`ws_client_recv`); ogni estrazione successiva nello stesso risveglio usa
`bridge_recv_buffered` (puro peek sul reader, mai rete) — stesso principio
di `line_buffered` sul lato IRC.

**PRIVMSG round trip: fatto, provato live in entrambe le direzioni** (con
l'account reale di produzione, non solo SonicTest — messaggi scambiati con
Sonic su azzurra). Outbound: §4's correzione (REST, non WS push) —
`send_privmsg_rest` in `connection.c`, via il client HTTP persistente
(sotto). Inbound: `handle_grappa_event` fa l'unwrap corretto della busta
Phoenix a 5 elementi (bug reale trovato e corretto — la prima versione
trattava l'intera busta `[join_ref, ref, topic, event, payload]` come se
fosse già il payload interno, quindi `"kind"` non veniva mai trovato) e
smista solo `event == "event"` con `payload.kind == "message"` verso
`handle_grappa_message_event`, che filtra il proprio echo e fa il re-key
DM (§5) prima di un `send_line`.

**Terzo gotcha reale trovato e corretto, il più insidioso finora — vedi
`WIRE.md` §5.5**: il segmento `channel:` di un topic (canale reale o
`{ownNick}`) va ASCII-folded (`A-Z`→`a-z`) PRIMA di costruire la stringa
del `phx_join`, altrimenti il join ha successo (`status: "ok"`, `join_ref`
vero) ma non riceve MAI un broadcast — nessun errore, `Grappa.PubSub.
Topic.channel/3` (usata da OGNI broadcaster) folda sempre incondizionatamente,
Phoenix.PubSub fa match esatto di stringa. Trovato live SOLO grazie a
messaggi reali scambiati con l'utente durante il debug — senza traffico
vero non sarebbe emerso. Stessa cautela needed lato confronto: il campo
`channel` di un evento DM arriva già foldato dal wire (grappa folda le
channel KEY a scrittura), `sender` no (resta display-case) — sia il
self-echo check che il re-key §5 foldano ora ENTRAMBI i lati prima di
confrontare. `ascii_fold_lower()` in `connection.c`, mirror byte-esatto di
`Identifier.fold_ascii_byte/1`.

**Client HTTP persistente (keep-alive), non più una connessione TLS per
chiamata**: flaggato dall'utente ("paghiamo un handshake HTTPS ad ogni
msg, decisamente troppo") appena scoperto che `PRIVMSG` è REST — un
handshake TLS per ogni riga inviata era inaccettabile. `http.c` riscritto
attorno a `struct http_client` (uno per connessione IRC, aperto pigro al
primo uso, tenuto vivo fino a `cleanup:`), risposte lette via
Content-Length (non più "leggi finché il peer chiude" — quel pattern è
incompatibile con keep-alive per costruzione) con un retry automatico se
la connessione pooled risulta stale. Provato live: un solo
"new keep-alive connection" loggato per l'intera sessione (login + 2 GET
di bootstrap + invio PRIVMSG), non quattro.

**JOIN/PART: fatto, provato live** (`#essency`, con l'utente reale che poi
si è unito allo stesso canale e ci ha chattato). Anche questi due sono
REST, non push WS (§2.5 di `WIRE.md`, altra correzione allo stesso
modello): `POST /networks/:slug/channels` (`{"name": "#chan"[, "key":
"..."]}`) per JOIN, `DELETE /networks/:slug/channels/:chan` per PART —
`handle_join`/`handle_part` in `connection.c` parsano la lista
comma-separated di canali (e, solo per JOIN, la lista chiavi posizionale
RFC 2812 — grappa stesso supporta una sola chiave per l'intero
multi-join, quindi una chiamata REST per canale è più permissiva, non
meno). Un JOIN riuscito aggiorna `sess->channels[]` e — se il bridge è
già connesso — joina subito il topic WS del canale (foldato, §5.5),
così i suoi eventi iniziano ad arrivare senza aspettare una riconnessione;
un PART rimuove la entry (array tenuto denso via `remove_channel_at`) e
ORA fa anche `phx_leave` sul topic WS del canale (aggiunto in un secondo
momento — vedi la voce "smaller gaps" più sotto per il gotcha e la
riprova live). Un 202 di JOIN significa
solo "accettato, finestra `:pending` aperta" — non "riuscito": il
successo/fallimento arriva dopo come evento WS (`joined`/`join_failed`,
`kind` visti live ma non ancora tradotti in una riga IRC, vedi sotto).

**Snapshot di canale al JOIN: fatto, provato live su `#essency`.** I tre
eventi WS già ricevuti dopo ogni join di topic canale —
`topic_changed`/`channel_modes_changed`/`members_seeded`
(`Session.Wire`, `lib/grappa/session/wire.ex:905-992`) — ora si
traducono in numerici IRC veri: 332 RPL_TOPIC (solo se `topic.text` non
è nil — niente 331 RPL_NOTOPIC, non implementato), 324
RPL_CHANNELMODEIS (l'intero stato corrente, non un delta — non c'è
"chi" ha cambiato cosa in questo payload, quello è un `kind` di
`message` separato non ancora gestito), 353/366 RPL_NAMREPLY +
RPL_ENDOFNAMES (chunked a 20 nick per riga, sigillo singolo per membro
scelto sull'ordine PREFIX già dichiarato nel 005 — `o`→`@`, `h`→`%`,
`v`→`+` — non derivato dal non ancora consumato `isupport_changed`).
333 RPL_TOPICWHOTIME saltato apposta: `set_at` sul wire è una stringa
ISO8601 e non c'è un parser di date in questo codebase per convertirla
nell'unix timestamp che 333 vuole — TODO(next) se vale la pena
aggiungerne uno per un numerico solo.

**Quarto gotcha reale trovato e corretto, di nuovo in `bridge_join` —
questa volta lo scarto dei frame "non miei", non il match del ref.**
Domanda dell'utente ("cosa succede se ti riconnetti mentre sei già in un
canale?") ha scoperto che l'intero snapshot di un canale — topic, modes,
members — spariva SEMPRE al bootstrap, mai in un `JOIN` interattivo a
metà sessione. Causa: `join_grappa_topics` fa 3 `bridge_join` di fila
(topic utente, ogni canale già joinato, DM-listener), ciascuno con il
proprio loop "aspetta la mia risposta, scarta il resto" (il fix del
gotcha precedente). Se lo snapshot after-join di un topic joinato PRIMA
arriva mentre bicchierino sta ancora aspettando la risposta di un
`bridge_join` SUCCESSIVO, quel loop lo scarta silenziosamente — mai un
bug nel `JOIN` interattivo perché lì un solo `bridge_join` è mai in
volo alla volta. Fix: `bridge_join` accetta ora un callback
(`bridge_event_cb`) invocato su OGNI frame che non è la propria
risposta, invece di scartarlo — `connection.c` lo instrada a
`handle_grappa_event` tramite un piccolo context (`struct
bridge_event_ctx`) passato a tutte e 4 le chiamate a `bridge_join`
(le 3 del bootstrap + quella di `handle_join`). Provato live: una
riconnessione con `#essency` già joinato lato server ora mostra 332/324/
353/366 corretti, e l'intero snapshot del topic utente (bundle_hash,
query_windows_list, umode_changed, ...) arriva senza perdite.

**Attività live degli altri utenti: fatto, provato live su `#essency`**
(join/part reali di Sonic, MODE +o di ChanServ, MODE +k di Sonic — tutti
osservati durante un test dal vivo, non simulati). I kind di `message`
rimasti — `join`/`part`/`quit`/`nick_change`/`mode`/`kick`/`topic` — ora
si traducono in righe IRC vere, con le forme meta per-kind lette
direttamente da `Grappa.Scrollback.Meta` (`meta.ex:68-131`, il catalogo
che mancava e bloccava questo lavoro), non indovinate:
- `join`/`part`/`quit`: prefisso `nick!user@host` REALE quando
  `meta.sender_user`/`sender_host` sono presenti (visto live: PART/JOIN
  di Sonic con `~Sonic@sonic.azzurra.chat`), altrimenti fallback al
  placeholder `bicchierino@bicchierino` — mai mezza coppia, com'è la
  garanzia del wire stesso.
- `nick_change` → `NICK`, `mode` → `MODE canale modi arg...` (il delta
  con attore, distinto dallo snapshot 324 già esistente — visto live
  arrivare INSIEME dopo un `+k`, i due meccanismi coesistono
  correttamente), `kick` → `KICK canale target[ :motivo]`, `topic` →
  `TOPIC canale :nuovo testo` (la notifica di cambio live, distinta dal
  332 di snapshot-al-join).
- Self-echo soppresso UNIFORMEMENTE su tutti i kind (stesso confronto
  foldato già usato per privmsg/notice/action) — necessario per
  join/part (altrimenti riga doppia: l'eco ottimistico di
  `handle_join`/`handle_part` PIÙ questo evento), innocuo oggi per
  mode/kick (bicchierino non genera ancora comandi in uscita per questi,
  quindi non può mai esserne il sender). **Gap noto e voluto**: sopprime
  anche un NOSTRO `nick_change` — bicchierino non traccia affatto un
  nick live mutabile (`reg.nick` è fisso alla registrazione), quindi non
  c'è nulla di corretto da renderizzare comunque; risolverlo per bene
  richiede stato di sessione più ampio, fuori scope per questo giro.
  `server_event` resta l'unico kind non gestito — il suo meta è un
  grab-bag da router-catchall, non vale un render senza un caso concreto
  a guidarlo.

**MODE in uscita: fatto, provato live — con la controprova più
convincente possibile.** WIRE.md §2.5: MODE (a differenza di PRIVMSG/
JOIN/PART/TOPIC-set) è un vero verbo push WS, `grappa_channel.ex`'s
`"mode"` clause, payload `{"network_id", "target", "modes", "params"}`
→ `Session.send_mode/5`. `handle_mode` in `connection.c` costruisce il
payload e fa `bridge_push` sul topic del canale già joinato (usando il
suo `join_ref` — nessun push possibile su un canale non joinato, niente
a cui Phoenix potrebbe instradare il frame), fire-and-forget come
`visibility`. Scoped ai soli target canale (`#`-prefixed) — un target
nick (umode, `MODE miocnick +i`) è un verbo WS SEPARATO
("umode"), non implementato; un `MODE #chan` senza modestring è una
query, non implementata (324 al join + lo snapshot live coprono già il
caso). Test live: `MODE #essency +n` da SonicTest (che non ha op lì) →
l'ircd reale ha rifiutato con `482 ERR_CHANOPRIVSNEEDED`, grappa l'ha
inoltrato come evento `notice`, e il codice NOTICE già esistente
(`handle_grappa_message_event`) l'ha renderizzato correttamente:
`:allnight6.azzurra.chat!... NOTICE #essency :You're not channel
operator`. Un rifiuto prova il percorso ESATTO che userebbe un MODE
riuscito — controprova più solida di un no-op silenzioso.

**`isupport_changed` → 005 corretto: fatto, provato live — e ha trovato
un errore reale nel fallback statico.** `chanmodes_a..d` + `prefix`
(`Session.Wire.isupport_changed/2`, `wire.ex:113-131` — `casemapping`/
`statusmsg` sono tracciati server-side ma NON esposti su questo evento,
confermato contro `ISupport.t/0`: restano il valore di fallback,
niente di live da preferire) si traducono in un 005 rispedito ogni
volta che l'evento arriva (una volta per ogni topic canale-shaped
joinato — visto live, due 005 per una sessione con un canale + il
DM-listener; innocuo, i client veri lo gestiscono). PREFIX ricostruito
in ordine canonico (o>h>v, poi qualunque altra lettera l'oggetto porti,
in coda — l'ordine di iterazione delle mappe Elixir non è
insertion-order-stabile, quindi non c'è segnale di rango affidabile
per lettere non riconosciute) nonostante l'oggetto JSON non garantisca
ordine. **Trovato live**: il vero CHANMODES di azzurra è `bz,k,l,...`
— non `beI,k,l,...` come indovinava il fallback statico
(`ISupport.default/0`) — la seconda classe A non è `e`/`I`, è
letteralmente `b`/`z`.

**Correzione dell'utente, applicata subito**: il 005 di registrazione
NON manda più il fallback bahamut-shaped indovinato
(`PREFIX=(ohv)@%+ CHANMODES=beI,...`) — l'errore appena trovato sopra
è la prova diretta che asserire un valore non ancora verificato PER
QUESTA rete è la stessa classe di bug del "silent-swallow" di
CLAUDE.md, solo capovolta: un numerico sbagliato con sicurezza invece
di uno mancante. `send_welcome` ora manda solo `CHANTYPES=#`
(decisione di bicchierino, non da rete — grappa non traccia nemmeno
questo campo) e `CASEMAPPING=ascii` (fallback pre-005 di grappa
stesso, MAI corretto da `isupport_changed` perché quell'evento non
porta casemapping — quindi non è un guess temporaneo, è la verità
migliore disponibile per l'intera sessione). PREFIX/CHANMODES/
STATUSMSG restano assenti dal 005 di registrazione finché
`handle_grappa_isupport_changed_event` non manda quello vero,
confermato dalla rete — arriva entro pochi istanti dal primo join di
topic canale-shaped. Provato live: `005` di registrazione ora è
`CHANTYPES=# CASEMAPPING=ascii` nudo, seguito a ruota dal 005 completo
e corretto una volta joinato `#essency`.

**`join_failed`: fatto, provato live con un fallimento vero (`+k`
sbagliata).** `handle_join` fa un eco OTTIMISTICO subito dopo il `202`
REST (che significa solo "accettato, finestra `:pending` aperta" —
WIRE.md §2.5 — non "riuscito"), quindi un fallimento reale a monte deve
correggere quell'eco. `join_failed_payload` (`wire.ex:379-386`) porta
`reason`/`numeric` opzionali dall'ircd vero — `handle_grappa_
join_failed_event` manda il numerico reale se presente (altrimenti una
NOTICE), poi una PART sintetica così un client ben educato corregge da
solo la propria lista canali, e rimuove il canale da `sess->channels[]`
(altrimenti un retry dopo il fix crederebbe di essere già joinato,
saltando sia il tracking che il join del topic WS per-canale). Test
live: PART `#essency` reale → JOIN con chiave sbagliata → `475
testnick21 #essency :Cannot join channel (+k)` (numerico E testo
dell'ircd reale, non inventati) → PART sintetica di correzione → JOIN
con la chiave giusta → snapshot completo reale, confermato anche via
`GET /networks/azzurra/channels` (`joined: true`) che lo stato server
è davvero tornato coerente.

Gli altri kind rimasti sono no-op deliberati, non gap: `joined`
(controparte di successo di `join_failed` — l'eco ottimistico di
`handle_join` ha già detto tutto), `channels_changed` (`wire.ex:105`,
zero campi oltre kind — un "vai a rifare GET /channels se ti importa"
per un client che fa polling, cosa che bicchierino non fa),
`archive_changed`/`window_counts`/`query_windows_list` (concetti
tutti-UI-cicchetto — badge non lette, tab DM in sidebar — senza
equivalente nel protocollo IRC da renderizzare).

**Heartbeat applicativo Phoenix: fatto, provato live — chiudeva un gap
reale, non ipotetico.** Domanda dell'utente ("se un client manda
PING... riceviamo una risposta?") ha aperto la verifica: `endpoint.ex`
non imposta nessun `:timeout` sul transport `websocket:`, quindi vale
il default di Phoenix — 60s senza ricevere NULLA dal client prima che
il socket venga chiuso lato server. Prima di questo fix bicchierino non
mandava mai nulla di sua iniziativa dopo la join sequence: un client
IRC genuinamente idle (connesso, non digita nulla) avrebbe perso il
bridge WS dopo un minuto, innescando la chiusura `ERROR :lost grappa
connection` di CLAUDE.md §3.3 per colpa di nessuno. Fix, stessa cadenza
di `ws_pump` di shottino: ogni 25s (comodamente dentro la finestra dei
60s) un push `"heartbeat"` sul topic `"phoenix"` (mai joinato — nuovo
sentinel `join_ref == 0` in `bridge_push`, codificato come `null` JSON
non la stringa `"0"`, altro bug reale trovato mentre si implementava
questo: la vecchia `bridge_push` quotava SEMPRE il join_ref, non
poteva mandare null affatto) + un re-push di `visibility` alla stessa
cadenza (stessa finestra di staleness governa anche la presenza, per
lo stesso motivo di shottino). Il `poll()` di Fase 2 non è più a
timeout infinito (`-1`) ma 5s — l'unico modo per accorgersi che è ora
di mandare l'heartbeat anche quando nessuno dei due fd ha attività.
Test live: 80 secondi di connessione idle (oltre la finestra dei 60s),
poi un PING del client ha ricevuto PONG regolare — nessun errore, il
bridge era ancora vivo. Bonus: si è visto anche il client HTTP
persistente riconnettersi correttamente da solo per la `DELETE
/auth/logout` finale dopo lo stesso periodo idle — conferma che sia il
keep-alive HTTP che l'heartbeat WS reggono un'attesa reale, non solo
sulla carta.

**Rilevamento client-fantasma: fatto, provato live.** Domanda diretta
dell'utente ("potrebbe restare così per 30 minuti?") — risposta onesta:
sì, poteva davvero. L'heartbeat sopra tiene vivo IL BRIDGE verso
grappa, ma non dice nulla sul fatto che il client IRC sia ancora lì: un
peer TCP sparito senza un FIN/RST pulito (rete caduta, laptop in
sospensione, ...) non produce MAI attività su `poll()` — nessun modo di
distinguerlo da un client vivo ma silenzioso. Fix: bicchierino ora fa
quello che fa ogni ircd vero — pinga da solo un client rimasto in
silenzio, invece di rispondere solo ai PING che riceve. Dopo
`CLIENT_PING_THRESHOLD` (180s) di silenzio manda `PING :bicchierino`;
se non arriva NULLA (non necessariamente una PONG — qualunque traffico
resetta il timer, stesso criterio di un ircd vero) entro
`CLIENT_PING_TIMEOUT` (60s) altri, manda `ERROR :Ping timeout` e
chiude — percorso di cleanup identico a ogni altra disconnessione
(`bridge_close`/`logout_grappa`/`http_client_close`). Un client vero
raramente tocca questo percorso: la maggior parte dei client IRC pinga
già bicchierino per conto proprio ben dentro i 180s. Provato live
(soglie temporaneamente abbassate a 5s/3s, poi ripristinate a 180/60):
client connesso, registrato, poi silenzioso — `PING :bicchierino`
arrivato al momento giusto, poi `ERROR :Ping timeout` e socket chiuso
da bicchierino, log conferma tutto il cleanup (`client ping timeout,
closing` → `grappa session terminated`).

**KICK/INVITE/OPER + RAW come fallback universale: fatto, provato live
— incluso un incidente reale, non simulato.** `handle_kick`/
`handle_invite`/`handle_oper` in `connection.c` spingono i rispettivi
verbi WS (`{"network_id", "channel", "nick", "reason"}` per kick,
`{"network_id", "channel", "nick"}` per invite,
`{"network_id", "name", "password"}` per oper) sul topic utente via un
nuovo `push_on_user_topic` condiviso. Per tutto il resto —
`reconstruct_irc_line` ricostruisce la riga IRC verbatim dai `params`
già parsati (quoting `:` finale solo se necessario, RFC-corretto) e
`handle_raw` la spinge come verbo `"raw"` (`{"network_id", "line"}`,
`Session.send_raw/3`) — l'escape hatch che grappa stesso espone per
`/quote`: un client IRC vero non manda un comando "RAW" distinguibile,
`/quote` è testo verbatim, quindi RAW è l'UNICO fallback corretto per
qualunque comando senza un handler dedicato (WHOWAS/LINKS/LUSERS/
servizi/...), non un'approssimazione. **Insight scoperto implementando
KICK, non chiesto dall'utente**: op/deop/voice/devoice/ban/unban NON
servono handler dedicati — un client IRC vero non manda mai questi come
comandi wire distinti, `/op nick` genera SEMPRE lato client una riga
`MODE #chan +o nick` grezza, già coperta da `handle_mode` esistente; i
verbi WS dedicati con questi nomi in `grappa_channel.ex` esistono solo
per comodità UI di cicchetto (selezione multipla + chunking
automatico), non servono a bicchierino. **Test live**: `OPER claude
melohadettosonic!` (credenziali volutamente sbagliate, richiesto
esplicitamente dall'utente per farlo vedere a tutti gli oper della
rete) → confermato via `journalctl -u grappa`:
`verb=oper nick=claude [info] OPER request submitted`. `KICK #essency
tsk_ :test kick`, pensato come test "deve fallire" (basato su un test
PRECEDENTE nella stessa sessione dove SonicTest non aveva op) — è
invece RIUSCITO per davvero: SonicTest aveva nel frattempo ottenuto op
su `#essency` (confermato via `GET .../members`, `modes: ["@"]`), quindi
`tsk_` è stato espulso realmente dal canale reale. Nessun danno vero
(bouncer abbandonato da 2 mesi), ma lezione operativa: un rifiuto visto
in un test PRECEDENTE della stessa sessione non è garanzia che valga
ancora — i privilegi cambiano — e per un test "deve fallire in modo
affidabile" un bersaglio protetto dall'ircd stesso (bot ufficiale
speciale, es. GameBot su azzurra) è la scelta sicura, un nick umano
qualunque no.

**Quinto gotcha reale, stavolta lato RICEZIONE — WHOIS/WHO/NAMES/
BANLIST hanno bisogno del verbo WS DEDICATO, RAW non basta.** Un primo
tentativo di `WHOIS Sonic` mandato via `handle_raw` non ha prodotto
NESSUNA risposta, silenziosamente — non un bug di rendering (nessun
handler ancora esisteva per `whois_bundle`, quello sì), ma qualcosa di
più a monte: `Session.send_whois/5` (e i gemelli `send_who`/
`send_names`/`send_banlist`) PRIMANO un accumulatore per-target
(`state.whois_pending` ecc, confermato leggendo `server.ex`) PRIMA di
mandare la riga raw a monte — `EventRouter` fonde i numerici di
risposta (311-319, 352+315, 353+366, 367+368) in un bundle tipizzato
SOLO per un target che risulta pending. Un `/quote WHOIS` via `"raw"`
manda la riga identica ma salta la priming: l'ircd risponde comunque,
ma grappa non ha nessun bundle da costruire e la risposta si perde.
Fix: `handle_whois`/`handle_who`/`handle_names`/`handle_banlist`
dedicati, che spingono i verbi WS propri (`"whois"` — `{network_id,
nick[, server]}`; `"who"` — `{network_id, channel}`, il nome campo
resta `channel` anche per una maschera/nick per compatibilità wire con
cic; `"names"` — `{network_id, channel}`; `"banlist"` — `{network_id,
channel}`, letteralmente lo stesso `MODE #chan b` che manderebbe il
verbo `"mode"` generico ma CON la priming). `handle_irc_line`
intercetta `MODE #chan b` (bare, senza `+`/`-`, il caso "smaller gap"
già noto) e lo instrada a `handle_banlist` invece che a `handle_mode`
proprio per questo motivo. Lato ricezione: `handle_grappa_names_reply_event`/
`handle_grappa_who_reply_event`/`handle_grappa_whois_bundle_event`/
`handle_grappa_banlist_bundle_event` traducono i bundle in 353/366,
352/315, 311/312/313/317/319/318/401 (+330/301/671/276/extra_lines per
un futuro network solanum — azzurra/bahamut non li emette mai),
367/368. **Provato live, dati reali**: `WHOIS Sonic` → 311/312/313
(`Sonic` è davvero Server Administrator su azzurra)/319 (canali reali
con sigilli)/318; `WHOIS <nick inesistente>` → 401+318 corretto;
`WHO #essency` → 5 righe 352 con hostmask/hopcount/realname reali;
`MODE #essency b` → 368 nudo (banlist vuota, corretto).

**Sesto gotcha reale, trovato mentre si ripuliva una NOTICE fossile**:
`handle_grappa_network` (il selettore Case B, `GRAPPA NETWORK <slug>`)
faceva `fetch_joined_channels` + `present_channels` ma non chiamava
MAI `bridge_connect`/`join_grappa_topics` — solo `connection_run` lo
faceva, e solo nel ramo Case A (rete già risolta da `PASS`). Una
connessione Case B riceveva quindi la lista canali completa alla
registrazione ma ZERO eventi live per tutta la vita della connessione,
in silenzio — la vecchia NOTICE "the websocket bridge isn't implemented
yet" era rimasta vera SOLO per questo percorso, mentre il resto del
codice l'aveva superata da un pezzo. Fix: `br_connected` ora è un
puntatore lungo tutta la catena `connection_run` → `handle_irc_line` →
`handle_grappa_network` (gli altri handler lo leggono ancora per
valore, sola lettura), così quando Case B risolve la rete a metà
sessione il loop `poll()` di Fase 2 vede la transizione down→up alla
`poll()` successiva, non dopo una riconnessione. Provato live: `PASS
bogus:!test88!` (nome rete non esistente, forza Case B per davvero —
occhio a `pick_network`, il fallback su rete vuota sceglie l'unica rete
disponibile se ce n'è una sola, serve un nome ESPLICITO e sbagliato per
testare Case B davvero) → NOTICE "not connected to any network" →
`GRAPPA NETWORK azzurra` → JOIN eco + 332/324/005-corretto/353/366
arrivano SUBITO dopo, prova diretta che il bridge WS è vivo (prima del
fix, silenzio totale oltre l'eco JOIN).

**Tracking del nick live: fatto, provato live — chiudeva un gap reale
segnalato dall'utente, non solo cosmetico.** Prima di questo fix,
`reg.nick` (lo snapshot preso una volta dal `NICK` di registrazione)
restava l'unico nick usato in OGNI numerico/prefisso verso il client per
tutta la vita della connessione — un `nick_change` che riguardava NOI
STESSI (rinominati dal client stesso via `/nick`, o da un altro
front-end sullo stesso account — cicchetto, shottino) veniva comunque
renderizzato (invio incondizionato, §precedente) ma senza aggiornare
nulla: ogni numerico SUCCESSIVO continuava a indirizzare il client col
nick VECCHIO. **Segnalazione dell'utente, precisa**: alcuni client IRC
veri, vedendo un numerico indirizzato a un nick diverso da quello che
credono sia il proprio, assumono di aver perso un `NICK` e si
riallineano da soli — quindi il disallineamento non restava solo
cosmetico, poteva fare RIALLINEARE IL CLIENT sul nick sbagliato,
peggiorando il desync invece di limitarsi a mostrarlo. Fix:
`sess->network_nick` (già usato per il self-detection fold, §5.5)
diventa l'UNICA fonte viva — aggiornato dentro
`handle_grappa_message_event` quando il `nick_change` è nostro
(`is_self`), e ogni chiamata client-facing che prima leggeva
`reg.nick`/`reg->nick` DOPO la risoluzione della rete (bootstrap Case A,
`handle_grappa_network` Case B, `handle_join`/`handle_part`/
`handle_kick`, il dispatch `handle_grappa_event` di Fase 2) ora legge
`sess->network_nick`. **Effetto collaterale corretto, non voluto ma
giusto**: prima di questo fix il welcome iniziale (001-004) usava
sempre il nick DICHIARATO dal client (`reg.nick`, es. `claude`), anche
quando differiva dal vero nick di rete dell'account (es. `SonicTest`) —
un mismatch presente fin dalla primissima riga, visibile confrontando
il proprio prefisso JOIN con la propria voce nella 353 dello stesso
canale. Ora il welcome stesso usa `sess.network_nick` (popolato da
`pick_network` PRIMA del welcome in Case A), quindi è coerente con la
realtà di rete fin dal primo numerico, non solo dopo un eventuale
`nick_change`. **Test live**: `NICK SonicTestX` da client → eco
`:SonicTest!... NICK :SonicTestX` (rename upstream riuscito per
davvero) → `WHOIS SonicTestX` immediatamente dopo mostra OGNI numerico
(311/312/317/319/318) indirizzato a `SonicTestX`, non più al vecchio
`SonicTest` — provato che il tracking segue davvero il cambio, non solo
che la riga NICK viene mostrata. **Attenzione per test futuri**:
`SonicTest` è un account grappa SEMPRE-ON condiviso fra sessioni — un
test che rinomina il nick di rete lo lascia rinominato anche dopo la
disconnessione del client bicchierino (grappa non si disconnette da
monte solo perché un front-end locale chiude), quindi un test così va
SEMPRE riportato a `SonicTest` prima di chiudere, verificato con un
secondo connect pulito (fatto qui, entrambi provati live).

**Gap noto correlato, non chiuso da questo fix**: il topic WS del
DM-listener (`grappa:user:{subject}/network:{net}/channel:{proprio-nick
foldato}`, §4) resta ANCORA agganciato al nick VECCHIO dopo un
self-`nick_change` — è un path di topic Phoenix costruito UNA VOLTA al
bootstrap (`join_grappa_topics`), non ri-joinato. Dopo un cambio nick
live, i DM in arrivo smetterebbero silenziosamente di arrivare (stesso
meccanismo del gotcha ASCII-fold, §5.5: nessun errore, solo un topic
path che non matcha più) finché la connessione non si riavvia. Risolverlo
per bene serve `phx_leave` (mai implementato, `bridge.c`/`.h` non ha
alcuna primitiva di leave) più un ri-join del nuovo topic — fuori scope
per questo fix, che ha chiuso solo il desync di numerici/prefissi
segnalato dall'utente.

**`ensure_network_connected`: fatto, provato live — chiudeva un gap reale
di produzione, scoperto investigando un account admin-creato ("Testone")
rimasto bloccato senza mai connettersi a IRC.** Indagine: `journalctl`
non mostrava ALCUN errore di connessione, perché non c'era stato ALCUN
tentativo — `POST /admin/credentials` (il bind dell'admin panel) è un
`Repo.insert` puro (confermato leggendo `Credentials.bind_credential/3`
in grappa-irc): scrive la riga DB con `connection_state: "connected"`
ma non chiama MAI `SpawnOrchestrator`, quindi nessun `Session.Server`
nasce mai. `GET /networks` da solo non lo fa partire nemmeno lui — è per
questo che cicchetto ha un bottone "connetti" (`PATCH
/networks/:network_id {"connection_state":"connected"}`, che DELEGA a
`SpawnOrchestrator.spawn/4` e blocca fino a spawn riuscito o fallito
prima di rispondere). Bicchierino non aveva alcun equivalente: un client
che si collegava a un account mai stato live prima restava semplicemente
registrato, canale-list vuota, per sempre, senza errore visibile.

**Fix**: nuova `ensure_network_connected`, chiamata INCONDIZIONATAMENTE
a ogni bootstrap (Case A dentro `connection_run`, Case B dentro
`handle_grappa_network`), PRIMA di `fetch_joined_channels` — mai gated
su un check "sembra già connesso", perché grappa stesso documenta il
caso già-connesso come esplicitamente idempotente
(`SpawnOrchestrator.spawn/4` deduplica su `:already_started`,
`Networks.connect/1` no-op su `:connected` già presente) — un check
condizionale qui sarebbe stato un caso speciale non necessario per un
costo già irrisorio (un round-trip REST in più per CONNESSIONE, non per
messaggio). Un fallimento (capacità/admission/resolve_failed) è
riportato onestamente con una NOTICE al client, ma non è fatale — stessa
filosofia della NOTICE già esistente per il fallimento del bridge WS: il
resto del bootstrap procede comunque, come farebbe un bouncer vero che
mostra "non connesso" invece di rifiutare l'intera sessione.

**Gotcha reale nel fix stesso, trovato SUBITO al primo test live**: la
prima versione costruiva il path come `/networks/%ld` usando
`sess->network_id` (l'ID numerico) — 404 immediato, anche testando
contro `SonicTest` GIÀ connesso. Causa: il param di route si chiama
`:network_id` ma `Plugs.ResolveNetwork` lo risolve SEMPRE via
`Networks.get_network_by_slug/1` — è uno SLUG (`"azzurra"`), non la FK
numerica, nonostante il nome. Lo stesso gotcha che ogni ALTRA chiamata
REST in questo file già evita usando `network_slug`
(`fetch_joined_channels`, `send_join_rest`, `send_part_rest`) — stavolta
mi è sfuggito fidandomi del nome del param nella moduledoc invece di
leggere l'implementazione del plug. Fix: `url_encode(sess->network_slug,
...)`, stesso pattern delle altre tre chiamate. **Provato live, due
volte**: prima la versione rotta (404, riprodotto anche su `SonicTest`
già connesso — prova che l'idempotenza NON c'entrava, era proprio il
path sbagliato), poi la versione corretta (200, nessuna NOTICE di
fallimento, tutto il resto del bootstrap identico a prima — la
riconferma che il caso già-connesso resta innocuo). **Non ancora provato
contro un account VERAMENTE mai connesso** (`Testone` — non ho le sue
credenziali di login grappa, solo accesso DB/journalctl da root):
l'utente testerà questo caso specifico da un client reale.

**Il resto della lista "smaller gaps": chiuso in un solo giro, tre su
quattro provati live.**

- **`umode`: fatto, provato live.** Verbo WS separato da `mode` canale
  (`Session.send_umode/3`, payload `{network_id, modes}`) —
  `handle_irc_line` intercetta `MODE <propriosnick> <modestring>` (target
  folda uguale a `sess->network_nick`, nessun `#`) PRIMA che raggiunga
  `handle_mode`, che altrimenti farebbe no-op silenzioso su un target non
  canale. Lato ricezione, `umode_changed` (`{kind, network_id, modes:
  [letters...]}`) è uno SNAPSHOT assoluto, non un delta — nessun attore,
  nessuna info su cosa fu aggiunto vs rimosso — renderizzato come la
  miglior approssimazione onesta disponibile: una riga MODE che aggiunge
  ogni lettera nello snapshot, mai una lettera non realmente attiva.
  Limite noto, non un bug: una RIMOZIONE non è rappresentabile da uno
  snapshot da solo (un client locale potrebbe restare convinto che una
  lettera rimossa sia ancora attiva). Test live: `MODE SonicTest +i` (già
  attivo, nessun evento — nessun cambio reale = nessun evento reale, non
  un bug) poi `MODE SonicTest -i` → `MODE SonicTest :+S` (lo stato
  risultante corretto, S = quello che restava). Riconnessione pulita
  successiva conferma lo stato di rete davvero tornato a `+S` nudo.
- **333 RPL_TOPICWHOTIME: fatto, provato live.** L'unico di questi che
  serviva vero lavoro nuovo, non solo wiring: `topic.set_at` sul wire è
  una stringa ISO8601 (`topic_entry_wire`, `wire.ex:220-224`), 333 vuole
  un unix epoch — niente libreria di date in questo codebase, quindi
  `parse_iso8601_utc_epoch`/`utc_to_unix` fanno la conversione a mano
  (loop anno-per-anno deliberato, non una formula chiusa per i giorni
  bisestili — troppo facile sbagliare l'off-by-one — né `timegm()`, non
  esposto sotto `_POSIX_C_SOURCE=200809L` di questo progetto senza tirare
  dentro anche `_DEFAULT_SOURCE`). Mandato solo quando `set_by`/`set_at`
  sono ENTRAMBI presenti — mai un valore inventato. Test live:
  `#essency`, topic reale di `Sonic` → `333 SonicTest #essency Sonic
  1776727755`, convertito a mano per conferma → 2026-04-20, data
  plausibile per un topic già visto prima in questa stessa sessione.
- **`phx_leave` su PART: fatto.** `bridge_push` con evento `"phx_leave"`
  payload `"{}"` è già sufficiente — non serviva una nuova funzione in
  `bridge.c`/`.h`, `bridge_push` è già abbastanza generico (fire-and-
  forget, qualunque `phx_reply` di ritorno viene assorbito dal ramo
  generico già esistente in `handle_grappa_event`). `handle_part` ora
  chiama questo PRIMA di `remove_channel_at` (serve ancora il join_ref
  dell'entry che sta per sparire).
- **`phx_leave` + rejoin sul DM-listener dopo un self nick_change: fatto,
  provato live — il vero motivo per implementare `phx_leave` affatto**,
  non il leak innocuo di PART. Gotcha di design reale, non solo
  implementativo: il rejoin non può avvenire INLINE dentro
  `handle_grappa_message_event`, perché quella funzione può girare
  NIDIFICATA dentro il proprio loop di attesa di un ALTRO `bridge_join`
  (via `bridge_event_dispatch` — capita davvero durante il bootstrap, 3
  `bridge_join` di fila) — un `bridge_join` bloccante lanciato da lì
  dentro rischierebbe di rubare la risposta di quello ESTERNO. Fix in due
  tempi: la LEAVE (fire-and-forget, mai bloccante, sicura ovunque) avviene
  subito, inline, usando `folded_sender` (il nick VECCHIO, già foldato
  per il controllo `is_self` — nessun bisogno di salvarlo altrove); un
  nuovo flag `sess->dm_needs_rejoin` viene settato invece di fare la JOIN
  lì; il loop principale di Fase 2 (mai nidificato dentro un
  `bridge_join`, stesso punto sicuro già usato per l'heartbeat) controlla
  il flag una volta per iterazione e fa la JOIN vera lì. Ha richiesto di
  far passare `struct bridge *br` lungo tutta la catena di dispatch
  eventi (`handle_grappa_event`, `bridge_event_ctx`,
  `handle_grappa_message_event`) — non c'era prima, tutti gli altri
  handler leggono solo `fd`/`nick`/`sess`. **Provato live, ciclo
  completo**: `NICK SonicTestY` → log conferma `joined DM listener
  .../channel:sonictest` (bootstrap) seguito da `DM listener rejoined
  .../channel:sonictesty` — E un secondo 005 inatteso arrivato subito
  dopo la riga NICK nel client si è rivelato la controprova indiretta
  perfetta: OGNI join di topic canale-shaped (compreso il DM-listener)
  ritrigghera `isupport_changed`, quindi un 005 fresco (indirizzato al
  NUOVO nick) è esattamente ciò che ci si aspetterebbe da un rejoin
  riuscito. Poi `NICK SonicTest` (revert) → `DM listener rejoined
  .../channel:sonictest`, tornato all'originale, confermato anche da una
  riconnessione pulita successiva.

**Query `MODE #chan` senza modestring: fatto, provato live — l'utente ha
corretto la valutazione "caso raro" appena scritta qui sopra: alcuni
client la usano davvero per chiedere lo stato corrente, non va
liquidata.** Design scelto DOPO aver capito come funziona un ircd vero:
il server risponde 324 dal proprio stato IN MEMORIA, senza bisogno di
richiedere nulla a monte — bicchierino può fare esattamente lo stesso,
perché ha GIÀ tutta l'informazione necessaria in cache, aggiornata a ogni
`channel_modes_changed` (sia lo snapshot al join sia ogni update live) —
niente round-trip a grappa, risposta istantanea, stesso principio con
cui cicchetto stesso funziona lato client ("mirror, mai richiedere").
Nuovi campi paralleli a `sess->channels[]`: `channel_mode_str[]` +
`channel_mode_params[]`, scritti da
`handle_grappa_channel_modes_changed_event` (che ora riceve anche
`sess`), letti da `handle_channel_modes_query` per una `MODE #chan`
bare (`param_count == 1`, distinta sia dal caso banlist `MODE #chan b`
sia dal caso umode `MODE <ownnick> <modestring>`, entrambi già
intercettati prima nello stesso `if`). **Gotcha reale trovato
implementando, non solo teorico**: uno slot dell'array può restare
"sporco" — un PART che rimuove l'ULTIMA entry non fa shift (solo
`channel_count--`), quindi una JOIN successiva che rioccupa quello
stesso indice troverebbe ancora la cache del canale VECCHIO finché il
proprio `channel_modes_changed` non arriva — fix: `handle_join` pulisce
esplicitamente `channel_mode_str[idx]`/`channel_mode_params[idx]` al
momento dell'append, non solo `remove_channel_at` che tiene l'array
denso per lo shift-down normale. Nessuna riga inventata quando la cache
è vuota (finestra breve fra il 202 REST di una JOIN e il primo snapshot
WS, o un canale mai joinato) — silenzio, non un "+" fabbricato. **Provato
live**: `MODE #essency` (bare) → `324 SonicTest #essency +rnts`
(istantaneo, stesso valore già visto al join); `MODE #nonexistent`
(bare, mai joinato) → silenzio, nessuna riga.

**MODE su un canale NON joinato via bicchierino: analizzato a fondo,
DELIBERATAMENTE non implementato — vedi issue #1.** L'utente ha chiesto
se, come fa cicchetto, si potesse controllare i modi di un canale senza
esserci dentro (uso reale da operator: controllare i modi di un canale
altrui per aiutare qualcuno, senza volerci comparire dentro). Scoperto
insieme all'utente, leggendo il codice reale: cicchetto stesso NON fa
una query live — `push_channel_snapshot`'s mode push è gated
`push_modes_if_cached`, quindi rimanda SOLO stato già in cache lato
grappa da un'occasione precedente; un canale mai visto prima non
risponde nemmeno a cicchetto. Un fix vero (query live per QUALSIASI
canale) servirebbe una sottoscrizione temporanea al topic WS del canale
(la reply arriva SOLO su quel topic specifico, `Broadcaster.to_channel`,
mai sull'user topic) — confermato che iscriversi al topic NON fa un
JOIN IRC reale (`Client.send_join` non viene mai chiamato dal path di
join WS, tracciato su ogni call site), quindi l'operator non
comparirebbe mai nel canale. Ma un "join, aspetta LA MIA reply, poi
lascia" naive si rompe se due query diverse (es. `/mode` poi `/topic`
sullo stesso canale non joinato) condividono la stessa sottoscrizione —
chi arriva prima la chiuderebbe sotto i piedi dell'altra. Design
corretto discusso ma non implementato: MAI chiudere una sottoscrizione
"shadow" aperta solo per query, tenerne una lista dedup per evitare
sottoscrizioni duplicate, lasciarle morire naturalmente alla chiusura
della connessione — evita il ref-counting del tutto. **Deciso di NON
costruirlo ora**: l'utente ha aperto un bug upstream su grappa stesso
(https://github.com/vjt/grappa-irc/issues/975) — sembra che la fix di
vjt possa far arrivare queste reply sull'user topic (sempre
sottoscritto), il che eliminerebbe la necessità di QUALSIASI
meccanismo di sottoscrizione temporanea lato bicchierino. Tracciato in
`irc/bicchierino#1` su GitLab, che referenzia l'issue grappa — si
aspetta quella prima di toccare altro qui.

**LINKS/WHOWAS/LUSERS/INFO/VERSION/MOTD-on-demand: fatto in un solo
giro, tutti provati live con dati reali di produzione.** Stessa identica
classe di verbi dedicati di WHOIS/WHO/NAMES/BANLIST (priming lato
grappa confermato per links/whowas/info/version/motd — solo `lusers` non
sembra avere un `*_pending` da nessuna parte nel sorgente, implementato
comunque come verbo dedicato per coerenza) — TUTTI e sei rispondono
sull'user topic (nessuno dei complicati problemi di sottoscrizione del
caso MODE-su-canale-non-joinato sopra, perché nessuno di questi è
scoped a un canale). **Gotcha reale trovato al primo giro di test**:
`handle_lusers`'s ramo bare (`LUSERS` senza argomenti) mandava un
payload `{}` vuoto — mancava letteralmente `network_id`, l'UNICO campo
richiesto dal verbo grappa anche nella forma più semplice. Il push
andava a segno lato WS (nessun errore di rete) ma grappa non trovava
nessuna clausola `do_handle_in` che facesse match su un payload senza
quella chiave, quindi cadeva nel catch-all "verbo sconosciuto" silenzioso
(contratto additive-only del wire, mai fatale) — zero risposta, zero
errore visibile, il tipo di bug più insidioso perché sembra un timeout
di rete invece che un payload malformato. Fix: `{"network_id":...}`
anche nel ramo a zero argomenti, provato di nuovo, tutti e 7 i numerici
(251-255, 265-266) arrivati con statistiche di rete reali. **Provato
live, tutti con dati reali**: `LINKS` → topologia completa di azzurra (8
server, hop reali); `WHOWAS Sonic` → 314+312 con vero orario di
disconnessione storico; `WHOWAS <inesistente>` → 406 corretto; `LUSERS`
→ 7 numerici con statistiche di rete vere; `INFO` → dump completo reale
del bahamut di produzione (crediti, ASCII cow art compresa); `VERSION`
→ stringa versione reale; `MOTD` on-demand → MOTD reale di Azzurra,
identico a quello mostrato da un client IRC vero. **Confermato anche
lato ircd**, indipendentemente dal client di test — l'utente ha
verificato i propri log operatore reali sull'ircd stesso: notice reali
di LINKS/INFO/MOTD "requested by SonicTest" con timestamp coincidenti
con i test qui sopra, prova che le richieste sono davvero arrivate a
monte, non solo che grappa ha risposto qualcosa di plausibile.

**AWAY (set/unset) e TOPIC (in uscita, set + clear): fatti, provati
live.** `AWAY` è l'UNICO verbo in tutto il catalogo chiavato su
`"network"` (lo slug, stringa) invece di `"network_id"` (la FK numerica
che ogni altro verbo usa) — vera inconsistenza nel wire di grappa
stesso, confermata leggendo `grappa_channel.ex` direttamente, non
assunta dal pattern di naming che ogni altro verbo segue. Ricezione:
`away_confirmed` (broadcast su `Topic.user`, quindi niente problemi di
sottoscrizione) è uno stato assoluto (`:present`/`:away`), mai un
delta — 306/305 di conseguenza, mai indirizzati a niente altro che
questa transizione specifica.

TOPIC in uscita ha risolto l'ambiguità REST-vs-WS lasciata aperta a
metà sessione: il SET resta REST (`POST .../topic`, stesso bucket di
JOIN/PART/PRIVMSG, mai un twin WS usato) ma il CLEAR deve passare dal
verbo WS dedicato `topic_clear` — **confermato leggendo il controller
REST stesso**: `ChannelsController.topic/2` ha una guard esplicita
`body != ""`, quindi un body vuoto non fa nemmeno match sulla clausola
e cade su `{:error, :bad_request}` — non esiste ALCUN modo di
cancellare un topic via REST, mai stato un'ambiguità reale una volta
letto il codice giusto. `handle_topic` smista fra i due in base a
`msg->params[1][0] == '\0'`. Nessun eco ottimistico manuale servito per
nessuno dei due — il vero eco TOPIC dell'ircd arriva già come evento
`message` di kind `"topic"`, renderizzato incondizionatamente (self-echo
NON soppresso per topic, stessa scelta di kick/mode/quit) dal codice
già esistente. **Provato live su `#essency` (canale reale dell'utente),
topic reale ripristinato al termine come richiesto**: SET → eco TOPIC +
332/333 con testo e timestamp reali; CLEAR → 332 con testo vuoto
(nessun 331 RPL_NOTOPIC — gap pre-esistente già noto, non introdotto
ora); SET di ripristino → eco + 332/333 corretti; **verificato con una
connessione pulita separata, non solo l'eco della stessa sessione che
ha fatto la modifica** — `=S= Sonic Private Channel =S=` confermato
davvero tornato.

**Prossimo passo vero**: nessuno di ops/info resta scoperto lato invio
(RAW copre tutto il resto), a parte MODE-su-canale-non-joinato (sopra,
volutamente in attesa di grappa).

**PONG a un PING WS raw: fatto — ma è l'unica cosa di questa sessione
NON provata live contro grappa reale, e va detto esplicitamente.**
grappa non manda mai un vero PING WS-level (usa solo l'heartbeat
applicativo di Phoenix), quindi non esiste un modo di innescare questo
path contro il traffico reale di produzione — costruire un finto peer
WS solo per sintetizzare un PING avrebbe richiesto reimplementare buona
parte del protocollo di join di Phoenix, sproporzionato per un path che
probabilmente non scatterà mai. Compensato con: (1) trace byte-per-byte
di `send_masked_frame` contro RFC 6455 §5.2/§5.3 (byte FIN/opcode,
encoding della lunghezza incluse le forme estese 126/127, XOR di
masking) — combacia esattamente; (2) refactor, non codice nuovo da
zero — `ws_client_send_text` (usato con successo per OGNI push WS di
tutta questa sessione, decine di round-trip reali) ora passa dalla
stessa `send_masked_frame` condivisa, quindi la logica header/masking
NON è nuova, è quella già provata dozze di volte — l'unico delta vero è
il byte opcode (0xA invece di 0x1) e una lunghezza esplicita invece di
`strlen`; (3) **regression check live**: dopo il refactor, un bootstrap
completo (3 push WS: user topic, canale, DM-listener) + un WHOIS
round-trip funzionano identici a prima — nessuna rottura introdotta dal
refactor stesso. Non è lo stesso livello di certezza di "provato live
con un vero PING", ma è la miglior verifica disponibile senza costruire
un finto server grappa completo — onestamente segnalato come tale.

La lista "smaller gaps" è ora COMPLETAMENTE chiusa.
`ensure_network_connected` non ancora confermato contro un account
genuinamente mai connesso (`Testone` — l'utente testerà da un client
reale).

## 8. `bind ... tls` era finto — mai provato live, l'utente l'ha beccato

**L'utente ha insistito per mesi/sessioni che un listener non-loopback
DEVE essere TLS (password grappa dentro PASS, in chiaro fuori da TLS è
un secret vero), al punto da doversi inventare `--insecure` come
workaround per lo sviluppo locale — e poi ha chiesto direttamente: ma
il listener TLS stesso, l'hai MAI provato per davvero?** Risposta
onesta: no. Ogni singolo test di questa sessione (e a giudicare dal
codice, anche di sessioni precedenti) ha usato `bind 127.0.0.1 ... plain`
— il path TLS lato listener non era MAI stato esercitato.

**La cosa peggiore possibile NON era vera, ma per un pelo**: `main.c`
portava già un TODO onesto ("TLS listeners accept plaintext for now and
never wrap the socket in an SSL_accept") — MAI sistemato. Un vero
client TLS (Python `ssl`, `openssl s_client`) che si connette a un bind
`tls` restava con l'handshake appeso per sempre (bicchierino leggeva i
byte grezzi del ClientHello come se fossero testo IRC in chiaro) — quindi
in pratica nessun client TLS reale avrebbe MAI potuto connettersi con
successo. Non era un buco di sicurezza SFRUTTABILE (nessuno stava
davvero mandando password in chiaro su quella porta, perché nessuna
connessione TLS reale funzionava affatto), ma la promessa del `bind ...
tls` era comunque falsa — esattamente la classe di bug ("asserire
qualcosa non vero") che questo progetto ha sempre trattato come serio.

**Fix, sul branch principale (`develop`), non su `feature/chathistory`
dove stava girando il lavoro del momento — deliberatamente, su
richiesta esplicita.** Grep mirato ha confermato: SOLO due punti in
tutto `connection.c` toccano il socket client direttamente (`recv()`
dentro `next_line`, `write()` dentro `send_line`) — nessun altro punto
fa I/O grezzo sul client. Invece di far passare un nuovo parametro SSL
attraverso decine di funzioni che chiamano `send_line` (quasi tutto il
file), la SSL è thread-local (`static _Thread_local SSL *g_client_ssl`)
— sound proprio perché il modello di concorrenza di questo codebase è
già un thread per connessione con zero stato condiviso (CLAUDE.md §3):
lo storage thread-local si scopa naturalmente a esattamente la sessione
SSL di un client, stessa garanzia di un parametro `struct`, senza il
costo meccanico di rifare la firma di ogni funzione in un file di
questa taglia. `client_tls_accept`/`client_tls_close` fanno il vero
`SSL_accept` handshake in cima a `connection_run` (usando `cert_path`/
`key_path` già presenti in `struct bind_config`, mai serviti prima
d'ora) e il teardown a OGNI exit path (il ritorno anticipato pre-Phase-1
E il `cleanup:` esistente). Un bind `plain` non tocca per niente questo
codice — `g_client_ssl` resta NULL, `client_recv`/`client_write`
degradano esattamente al vecchio `recv`/`write`.

**Provato live, entrambi i path**: (1) client TLS reale (Python `ssl`,
TLS 1.3, `TLS_AES_256_GCM_SHA384`) contro un bind `tls` con lo stesso
certificato self-signed già generato per `bicchierino-preprod` →
handshake riuscito, registrazione completa, bootstrap reale contro
grappa, round-trip WHOIS — tutto identico a un client plain, ma
davvero cifrato stavolta; (2) bind `plain` esistente riprovato dopo il
fix → nessuna regressione, comportamento identico a prima (`next_line`/
`send_line` toccati da questo fix, quindi la riprova non era
opzionale).

## 9. Primo test con un client IRC vero (irssi, via `bicchierino-preprod`) —
trovato un bug reale al primo giro

**`bicchierino-preprod`** (`~/progetti/bicchierino-preprod`, LAN IP
`192.168.2.54:4688`, TLS, certificato self-signed) è stato messo su per
far testare l'utente con irssi vero — la prima volta in assoluto che
bicchierino viene toccato da un client IRC reale invece che dai miei
script Python. Ha trovato SUBITO un bug genuino.

**Bug: `/names` non mostrava MAI un sigillo (@/%/+), nemmeno per
`SonicTest`, op confermato in `#essency` (visto più volte questa sessione
via WHOIS's 319: `@#essency`).** Causa, confermata leggendo il sorgente
reale di grappa (`event_router.ex:2908-2912`, `split_mode_prefix/1`): il
campo `modes` di un member in `members_seeded`/`names_reply` contiene
GIÀ il carattere sigillo grezzo (`@`/`%`/`+`), MAI una lettera di modo
(`o`/`h`/`v`) — `split_mode_prefix` lo costruisce direttamente dal primo
byte di un token 353 RPL_NAMREPLY (`<<prefix, rest::binary>> when prefix
in [?@, ?%, ?+] -> {rest, [<<prefix>>]}`), nessuna traduzione a lettera
avviene MAI lato grappa. Il codice di `render_names_353_366` invece
cercava `letter[0] == 'o'` — un'assunzione MAI verificata contro il
sorgente reale (il campo `modes` di WHO è davvero fatto di lettere,
un evento DIVERSO con lo stesso nome di campo — probabile origine della
confusione), quindi non ha MAI trovato una corrispondenza, in silenzio,
per tutta la sessione. Fix: legge direttamente `modes[0]` come sigillo
(al massimo un elemento — grappa/bahamut mandano un solo sigillo
principale per token NAMES, mai una forma multi-prefix `@+nick`, coerente
col fatto che questo codice non annuncia nemmeno `multi-prefix`),
validato contro l'insieme noto di sigilli invece di fidarsi alla cieca.
**Più semplice del codice sbagliato precedente, non più complesso.**

**Provato live**: riconnessione pulita dopo il fix → `353 ... :@Sonic
@SonicTest GameBot Hypnotize tromBOTic` — entrambi gli op reali mostrano
correttamente `@`.

Bug separato, risolto dall'utente stesso lato client prima che potessi
indagare: il primo tentativo di connessione irssi ha prodotto
`SSL routines::wrong version number` lato server (bicchierino riceveva
byte non-TLS su una porta TLS) — sintomo tipico di un client che non ha
davvero attivato TLS nella sua invocazione, non un bug di bicchierino.
L'utente ha risolto da solo la sintassi lato irssi.

## 10. Multi-client sullo stesso account grappa — 2 bug reali trovati testando live, 1 gap architetturale scoperto per caso

Su richiesta esplicita dell'utente ("collega 2 client irc a bicchierino,
ho paura che quando ha 2 client per lo stesso user si incasini"): due
connessioni bicchierino indipendenti (thread, socket, `struct
grappa_session`, login/token grappa separati) che condividono LO STESSO
account grappa (stesso subject) non erano mai state testate. Trovati due
bug reali, più un gap pre-esistente scoperto mentre si verificava il
secondo.

**Bug 1 — perdita di messaggi tra connessioni gemelle (FIXATO).**
`is_self` (mittente foldato == proprio nick) non distingueva "il mio
echo ottimistico da QUESTA connessione" da "un messaggio appena mandato
da una connessione GEMELLA con la stessa identità" — entrambi risultano
`is_self == true`, e il vecchio codice sopprimeva ENTRAMBI, quindi un
PRIVMSG mandato dal client A spariva anche dal client B (stesso
account) — perdita di messaggi vera, non soppressione corretta
dell'eco. Fix: `send_privmsg_rest` ora legge il body della risposta
REST su 201 (`Wire.to_json/1`, stesso shape ovunque) ed estrae l'`id`
del messaggio appena persistito, salvato in un piccolo ring
`pending_self_msg_ids[16]` su `struct grappa_session`.
`handle_grappa_message_event` sopprime un evento self-labeled SOLO se il
suo `id` combacia con qualcosa nel pending set (rimuovendolo una volta
consumato) — altrimenti (mandato da un gemello) lo rende normalmente.

**Correzione critica dell'utente durante l'implementazione**: per il
caso specifico di una DM IN USCITA da una connessione gemella (non un
messaggio di canale), renderla alla lettera (`me!...  PRIVMSG me
:body`, target = proprio nick) avrebbe fatto aprire a un client IRC
vero una query bacata verso se stesso, perché i client instradano le
righe in arrivo per TARGET, non per prefisso. Fix: la riga viene
falsificata come se arrivasse DAL PEER (`peer!bicchierino@bicchierino
PRIVMSG <propriconick> :<propriconick> body`), così la query si
apre/aggiorna sotto il nick del PEER (la finestra corretta), col corpo
prefissato da `<propriconick>` per indicare che il mittente reale sono
io da un'altra connessione — la convenzione standard dei bouncer
multi-client per questo esatto limite di protocollo.

Verificato live: PRIVMSG di canale da A appare correttamente su B, non
duplicato su A. Vedi il gap sotto per la DM.

**Bug 2 — QUIT da un client ammazzava TUTTE le connessioni gemelle
(FIXATO).** Confermato via log server: il QUIT/logout pulito del
client B era seguito IMMEDIATAMENTE dalla morte del WebSocket di A
verso grappa. Causa root, letta nel sorgente grappa reale:
`auth_controller.ex`'s `logout/2` → `maybe_disconnect_socket/1` →
`UserSocket.disconnect_subject/1` → `disconnect_user_name/1` →
`Endpoint.broadcast(socket_id, "disconnect", %{})` — il meccanismo
standard di Phoenix per chiudere OGNI socket che condivide quel
`socket_id`, condiviso da TUTTI i socket dello stesso subject/account,
non solo dalla sessione che sta facendo logout.

Fix: bicchierino non chiama più `DELETE /auth/logout` nel teardown
ordinario (rimossa `logout_grappa` e la sua chiamata in `cleanup:`).
Giustificato da `accounts.ex` (commento: "Sliding 7-day idle expiry") —
i token di sessione grappa NON sono permanenti, quindi un token
abbandonato e mai revocato si pulisce comunque da solo entro una
finestra limitata, un costo molto più basso di ammazzare ogni
connessione gemella a ogni QUIT. Verificato live: dopo il QUIT di B, A
risponde ancora a PING e riesce ancora a mandare PRIVMSG.

**Gap architetturale scoperto (NON FIXATO, fuori scope per oggi) — le
DM in uscita non tornano MAI indietro, nemmeno al mittente stesso, su
NESSUN client.** Testando la DM A→GameBot: la POST REST riesce (201,
`id` valido, `channel:"gamebot"` nel body), ma NESSUN client (nemmeno
A) vede mai l'eco. Causa, confermata leggendo `Session.Persistor.
persist_and_broadcast/3` + `handle_persisting_send` in
`~/progetti/grappa-irc/lib/grappa/session/{persistor,server}.ex`: il
topic PubSub su cui grappa fa broadcast è SEMPRE derivato da
`attrs.channel` (`Topic.channel(subject, network, attrs.channel)`), e
per una DM IN USCITA `attrs.channel` è il nome (foldato) del
DESTINATARIO (`gamebot`), non il proprio nick — asimmetrico rispetto
alle DM IN ENTRATA, dove invece `channel` viene re-keyed al proprio
nick (`server.ex:4600-4607`, già noto e verificato prima in sessione).
bicchierino oggi si iscrive SOLO al topic statico del proprio nick
(`channel:sonictest`, per le DM in entrata) più i topic dei canali
joinati — MAI a un topic per-peer come `channel:gamebot`. L'evento che
segnalerebbe "si è aperta una nuova query window" (`query_windows_list`,
broadcast sul topic utente dopo il persist+broadcast, per-#422) è un
no-op deliberato in `handle_grappa_message_event` (connection.c
~3208-3211) — mai implementato.

Questo NON è un bug introdotto dal lavoro di oggi: è un limite
pre-esistente del modello di sottoscrizione DM di bicchierino, mai
notato prima perché nessuna DM in uscita era mai stata testata contro
un peer nuovo con un secondo client in ascolto. Serve una feature vera
(iscriversi dinamicamente a `channel:<peer>` per ogni DM mandata/
ricevuta, o fetchare la lista `query_windows` esistente al bootstrap e
joinarle tutte, specchiando cosa fa cic) — non una one-liner fix,
quindi rimandato a una sessione dedicata invece di espandere lo scope
di questa.

`bicchierino-preprod` NON è ancora stato ricompilato/ridistribuito con
i fix di questa sezione — build attuale = HEAD di `feature/chathistory`
prima di questo lavoro (CAP negotiation + TLS fix + sigilli NAMES, non
i fix multi-client). Serve un rebase di `feature/chathistory` su
`develop` e un redeploy prima che l'utente possa ritestare con irssi.
