/*=================================================================
  ESP32 TFT HONEYPOT  v1.6
  -----------------------------------------------------------------
  A low/medium-interaction honeypot. It exposes five decoy surfaces
  (ICMP, Telnet, SSH, FTP, HTTP), records every probe, credential and
  command, and shows a live dashboard on a TFT.

  v1.6: live browser dashboard on port 8080, reading the same SD
        log the TFT reads. Both views run simultaneously.

  v1.5 STORAGE CHANGE:
    All logging now goes to the microSD card, NOT internal flash.
    - The internal 4 MB chip is no longer written to at all.
    - Insert a FAT32-formatted microSD card. Logs persist there and
      survive reboots; the dashboard always reads history from it.
    - With no card inserted the honeypot still runs and detects, but
      warns "NO SD" and nothing is saved.

  SD card wiring on the ESP32-3248S035R (fixed on the PCB):
      CS=5  SCK=18  MOSI=23  MISO=19   (VSPI bus, separate from TFT)

  DEFENSIVE / RESEARCH USE ONLY. Own network or written authorisation
  only. Never place the decoy login where a real user could be fooled.

  Board : ESP32-3248S035R (3.5" 480x320 ST7796)  -- Option C
  Libs  : TFT_eSPI (Bodmer), SD, FS  (SD/FS ship with the ESP32 core)
  Core  : arduino-esp32 2.0.x or 3.x

  STRUCTURE NOTE: every type and global is declared above the first
  function on purpose. The Arduino IDE auto-generates prototypes and
  injects them ahead of the first function definition, so a type used
  in any signature must already exist. Do not move these blocks down.
=================================================================*/

#include <WiFi.h>
#include <SPI.h>
#include <TFT_eSPI.h>
#include <FS.h>
#include <SD.h>
#include <time.h>

/* lwIP raw layer. Arduino's WiFiServer only ever sees TCP, so ICMP
   (ping) is invisible to it. Hooking lwIP directly is the only way. */
#include "lwip/raw.h"
#include "lwip/icmp.h"
#include "lwip/tcpip.h"
#include "lwip/ip_addr.h"

/* TFT_eSPI defines FS_NO_GLOBALS before including FS.h, which hides
   the global `File` type. Use fs::File explicitly in this sketch.  */

/*=================== 1. USER SETTINGS ==========================*/
static const char *WIFI_SSID = "YOUR_WIFI_NAME";
static const char *WIFI_PASS = "YOUR_WIFI_PASSWORD";

// Identity the honeypot pretends to be. Boring = believable.
static const char *FAKE_HOST = "DVR-CAM-04";

// Key for YOUR real dashboard on port 8080. Change it.
static const char *ADMIN_KEY = "change-this-key";

// Timezone (Dhaka = UTC+6)
static const long GMT_OFFSET_SEC = 6 * 3600;
static const int  DST_OFFSET_SEC = 0;

// Optional buzzer / LED that pulses on a hit. -1 = disabled.
#define ALERT_PIN     -1
#define ALERT_MS      60

// Let attackers "log in" after 2 failures and drop them into a fake
// shell. This is where the good data is (payload URLs). true/false.
#define FAKE_SHELL    true

// --- microSD card (VSPI bus on the 3248S035 board) ---
#define SD_CS    5
#define SD_SCK   18
#define SD_MISO  19
#define SD_MOSI  23
#define SD_FREQ  20000000          // 20 MHz; drop to 10 MHz if flaky

#define LOG_PATH    "/honeypot.log"
#define STATE_PATH  "/state.bin"

// Repeat pings from one IP inside this window are counted but not
// re-printed, so a ping flood cannot scroll the screen away.
#define PING_QUIET_MS 8000

// Minimum gap between state writes. Credentials and payloads bypass
// this and save immediately.
#define STATE_SAVE_MS 20000
/*===============================================================*/


/*=================== 2. TYPES AND GLOBALS ======================*/
TFT_eSPI tft = TFT_eSPI();

// The TFT owns its own SPI bus (HSPI, pins 12/13/14/15). The SD card
// lives on VSPI, so it gets a separate SPIClass instance.
SPIClass sdSPI(VSPI);
bool sdOk = false;                  // true once a card is mounted

WiFiServer srvTelnet(23);
WiFiServer srvSSH(22);
WiFiServer srvFTP(21);
WiFiServer srvHTTP(80);
WiFiServer srvAdmin(8080);

/* ---- counters ---- */
struct Stats {
  uint32_t telnet;
  uint32_t ssh;
  uint32_t ftp;
  uint32_t http;
  uint32_t ping;
  uint32_t total;
  uint32_t creds;
  uint32_t payloads;
  uint32_t scans;
  uint32_t boots;
};
Stats st;

/* ---- unique-IP table, also drives scan detection ----
   mask bits: 1=telnet 2=ssh 4=ftp 8=http 16=icmp        */
#define MAX_IPS 40
struct IpRec {
  uint32_t ip;
  uint8_t  mask;
  bool     flagged;
  uint32_t lastPing;
};
IpRec   ipTab[MAX_IPS];
uint8_t ipCount = 0;

/* ---- ICMP queue ----
   The lwIP callback runs in the TCP/IP task, NOT in loop(). It must
   never touch the TFT or the SD card, so it only pushes a source
   address into this ring buffer. loop() drains it safely.        */
#define ICMP_Q 12
volatile uint32_t icmpQ[ICMP_Q];
volatile uint8_t  icmpHead = 0;
volatile uint8_t  icmpTail = 0;
portMUX_TYPE      icmpMux = portMUX_INITIALIZER_UNLOCKED;

/* ---- persistence ---- */
#define STATE_MAGIC 0x484E5035UL      /* 'HNP5' */
struct StateBlob {
  uint32_t magic;
  Stats    st;
  uint8_t  ipCount;
  IpRec    ipTab[MAX_IPS];
  uint32_t sum;
};
bool     stateDirty    = false;
uint32_t lastStateSave = 0;

/* ---- per-connection session state ---- */
struct Session {
  WiFiClient c;
  bool       active;
  uint8_t    stage;      // 1=user 2=pass 3=shell
  uint8_t    tries;
  uint32_t   last;
  String     line;
  String     user;
  IPAddress  ip;
};
Session tn;
Session ft;

/* ---- on-screen scrolling log ---- */
#define UI_MAX_LINES 26
#define UI_MAX_COLS  80
struct UiLine {
  char     txt[UI_MAX_COLS + 1];
  uint16_t col;
};
UiLine  uiLog[UI_MAX_LINES];
uint8_t uiUsed = 0;

/* ---- layout, computed at boot from the real panel size ---- */
int SW, SH;
int hdrH, tileY, tileH, tileW, statY, logY, logH, barY;
int lineH   = 12;
int nLines  = 10;
int nCols   = 50;
int numFont = 2;

/* ---- colours ---- */
#define C_BG      TFT_BLACK
#define C_BAR     0x0209
#define C_PANEL   0x1082
#define C_TELNET  TFT_GREEN
#define C_SSH     TFT_CYAN
#define C_FTP     TFT_YELLOW
#define C_HTTP    TFT_ORANGE
#define C_PING    TFT_PINK
#define C_CRED    TFT_RED
#define C_SCAN    TFT_MAGENTA
#define C_DIM     0x7BEF

bool     dirtyTiles = true;
bool     dirtyLog   = true;
uint32_t lastClock  = 0;


/*=================== 3. SMALL HELPERS ==========================*/

// arduino-esp32 3.x renamed WiFiServer::available() -> accept()
static inline WiFiClient srvAccept(WiFiServer &s) {
#if defined(ESP_ARDUINO_VERSION_MAJOR) && (ESP_ARDUINO_VERSION_MAJOR >= 3)
  return s.accept();
#else
  return s.available();
#endif
}

void timeStr(char *out, size_t n, bool full) {
  struct tm t;
  if (!getLocalTime(&t, 5)) {
    snprintf(out, n, full ? "0000-00-00 00:00:00" : "--:--:--");
    return;
  }
  strftime(out, n, full ? "%Y-%m-%d %H:%M:%S" : "%H:%M:%S", &t);
}

void alertPulse() {
#if ALERT_PIN >= 0
  digitalWrite(ALERT_PIN, HIGH);
  delay(ALERT_MS);
  digitalWrite(ALERT_PIN, LOW);
#endif
}

String clean(const String &in, size_t cap = 64) {
  String o;
  for (size_t i = 0; i < in.length() && o.length() < cap; i++) {
    char c = in[i];
    if (c >= 32 && c <= 126) o += c;
  }
  o.trim();
  return o;
}

void touchIp(IPAddress ip, uint8_t bit, bool &isNewIp, bool &isScan) {
  uint32_t v = (uint32_t)ip;
  isNewIp = false;
  isScan  = false;
  for (uint8_t i = 0; i < ipCount; i++) {
    if (ipTab[i].ip == v) {
      ipTab[i].mask |= bit;
      uint8_t m = ipTab[i].mask;
      uint8_t n = 0;
      while (m) { n += m & 1; m >>= 1; }
      if (n >= 3 && !ipTab[i].flagged) {
        ipTab[i].flagged = true;
        isScan = true;
        st.scans++;
      }
      return;
    }
  }
  if (ipCount < MAX_IPS) {
    ipTab[ipCount].ip       = v;
    ipTab[ipCount].mask     = bit;
    ipTab[ipCount].flagged  = false;
    ipTab[ipCount].lastPing = 0;
    ipCount++;
    isNewIp = true;
  }
}


/*=================== 4. SD CARD ================================
  Everything is stored on the microSD card. The internal flash is
  never touched. If no card is present, sdOk stays false and every
  storage call below becomes a no-op - the honeypot keeps detecting
  and displaying, it just cannot persist.
================================================================*/
bool mountSD() {
  sdSPI.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);
  if (!SD.begin(SD_CS, sdSPI, SD_FREQ)) {
    Serial.println("SD: no card / mount failed");
    return false;
  }
  uint8_t type = SD.cardType();
  if (type == CARD_NONE) {
    Serial.println("SD: slot empty");
    return false;
  }
  uint64_t mb = SD.cardSize() / (1024ULL * 1024ULL);
  Serial.printf("SD: mounted, %llu MB\n", mb);
  return true;
}


/*=================== 5. PERSISTENT STATE =======================
  Counters and the IP table are serialised to /state.bin on the SD
  card with a checksum, so a power cycle restores the full dashboard
  instead of coming back at zero.
================================================================*/
uint32_t blobSum(const StateBlob &b) {
  const uint8_t *p = (const uint8_t *)&b;
  size_t n = sizeof(StateBlob) - sizeof(uint32_t);
  uint32_t s = 0x1234;
  for (size_t i = 0; i < n; i++) s = s * 31 + p[i];
  return s;
}

void saveState(bool force) {
  if (!sdOk) return;
  if (!force && !stateDirty) return;
  if (!force && (millis() - lastStateSave) < STATE_SAVE_MS) return;

  StateBlob b;
  memset(&b, 0, sizeof(b));
  b.magic   = STATE_MAGIC;
  b.st      = st;
  b.ipCount = ipCount;
  memcpy(b.ipTab, ipTab, sizeof(ipTab));
  b.sum = blobSum(b);

  fs::File f = SD.open(STATE_PATH, FILE_WRITE);
  if (!f) return;
  f.write((uint8_t *)&b, sizeof(b));
  f.close();

  lastStateSave = millis();
  stateDirty    = false;
}

bool loadState() {
  if (!sdOk) return false;
  fs::File f = SD.open(STATE_PATH, FILE_READ);
  if (!f) return false;
  if (f.size() != sizeof(StateBlob)) { f.close(); return false; }

  StateBlob b;
  f.read((uint8_t *)&b, sizeof(b));
  f.close();

  if (b.magic != STATE_MAGIC) return false;
  if (b.sum   != blobSum(b))  return false;   // corrupt or half-written

  st      = b.st;
  ipCount = (b.ipCount > MAX_IPS) ? MAX_IPS : b.ipCount;
  memcpy(ipTab, b.ipTab, sizeof(ipTab));
  return true;
}


/*=================== 6. LOGGING ================================*/
void fileLog(const char *svc, IPAddress ip, const char *detail) {
  if (!sdOk) return;                 // no card -> nothing persisted
  fs::File f = SD.open(LOG_PATH, FILE_APPEND);
  if (!f) return;
  char ts[24];
  timeStr(ts, sizeof(ts), true);
  f.printf("%s\t%s\t%s\t%s\n", ts, svc, ip.toString().c_str(), detail);
  f.close();
}

void logEvent(const char *svc, IPAddress ip, const String &detail,
              uint16_t colour, bool loud) {
  st.total++;
  char ts[10];
  timeStr(ts, sizeof(ts), false);

  if (uiUsed >= nLines) {
    for (int i = 0; i < nLines - 1; i++) uiLog[i] = uiLog[i + 1];
    uiUsed = nLines - 1;
  }
  snprintf(uiLog[uiUsed].txt, nCols + 1, "%s %-6s %-15s %s",
           ts, svc, ip.toString().c_str(), detail.c_str());
  uiLog[uiUsed].col = colour;
  uiUsed++;

  Serial.printf("[%s] %-6s %-15s %s\n", ts, svc,
                ip.toString().c_str(), detail.c_str());
  fileLog(svc, ip, detail.c_str());

  dirtyLog   = true;
  dirtyTiles = true;
  stateDirty = true;
  if (loud) alertPulse();
}

void logCreds(const char *svc, IPAddress ip, const String &u, const String &p) {
  st.creds++;
  logEvent(svc, ip, "CREDS " + u + " / " + p, C_CRED, true);
  saveState(true);              // captured credentials are never lost
}

void checkPayload(const char *svc, IPAddress ip, const String &cmd) {
  String l = cmd;
  l.toLowerCase();
  if (l.indexOf("wget") >= 0 || l.indexOf("curl") >= 0 ||
      l.indexOf("tftp") >= 0 || l.indexOf("http://") >= 0 ||
      l.indexOf("busybox") >= 0) {
    st.payloads++;
    logEvent(svc, ip, "PAYLOAD " + cmd, C_CRED, true);
    saveState(true);            // payload URLs are the highest value data
  }
}


/*=================== 7. ICMP / PING DETECTION ==================
  Registering a raw PCB on IP_PROTO_ICMP gives us a copy of every
  echo request. Returning 0 means "not consumed", so lwIP still
  sends the normal reply - the honeypot must look alive.
================================================================*/
#if LWIP_RAW
static struct raw_pcb *icmpPcb = NULL;

static u8_t icmpRecv(void *arg, struct raw_pcb *pcb, struct pbuf *p,
                     const ip_addr_t *addr) {
  (void)arg;
  (void)pcb;
  if (p != NULL && addr != NULL && p->len > 20) {
    const uint8_t *d = (const uint8_t *)p->payload;   // starts at IP header
    uint8_t ihl = (uint8_t)((d[0] & 0x0F) * 4);
    if (p->len > ihl && d[ihl] == 8) {                // 8 = echo request
      uint32_t src = ip4_addr_get_u32(ip_2_ip4(addr));
      portENTER_CRITICAL_ISR(&icmpMux);
      uint8_t nxt = (uint8_t)((icmpHead + 1) % ICMP_Q);
      if (nxt != icmpTail) {
        icmpQ[icmpHead] = src;
        icmpHead = nxt;
      }
      portEXIT_CRITICAL_ISR(&icmpMux);
    }
  }
  return 0;                       // let lwIP reply normally
}

static void icmpInstall(void *arg) {
  (void)arg;
  icmpPcb = raw_new(IP_PROTO_ICMP);
  if (icmpPcb == NULL) return;
  raw_bind(icmpPcb, IP_ADDR_ANY);
  raw_recv(icmpPcb, icmpRecv, NULL);
}

void startIcmpWatch() {
  // Must run inside the lwIP task, not here. tcpip_callback does that.
  tcpip_callback(icmpInstall, NULL);
}
#else
void startIcmpWatch() {
  Serial.println("LWIP_RAW disabled - ping detection unavailable");
}
#endif

/*---- drain the ICMP queue, in loop() context ----*/
void serviceIcmp() {
  while (true) {
    uint32_t src = 0;
    portENTER_CRITICAL(&icmpMux);
    if (icmpTail != icmpHead) {
      src = icmpQ[icmpTail];
      icmpTail = (uint8_t)((icmpTail + 1) % ICMP_Q);
    }
    portEXIT_CRITICAL(&icmpMux);
    if (src == 0) break;

    st.ping++;
    IPAddress ip(src);

    bool nu = false, sc = false;
    touchIp(ip, 16, nu, sc);

    // Rate limit the printed line so a ping flood cannot scroll the
    // screen clean. The counter still increments for every packet.
    bool quiet = false;
    for (uint8_t i = 0; i < ipCount; i++) {
      if (ipTab[i].ip == src) {
        if (ipTab[i].lastPing != 0 &&
            (millis() - ipTab[i].lastPing) < PING_QUIET_MS) quiet = true;
        ipTab[i].lastPing = millis();
        break;
      }
    }

    if (!quiet) {
      logEvent("PING", ip, "icmp echo request", C_PING, false);
    } else {
      dirtyTiles = true;
      stateDirty = true;
    }

    if (sc) logEvent("SCAN", ip, "multi-service probe", C_SCAN, true);
  }
}


/*=================== 8. FAKE BUSYBOX SHELL =====================*/
String fakeShell(const String &cmd) {
  String c = cmd;
  c.trim();
  String l = c;
  l.toLowerCase();

  if (l == "")             return "";
  if (l.startsWith("ls"))  return "bin\ndev\netc\nlib\nmnt\nproc\nsbin\ntmp\nusr\nvar\n";
  if (l.startsWith("pwd")) return "/\n";
  if (l.startsWith("id") || l.startsWith("whoami"))
                           return "uid=0(root) gid=0(root)\n";
  if (l.startsWith("uname"))
                           return "Linux " + String(FAKE_HOST) +
                                  " 3.10.14 #1 SMP mips GNU/Linux\n";
  if (l.startsWith("cat /proc/cpuinfo"))
                           return "system type\t: MT7620A\ncpu model\t: MIPS 24KEc V5.0\n"
                                  "BogoMIPS\t: 385.02\n";
  if (l.startsWith("cat /proc/mounts"))
                           return "rootfs / rootfs rw 0 0\nproc /proc proc rw 0 0\n"
                                  "tmpfs /tmp tmpfs rw 0 0\n";
  if (l.startsWith("free"))
                           return "  total   used   free\nMem:  61120  42188  18932\n";
  if (l.startsWith("ps"))
                           return "  PID USER  COMMAND\n    1 root  init\n"
                                  "  412 root  telnetd\n  530 root  httpd\n";
  if (l.startsWith("busybox"))
                           return "BusyBox v1.20.2 (2016-11-28) multi-call binary.\n";
  if (l.startsWith("wget") || l.startsWith("curl") || l.startsWith("tftp"))
                           return "sh: write error: Permission denied\n";
  if (l.startsWith("rm") || l.startsWith("chmod") || l.startsWith("mv"))
                           return "";
  if (l.startsWith("echo "))
                           return c.substring(5) + "\n";
  if (l.startsWith("enable") || l.startsWith("system") ||
      l.startsWith("shell")  || l == "sh")
                           return "";

  int sp = c.indexOf(' ');
  return "sh: " + c.substring(0, sp > 0 ? sp : c.length()) + ": applet not found\n";
}


/*=================== 9. TELNET =================================*/
/* reads bytes, strips telnet IAC negotiation, true when a line ends */
bool readLine(Session &s) {
  while (s.c.available()) {
    int b = s.c.read();
    if (b < 0) break;
    s.last = millis();
    if (b == 0xFF) {                       // IAC: skip the 2 bytes after
      if (s.c.available()) s.c.read();
      if (s.c.available()) s.c.read();
      continue;
    }
    if (b == '\n') return true;
    if (b == '\r' || b == 0) continue;
    if (s.line.length() < 96) s.line += (char)b;
  }
  return false;
}

void telnetPrompt() {
  tn.c.print("\r\n");
  tn.c.print(FAKE_HOST);
  tn.c.print(" login: ");
}

void handleTelnet() {
  if (!tn.active) {
    WiFiClient nc = srvAccept(srvTelnet);
    if (!nc) return;
    tn.c      = nc;
    tn.active = true;
    tn.stage  = 1;
    tn.tries  = 0;
    tn.line   = "";
    tn.user   = "";
    tn.last   = millis();
    tn.ip     = nc.remoteIP();
    st.telnet++;
    bool nu = false, sc = false;
    touchIp(tn.ip, 1, nu, sc);
    logEvent("TELNET", tn.ip, "connect", C_TELNET, false);
    if (sc) logEvent("SCAN", tn.ip, "multi-service probe", C_SCAN, true);
    telnetPrompt();
    return;
  }

  if (!tn.c.connected() || (millis() - tn.last) > 120000) {
    tn.c.stop();
    tn.active = false;
    return;
  }

  if (!readLine(tn)) return;
  String in = clean(tn.line);
  tn.line = "";

  if (tn.stage == 1) {
    tn.user = in.length() ? in : "(empty)";
    tn.c.print("\r\nPassword: ");
    tn.stage = 2;
  } else if (tn.stage == 2) {
    logCreds("TELNET", tn.ip, tn.user, in.length() ? in : "(empty)");
    tn.tries++;
    if (FAKE_SHELL && tn.tries >= 2) {
      tn.c.print("\r\n\r\nBusyBox v1.20.2 built-in shell (ash)\r\n\r\n# ");
      tn.stage = 3;
    } else if (tn.tries >= 3) {
      tn.c.print("\r\nLogin incorrect\r\n");
      tn.c.stop();
      tn.active = false;
    } else {
      tn.c.print("\r\nLogin incorrect\r\n");
      telnetPrompt();
      tn.stage = 1;
    }
  } else {                                   // fake shell
    if (in.length()) {
      logEvent("TELNET", tn.ip, "cmd: " + in, C_TELNET, false);
      checkPayload("TELNET", tn.ip, in);
    }
    String low = in;
    low.toLowerCase();
    if (low == "exit" || low == "quit" || low == "logout") {
      tn.c.print("\r\n");
      tn.c.stop();
      tn.active = false;
      return;
    }
    tn.c.print("\r\n");
    tn.c.print(fakeShell(in));
    tn.c.print("# ");
  }
}


/*=================== 10. FTP ===================================*/
void handleFTP() {
  if (!ft.active) {
    WiFiClient nc = srvAccept(srvFTP);
    if (!nc) return;
    ft.c      = nc;
    ft.active = true;
    ft.stage  = 1;
    ft.tries  = 0;
    ft.line   = "";
    ft.user   = "";
    ft.last   = millis();
    ft.ip     = nc.remoteIP();
    st.ftp++;
    bool nu = false, sc = false;
    touchIp(ft.ip, 4, nu, sc);
    logEvent("FTP", ft.ip, "connect", C_FTP, false);
    if (sc) logEvent("SCAN", ft.ip, "multi-service probe", C_SCAN, true);
    ft.c.printf("220 %s FTP server (Version 6.4) ready.\r\n", FAKE_HOST);
    return;
  }

  if (!ft.c.connected() || (millis() - ft.last) > 90000) {
    ft.c.stop();
    ft.active = false;
    return;
  }
  if (!readLine(ft)) return;

  String in = clean(ft.line);
  ft.line = "";
  String up = in;
  up.toUpperCase();

  if (up.startsWith("USER")) {
    ft.user = in.length() > 5 ? in.substring(5) : "(empty)";
    ft.c.printf("331 Password required for %s.\r\n", ft.user.c_str());
  } else if (up.startsWith("PASS")) {
    String p = in.length() > 5 ? in.substring(5) : "(empty)";
    logCreds("FTP", ft.ip, ft.user, p);
    ft.tries++;
    ft.c.print("530 Login incorrect.\r\n");
    if (ft.tries >= 3) { ft.c.stop(); ft.active = false; }
  } else if (up.startsWith("QUIT")) {
    ft.c.print("221 Goodbye.\r\n");
    ft.c.stop();
    ft.active = false;
  } else if (up.startsWith("SYST")) {
    ft.c.print("215 UNIX Type: L8\r\n");
  } else if (in.length()) {
    logEvent("FTP", ft.ip, "cmd: " + in, C_FTP, false);
    ft.c.print("530 Please login with USER and PASS.\r\n");
  }
}


/*=================== 11. SSH (banner grab) =====================*/
void handleSSH() {
  WiFiClient c = srvAccept(srvSSH);
  if (!c) return;
  IPAddress ip = c.remoteIP();
  st.ssh++;
  bool nu = false, sc = false;
  touchIp(ip, 2, nu, sc);
  logEvent("SSH", ip, "connect", C_SSH, false);
  if (sc) logEvent("SCAN", ip, "multi-service probe", C_SCAN, true);

  c.print("SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n");

  String ident;
  uint32_t t0 = millis();
  bool done = false;
  while ((millis() - t0) < 1200 && c.connected() &&
         ident.length() < 80 && !done) {
    while (c.available()) {
      int b = c.read();
      if (b == '\n') { done = true; break; }
      if (b >= 32 && b <= 126) ident += (char)b;
    }
    if (!done) delay(10);
  }
  if (ident.length()) logEvent("SSH", ip, "client: " + clean(ident), C_SSH, false);
  c.stop();
}


/*=================== 12. HTTP DECOY ============================*/
const char LOGIN_PAGE[] PROGMEM =
  "<!DOCTYPE html><html><head><meta name=viewport content='width=device-width'>"
  "<title>Router Login</title><style>body{font-family:Arial;background:#e8ebf0;"
  "margin:0;padding:60px 12px;}div{max-width:320px;margin:auto;background:#fff;"
  "border:1px solid #ccd;padding:22px;}h2{margin:0 0 4px;font-size:18px;color:#123;}"
  "p{margin:0 0 18px;color:#789;font-size:12px;}input{width:100%;padding:8px;"
  "margin:5px 0 12px;border:1px solid #bbc;box-sizing:border-box;}"
  "button{width:100%;padding:9px;background:#15487a;color:#fff;border:0;}"
  "b{color:#b00;font-size:12px;}</style></head><body><div>"
  "<h2>Device Management</h2><p>Firmware 1.4.7 &middot; Sign in to continue</p>"
  "%MSG%<form method='POST' action='/login'>"
  "<input name='username' placeholder='Username' autocomplete='off'>"
  "<input name='password' type='password' placeholder='Password'>"
  "<button type='submit'>Log In</button></form></div></body></html>";

String urlDecode(String s) {
  String o;
  char a, b;
  for (uint16_t i = 0; i < s.length(); i++) {
    if (s[i] == '%' && (uint32_t)(i + 2) < s.length()) {
      a = s[i + 1];
      b = s[i + 2];
      a = (a <= '9') ? a - '0' : (a & 0xDF) - 'A' + 10;
      b = (b <= '9') ? b - '0' : (b & 0xDF) - 'A' + 10;
      o += (char)(a * 16 + b);
      i += 2;
    } else if (s[i] == '+') {
      o += ' ';
    } else {
      o += s[i];
    }
  }
  return o;
}

String formField(const String &body, const String &key) {
  int i = body.indexOf(key + "=");
  if (i < 0) return "";
  i += key.length() + 1;
  int e = body.indexOf('&', i);
  return urlDecode(body.substring(i, e < 0 ? body.length() : e));
}

void handleHTTP() {
  WiFiClient c = srvAccept(srvHTTP);
  if (!c) return;
  IPAddress ip = c.remoteIP();
  st.http++;
  bool nu = false, sc = false;
  touchIp(ip, 8, nu, sc);

  String headers;
  uint32_t t0 = millis();
  while ((millis() - t0) < 2000 && c.connected()) {
    if (c.available()) {
      char ch = c.read();
      headers += ch;
      if (headers.length() > 2000) break;
      if (headers.endsWith("\r\n\r\n")) break;
    } else {
      delay(2);
    }
  }
  int nl = headers.indexOf("\r\n");
  String req = (nl > 0) ? headers.substring(0, nl) : headers;

  String body;
  int cl = 0;
  int p = headers.indexOf("Content-Length:");
  if (p < 0) p = headers.indexOf("content-length:");
  if (p >= 0) cl = headers.substring(p + 15, headers.indexOf("\r\n", p)).toInt();
  if (cl > 0 && cl < 1024) {
    t0 = millis();
    while ((int)body.length() < cl && (millis() - t0) < 1500 && c.connected()) {
      while (c.available() && (int)body.length() < cl) body += (char)c.read();
      delay(2);
    }
  }

  String ua;
  p = headers.indexOf("User-Agent:");
  if (p < 0) p = headers.indexOf("user-agent:");
  if (p >= 0) ua = clean(headers.substring(p + 11, headers.indexOf("\r\n", p)), 40);

  String path = "/", method = "GET";
  int s1 = req.indexOf(' ');
  int s2 = req.indexOf(' ', s1 + 1);
  if (s1 > 0) {
    method = req.substring(0, s1);
    if (s2 > s1) path = req.substring(s1 + 1, s2);
  }

  logEvent("HTTP", ip, method + " " + clean(path, 30), C_HTTP, false);
  if (sc) logEvent("SCAN", ip, "multi-service probe", C_SCAN, true);
  if (ua.length()) logEvent("HTTP", ip, "UA " + ua, C_DIM, false);

  if (path != "/" && path != "/favicon.ico" && path != "/login")
    logEvent("HTTP", ip, "PROBE " + clean(path, 34), C_CRED, true);

  String msg;
  if (method == "POST" && body.length()) {
    String u = clean(formField(body, "username"));
    String w = clean(formField(body, "password"));
    if (u.length() || w.length()) {
      logCreds("HTTP", ip, u.length() ? u : "(empty)", w.length() ? w : "(empty)");
    } else {
      logEvent("HTTP", ip, "POST " + clean(body, 34), C_CRED, true);
    }
    msg = "<b>Invalid username or password.</b><br><br>";
  }

  String page = FPSTR(LOGIN_PAGE);
  page.replace("%MSG%", msg);
  c.print("HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.35\r\n"
          "Content-Type: text/html\r\nConnection: close\r\nContent-Length: ");
  c.print(page.length());
  c.print("\r\n\r\n");
  c.print(page);
  delay(5);
  c.stop();
}


/*=================== 13. WEB DASHBOARD :8080 ==================
  A live browser dashboard, served by the ESP32 itself, reading the
  same SD card log the TFT reads. The TFT is unchanged - both views
  run at once from one source of truth.

  Endpoints (all require ?key=ADMIN_KEY):
    /            dashboard page
    /api         JSON counters + IP table   (polled every 3s)
    /tail        recent log as TSV text     (polled every 3s)
    /raw         whole log, for download
    /clear       wipe log + state

  NEVER port-forward 8080. It exposes your captured data.
================================================================*/
static const char DASH_HTML[] PROGMEM = R"HTML(<!DOCTYPE html><html><head>
<meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Honeypot Dashboard</title><style>
:root{--bg:#0b0f14;--card:#141b23;--line:#1f2a35;--txt:#c9d6e2;--dim:#6b7d8f;
--telnet:#3fb950;--ssh:#39c5cf;--ftp:#d29922;--http:#f0883e;--ping:#db61a2;
--cred:#f85149;--scan:#bc8cff;--sys:#6b7d8f}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);
font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{padding:12px 16px;border-bottom:1px solid var(--line);
display:flex;flex-wrap:wrap;gap:8px;align-items:center}
h1{font-size:15px;margin:0;color:#58a6ff;letter-spacing:1px;margin-right:auto}
.pill{background:var(--card);border:1px solid var(--line);padding:3px 9px;
border-radius:99px;font-size:11px;color:var(--dim)}
.pill.ok{color:var(--telnet);border-color:#1c3a24}
.pill.bad{color:var(--cred);border-color:#4a1d1d}
main{padding:14px 16px;max-width:1250px;margin:auto}
.grid{display:grid;gap:9px;grid-template-columns:repeat(auto-fit,minmax(108px,1fr));
margin-bottom:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:9px 11px}
.card .k{font-size:10.5px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
.card .v{font-size:23px;font-weight:600;margin-top:1px}
.bar{display:flex;align-items:center;gap:8px;margin:3px 0;font-size:11.5px}
.bar .lbl{width:56px;color:var(--dim)}
.bar .track{flex:1;background:#0f1720;border-radius:4px;height:13px;overflow:hidden}
.bar .fill{height:100%;border-radius:4px;transition:width .4s;min-width:2px}
.bar .num{width:46px;text-align:right}
h2{font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.8px;
margin:16px 0 7px;font-weight:500}
.tools{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:7px;align-items:center}
button{background:var(--card);color:var(--txt);border:1px solid var(--line);
padding:4px 10px;border-radius:6px;cursor:pointer;font:inherit;font-size:11.5px}
button.on{border-color:#58a6ff;color:#58a6ff}
button:hover{border-color:#58a6ff}
input{background:var(--card);border:1px solid var(--line);color:var(--txt);
padding:4px 9px;border-radius:6px;font:inherit;font-size:11.5px;flex:1;min-width:120px}
.wrap{max-height:460px;overflow:auto;border:1px solid var(--line);border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;color:var(--dim);font-weight:500;padding:6px 8px;
border-bottom:1px solid var(--line);position:sticky;top:0;background:#0f151c}
td{padding:4px 8px;border-bottom:1px solid #121a22;vertical-align:top;white-space:nowrap}
td.det{white-space:normal;word-break:break-all;color:#e6edf3}
tr.hot td{background:#1e1113}
.badge{padding:1px 6px;border-radius:4px;font-size:10.5px;font-weight:700;color:#0b0f14}
footer{padding:12px 16px;color:var(--dim);font-size:11px}
a{color:#58a6ff}
.empty{padding:22px;text-align:center;color:var(--dim)}
</style></head><body>
<header><h1>ESP32 HONEYPOT</h1>
<span class=pill id=pSd>storage</span><span class=pill id=pIp>ip</span>
<span class=pill id=pUp>uptime</span><span class=pill id=pHeap>heap</span>
<span class=pill id=pSeen>updated</span></header>
<main>
<div class=grid>
<div class=card><div class=k>Telnet</div><div class=v id=cTelnet>0</div></div>
<div class=card><div class=k>SSH</div><div class=v id=cSsh>0</div></div>
<div class=card><div class=k>FTP</div><div class=v id=cFtp>0</div></div>
<div class=card><div class=k>HTTP</div><div class=v id=cHttp>0</div></div>
<div class=card><div class=k>Ping</div><div class=v id=cPing>0</div></div>
</div>
<div class=grid>
<div class=card><div class=k>Total hits</div><div class=v id=cTotal>0</div></div>
<div class=card><div class=k>Unique IPs</div><div class=v id=cIps>0</div></div>
<div class=card><div class=k>Credentials</div><div class=v id=cCreds
style=color:var(--cred)>0</div></div>
<div class=card><div class=k>Payloads</div><div class=v id=cPayl
style=color:var(--cred)>0</div></div>
<div class=card><div class=k>Scanners</div><div class=v id=cScans
style=color:var(--scan)>0</div></div>
<div class=card><div class=k>Boots</div><div class=v id=cBoots>0</div></div>
</div>
<h2>Service distribution</h2><div id=bars></div>
<h2>Attacking hosts</h2>
<div class=wrap style=max-height:200px><table><thead><tr>
<th>Source IP</th><th>Services touched</th><th>Flag</th>
</tr></thead><tbody id=ipBody></tbody></table></div>
<h2>Live events</h2>
<div class=tools>
<button data-f=ALL class=on>All</button><button data-f=TELNET>Telnet</button>
<button data-f=SSH>SSH</button><button data-f=FTP>FTP</button>
<button data-f=HTTP>HTTP</button><button data-f=PING>Ping</button>
<button data-f=HOT>Alerts only</button>
<input id=q placeholder="filter text, e.g. an IP or password">
<button id=pause>Pause</button></div>
<div class=wrap><table><thead><tr>
<th style=width:78px>Time</th><th style=width:74px>Service</th>
<th style=width:120px>Source</th><th>Detail</th>
</tr></thead><tbody id=evBody></tbody></table></div>
</main>
<footer>Reading /honeypot.log from the microSD card &middot;
<a id=lnkRaw href=#>download full log</a> &middot;
<a id=lnkClear href=# style=color:var(--cred)>clear all</a></footer>
<script>
var KEY=new URLSearchParams(location.search).get('key')||'';
var COL={TELNET:'--telnet',SSH:'--ssh',FTP:'--ftp',HTTP:'--http',
PING:'--ping',SCAN:'--scan',SYS:'--sys'};
var filter='ALL',live=true,rows=[];
document.getElementById('lnkRaw').href='/raw?key='+encodeURIComponent(KEY);
document.getElementById('lnkClear').onclick=function(e){e.preventDefault();
if(confirm('Erase the whole log and all counters?'))
fetch('/clear?key='+encodeURIComponent(KEY)).then(function(){location.reload()});};
document.querySelectorAll('button[data-f]').forEach(function(b){
b.onclick=function(){filter=b.dataset.f;
document.querySelectorAll('button[data-f]').forEach(function(x){
x.classList.toggle('on',x===b)});draw();};});
document.getElementById('q').oninput=draw;
document.getElementById('pause').onclick=function(){live=!live;
this.textContent=live?'Pause':'Resume';this.classList.toggle('on',!live);};
function esc(t){return (t||'').replace(/[<>&]/g,function(c){
return {'<':'&lt;','>':'&gt;','&':'&amp;'}[c]});}
function hot(sv,d){return sv==='SCAN'||/^(CREDS|PAYLOAD|PROBE)/.test(d);}
function svcName(m){var o=[];if(m&1)o.push('telnet');if(m&2)o.push('ssh');
if(m&4)o.push('ftp');if(m&8)o.push('http');if(m&16)o.push('ping');
return o.join(', ')||'-';}
function draw(){
var q=document.getElementById('q').value.toLowerCase();
var out=rows.filter(function(r){
if(filter==='HOT'&&!hot(r[1],r[3]))return false;
if(filter!=='ALL'&&filter!=='HOT'&&r[1]!==filter)return false;
if(q&&(r.join(' ').toLowerCase().indexOf(q)<0))return false;
return true;}).slice(-300).reverse();
var b=document.getElementById('evBody');
if(!out.length){b.innerHTML='<tr><td colspan=4 class=empty>no matching events</td></tr>';
return;}
b.innerHTML=out.map(function(r){
var c=COL[r[1]]||'--sys';
return '<tr class="'+(hot(r[1],r[3])?'hot':'')+'"><td>'+esc(r[0])+
'</td><td><span class=badge style="background:var('+c+')">'+esc(r[1])+
'</span></td><td>'+esc(r[2])+'</td><td class=det>'+esc(r[3])+'</td></tr>';
}).join('');}
function bars(d){
var S=[['TELNET',d.telnet,'--telnet'],['SSH',d.ssh,'--ssh'],['FTP',d.ftp,'--ftp'],
['HTTP',d.http,'--http'],['PING',d.ping,'--ping']];
var mx=Math.max(1,d.telnet,d.ssh,d.ftp,d.http,d.ping);
document.getElementById('bars').innerHTML=S.map(function(x){
return '<div class=bar><span class=lbl>'+x[0]+'</span><span class=track>'+
'<span class=fill style="width:'+(x[1]/mx*100)+'%;background:var('+x[2]+')"></span>'+
'</span><span class=num>'+x[1]+'</span></div>';}).join('');}
function fmtUp(s){var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),
m=Math.floor(s%3600/60);return (d?d+'d ':'')+(h?h+'h ':'')+m+'m';}
function poll(){
if(!live)return;
fetch('/api?key='+encodeURIComponent(KEY)).then(function(r){return r.json()})
.then(function(d){
['telnet','ssh','ftp','http','ping','total','creds','scans','boots'].forEach(function(k){
var e=document.getElementById('c'+k[0].toUpperCase()+k.slice(1));
if(e)e.textContent=d[k];});
document.getElementById('cPayl').textContent=d.payloads;
document.getElementById('cIps').textContent=d.ips.length;
var sd=document.getElementById('pSd');
sd.textContent=d.sd?'microSD OK':'NO SD CARD';
sd.className='pill '+(d.sd?'ok':'bad');
document.getElementById('pIp').textContent=d.ip;
document.getElementById('pUp').textContent='up '+fmtUp(d.up);
document.getElementById('pHeap').textContent=Math.round(d.heap/1024)+'k free';
document.getElementById('pSeen').textContent=new Date().toLocaleTimeString();
bars(d);
document.getElementById('ipBody').innerHTML=d.ips.length?d.ips.map(function(x){
return '<tr class="'+(x.f?'hot':'')+'"><td>'+esc(x.a)+'</td><td>'+svcName(x.m)+
'</td><td>'+(x.f?'<span class=badge style="background:var(--scan)">SCAN</span>':'')+
'</td></tr>';}).join(''):'<tr><td colspan=3 class=empty>none yet</td></tr>';
}).catch(function(){document.getElementById('pSeen').textContent='offline';});
fetch('/tail?key='+encodeURIComponent(KEY)).then(function(r){return r.text()})
.then(function(t){
rows=t.split('\n').map(function(l){return l.split('\t')})
.filter(function(r){return r.length>=4})
.map(function(r){return [r[0].slice(11),r[1],r[2],r.slice(3).join(' ')];});
draw();}).catch(function(){});}
poll();setInterval(poll,3000);
</script></body></html>)HTML";

void handleAdmin() {
  WiFiClient c = srvAccept(srvAdmin);
  if (!c) return;
  String req;
  uint32_t t0 = millis();
  while ((millis() - t0) < 1500 && c.connected()) {
    if (c.available()) {
      char ch = c.read();
      if (ch == '\n') break;
      req += ch;
    } else {
      delay(2);
    }
  }
  while (c.available()) c.read();

  if (req.indexOf(ADMIN_KEY) < 0) {
    c.print("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\nnope\r\n");
    delay(5);
    c.stop();
    return;
  }

  /* ---- JSON counters, polled by the page ---- */
  if (req.indexOf("/api") >= 0) {
    String j = "{";
    j += "\"sd\":";       j += (sdOk ? "true" : "false");
    j += ",\"ip\":\"" + WiFi.localIP().toString() + "\"";
    j += ",\"rssi\":"   + String(WiFi.RSSI());
    j += ",\"heap\":"   + String(ESP.getFreeHeap());
    j += ",\"up\":"     + String(millis() / 1000);
    j += ",\"boots\":"  + String(st.boots);
    j += ",\"telnet\":" + String(st.telnet);
    j += ",\"ssh\":"    + String(st.ssh);
    j += ",\"ftp\":"    + String(st.ftp);
    j += ",\"http\":"   + String(st.http);
    j += ",\"ping\":"   + String(st.ping);
    j += ",\"total\":"  + String(st.total);
    j += ",\"creds\":"  + String(st.creds);
    j += ",\"payloads\":" + String(st.payloads);
    j += ",\"scans\":"  + String(st.scans);
    j += ",\"ips\":[";
    for (uint8_t i = 0; i < ipCount; i++) {
      IPAddress a(ipTab[i].ip);
      if (i) j += ",";
      j += "{\"a\":\"" + a.toString() + "\",\"m\":" + String(ipTab[i].mask) +
           ",\"f\":" + String(ipTab[i].flagged ? "true" : "false") + "}";
    }
    j += "]}";
    c.print("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            "Cache-Control: no-store\r\nConnection: close\r\n\r\n");
    c.print(j);
    delay(5);
    c.stop();
    return;
  }

  /* ---- recent log as TSV, streamed straight off the card ---- */
  if (req.indexOf("/tail") >= 0) {
    c.print("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            "Cache-Control: no-store\r\nConnection: close\r\n\r\n");
    if (sdOk) {
      fs::File f = SD.open(LOG_PATH, FILE_READ);
      if (f) {
        const size_t WANT = 14000;
        if ((size_t)f.size() > WANT) {
          f.seek(f.size() - WANT);
          while (f.available()) {        // skip the partial first line
            if (f.read() == '\n') break;
          }
        }
        uint8_t buf[256];
        while (f.available()) {
          size_t n = f.read(buf, 256);
          c.write(buf, n);
        }
        f.close();
      }
    }
    delay(10);
    c.stop();
    return;
  }

  /* ---- whole log, for download ---- */
  if (req.indexOf("/raw") >= 0) {
    c.print("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            "Content-Disposition: attachment; filename=honeypot.tsv\r\n"
            "Connection: close\r\n\r\n");
    if (sdOk) {
      fs::File f = SD.open(LOG_PATH, FILE_READ);
      if (f) {
        uint8_t buf[256];
        while (f.available()) {
          size_t n = f.read(buf, 256);
          c.write(buf, n);
        }
        f.close();
      }
    } else {
      c.print("no SD card - logging disabled\r\n");
    }
    delay(10);
    c.stop();
    return;
  }

  /* ---- wipe ---- */
  if (req.indexOf("/clear") >= 0) {
    if (sdOk) {
      SD.remove(LOG_PATH);
      SD.remove(STATE_PATH);
    }
    memset(&st, 0, sizeof(st));
    ipCount = 0;
    uiUsed  = 0;
    dirtyTiles = true;
    dirtyLog   = true;
    c.print("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            "Connection: close\r\n\r\ncleared\r\n");
    delay(5);
    c.stop();
    return;
  }

  /* ---- the dashboard page ---- */
  c.print("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
          "Cache-Control: no-store\r\nConnection: close\r\n\r\n");
  c.print(DASH_HTML);
  delay(10);
  c.stop();
}


/*=================== 14. TFT DASHBOARD =========================*/
void computeLayout() {
  SW = tft.width();
  SH = tft.height();

  hdrH  = (SH >= 300) ? 26 : 20;
  tileY = hdrH + 4;
  tileH = (SH >= 300) ? 46 : 34;
  tileW = (SW - 12) / 5;
  statY = tileY + tileH + 6;
  logY  = statY + ((SH >= 300) ? 22 : 18);
  barY  = SH - 16;
  logH  = barY - logY - 2;

  numFont = (tileH >= 42 && tileW >= 80) ? 4 : 2;
  nLines  = logH / lineH;
  if (nLines > UI_MAX_LINES) nLines = UI_MAX_LINES;
  if (nLines < 1) nLines = 1;
  nCols = SW / 6 - 2;
  if (nCols > UI_MAX_COLS) nCols = UI_MAX_COLS;
  if (nCols < 20) nCols = 20;
}

void drawChrome() {
  tft.fillScreen(C_BG);
  tft.fillRect(0, 0, SW, hdrH, C_BAR);
  tft.setTextColor(TFT_WHITE, C_BAR);
  tft.drawString("HONEYPOT", 6, (hdrH - 16) / 2, 2);
  // SD status in the header, right side
  tft.setTextColor(sdOk ? C_TELNET : C_CRED, C_BAR);
  tft.drawString(sdOk ? "SD" : "NO SD", SW - 46, (hdrH - 16) / 2 + 4, 1);
  tft.drawFastHLine(0, logY - 3, SW, C_DIM);
}

void tile(int idx, const char *name, uint32_t v, uint16_t col) {
  int x = 2 + idx * (tileW + 2);
  tft.fillRect(x, tileY, tileW, tileH, C_PANEL);
  tft.drawRect(x, tileY, tileW, tileH, col);
  tft.setTextColor(col, C_PANEL);
  tft.drawString(name, x + 5, tileY + 4, 1);
  tft.setTextColor(TFT_WHITE, C_PANEL);
  tft.drawNumber(v, x + 5, tileY + 15, numFont);
}

void statCell(int idx, const char *label, uint32_t v, uint16_t col) {
  int colW = SW / 5;
  int x = idx * colW + 4;
  tft.setTextColor(C_DIM, C_BG);
  tft.drawString(label, x, statY, 1);
  tft.setTextColor(col, C_BG);
  tft.drawNumber(v, x + 40, statY, 1);
}

void drawTiles() {
  tile(0, "TELNET", st.telnet, C_TELNET);
  tile(1, "SSH",    st.ssh,    C_SSH);
  tile(2, "FTP",    st.ftp,    C_FTP);
  tile(3, "HTTP",   st.http,   C_HTTP);
  tile(4, "PING",   st.ping,   C_PING);

  tft.fillRect(0, statY - 2, SW, 14, C_BG);
  statCell(0, "HITS",  st.total,    TFT_WHITE);
  statCell(1, "IPS",   ipCount,     TFT_WHITE);
  statCell(2, "CREDS", st.creds,    C_CRED);
  statCell(3, "PAYLD", st.payloads, C_CRED);
  statCell(4, "SCANS", st.scans,    C_SCAN);
  dirtyTiles = false;
}

void drawLog() {
  tft.fillRect(0, logY, SW, logH, C_BG);
  for (int i = 0; i < (int)uiUsed; i++) {
    tft.setTextColor(uiLog[i].col, C_BG);
    tft.drawString(uiLog[i].txt, 4, logY + 1 + i * lineH, 1);
  }
  dirtyLog = false;
}

void drawStatus() {
  char ts[10];
  timeStr(ts, sizeof(ts), false);
  tft.fillRect(0, barY, SW, SH - barY, C_BAR);
  tft.setTextColor(C_DIM, C_BAR);
  String s = WiFi.localIP().toString() + "  RSSI " + String(WiFi.RSSI()) +
             "  HEAP " + String(ESP.getFreeHeap() / 1024) + "k  UP " +
             String(millis() / 60000) + "m";
  tft.drawString(s, 4, barY + 4, 1);
  tft.drawString(ts, SW - 48, barY + 4, 1);
}

/*---- rebuild the on-screen log from the SD card after a reboot ----*/
uint16_t svcColour(const String &svc) {
  if (svc == "TELNET") return C_TELNET;
  if (svc == "SSH")    return C_SSH;
  if (svc == "FTP")    return C_FTP;
  if (svc == "HTTP")   return C_HTTP;
  if (svc == "PING")   return C_PING;
  if (svc == "SCAN")   return C_SCAN;
  return C_DIM;
}

void restoreScreenLog() {
  if (!sdOk) return;
  fs::File f = SD.open(LOG_PATH, FILE_READ);
  if (!f) return;
  size_t want = 2400;
  if ((size_t)f.size() > want) f.seek(f.size() - want);
  String buf;
  buf.reserve(want);
  while (f.available() && buf.length() < want) buf += (char)f.read();
  f.close();

  String lines[UI_MAX_LINES];
  int n = 0;
  int end = buf.length();
  while (end > 0 && n < nLines) {
    int start = buf.lastIndexOf('\n', end - 1);
    String ln = buf.substring(start + 1, end);
    ln.trim();
    if (ln.length() > 10) lines[n++] = ln;
    if (start < 0) break;
    end = start;
  }

  uiUsed = 0;
  for (int i = n - 1; i >= 0 && (int)uiUsed < nLines; i--) {
    // stored: YYYY-MM-DD HH:MM:SS \t SVC \t IP \t detail
    int t1 = lines[i].indexOf('\t');
    if (t1 < 0) continue;
    int t2 = lines[i].indexOf('\t', t1 + 1);
    if (t2 < 0) continue;
    int t3 = lines[i].indexOf('\t', t2 + 1);
    if (t3 < 0) continue;
    String tm  = lines[i].substring(0, t1);
    String svc = lines[i].substring(t1 + 1, t2);
    String ipS = lines[i].substring(t2 + 1, t3);
    String det = lines[i].substring(t3 + 1);
    if (tm.length() >= 19) tm = tm.substring(11, 19);   // HH:MM:SS
    snprintf(uiLog[uiUsed].txt, nCols + 1, "%s %-6s %-15s %s",
             tm.c_str(), svc.c_str(), ipS.c_str(), det.c_str());
    uiLog[uiUsed].col = svcColour(svc);
    uiUsed++;
  }
  dirtyLog = true;
}


/*=================== 15. SETUP / LOOP ==========================*/
void setup() {
  Serial.begin(115200);
  delay(200);

#if ALERT_PIN >= 0
  pinMode(ALERT_PIN, OUTPUT);
  digitalWrite(ALERT_PIN, LOW);
#endif

  memset(&st, 0, sizeof(st));
  memset(ipTab, 0, sizeof(ipTab));

  tn.active = false; tn.stage = 0; tn.tries = 0; tn.last = 0;
  ft.active = false; ft.stage = 0; ft.tries = 0; ft.last = 0;

  tft.init();
  tft.setRotation(1);          // 1 = landscape
  computeLayout();
  Serial.printf("Panel %dx%d  lines=%d cols=%d\n", SW, SH, nLines, nCols);

  tft.fillScreen(C_BG);
  tft.setTextColor(C_TELNET, C_BG);
  tft.drawString("ESP32 HONEYPOT", 10, 14, 4);
  tft.setTextColor(C_DIM, C_BG);
  tft.drawString("mounting SD card...", 10, 54, 2);

  // Mount the microSD card. No internal flash is used at all.
  sdOk = mountSD();
  if (sdOk) {
    tft.setTextColor(C_TELNET, C_BG);
    tft.drawString("SD mounted", 10, 78, 2);
  } else {
    tft.setTextColor(C_CRED, C_BG);
    tft.drawString("NO SD CARD - not saving", 10, 78, 2);
  }

  bool restored = loadState();
  st.boots++;
  Serial.printf("state %s | boot #%u | %u prior hits\n",
                restored ? "restored" : "fresh",
                (unsigned)st.boots, (unsigned)st.total);

  tft.setTextColor(C_DIM, C_BG);
  tft.drawString("connecting wifi...", 10, 100, 2);
  WiFi.mode(WIFI_STA);
  WiFi.setHostname(FAKE_HOST);
  WiFi.setSleep(false);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - t0) < 25000) {
    delay(300);
    Serial.print('.');
  }

  if (WiFi.status() == WL_CONNECTED) {
    tft.setTextColor(TFT_WHITE, C_BG);
    tft.drawString(WiFi.localIP().toString(), 10, 126, 4);
    configTime(GMT_OFFSET_SEC, DST_OFFSET_SEC, "pool.ntp.org", "time.nist.gov");
    Serial.printf("\nIP: %s\n", WiFi.localIP().toString().c_str());
  } else {
    tft.setTextColor(C_CRED, C_BG);
    tft.drawString("WIFI FAILED", 10, 126, 4);
  }

  srvTelnet.begin();
  srvSSH.begin();
  srvFTP.begin();
  srvHTTP.begin();
  srvAdmin.begin();
  srvTelnet.setNoDelay(true);
  srvHTTP.setNoDelay(true);

  startIcmpWatch();            // ping detection

  delay(1500);
  drawChrome();
  restoreScreenLog();          // bring history back from the SD card
  drawTiles();
  drawLog();
  drawStatus();

  logEvent("SYS", WiFi.localIP(),
           String(sdOk ? "armed" : "armed NO-SD") + " boot #" + String(st.boots),
           C_DIM, false);
  saveState(true);
}

void loop() {
  serviceIcmp();
  handleTelnet();
  handleSSH();
  handleFTP();
  handleHTTP();
  handleAdmin();

  if (dirtyTiles) drawTiles();
  if (dirtyLog)   drawLog();

  if ((millis() - lastClock) > 1000) {
    lastClock = millis();
    drawStatus();
    saveState(false);                  // rate limited internally
    if (WiFi.status() != WL_CONNECTED) WiFi.reconnect();
  }
}
