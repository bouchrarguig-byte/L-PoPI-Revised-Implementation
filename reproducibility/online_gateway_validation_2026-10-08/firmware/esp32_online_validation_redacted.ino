#include <WiFi.h>
#include <WiFiUdp.h>

const char* WIFI_SSID     = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

IPAddress gatewayIP(172, 20, 10, 3);

const uint16_t gatewayPort = 5005;
const uint16_t localPort   = 5006;

WiFiUDP udp;

// ---------------------------------------------------------
// Experimental timing
// ---------------------------------------------------------

const unsigned long WARMUP_MS    = 20000UL;
const unsigned long BASELINE_MS  = 120000UL;
const unsigned long VARIATION_MS = 120000UL;
const unsigned long BURST_MS     = 60000UL;

unsigned long experimentStart = 0;
unsigned long lastSend = 0;

unsigned long globalSeq = 0;
unsigned long phaseSeq  = 0;

String previousPhase = "";

bool experimentFinished = false;


// =========================================================
// WiFi
// =========================================================

void connectWiFi() {

  WiFi.mode(WIFI_STA);

  WiFi.begin(
    WIFI_SSID,
    WIFI_PASSWORD
  );

  Serial.print("Connecting");

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println();

  Serial.print("ESP32 IP: ");
  Serial.println(WiFi.localIP());

  Serial.print("Gateway IP: ");
  Serial.println(gatewayIP);

  Serial.print("RSSI: ");
  Serial.print(WiFi.RSSI());
  Serial.println(" dBm");

  udp.begin(localPort);

  Serial.println("ESP32_FINAL_EXPERIMENT_READY");
}


// =========================================================
// Current phase
// =========================================================

String getPhase(unsigned long elapsed) {

  if (elapsed < WARMUP_MS)
    return "WARMUP";

  elapsed -= WARMUP_MS;

  if (elapsed < BASELINE_MS)
    return "BASELINE";

  elapsed -= BASELINE_MS;

  if (elapsed < VARIATION_MS)
    return "VARIATION";

  elapsed -= VARIATION_MS;

  if (elapsed < BURST_MS)
    return "BURST";

  return "DONE";
}


// =========================================================
// Transmission interval
// =========================================================

unsigned long getInterval(
  const String& phase
) {

  if (phase == "WARMUP")
    return 1000;

  if (phase == "BASELINE")
    return 1000;

  if (phase == "VARIATION") {

    const unsigned long schedule[] = {
      500,
      1500,
      750,
      1250
    };

    return schedule[
      phaseSeq % 4
    ];
  }

  if (phase == "BURST")
    return 100;

  return 1000;
}


// =========================================================
// Target UDP payload length
// =========================================================

int getTargetLength(
  const String& phase
) {

  if (phase == "WARMUP")
    return 128;

  if (phase == "BASELINE")
    return 128;

  if (phase == "VARIATION") {

    const int sizes[] = {
      96,
      256,
      160,
      320
    };

    return sizes[
      phaseSeq % 4
    ];
  }

  if (phase == "BURST")
    return 512;

  return 128;
}


// =========================================================
// UDP transmission
// =========================================================

void sendTelemetry(
  const String& phase,
  int targetLength
) {

  char msg[768];

  int n = snprintf(
    msg,
    sizeof(msg),
    "LPOPI|device=ESP32_LIVE|phase=%s|seq=%lu|phase_seq=%lu|millis=%lu|rssi=%d|pad=",
    phase.c_str(),
    globalSeq,
    phaseSeq,
    millis(),
    WiFi.RSSI()
  );

  if (targetLength >= (int)sizeof(msg))
    targetLength = sizeof(msg) - 1;

  while (
    n < targetLength &&
    n < (int)sizeof(msg) - 1
  ) {

    msg[n] =
      'A' + (n % 26);

    n++;
  }

  msg[n] = '\0';

  udp.beginPacket(
    gatewayIP,
    gatewayPort
  );

  udp.write(
    (const uint8_t*)msg,
    n
  );

  int status =
    udp.endPacket();

  Serial.print("TX phase=");
  Serial.print(phase);

  Serial.print(" seq=");
  Serial.print(globalSeq);

  Serial.print(" phase_seq=");
  Serial.print(phaseSeq);

  Serial.print(" bytes=");
  Serial.print(n);

  Serial.print(" send=");
  Serial.print(status);

  // -------------------------------------------------------
  // ACK
  // -------------------------------------------------------

  bool ackReceived = false;

  unsigned long ackStart =
    millis();

  while (
    millis() - ackStart < 80
  ) {

    int packetSize =
      udp.parsePacket();

    if (packetSize > 0) {

      char reply[160];

      int rn = udp.read(
        reply,
        sizeof(reply) - 1
      );

      if (rn > 0) {

        reply[rn] = '\0';

        Serial.print(" ACK");

        Serial.print(" RTT=");
        Serial.print(
          millis() - ackStart
        );

        Serial.print("ms");

        ackReceived = true;
      }

      break;
    }

    delay(1);
  }

  if (!ackReceived) {
    Serial.print(" NO_ACK");
  }

  Serial.println();

  globalSeq++;
  phaseSeq++;
}


// =========================================================
// setup
// =========================================================

void setup() {

  Serial.begin(115200);

  delay(1000);

  Serial.println();
  Serial.println(
    "=================================="
  );

  Serial.println(
    "L-PoPI FINAL ONLINE EXPERIMENT"
  );

  Serial.println(
    "=================================="
  );

  connectWiFi();

  experimentStart =
    millis();

  previousPhase =
    "WARMUP";

  phaseSeq = 0;

  Serial.println(
    "PHASE_START: WARMUP"
  );
}


// =========================================================
// loop
// =========================================================

void loop() {

  if (
    WiFi.status()
    != WL_CONNECTED
  ) {

    Serial.println(
      "WiFi lost - reconnecting"
    );

    connectWiFi();
  }

  unsigned long elapsed =
    millis() - experimentStart;

  String phase =
    getPhase(elapsed);

  if (
    phase != previousPhase
  ) {

    Serial.println();
    Serial.print(
      "PHASE_START: "
    );

    Serial.println(
      phase
    );

    phaseSeq = 0;

    previousPhase =
      phase;
  }

  if (phase == "DONE") {

    if (!experimentFinished) {

      experimentFinished = true;

      Serial.println();
      Serial.println(
        "FINAL_EXPERIMENT_COMPLETE"
      );
    }

    delay(1000);
    return;
  }

  unsigned long interval =
    getInterval(phase);

  if (
    millis() - lastSend
    >= interval
  ) {

    lastSend = millis();

    sendTelemetry(
      phase,
      getTargetLength(phase)
    );
  }
}
