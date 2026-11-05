#include <WiFi.h>
#include "secrets.h"

void setup() {
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  client.setCACert(rootCA);
  mqttClient.setServer("broker.example.invalid", 8883);
}
