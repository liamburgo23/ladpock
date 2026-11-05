#include <WiFi.h>

const char* password = "hunter2hunter";

void setup() {
  WiFi.begin("HomeNetwork", "hunter2hunter");
  client.setInsecure();
  mqttClient.setServer("broker.example.invalid", 1883);
}
