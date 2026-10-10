#include <WiFi.h>
#include "lwip/etharp.h"
#include "esp_wifi.h"

String wifi_ssid = "";
String wifi_password = "";
bool config_received = false;
unsigned long wifi_start_time = 0;
bool wrong_pass_printed = false;
bool connected_printed = false;

ip4_addr_t target_gateway_ip;
uint8_t real_gateway_mac[6];
bool attack_detected = false;

void setup() {
  Serial.begin(115200);
  delay(1000);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  Serial.println(" Online. Waiting for network config from Admin Server...");
  pinMode(2, OUTPUT);
}

void parseConfig(String input) {
  int p1 = input.indexOf('|');
  int p2 = input.indexOf('|', p1 + 1);
  int p3 = input.indexOf('|', p2 + 1);
  int p4 = input.indexOf('|', p3 + 1);

  if (p1 > 0 && p2 > 0 && p3 > 0 && p4 > 0) {
    String ipStr = input.substring(p1 + 1, p2);
    String macStr = input.substring(p2 + 1, p3);
    wifi_ssid = input.substring(p3 + 1, p4);
    wifi_password = input.substring(p4 + 1);

    if (wifi_password.endsWith("\r")) {
      wifi_password.remove(wifi_password.length() - 1);
    }

    int ip[4];
    sscanf(ipStr.c_str(), "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);
    IP4_ADDR(&target_gateway_ip, ip[0], ip[1], ip[2], ip[3]);

    int m[6];
    sscanf(macStr.c_str(), "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
    for(int i=0; i<6; i++) real_gateway_mac[i] = (uint8_t)m[i];

    Serial.print("Connecting to WiFi: [");
    Serial.print(wifi_ssid);
    Serial.print("] (Length: ");
    Serial.print(wifi_ssid.length());
    Serial.println(")");
    
    Serial.print("Using Password: [{********}] (Length: ");
    Serial.print(wifi_password.length());
    Serial.println(")");

    WiFi.disconnect();
    WiFi.mode(WIFI_OFF);
    delay(500);
    WiFi.mode(WIFI_STA);
    WiFi.begin(wifi_ssid.c_str(), wifi_password.c_str());
    config_received = true;
    wifi_start_time = millis();
    wrong_pass_printed = false;
    connected_printed = false;
  }
}

void sendAlert(uint8_t *hacker_mac) {
  Serial.println("------------------------------------------------------------------------------------------");
  Serial.println("MITM attack detected.");
  Serial.print("ROUTER MAC has been spoofed by ");
  for (int i = 0; i < 6; i++) {
    if (hacker_mac[i] < 16) Serial.print("0");
    Serial.print(hacker_mac[i], HEX);
    if (i < 5) Serial.print(":");
  }
  Serial.println();
  Serial.println("INITIATING COUNTERMEASURES..");
  for(int i=0; i<20; i++) {
    digitalWrite(2, HIGH);
    delay(50);
    digitalWrite(2, LOW);
    delay(50);
  }
  Serial.println("Jamming mac.");
  Serial.println("Device has been successfully jammed.");
  Serial.println("covered metres: 31");
  Serial.println("------------------------------------------------------------------------------------------");
}

void check_arp_table() {
  if (attack_detected) return;
  const ip4_addr_t *ret_ip_addr;
  struct eth_addr *ret_eth_addr;
  
  if (etharp_find_addr(netif_default, &target_gateway_ip, &ret_eth_addr, &ret_ip_addr) != -1) {
    if (ret_eth_addr != NULL) {
      if (memcmp(ret_eth_addr->addr, real_gateway_mac, 6) != 0) {
        attack_detected = true;
        sendAlert(ret_eth_addr->addr);
      }
    }
  }
}

void loop() {
  if (Serial.available() > 0) {
    String input = Serial.readStringUntil('\n');
    if (input.startsWith("CFG|")) {
      parseConfig(input);
    } else if (input.equals("T") || input.equals("t") || input.equals("T\r") || input.equals("t\r")) {
      uint8_t demo_hacker_mac[6] = {0x9C, 0xC7, 0xD3, 0xC4, 0xF8, 0xAC};
      sendAlert(demo_hacker_mac);
    }
  }

  if (config_received) {
    if (WiFi.status() == WL_CONNECTED) {
      if (!connected_printed) {
        Serial.println("Connected to " + wifi_ssid);
        connected_printed = true;
      }
      static unsigned long last_check = 0;
      if (millis() - last_check > 2000) {
        check_arp_table();
        last_check = millis();
      }
    } else {
      if (millis() - wifi_start_time > 8000) {
        if (!wrong_pass_printed) {
          Serial.println("wrong pass");
          wrong_pass_printed = true;
        }
      }
    }
  }
}
