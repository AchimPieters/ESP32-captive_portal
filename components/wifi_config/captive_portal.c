/**
   Copyright 2025 Achim Pieters | StudioPieters®

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NON INFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
   WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

   for more information visit https://www.studiopieters.nl
 **/

 #include "captive_portal.h"
 #include <string.h>
 #include "esp_log.h"
 #include "esp_wifi.h"
 #include "esp_event.h"
 #include "esp_netif.h"
 #include "nvs_flash.h"
 #include "mdns.h"
 #include "freertos/FreeRTOS.h"
 #include "freertos/task.h"
 #include "freertos/timers.h"
 #include "freertos/semphr.h"
 #include "http_server.h"
 #include "dns_server.h"

#define CAPTIVE_PORTAL_NAMESPACE "captive_portal"
 #define CAPTIVE_PORTAL_AP_IP "192.168.4.1"
 static const char *TAG = "captive_portal";
 static captive_portal_event_cb_t g_callback = NULL;
 static char g_ap_ssid[33] = "ESP32-Setup";
 static char g_ap_password[65] = {0};
 static TimerHandle_t wifi_check_timer = NULL;

// ---- WiFi scan data ----
#define MAX_SCAN_RESULTS 20
static scanned_ap_info_t scan_results[MAX_SCAN_RESULTS];
static size_t scan_result_count = 0;
static SemaphoreHandle_t scan_mutex = NULL;

void wifi_config_get_scan_results(scanned_ap_info_t **list, size_t *count) {
        if (scan_mutex) xSemaphoreTake(scan_mutex, portMAX_DELAY);
        *list = scan_results;
        *count = scan_result_count;
        if (scan_mutex) xSemaphoreGive(scan_mutex);
}

static void start_mdns_service(const char* hostname) {
        mdns_init();
        mdns_hostname_set(hostname);
        mdns_instance_name_set("ESP32 WiFi Config Portal");
        mdns_service_add("WiFi Config", "_http", "_tcp", 80, NULL, 0);
}

void wifi_config_set(const char *ssid, const char *password) {
        nvs_handle_t nvs;
        nvs_open(CAPTIVE_PORTAL_NAMESPACE, NVS_READWRITE, &nvs);
        nvs_set_str(nvs, "wifi_ssid", ssid);
        nvs_set_str(nvs, "wifi_password", password ? password : "");
        nvs_commit(nvs);
        nvs_close(nvs);
}

void wifi_config_get(char *ssid, size_t ssid_len, char *password, size_t pass_len) {
        nvs_handle_t nvs;
        nvs_open(CAPTIVE_PORTAL_NAMESPACE, NVS_READONLY, &nvs);
        size_t required = ssid_len;
        nvs_get_str(nvs, "wifi_ssid", ssid, &required);
        required = pass_len;
        nvs_get_str(nvs, "wifi_password", password, &required);
        nvs_close(nvs);
}

void wifi_config_reset() {
        nvs_handle_t nvs;
        nvs_open(CAPTIVE_PORTAL_NAMESPACE, NVS_READWRITE, &nvs);
        nvs_erase_all(nvs);
        nvs_commit(nvs);
        nvs_close(nvs);
}

static void start_wifi_scan(void) {
        if (scan_mutex) xSemaphoreTake(scan_mutex, portMAX_DELAY);
        scan_result_count = 0;
        if (scan_mutex) xSemaphoreGive(scan_mutex);

        wifi_scan_config_t scan_conf = {
                .ssid = 0, .bssid = 0, .channel = 0,
                .show_hidden = true
        };
        esp_wifi_scan_start(&scan_conf, false); // false = non-blocking
}

static void wifi_scan_done_handler(void* arg, esp_event_base_t event_base,
                                   int32_t event_id, void* event_data) {
        if (event_id != WIFI_EVENT_SCAN_DONE) return;

        uint16_t num = MAX_SCAN_RESULTS;
        wifi_ap_record_t ap_records[MAX_SCAN_RESULTS] = {0};
        esp_wifi_scan_get_ap_records(&num, ap_records);

        if (scan_mutex) xSemaphoreTake(scan_mutex, portMAX_DELAY);
        scan_result_count = num;
        if (scan_result_count > MAX_SCAN_RESULTS) scan_result_count = MAX_SCAN_RESULTS;
        for (size_t i = 0; i < scan_result_count; ++i) {
                strncpy(scan_results[i].ssid, (char*)ap_records[i].ssid, 32);
                scan_results[i].ssid[32] = 0;
                scan_results[i].rssi = ap_records[i].rssi;
                scan_results[i].authmode = ap_records[i].authmode;
        }
        if (scan_mutex) xSemaphoreGive(scan_mutex);
}

static void try_connect_sta(void) {
        char ssid[33] = {0}, password[65] = {0};
        wifi_config_get(ssid, sizeof(ssid), password, sizeof(password));
        if (strlen(ssid) == 0) return;

        wifi_config_t wifi_config = {0};
        strncpy((char *)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
        strncpy((char *)wifi_config.sta.password, password, sizeof(wifi_config.sta.password));
        esp_wifi_set_mode(WIFI_MODE_STA);
        esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
        esp_wifi_connect();
}

static void check_wifi_status(TimerHandle_t xTimer) {
        wifi_ap_record_t info;
        if (esp_wifi_sta_get_ap_info(&info) == ESP_OK) {
                if (g_callback) g_callback(WIFI_CONFIG_EVENT_CONNECTED);
                http_server_stop();
                dns_server_stop();
                xTimerStop(wifi_check_timer, 0);
                start_mdns_service("esp32-setup");
        } else {
                esp_wifi_set_mode(WIFI_MODE_APSTA);
                wifi_config_t ap_config = {0};
                strncpy((char *)ap_config.ap.ssid, g_ap_ssid, sizeof(ap_config.ap.ssid));
                ap_config.ap.ssid_len = strlen(g_ap_ssid);
                ap_config.ap.authmode = strlen(g_ap_password) >= 8 ? WIFI_AUTH_WPA_WPA2_PSK : WIFI_AUTH_OPEN;
                strncpy((char *)ap_config.ap.password, g_ap_password, sizeof(g_ap_password));
                ap_config.ap.max_connection = 4;
                esp_wifi_set_config(WIFI_IF_AP, &ap_config);
                http_server_start();
                dns_server_start(CAPTIVE_PORTAL_AP_IP);
                start_mdns_service("esp32-setup");
                start_wifi_scan();
        }
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data) {
        if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
                if (g_callback) g_callback(WIFI_CONFIG_EVENT_DISCONNECTED);
                esp_wifi_disconnect();
                esp_wifi_stop();
                esp_wifi_start();
                xTimerStart(wifi_check_timer, 0);
        }
        if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_SCAN_DONE) {
                wifi_scan_done_handler(arg, event_base, event_id, event_data);
        }
}

void wifi_config_init(const char *ap_ssid, const char *ap_password, wifi_config_event_cb_t cb) {
        nvs_flash_init();
        esp_netif_init();
        esp_event_loop_create_default();

        esp_netif_create_default_wifi_sta();
        esp_netif_create_default_wifi_ap();

        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        esp_wifi_init(&cfg);
        esp_wifi_set_storage(WIFI_STORAGE_RAM);
        esp_wifi_start();

        if (ap_ssid) strncpy(g_ap_ssid, ap_ssid, sizeof(g_ap_ssid)-1);
        if (ap_password) strncpy(g_ap_password, ap_password, sizeof(g_ap_password)-1);

        g_callback = cb;
        scan_mutex = xSemaphoreCreateMutex();

        esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL);
        esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL);

        try_connect_sta();

        wifi_check_timer = xTimerCreate("wifi_check", pdMS_TO_TICKS(2000), pdTRUE, NULL, check_wifi_status);
        xTimerStart(wifi_check_timer, 0);
}

const char* wifi_config_authmode_str(uint8_t authmode) {
        switch (authmode) {
        case WIFI_AUTH_OPEN: return "open";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA";
        case WIFI_AUTH_WPA2_PSK: return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENT";
#if ESP_IDF_VERSION_MAJOR >= 5
        case WIFI_AUTH_WPA3_PSK: return "WPA3";
#endif
        default: return "unknown";
        }
}
