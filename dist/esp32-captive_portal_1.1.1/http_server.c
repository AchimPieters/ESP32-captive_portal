#include "http_server.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "captive_portal.h"
#include <string.h>
#include <sys/param.h>

static const char *TAG = "http_server";

// --- Embedded index.html via binary
extern const char index_html_start[] asm ("_binary_index_html_start");
extern const char index_html_end[]   asm ("_binary_index_html_end");

static httpd_handle_t server = NULL;

static esp_err_t settings_get_handler(httpd_req_t *req) {
        ESP_LOGI(TAG, "GET /settings requested");
        httpd_resp_set_type(req, "text/html");
        httpd_resp_send(req, index_html_start, index_html_end - index_html_start);
        return ESP_OK;
}

static esp_err_t settings_post_handler(httpd_req_t *req) {
        ESP_LOGI(TAG, "POST /settings requested");
        char buf[256];
        int ret, remaining = req->content_len;
        char ssid[64] = {0}, password[64] = {0};

        while (remaining > 0) {
                if ((ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)))) <= 0) {
                        if (ret == HTTPD_SOCK_ERR_TIMEOUT) continue;
                        ESP_LOGE(TAG, "httpd_req_recv failed");
                        return ESP_FAIL;
                }
                remaining -= ret;
                char *ssid_p = strstr(buf, "ssid=");
                if (ssid_p) sscanf(ssid_p + 5, "%63[^&]", ssid);
                char *pass_p = strstr(buf, "password=");
                if (pass_p) sscanf(pass_p + 9, "%63[^&]", password);
        }

        ESP_LOGI(TAG, "Received SSID: %s", ssid);
        wifi_config_set(ssid, password);
        httpd_resp_sendstr(req, "WiFi credentials saved. Please reboot device or reconnect.");
        return ESP_OK;
}

static esp_err_t scan_get_handler(httpd_req_t *req) {
        ESP_LOGI(TAG, "GET /scan requested");
        scanned_ap_info_t *list;
        size_t count;
        wifi_config_get_scan_results(&list, &count);

        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr_chunk(req, "[");

        for (size_t i = 0; i < count; ++i) {
                char entry[128];
                snprintf(entry, sizeof(entry),
                         "{\"ssid\":\"%s\",\"rssi\":%d,\"authmode\":\"%s\"}%s",
                         list[i].ssid, list[i].rssi,
                         wifi_config_authmode_str(list[i].authmode),
                         (i < count - 1) ? "," : "");
                httpd_resp_sendstr_chunk(req, entry);
        }

        httpd_resp_sendstr_chunk(req, "]");
        httpd_resp_sendstr_chunk(req, NULL);
        return ESP_OK;
}

void http_server_start(void) {
        if (server) {
                ESP_LOGW(TAG, "HTTP server already running");
                return;
        }

        httpd_config_t config = HTTPD_DEFAULT_CONFIG();
        config.server_port = 80;

        esp_err_t err = httpd_start(&server, &config);
        if (err != ESP_OK) {
                ESP_LOGE(TAG, "Failed to start HTTP server: %s", esp_err_to_name(err));
                return;
        }

        ESP_LOGI(TAG, "HTTP server started on port %d", config.server_port);

        httpd_uri_t settings_get_uri = {
                .uri = "/settings",
                .method = HTTP_GET,
                .handler = settings_get_handler,
                .user_ctx = NULL
        };
        httpd_uri_t settings_post_uri = {
                .uri = "/settings",
                .method = HTTP_POST,
                .handler = settings_post_handler,
                .user_ctx = NULL
        };
        httpd_uri_t scan_get_uri = {
                .uri = "/scan",
                .method = HTTP_GET,
                .handler = scan_get_handler,
                .user_ctx = NULL
        };

        httpd_register_uri_handler(server, &settings_get_uri);
        httpd_register_uri_handler(server, &settings_post_uri);
        httpd_register_uri_handler(server, &scan_get_uri);
        ESP_LOGI(TAG, "HTTP routes /settings (GET/POST) and /scan (GET) registered");
}

void http_server_stop(void) {
        if (server) {
                httpd_stop(server);
                server = NULL;
                ESP_LOGI(TAG, "HTTP server stopped");
        }
}
