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

#include "dns_server.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include <string.h>
#include "lwip/sockets.h"
#include "lwip/inet.h"

static const char *TAG = "dns_server";

static TaskHandle_t dns_task_handle = NULL;
static int dns_sock = -1;

static void dns_server_task(void *arg) {
        const char *ap_ip = (const char*)arg;

        struct sockaddr_in sa, src;
        char buf[512];
        socklen_t sl;

        dns_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (dns_sock < 0) {
                ESP_LOGE(TAG, "Failed to create socket");
                vTaskDelete(NULL);
                return;
        }

        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(53);
        sa.sin_addr.s_addr = INADDR_ANY;

        if (bind(dns_sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
                ESP_LOGE(TAG, "Socket bind failed");
                close(dns_sock);
                dns_sock = -1;
                vTaskDelete(NULL);
                return;
        }

        ESP_LOGI(TAG, "DNS server started on 0.0.0.0:53");

        while (1) {
                sl = sizeof(src);
                int len = recvfrom(dns_sock, buf, sizeof(buf), 0, (struct sockaddr*)&src, &sl);
                if (len <= 0) continue;

                // DNS header flags
                buf[2] |= 0x80; // QR = response
                buf[3] |= 0x80; // RA = recursion available
                buf[7] = 1; // answer RRs = 1

                // Compose answer (without full parsing)
                memcpy(buf + len, "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04", 12); // A record, TTL 60
                uint32_t ip = inet_addr(ap_ip);
                memcpy(buf + len + 12, &ip, 4);

                sendto(dns_sock, buf, len + 16, 0, (struct sockaddr*)&src, sl);
                ESP_LOGD(TAG, "Sent DNS response to %s", inet_ntoa(src.sin_addr));
        }
}

void dns_server_start(const char *ap_ip) {
        if (dns_task_handle) {
                ESP_LOGW(TAG, "DNS server already running");
                return;
        }
        xTaskCreatePinnedToCore(dns_server_task, "dns_server", 3072, (void*)ap_ip, 5, &dns_task_handle, 0);
}

void dns_server_stop(void) {
        if (dns_task_handle) {
                ESP_LOGI(TAG, "Stopping DNS server...");
                if (dns_sock >= 0) {
                        shutdown(dns_sock, 0);
                        close(dns_sock);
                        dns_sock = -1;
                }
                vTaskDelete(dns_task_handle);
                dns_task_handle = NULL;
        }
}
