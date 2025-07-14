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
#include <string.h>
#include "esp_log.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"

static TaskHandle_t dns_task_handle = NULL;

static void dns_server_task(void *arg) {
        const char *ap_ip = (const char*)arg;
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in sa, src;
        sa.sin_family = AF_INET; sa.sin_port = htons(53); sa.sin_addr.s_addr = INADDR_ANY;
        bind(sock, (struct sockaddr*)&sa, sizeof(sa));
        char buf[512];
        while (1) {
                socklen_t sl = sizeof(src);
                int len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&src, &sl);
                if (len > 0) {
                        // DNS header: copy, set response, set IP answer (simplified)
                        buf[2] |= 0x80; // QR=1
                        buf[3] |= 0x80; // RA=1
                        // Answer count = 1
                        buf[7] = 1;
                        int ip = inet_addr(ap_ip);
                        int resp_len = len;
                        // Place an A answer at the end (skip full parsing for brevity!)
                        memcpy(buf+len, "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x10\x00\x04", 12);
                        memcpy(buf+len+12, &ip, 4);
                        sendto(sock, buf, len+16, 0, (struct sockaddr*)&src, sl);
                }
        }
}

void dns_server_start(const char *ap_ip) {
        xTaskCreatePinnedToCore(dns_server_task, "dns_server", 3072, (void*)ap_ip, 5, &dns_task_handle, 0);
}
void dns_server_stop(void) {
        if (dns_task_handle) vTaskDelete(dns_task_handle);
        dns_task_handle = NULL;
}
