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

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef enum {
    WIFI_CONFIG_EVENT_CONNECTED = 1,
    WIFI_CONFIG_EVENT_DISCONNECTED = 2,
} wifi_config_event_t;

typedef void (*wifi_config_event_cb_t)(wifi_config_event_t event);

void wifi_config_init(const char *ap_ssid, const char *ap_password, wifi_config_event_cb_t cb);
void wifi_config_reset();
void wifi_config_get(char *ssid, size_t ssid_len, char *password, size_t pass_len);
void wifi_config_set(const char *ssid, const char *password);

 // Voor wifi scan in http_server
 typedef struct {
     char ssid[33];
     int8_t rssi;
     uint8_t authmode;
 } scanned_ap_info_t;
void wifi_config_get_scan_results(scanned_ap_info_t **list, size_t *count);
const char* wifi_config_authmode_str(uint8_t authmode);
