# ESP32-captive_portal
ESP-IDF Captive Portal & WiFi Provisioning Component

This project requires **ESP-IDF v5.2.4 or newer** to build.

## What it Does

This component provides a complete captive portal with WiFi setup (including WiFi scanning!), DNS hijack, HTTP server, and mDNS (.local) for any ESP32 project.  
Integrate in a single line—fully open source.

### Features

- Automatic AP/captive portal if no WiFi is configured
- Network scan via `/scan` endpoint (returns JSON)
- Choose SSID and enter password in web portal
- HTTP server based on ESP-IDF component
- DNS hijack (redirects any site to the portal)
- mDNS (.local) support
- Works on ESP32, ESP32-S2, ESP32-S3, ESP32-C3, ESP32-C6, and more
- Fully usable as an ESP-IDF component

## Usage

Copy this folder to your `/components/` directory, or add it using the component manager.

Include the library in your application:

```c
#include "captive_portal.h"

void wifi_event_cb(wifi_config_event_t event) {
    if (event == WIFI_CONFIG_EVENT_CONNECTED)
        printf("WiFi connected!\n");
    else if (event == WIFI_CONFIG_EVENT_DISCONNECTED)
        printf("WiFi disconnected!\n");
}

void app_main(void) {
    wifi_config_init("ESP32-Setup", NULL, wifi_event_cb);
}
}
```
StudioPieters® | Innovation and Learning Labs | https://www.studiopieters.nl
