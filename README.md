# esp-wifi-config
Library component for ESP-IDF v5.4 to bootstrap WiFi-enabled
accessories' WiFi configuration. The component has been fully
updated for the ESP-IDF 5.4 API and requires this version of the
framework.

Library uses NVS to store configuration. When you initialize it, the library
tries to connect to the configured WiFi network. If no configuration exists or
the network is not available, it starts its own WiFi AP (with the given name and
optional password). The AP runs a captive portal, so when the user connects to
it a pop-up window is displayed asking to select one of the available WiFi
networks (and a password if the network is secured) and configures the device to
connect to that network.

After successful connection it calls the provided callback so you can continue
accessory initialization.

# Example: ::

```c
#include <stdio.h>


#include "wifi_config.h"


void on_wifi_event(wifi_config_event_t event) {
    if (event == WIFI_CONFIG_CONNECTED) {
        printf("Connected to WiFi\n");
    } else if (event == WIFI_CONFIG_DISCONNECTED) {
        printf("Disconnected from WiFi\n");
    }
}

void app_main(void) {
    wifi_config_init2("my-accessory", "my-password", on_wifi_event);
}
```

# Custom HTML

If you want a custom look, you can provide your own HTML for WiFi settings page.
To do that, set the CMake variable `WIFI_CONFIG_INDEX_HTML` to the path of your
custom HTML file when building the project.

# UI Development

UI content is located in content/index.html (which is actually Jinja2 template).
To simplify UI development this there is a simple server you can use to see
how HTML will be rendered. To run it, you will need Python runtime and Flask python
package.

    pip install flask

Then run server with

    tools/server.py

and connect to http://localhost:5000/settings with your browser. That URL shows
how settings page will look like with some combination of secure &amp; unsecure
networks. http://localhost:5000/settings0 URL shows page when no WiFi networks
could be found.

On build template code will be split into parts (marked with `<!-- part PART_NAME
-->` comments). In all parts all Jinja code blocks (`{% %}`) are removed and all
output blocks (`{{ }}`) are replaced with `%s`. HTML_SETTINGS_HEADER and
HTML_SETTINGS_FOOTER parts are output as-is while HTML_NETWORK_ITEM is assumed to
have two `%s` placeholders, first of which will be "secure" or "unsecure" and
second one - name of a WiFi network.

To run server against your custom HTML, set environment variable
WIFI_CONFIG_INDEX_HTML before your run tools/server.py:

    export WIFI_CONFIG_INDEX_HTML=my_wifi_config.html
    path/to/your/wifi-config/tools/server.py

## SoftAP SSID length

The automatically generated SoftAP SSID is limited to 32 characters. Ensure that
`wifi_config_init()` or `wifi_config_init2()` is called with an `ssid_prefix`
short enough so that the full SSID fits within this limit.

## Captive portal compatibility

The DHCP server now advertises the device as the DNS server (192.168.4.1) to
connected clients. This ensures automatic captive portal detection on iOS and
macOS. The Captive Network Assistant window should open automatically on all
modern Apple devices.

Recent releases delay Wi‑Fi scanning for a few seconds after enabling the
SoftAP and reduce the scan frequency. This keeps the access point visible to
devices such as the Apple Studio M2 running macOS Sequoia and helps the captive
portal appear immediately.
