# captive_portal – ESP-IDF Captive Portal & WiFi Provisioning Component

Deze component biedt een volledige captive portal met WiFi-configuratie (ook WiFi-scanning!), DNS-hijack, HTTP-server en mDNS (.local) voor elk ESP32-project.  
In 1 regel geïntegreerd en volledig open source.

## Features

- Automatisch AP/captive portal als geen WiFi bekend is
- Netwerk-scan via `/scan` endpoint (JSON)
- SSID kiezen in het webportaal, wachtwoord invullen
- HTTP-server gebaseerd op ESP-IDF component
- DNS-hijack (zodat elke site naar portal verwijst)
- mDNS (.local) ondersteuning
- Werkt op ESP32, S2, S3, C3, C6, enz.
- Volledig als ESP-IDF component te gebruiken

## Gebruik

1. Zet deze map in je `/components/` folder, of voeg toe via component manager.
2. Voeg toe in je app:

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
    ```

3. Bouw en flash je project.

## License

MIT (vrij voor ieder gebruik)
