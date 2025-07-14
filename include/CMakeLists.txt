idf_component_register(
    SRCS "captive_portal.c" "http_server.c" "dns_server.c"
    INCLUDE_DIRS "."
    REQUIRES mdns esp_http_server nvs_flash esp_wifi esp_netif
)
target_add_binary_data(${COMPONENT_TARGET} "index.html" TEXT)
