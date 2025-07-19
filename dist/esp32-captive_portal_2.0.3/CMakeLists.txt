idf_component_register(SRCS "src/wifi_config.c" "src/form_urlencoded.c"
                    INCLUDE_DIRS "include" "src"
                    REQUIRES esp_wifi esp_event esp_netif nvs_flash http_parser esp_timer
                    EMBED_TXTFILES "content/index.html")



# Propagate optional configuration flags for backwards compatibility
if(WIFI_CONFIG_DEBUG)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE WIFI_CONFIG_DEBUG)
endif()

if(WIFI_CONFIG_NO_RESTART)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE WIFI_CONFIG_NO_RESTART)
endif()

if(DEFINED WIFI_CONFIG_CONNECT_TIMEOUT)
    target_compile_definitions(
        ${COMPONENT_LIB} PRIVATE WIFI_CONFIG_CONNECT_TIMEOUT=${WIFI_CONFIG_CONNECT_TIMEOUT})
endif()

if(DEFINED WIFI_CONFIG_CONNECTED_MONITOR_INTERVAL)
    target_compile_definitions(
        ${COMPONENT_LIB} PRIVATE WIFI_CONFIG_CONNECTED_MONITOR_INTERVAL=${WIFI_CONFIG_CONNECTED_MONITOR_INTERVAL})
endif()

if(DEFINED WIFI_CONFIG_DISCONNECTED_MONITOR_INTERVAL)
    target_compile_definitions(
        ${COMPONENT_LIB} PRIVATE WIFI_CONFIG_DISCONNECTED_MONITOR_INTERVAL=${WIFI_CONFIG_DISCONNECTED_MONITOR_INTERVAL})
endif()
