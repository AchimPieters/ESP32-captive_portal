idf_component_register(SRCS "src/wifi_config.c" "src/form_urlencoded.c"
                    INCLUDE_DIRS "include" "src"
                    PRIV_INCLUDE_DIRS "${CMAKE_CURRENT_BINARY_DIR}"
                    REQUIRES esp_wifi esp_event esp_netif nvs_flash http_parser
)

# Allow projects to override the default HTML page
if(DEFINED WIFI_CONFIG_INDEX_HTML)
    set(html_file "${WIFI_CONFIG_INDEX_HTML}")
else()
    set(html_file "${CMAKE_CURRENT_SOURCE_DIR}/content/index.html")
endif()
set(generated_file ${CMAKE_CURRENT_BINARY_DIR}/index.html)
add_custom_command(OUTPUT ${generated_file}
    COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/tools/embed.py ${html_file} > ${generated_file}
    DEPENDS ${html_file}
    VERBATIM)

add_custom_target(generate_html DEPENDS ${generated_file})
add_dependencies(${COMPONENT_LIB} generate_html)

target_include_directories(${COMPONENT_LIB} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

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
