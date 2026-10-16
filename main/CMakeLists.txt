idf_component_register(SRCS "main.c" "rc522.c"
                    INCLUDE_DIRS "."
                    REQUIRES log esp_driver_spi esp_driver_gpio esp_timer)
