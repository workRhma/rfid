idf_component_register(SRCS "main.c" "rc522.c" "iso_dep.c" "tlv.c" "emv.c"
                    INCLUDE_DIRS "."
                    REQUIRES log esp_driver_spi esp_driver_gpio esp_timer freertos)
