#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"

typedef struct {
    spi_host_device_t host;
    gpio_num_t sck;
    gpio_num_t mosi;
    gpio_num_t miso;
    gpio_num_t cs;
    gpio_num_t rst;   // GPIO_NUM_NC if not connected
    int clock_hz;
} rc522_config_t;

typedef struct {
    uint8_t uid[10];
    uint8_t uid_len;   // 4, 7 or 10
    uint8_t atqa[2];
    uint8_t sak;
} rc522_card_t;

typedef enum {
    RC522_OK = 0,
    RC522_ERR,
    RC522_TIMEOUT,
    RC522_COLLISION,
    RC522_NO_ROOM,
    RC522_CRC_WRONG,
    RC522_NAK,
} rc522_status_t;

esp_err_t rc522_init(const rc522_config_t *cfg);
uint8_t rc522_version(void);

// Detect a card in the field. wakeup=false sends REQA (ignores halted cards),
// wakeup=true sends WUPA (also wakes halted cards).
rc522_status_t rc522_request(bool wakeup, uint8_t atqa[2]);

// Run anticollision + select for all cascade levels. Fills card->uid/sak.
rc522_status_t rc522_select(rc522_card_t *card);

rc522_status_t rc522_halt(void);

// MIFARE Classic: authenticate with key A (0x60) or key B (0x61).
rc522_status_t rc522_mifare_auth(uint8_t key_type, uint8_t block, const uint8_t key[6],
                                 const rc522_card_t *card);
void rc522_mifare_stop_crypto(void);

// READ command (0x30): returns 16 bytes. Works for MIFARE Classic blocks
// (after auth) and Ultralight/NTAG pages (4 pages per read).
rc522_status_t rc522_mifare_read(uint8_t addr, uint8_t out[16]);

// WRITE command (0xA0): writes 16 bytes to a MIFARE Classic block. The sector
// must be authenticated first with a key that grants write access.
rc522_status_t rc522_mifare_write(uint8_t addr, const uint8_t data[16]);

const char *rc522_card_type(uint8_t sak);
const char *rc522_status_str(rc522_status_t s);
