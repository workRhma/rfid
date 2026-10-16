#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "rc522.h"

static const char *TAG = "rfid";

// Operating mode:
//   0 = read cards and dump their contents to the log (default)
//   1 = write the stored image below onto the presented (blank) card
#define MODE_CLONE   0

// ---- RC522 wiring (SPI) ----
#define RC522_SCK     GPIO_NUM_4
#define RC522_MISO    GPIO_NUM_5
#define RC522_MOSI    GPIO_NUM_6
#define RC522_SDA     GPIO_NUM_7    // chip select
#define RC522_RST     GPIO_NUM_3

// Keys tried per sector, as (key type, key) pairs. Key type 0x60 = key A,
// 0x61 = key B. Add your own keys here if a sector uses non-default keys.
typedef struct { uint8_t type; uint8_t key[6]; } mf_key_t;

static const mf_key_t KEY_DICT[] = {
    { 0x60, { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } },  // key A, factory default
    { 0x61, { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } },  // key B, factory default
    { 0x60, { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 } },  // common MAD key A
    { 0x60, { 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7 } },  // NDEF public key A
};
#define KEY_DICT_LEN (sizeof(KEY_DICT) / sizeof(KEY_DICT[0]))

static void print_row(const char *label, const uint8_t *data, int len)
{
    char line[128];
    int p = snprintf(line, sizeof(line), "%s ", label);
    for (int i = 0; i < len; i++) p += snprintf(line + p, sizeof(line) - p, "%02X ", data[i]);
    p += snprintf(line + p, sizeof(line) - p, " |");
    for (int i = 0; i < len; i++) line[p++] = isprint(data[i]) ? data[i] : '.';
    snprintf(line + p, sizeof(line) - p, "|");
    ESP_LOGI(TAG, "%s", line);
}

// Re-activate a card after a failed MIFARE auth (card drops to IDLE state).
static bool reselect(rc522_card_t *card)
{
    rc522_mifare_stop_crypto();
    uint8_t atqa[2];
    rc522_card_t tmp;
    if (rc522_request(true, atqa) != RC522_OK) return false;
    if (rc522_select(&tmp) != RC522_OK) return false;
    return tmp.uid_len == card->uid_len && memcmp(tmp.uid, card->uid, card->uid_len) == 0;
}

// Try each key in the dictionary against a sector. On success, leave crypto
// active and report the key used; on failure, re-select the card so the next
// sector can be tried (a failed auth drops the card to IDLE).
static const mf_key_t *auth_sector(rc522_card_t *card, int trailer)
{
    for (size_t i = 0; i < KEY_DICT_LEN; i++) {
        if (rc522_mifare_auth(KEY_DICT[i].type, trailer, KEY_DICT[i].key, card) == RC522_OK) {
            return &KEY_DICT[i];
        }
        if (!reselect(card)) return NULL;   // card lost mid-dump
    }
    return (const mf_key_t *)-1;            // all keys failed, card still present
}

static void dump_classic(rc522_card_t *card, int sectors)
{
    ESP_LOGI(TAG, "Sector Block  Data                                              ASCII");
    for (int sector = 0; sector < sectors; sector++) {
        int first, count;
        if (sector < 32) { first = sector * 4; count = 4; }
        else             { first = 128 + (sector - 32) * 16; count = 16; }
        int trailer = first + count - 1;

        const mf_key_t *k = auth_sector(card, trailer);
        if (k == NULL) {
            ESP_LOGW(TAG, "  card lost");
            return;
        }
        if (k == (const mf_key_t *)-1) {
            ESP_LOGW(TAG, "  %2d   auth failed (no key in dictionary)", sector);
            continue;
        }
        ESP_LOGI(TAG, "  %2d   (key %c %02X%02X%02X%02X%02X%02X)", sector,
                 k->type == 0x60 ? 'A' : 'B',
                 k->key[0], k->key[1], k->key[2], k->key[3], k->key[4], k->key[5]);
        for (int b = first; b <= trailer; b++) {
            uint8_t data[16];
            char label[32];
            snprintf(label, sizeof(label), "  %2d   %3d  ", sector, b);
            rc522_status_t s = rc522_mifare_read(b, data);
            if (s == RC522_OK) print_row(label, data, 16);
            else ESP_LOGW(TAG, "%s read failed: %s", label, rc522_status_str(s));
        }
    }
    rc522_mifare_stop_crypto();
}

static void dump_ultralight(void)
{
    ESP_LOGI(TAG, "Page  Data         ASCII");
    // READ returns 4 pages at a time; read the first 16 pages (64 bytes)
    for (int page = 0; page < 16; page += 4) {
        uint8_t data[16];
        rc522_status_t s = rc522_mifare_read(page, data);
        if (s != RC522_OK) {
            ESP_LOGW(TAG, "  %2d  read failed: %s", page, rc522_status_str(s));
            return;
        }
        for (int i = 0; i < 4; i++) {
            char label[24];
            snprintf(label, sizeof(label), "  %2d ", page + i);
            print_row(label, &data[i * 4], 4);
        }
    }
}

#if MODE_CLONE
// ---- Card image to clone (from the test card dump) ----
// Only data blocks are written. Block 0 (manufacturer/UID) and the sector
// trailers are intentionally left out: block 0 is read-only on normal cards,
// and the trailers' key A reads back as zeros (key A is never exposed), so
// copying them verbatim would lock the target. The target keeps its factory
// trailers, staying readable/writable with key FFFFFFFFFFFF.
static const struct { uint8_t block; uint8_t data[16]; } CLONE_BLOCKS[] = {
    { 40, { 0xC6,0x37,0x0E,0x19,0x33,0xCF,0x78,0xEF,0x0D,0x16,0x04,0x5C,0x26,0x02,0x20,0x2B } },
    { 41, { 0x0D,0x36,0x09,0x23,0x3C,0x3C,0x35,0xE5,0x0B,0x5B,0x39,0x5E,0x08,0x07,0xC7,0x47 } },
    { 42, { 0x92,0x5A,0x33,0x3B,0x0B,0x2B,0x63,0x41,0x3B,0x3F,0x0E,0x18,0x33,0x5B,0xAA,0x49 } },
    { 50, { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x02,0x05 } },
    { 54, { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x02,0x05 } },
    // All other data blocks on the source are zero and are left as-is on the
    // target. Add entries here if you want to force them to zero too.
};
#define CLONE_BLOCKS_LEN (sizeof(CLONE_BLOCKS) / sizeof(CLONE_BLOCKS[0]))

static int block_sector(int block) { return block / 4; }   // sectors 0-15 only

static void clone_card(rc522_card_t *card)
{
    ESP_LOGW(TAG, "CLONE MODE: writing %d block(s) to this card", (int)CLONE_BLOCKS_LEN);
    int ok = 0, fail = 0;
    for (size_t i = 0; i < CLONE_BLOCKS_LEN; i++) {
        uint8_t block = CLONE_BLOCKS[i].block;
        int trailer = block_sector(block) * 4 + 3;

        const mf_key_t *k = auth_sector(card, trailer);
        if (k == NULL) { ESP_LOGE(TAG, "card lost"); return; }
        if (k == (const mf_key_t *)-1) {
            ESP_LOGW(TAG, "  block %3d: no key authenticates its sector, skipped", block);
            fail++;
            continue;
        }
        rc522_status_t s = rc522_mifare_write(block, CLONE_BLOCKS[i].data);
        if (s != RC522_OK) {
            ESP_LOGW(TAG, "  block %3d: write failed: %s", block, rc522_status_str(s));
            fail++;
            if (!reselect(card)) { ESP_LOGE(TAG, "card lost"); return; }
            continue;
        }
        // Verify by reading the block back.
        uint8_t rb[16];
        s = rc522_mifare_read(block, rb);
        if (s == RC522_OK && memcmp(rb, CLONE_BLOCKS[i].data, 16) == 0) {
            ESP_LOGI(TAG, "  block %3d: OK", block);
            ok++;
        } else {
            ESP_LOGW(TAG, "  block %3d: verify mismatch", block);
            fail++;
        }
    }
    rc522_mifare_stop_crypto();
    ESP_LOGW(TAG, "CLONE done: %d written, %d failed. Remove card.", ok, fail);
}
#endif // MODE_CLONE

static void handle_card(const uint8_t atqa[2])
{
    rc522_card_t card = { 0 };
    rc522_status_t s = rc522_select(&card);
    if (s != RC522_OK) {
        ESP_LOGW(TAG, "Select failed: %s%s", rc522_status_str(s),
                 s == RC522_COLLISION ? " (more than one card?)" : "");
        return;
    }
    card.atqa[0] = atqa[0];
    card.atqa[1] = atqa[1];

    ESP_LOGI(TAG, "==== Card detected ====");
    char uid[32];
    int p = 0;
    for (int i = 0; i < card.uid_len; i++) {
        p += snprintf(uid + p, sizeof(uid) - p, "%02X%s", card.uid[i], i + 1 < card.uid_len ? ":" : "");
    }
    ESP_LOGI(TAG, "UID : %s  (%d bytes)", uid, card.uid_len);
    ESP_LOGI(TAG, "ATQA: %02X %02X", card.atqa[1], card.atqa[0]);
    ESP_LOGI(TAG, "SAK : %02X", card.sak);
    ESP_LOGI(TAG, "Type: %s", rc522_card_type(card.sak));

#if MODE_CLONE
    if ((card.sak & 0x7F) == 0x08 || (card.sak & 0x7F) == 0x18 ||
        (card.sak & 0x7F) == 0x09) {
        clone_card(&card);
    } else {
        ESP_LOGW(TAG, "Clone target must be a MIFARE Classic card");
    }
    rc522_halt();
    ESP_LOGI(TAG, "=======================");
    return;
#endif

    switch (card.sak & 0x7F) {
    case 0x09:              dump_classic(&card, 5);  break;
    case 0x01: case 0x08:
    case 0x28:              dump_classic(&card, 16); break;
    case 0x18: case 0x38:   dump_classic(&card, 40); break;
    case 0x00:              dump_ultralight();       break;
    default:
        ESP_LOGI(TAG, "(no memory dump for this card type)");
        break;
    }

    rc522_halt();
    ESP_LOGI(TAG, "=======================");
}

void app_main(void)
{
    ESP_LOGI(TAG, "RC522 RFID reader");

    rc522_config_t cfg = {
        .host = SPI2_HOST,
        .sck = RC522_SCK,
        .mosi = RC522_MOSI,
        .miso = RC522_MISO,
        .cs = RC522_SDA,
        .rst = RC522_RST,
        .clock_hz = 4 * 1000 * 1000,
    };
    ESP_ERROR_CHECK(rc522_init(&cfg));

    uint8_t ver = rc522_version();
    if (ver == 0x00 || ver == 0xFF) {
        ESP_LOGE(TAG, "RC522 not found (version 0x%02X) - check wiring!", ver);
    } else {
        ESP_LOGI(TAG, "RC522 version: 0x%02X %s", ver,
                 ver == 0x91 ? "(v1.0)" : ver == 0x92 ? "(v2.0)" :
                 ver == 0x88 || ver == 0x12 ? "(clone)" : "(unknown)");
    }
    ESP_LOGI(TAG, "Waiting for card...");

    while (1) {
        uint8_t atqa[2];
        // REQA only wakes cards that are not halted, so a card already read
        // stays quiet until it leaves the field and comes back.
        if (rc522_request(false, atqa) == RC522_OK) {
            handle_card(atqa);
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
