#include "rc522.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"

// Registers
#define REG_COMMAND       0x01
#define REG_COM_IRQ       0x04
#define REG_DIV_IRQ       0x05
#define REG_ERROR         0x06
#define REG_STATUS2       0x08
#define REG_FIFO_DATA     0x09
#define REG_FIFO_LEVEL    0x0A
#define REG_CONTROL       0x0C
#define REG_BIT_FRAMING   0x0D
#define REG_COLL          0x0E
#define REG_MODE          0x11
#define REG_TX_MODE       0x12
#define REG_RX_MODE       0x13
#define REG_TX_CONTROL    0x14
#define REG_TX_ASK        0x15
#define REG_CRC_RESULT_H  0x21
#define REG_CRC_RESULT_L  0x22
#define REG_MOD_WIDTH     0x24
#define REG_T_MODE        0x2A
#define REG_T_PRESCALER   0x2B
#define REG_T_RELOAD_H    0x2C
#define REG_T_RELOAD_L    0x2D
#define REG_VERSION       0x37

// PCD commands
#define CMD_IDLE          0x00
#define CMD_CALC_CRC      0x03
#define CMD_TRANSCEIVE    0x0C
#define CMD_MF_AUTHENT    0x0E
#define CMD_SOFT_RESET    0x0F

// PICC commands
#define PICC_REQA         0x26
#define PICC_WUPA         0x52
#define PICC_SEL_CL1      0x93
#define PICC_SEL_CL2      0x95
#define PICC_SEL_CL3      0x97
#define PICC_HLTA         0x50
#define PICC_MF_READ      0x30
#define PICC_MF_WRITE     0xA0
#define MIFARE_ACK        0x0A
#define PICC_CASCADE_TAG  0x88

static spi_device_handle_t s_spi;

static void write_reg(uint8_t reg, uint8_t val)
{
    uint8_t tx[2] = { (reg << 1) & 0x7E, val };
    spi_transaction_t t = { .length = 16, .tx_buffer = tx };
    spi_device_polling_transmit(s_spi, &t);
}

static uint8_t read_reg(uint8_t reg)
{
    uint8_t tx[2] = { ((reg << 1) & 0x7E) | 0x80, 0 };
    uint8_t rx[2] = { 0 };
    spi_transaction_t t = { .length = 16, .tx_buffer = tx, .rx_buffer = rx };
    spi_device_polling_transmit(s_spi, &t);
    return rx[1];
}

static void set_bits(uint8_t reg, uint8_t mask)   { write_reg(reg, read_reg(reg) | mask); }
static void clear_bits(uint8_t reg, uint8_t mask) { write_reg(reg, read_reg(reg) & ~mask); }

static void write_fifo(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        write_reg(REG_FIFO_DATA, data[i]);
    }
}

static rc522_status_t calc_crc(const uint8_t *data, size_t len, uint8_t out[2])
{
    write_reg(REG_COMMAND, CMD_IDLE);
    write_reg(REG_DIV_IRQ, 0x04);       // clear CRCIRq
    write_reg(REG_FIFO_LEVEL, 0x80);    // flush FIFO
    write_fifo(data, len);
    write_reg(REG_COMMAND, CMD_CALC_CRC);

    int64_t deadline = esp_timer_get_time() + 90000;
    while (esp_timer_get_time() < deadline) {
        if (read_reg(REG_DIV_IRQ) & 0x04) {
            write_reg(REG_COMMAND, CMD_IDLE);
            out[0] = read_reg(REG_CRC_RESULT_L);
            out[1] = read_reg(REG_CRC_RESULT_H);
            return RC522_OK;
        }
    }
    return RC522_TIMEOUT;
}

// Reprogram the chip's response timer so TimerIRq fires after ~`ms`
// milliseconds of silence from the card. The timer counts down at
// f = 13.56 MHz / (2*prescaler + 1); the reload value is chosen so it fits in
// the 16-bit reload register, growing the 12-bit prescaler for long timeouts
// (needed for ISO-DEP frame-waiting times up to ~5 s and WTX extensions).
static void set_timer_ms(uint32_t ms)
{
    if (ms == 0) ms = 1;
    uint32_t prescaler = 0xA9;              // default from init: ~40 kHz, 25 us/tick
    uint64_t reload;
    for (;;) {
        uint32_t ftimer = 13560000UL / (2 * prescaler + 1);
        reload = ((uint64_t)ms * ftimer) / 1000;
        if (reload <= 0xFFFF || prescaler >= 0xFFF) break;
        prescaler = (prescaler << 1) | 1;  // roughly double, stay odd
        if (prescaler > 0xFFF) prescaler = 0xFFF;
    }
    if (reload > 0xFFFF) reload = 0xFFFF;
    if (reload == 0) reload = 1;
    // TPrescaler is 12-bit: low 8 bits in T_PRESCALER, high 4 in T_MODE's low
    // nibble; keep TAuto (0x80) so the timer starts at end of transmission.
    write_reg(REG_T_MODE, 0x80 | ((prescaler >> 8) & 0x0F));
    write_reg(REG_T_PRESCALER, prescaler & 0xFF);
    write_reg(REG_T_RELOAD_H, (reload >> 8) & 0xFF);
    write_reg(REG_T_RELOAD_L, reload & 0xFF);
}

static rc522_status_t communicate(uint8_t cmd, uint8_t wait_irq,
                                  const uint8_t *send, size_t send_len,
                                  uint8_t *back, uint8_t *back_len,
                                  uint8_t *valid_bits, uint8_t rx_align, bool check_crc,
                                  uint32_t timeout_ms)
{
    uint8_t tx_last_bits = valid_bits ? *valid_bits : 0;
    uint8_t bit_framing = (rx_align << 4) | tx_last_bits;

    set_timer_ms(timeout_ms);
    write_reg(REG_COMMAND, CMD_IDLE);
    write_reg(REG_COM_IRQ, 0x7F);       // clear all IRQ flags
    write_reg(REG_FIFO_LEVEL, 0x80);    // flush FIFO
    write_fifo(send, send_len);
    write_reg(REG_BIT_FRAMING, bit_framing);
    write_reg(REG_COMMAND, cmd);
    if (cmd == CMD_TRANSCEIVE) {
        set_bits(REG_BIT_FRAMING, 0x80);    // StartSend
    }

    // The chip timer sets TimerIRq if the card stays silent; the host deadline
    // is a slightly longer backstop so a stuck transfer cannot hang forever.
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000 + 15000;
    bool done = false;
    while (esp_timer_get_time() < deadline) {
        uint8_t irq = read_reg(REG_COM_IRQ);
        if (irq & wait_irq) { done = true; break; }
        if (irq & 0x01) return RC522_TIMEOUT;
    }
    if (!done) return RC522_TIMEOUT;

    uint8_t err = read_reg(REG_ERROR);
    if (err & 0x13) return RC522_ERR;   // BufferOvfl, ParityErr, ProtocolErr

    uint8_t rx_bits = 0;
    if (back && back_len) {
        uint8_t n = read_reg(REG_FIFO_LEVEL);
        if (n > *back_len) return RC522_NO_ROOM;
        *back_len = n;
        for (uint8_t i = 0; i < n; i++) {
            back[i] = read_reg(REG_FIFO_DATA);
        }
        rx_bits = read_reg(REG_CONTROL) & 0x07;
        if (valid_bits) *valid_bits = rx_bits;
    }

    if (err & 0x08) return RC522_COLLISION;

    if (back && back_len && check_crc) {
        // 4-bit response is a MIFARE ACK/NAK
        if (*back_len == 1 && rx_bits == 4) return RC522_NAK;
        if (*back_len < 2 || rx_bits != 0) return RC522_CRC_WRONG;
        uint8_t crc[2];
        rc522_status_t s = calc_crc(back, *back_len - 2, crc);
        if (s != RC522_OK) return s;
        if (back[*back_len - 2] != crc[0] || back[*back_len - 1] != crc[1]) {
            return RC522_CRC_WRONG;
        }
    }
    return RC522_OK;
}

static rc522_status_t transceive(const uint8_t *send, size_t send_len, uint8_t *back,
                                 uint8_t *back_len, uint8_t *valid_bits, bool check_crc)
{
    return communicate(CMD_TRANSCEIVE, 0x30, send, send_len, back, back_len,
                       valid_bits, 0, check_crc, 40);
}

rc522_status_t rc522_transceive_raw(const uint8_t *send, size_t send_len,
                                    uint8_t *back, size_t *back_len,
                                    bool append_crc, bool check_crc,
                                    uint32_t timeout_ms)
{
    // Build the frame in a 64-byte scratch buffer (the FIFO's full depth).
    uint8_t buf[64];
    size_t n = send_len;
    if (append_crc) {
        if (send_len + 2 > sizeof(buf)) return RC522_NO_ROOM;
        memcpy(buf, send, send_len);
        rc522_status_t s = calc_crc(send, send_len, &buf[send_len]);
        if (s != RC522_OK) return s;
        n = send_len + 2;
    } else {
        if (send_len > sizeof(buf)) return RC522_NO_ROOM;
        memcpy(buf, send, send_len);
    }

    uint8_t cap = (*back_len > 255) ? 255 : (uint8_t)*back_len;
    uint8_t blen = cap;
    uint8_t valid_bits = 0;
    rc522_status_t s = communicate(CMD_TRANSCEIVE, 0x30, buf, n, back, &blen,
                                   &valid_bits, 0, check_crc, timeout_ms);
    if (s != RC522_OK) { *back_len = 0; return s; }

    size_t out = blen;
    if (check_crc) {
        // communicate already verified the CRC_A; drop the two trailing bytes.
        if (out < 2) { *back_len = 0; return RC522_CRC_WRONG; }
        out -= 2;
    }
    *back_len = out;
    return RC522_OK;
}

esp_err_t rc522_init(const rc522_config_t *cfg)
{
    spi_bus_config_t bus = {
        .sclk_io_num = cfg->sck,
        .mosi_io_num = cfg->mosi,
        .miso_io_num = cfg->miso,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    esp_err_t err = spi_bus_initialize(cfg->host, &bus, SPI_DMA_DISABLED);
    if (err != ESP_OK) return err;

    spi_device_interface_config_t dev = {
        .clock_speed_hz = cfg->clock_hz,
        .mode = 0,
        .spics_io_num = cfg->cs,
        .queue_size = 1,
    };
    err = spi_bus_add_device(cfg->host, &dev, &s_spi);
    if (err != ESP_OK) return err;

    if (cfg->rst != GPIO_NUM_NC) {
        gpio_reset_pin(cfg->rst);
        gpio_set_direction(cfg->rst, GPIO_MODE_OUTPUT);
        gpio_set_level(cfg->rst, 0);
        vTaskDelay(pdMS_TO_TICKS(10));
        gpio_set_level(cfg->rst, 1);
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    write_reg(REG_COMMAND, CMD_SOFT_RESET);
    vTaskDelay(pdMS_TO_TICKS(50));
    for (int i = 0; i < 10 && (read_reg(REG_COMMAND) & 0x10); i++) {   // PowerDown bit
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    write_reg(REG_TX_MODE, 0x00);
    write_reg(REG_RX_MODE, 0x00);
    write_reg(REG_MOD_WIDTH, 0x26);
    // Timer: TAuto, f = 13.56 MHz / (2*0xA9+1) ~ 40 kHz, reload 1000 -> 25 ms
    write_reg(REG_T_MODE, 0x80);
    write_reg(REG_T_PRESCALER, 0xA9);
    write_reg(REG_T_RELOAD_H, 0x03);
    write_reg(REG_T_RELOAD_L, 0xE8);
    write_reg(REG_TX_ASK, 0x40);        // 100% ASK
    write_reg(REG_MODE, 0x3D);          // CRC preset 0x6363

    // Antenna on
    if ((read_reg(REG_TX_CONTROL) & 0x03) != 0x03) {
        set_bits(REG_TX_CONTROL, 0x03);
    }
    return ESP_OK;
}

uint8_t rc522_version(void)
{
    return read_reg(REG_VERSION);
}

rc522_status_t rc522_request(bool wakeup, uint8_t atqa[2])
{
    uint8_t cmd = wakeup ? PICC_WUPA : PICC_REQA;
    uint8_t len = 2;
    uint8_t valid_bits = 7;             // short frame
    clear_bits(REG_COLL, 0x80);
    rc522_status_t s = transceive(&cmd, 1, atqa, &len, &valid_bits, false);
    if (s != RC522_OK) return s;
    if (len != 2 || valid_bits != 0) return RC522_ERR;
    return RC522_OK;
}

rc522_status_t rc522_select(rc522_card_t *card)
{
    static const uint8_t sel_cmds[3] = { PICC_SEL_CL1, PICC_SEL_CL2, PICC_SEL_CL3 };
    card->uid_len = 0;
    clear_bits(REG_COLL, 0x80);

    for (int level = 0; level < 3; level++) {
        uint8_t buf[9];
        uint8_t resp[5];
        uint8_t len = sizeof(resp);
        uint8_t valid_bits = 0;

        // ANTICOLLISION: request full UID CLn (4 bytes + BCC)
        buf[0] = sel_cmds[level];
        buf[1] = 0x20;
        rc522_status_t s = transceive(buf, 2, resp, &len, &valid_bits, false);
        if (s != RC522_OK) return s;    // RC522_COLLISION = more than one card
        if (len != 5) return RC522_ERR;
        if ((resp[0] ^ resp[1] ^ resp[2] ^ resp[3]) != resp[4]) return RC522_ERR;

        // SELECT
        buf[1] = 0x70;
        memcpy(&buf[2], resp, 5);
        s = calc_crc(buf, 7, &buf[7]);
        if (s != RC522_OK) return s;
        uint8_t sak[3];
        len = sizeof(sak);
        valid_bits = 0;
        s = transceive(buf, 9, sak, &len, &valid_bits, true);
        if (s != RC522_OK) return s;
        if (len != 3) return RC522_ERR;

        if (sak[0] & 0x04) {
            // UID not complete: first byte is cascade tag
            if (resp[0] != PICC_CASCADE_TAG) return RC522_ERR;
            memcpy(&card->uid[card->uid_len], &resp[1], 3);
            card->uid_len += 3;
        } else {
            memcpy(&card->uid[card->uid_len], resp, 4);
            card->uid_len += 4;
            card->sak = sak[0];
            return RC522_OK;
        }
    }
    return RC522_ERR;
}

rc522_status_t rc522_halt(void)
{
    uint8_t buf[4] = { PICC_HLTA, 0x00 };
    rc522_status_t s = calc_crc(buf, 2, &buf[2]);
    if (s != RC522_OK) return s;
    // A halted card must NOT respond, so timeout means success.
    s = transceive(buf, 4, NULL, NULL, NULL, false);
    return (s == RC522_TIMEOUT) ? RC522_OK : RC522_ERR;
}

rc522_status_t rc522_mifare_auth(uint8_t key_type, uint8_t block, const uint8_t key[6],
                                 const rc522_card_t *card)
{
    uint8_t buf[12];
    buf[0] = key_type;
    buf[1] = block;
    memcpy(&buf[2], key, 6);
    // Use the last 4 bytes of the UID (CL1 for 4-byte, CL2 for 7-byte UIDs)
    memcpy(&buf[8], &card->uid[card->uid_len - 4], 4);

    rc522_status_t s = communicate(CMD_MF_AUTHENT, 0x10, buf, sizeof(buf),
                                   NULL, NULL, NULL, 0, false, 40);
    if (s != RC522_OK) return s;
    return (read_reg(REG_STATUS2) & 0x08) ? RC522_OK : RC522_ERR;   // MFCrypto1On
}

void rc522_mifare_stop_crypto(void)
{
    clear_bits(REG_STATUS2, 0x08);
}

rc522_status_t rc522_mifare_read(uint8_t addr, uint8_t out[16])
{
    uint8_t cmd[4] = { PICC_MF_READ, addr };
    rc522_status_t s = calc_crc(cmd, 2, &cmd[2]);
    if (s != RC522_OK) return s;

    uint8_t resp[18];
    uint8_t len = sizeof(resp);
    uint8_t valid_bits = 0;
    s = transceive(cmd, 4, resp, &len, &valid_bits, true);
    if (s != RC522_OK) return s;
    if (len != 18) return RC522_ERR;
    memcpy(out, resp, 16);
    return RC522_OK;
}

// Send a frame and expect a 4-bit MIFARE ACK (0x0A). Any other short
// response is a NAK; a timeout or longer frame is an error.
static rc522_status_t mifare_ack(const uint8_t *send, size_t len)
{
    uint8_t resp[1];
    uint8_t back_len = 1;
    uint8_t valid_bits = 0;
    rc522_status_t s = transceive(send, len, resp, &back_len, &valid_bits, false);
    if (s != RC522_OK) return s;
    if (back_len != 1 || valid_bits != 4) return RC522_ERR;
    return ((resp[0] & 0x0F) == MIFARE_ACK) ? RC522_OK : RC522_NAK;
}

rc522_status_t rc522_mifare_write(uint8_t addr, const uint8_t data[16])
{
    // Stage 1: announce the write and target block.
    uint8_t cmd[4] = { PICC_MF_WRITE, addr };
    rc522_status_t s = calc_crc(cmd, 2, &cmd[2]);
    if (s != RC522_OK) return s;
    s = mifare_ack(cmd, 4);
    if (s != RC522_OK) return s;

    // Stage 2: send the 16 data bytes.
    uint8_t buf[18];
    memcpy(buf, data, 16);
    s = calc_crc(buf, 16, &buf[16]);
    if (s != RC522_OK) return s;
    return mifare_ack(buf, 18);
}

const char *rc522_card_type(uint8_t sak)
{
    switch (sak & 0x7F) {
    case 0x00: return "MIFARE Ultralight / NTAG";
    case 0x01: return "MIFARE Classic 1K (TNP3XXX)";
    case 0x08: return "MIFARE Classic 1K";
    case 0x09: return "MIFARE Mini";
    case 0x18: return "MIFARE Classic 4K";
    case 0x10:
    case 0x11: return "MIFARE Plus";
    case 0x20: return "ISO 14443-4 (DESFire / smartcard)";
    case 0x28: return "ISO 14443-4 + MIFARE Classic 1K";
    case 0x38: return "ISO 14443-4 + MIFARE Classic 4K";
    default:   return "Unknown";
    }
}

const char *rc522_status_str(rc522_status_t s)
{
    switch (s) {
    case RC522_OK:        return "OK";
    case RC522_TIMEOUT:   return "timeout";
    case RC522_COLLISION: return "collision";
    case RC522_NO_ROOM:   return "buffer too small";
    case RC522_CRC_WRONG: return "CRC error";
    case RC522_NAK:       return "NAK";
    default:              return "error";
    }
}
