#include "iso_dep.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "rc522.h"

static const char *TAG = "isodep";

// --- PCB (Protocol Control Byte) encoding, ISO 14443-4 7.1 ---
#define PCB_I_BASE      0x02    // I-block: bits b8..b1 = 0 0 0 0 0 0 1 (b1=block no)
#define PCB_CHAINING    0x10    // I-block: more blocks follow
#define PCB_CID         0x08    // CID byte present
#define PCB_NAD         0x04    // NAD byte present (I-block only)
#define PCB_R_ACK       0xA2    // R(ACK) base (b1 = block no)
#define PCB_R_NAK       0xB2    // R(NAK) base (b1 = block no)
#define PCB_S_DESELECT  0xC2    // S(DESELECT)
#define PCB_S_WTX       0xF2    // S(WTX) request/response

// FSDI/FSCI code -> frame size in bytes (ISO 14443-4 Table 4).
static const uint16_t FS_TABLE[] = { 16, 24, 32, 40, 48, 64, 96, 128, 256 };

// We announce FSDI=5 in RATS, i.e. we can receive frames up to 64 bytes -- the
// RC522 FIFO depth. Anything larger must arrive via response chaining.
#define OUR_FSDI        5

static iso_dep_t s_dep;

static uint16_t fs_from_code(uint8_t code)
{
    if (code > 8) code = 8;
    return FS_TABLE[code];
}

static bool is_i_block(uint8_t pcb) { return (pcb & 0xC0) == 0x00; }
static bool is_r_block(uint8_t pcb) { return (pcb & 0xC0) == 0x80; }
static bool is_s_block(uint8_t pcb) { return (pcb & 0xC0) == 0xC0; }
static bool i_chaining(uint8_t pcb) { return (pcb & PCB_CHAINING) != 0; }
static bool r_is_nak(uint8_t pcb)   { return (pcb & 0x10) != 0; }
static bool s_is_wtx(uint8_t pcb)   { return (pcb & 0x30) == 0x30; }

const iso_dep_t *iso_dep_info(void) { return &s_dep; }

// Send one complete block and receive one reply block. S(WTX) requests from the
// card are answered transparently here (we echo the WTX multiplier and keep
// waiting with an extended timeout). Transport errors (timeout/CRC) trigger a
// bounded retransmission of the block we sent. On success, `rx`/`*rx_len` hold
// the reply block (PCB + payload; CRC already stripped).
static esp_err_t send_and_recv(const uint8_t *tx, size_t tx_len,
                               uint8_t *rx, size_t *rx_len)
{
    size_t cap = *rx_len;
    uint32_t timeout = s_dep.fwt_ms;
    int retries = 3;

    // `cur` is what we actually transmit; it becomes a WTX response mid-loop.
    const uint8_t *cur = tx;
    size_t cur_len = tx_len;
    uint8_t wtx_resp[2];

    for (;;) {
        size_t n = cap;
        rc522_status_t s = rc522_transceive_raw(cur, cur_len, rx, &n,
                                                true, true, timeout);
        if (s != RC522_OK) {
            // No/garbled answer: retransmit the last block (ISO 14443-4 allows
            // the PCD to retransmit; full R(NAK) deadlock recovery is omitted).
            if (retries-- <= 0) {
                ESP_LOGW(TAG, "block exchange failed: %s", rc522_status_str(s));
                return ESP_ERR_TIMEOUT;
            }
            cur = tx;               // always retransmit the original block
            cur_len = tx_len;
            timeout = s_dep.fwt_ms;
            continue;
        }
        if (n < 1) {
            if (retries-- <= 0) return ESP_FAIL;
            continue;
        }

        uint8_t pcb = rx[0];
        if (is_s_block(pcb) && s_is_wtx(pcb)) {
            // S(WTX) request: INF low 6 bits = waiting-time multiplier.
            uint8_t wtxm = (n >= 2) ? (rx[1] & 0x3F) : 1;
            if (wtxm < 1) wtxm = 1;
            if (wtxm > 59) wtxm = 59;
            timeout = s_dep.fwt_ms * wtxm;      // grant the extension
            wtx_resp[0] = PCB_S_WTX;            // S(WTX) response (no CID used)
            wtx_resp[1] = wtxm;
            cur = wtx_resp;
            cur_len = 2;
            ESP_LOGD(TAG, "S(WTX) granted x%u (timeout %u ms)", wtxm, timeout);
            continue;                            // wait again for the real reply
        }

        *rx_len = n;
        return ESP_OK;
    }
}

esp_err_t iso_dep_activate(void)
{
    memset(&s_dep, 0, sizeof(s_dep));

    // RATS = E0 | (FSDI<<4 | CID). FSDI=5 (64-byte FSD), CID=0.
    uint8_t rats[2] = { 0xE0, (OUR_FSDI << 4) | 0x00 };
    uint8_t ats[32];
    size_t atslen = sizeof(ats);
    rc522_status_t s = rc522_transceive_raw(rats, sizeof(rats), ats, &atslen,
                                            true, true, 50);
    if (s != RC522_OK) {
        ESP_LOGE(TAG, "RATS failed: %s", rc522_status_str(s));
        return ESP_FAIL;
    }
    if (atslen < 1) return ESP_FAIL;

    // ATS: TL (length, counts itself), T0, [TA][TB][TC], historical bytes.
    uint8_t tl = ats[0];
    if (tl > atslen) tl = (uint8_t)atslen;

    // ISO 14443-4 defaults when the optional bytes are absent.
    s_dep.fsci = 2;   // FSC = 32 bytes
    s_dep.fwi  = 4;   // default FWT
    s_dep.sfgi = 0;

    if (tl >= 2) {
        uint8_t t0 = ats[1];
        size_t idx = 2;
        s_dep.fsci = t0 & 0x0F;
        bool ta = t0 & 0x10, tb = t0 & 0x20, tc = t0 & 0x40;
        if (ta && idx < tl) idx++;                        // TA(1): bit rates (ignored)
        if (tb && idx < tl) {                             // TB(1): FWI | SFGI
            uint8_t v = ats[idx++];
            s_dep.fwi = v >> 4;
            s_dep.sfgi = v & 0x0F;
        }
        if (tc && idx < tl) {                             // TC(1): protocol options
            uint8_t v = ats[idx++];
            s_dep.nad_supported = v & 0x01;
            s_dep.cid_supported = v & 0x02;
        }
    }

    s_dep.fsc = fs_from_code(s_dep.fsci);

    // FWT = (256 * 16 / fc) * 2^FWI, fc = 13.56 MHz. 4096/13.56e6 ~= 302 us.
    uint64_t fwt_us = (uint64_t)302 << s_dep.fwi;
    s_dep.fwt_ms = (uint32_t)(fwt_us / 1000) + 2;   // round up + small margin
    if (s_dep.fwt_ms < 5) s_dep.fwt_ms = 5;

    s_dep.pcb_block_num = 0;     // PCD block number starts at 0
    memcpy(s_dep.ats, ats, tl);
    s_dep.ats_len = tl;
    s_dep.active = true;

    ESP_LOGI(TAG, "ATS: FSC=%u FWI=%u (FWT~%ums) SFGI=%u CID=%d NAD=%d hist=%d B",
             s_dep.fsc, s_dep.fwi, s_dep.fwt_ms, s_dep.sfgi,
             s_dep.cid_supported, s_dep.nad_supported,
             tl > 1 ? (int)tl - 2 : 0);

    // Start-up frame guard time: wait before the first APDU if requested.
    if (s_dep.sfgi > 0) {
        uint32_t sfg_ms = (uint32_t)(((uint64_t)302 << s_dep.sfgi) / 1000) + 1;
        vTaskDelay(pdMS_TO_TICKS(sfg_ms));
    }
    return ESP_OK;
}

esp_err_t iso_dep_transceive_apdu(const uint8_t *cmd, size_t cmd_len,
                                  uint8_t *resp, size_t *resp_len)
{
    if (!s_dep.active) return ESP_ERR_INVALID_STATE;

    size_t resp_cap = *resp_len;
    *resp_len = 0;

    // Max INF per frame = min(card FSC, FIFO 64) - PCB(1) - CRC(2).
    uint16_t fs = s_dep.fsc < 64 ? s_dep.fsc : 64;
    size_t max_inf = (fs > 3) ? (size_t)(fs - 3) : 1;

    uint8_t frame[64];
    uint8_t rxbuf[64];
    size_t sent = 0;

    // ---- Command chaining: send every block except the final one ----
    while (cmd_len - sent > max_inf) {
        frame[0] = PCB_I_BASE | s_dep.pcb_block_num | PCB_CHAINING;
        memcpy(&frame[1], &cmd[sent], max_inf);

        size_t rl = sizeof(rxbuf);
        if (send_and_recv(frame, 1 + max_inf, rxbuf, &rl) != ESP_OK) return ESP_FAIL;
        // A chained I-block must be acknowledged with R(ACK).
        if (!(is_r_block(rxbuf[0]) && !r_is_nak(rxbuf[0]))) {
            ESP_LOGW(TAG, "expected R(ACK) during TX chaining, got PCB %02X", rxbuf[0]);
            return ESP_FAIL;
        }
        s_dep.pcb_block_num ^= 1;
        sent += max_inf;
    }

    // ---- Final command block; its reply is the first response block ----
    size_t chunk = cmd_len - sent;
    frame[0] = PCB_I_BASE | s_dep.pcb_block_num;    // no chaining bit
    memcpy(&frame[1], &cmd[sent], chunk);

    size_t rl = sizeof(rxbuf);
    if (send_and_recv(frame, 1 + chunk, rxbuf, &rl) != ESP_OK) return ESP_FAIL;

    // ---- Response chaining: gather I-blocks until one without the chain bit ----
    for (;;) {
        uint8_t pcb = rxbuf[0];
        if (!is_i_block(pcb)) {
            ESP_LOGW(TAG, "expected I-block in response, got PCB %02X", pcb);
            return ESP_FAIL;
        }
        s_dep.pcb_block_num ^= 1;       // toggle on receiving the matching I-block

        // Payload starts after PCB and any CID/NAD prologue bytes.
        size_t hdr = 1;
        if (pcb & PCB_CID) hdr++;
        if (pcb & PCB_NAD) hdr++;
        size_t inf = (rl > hdr) ? rl - hdr : 0;

        if (*resp_len + inf > resp_cap) {
            ESP_LOGW(TAG, "response buffer too small");
            return ESP_ERR_NO_MEM;
        }
        memcpy(resp + *resp_len, &rxbuf[hdr], inf);
        *resp_len += inf;

        if (!i_chaining(pcb)) break;    // last block of the response

        // Card has more: acknowledge with R(ACK) carrying our new block number.
        frame[0] = PCB_R_ACK | s_dep.pcb_block_num;
        rl = sizeof(rxbuf);
        if (send_and_recv(frame, 1, rxbuf, &rl) != ESP_OK) return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t iso_dep_deselect(void)
{
    if (!s_dep.active) return ESP_OK;
    uint8_t d = PCB_S_DESELECT;
    uint8_t rx[8];
    size_t rl = sizeof(rx);
    rc522_transceive_raw(&d, 1, rx, &rl, true, true, s_dep.fwt_ms);
    s_dep.active = false;
    return ESP_OK;
}
