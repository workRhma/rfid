#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

// ISO 14443-4 (ISO-DEP / T=CL) transport on top of the RC522. Activate it once
// after a successful rc522_select() on an ISO-DEP-capable card (SAK bit 0x20
// set), then exchange APDUs. A single module-static context is kept, so only
// one card is handled at a time.

// Parsed ATS parameters, exposed for logging / diagnostics.
typedef struct {
    uint8_t  fsci;          // frame size code of the PICC (from T0)
    uint16_t fsc;           // PICC max frame size in bytes (from fsci)
    uint8_t  fwi;           // frame waiting integer (from TB)
    uint32_t fwt_ms;        // frame waiting time in ms (derived from fwi)
    uint8_t  sfgi;          // start-up frame guard integer (from TB)
    bool     cid_supported;
    bool     nad_supported;
    uint8_t  pcb_block_num; // current block number (toggles 0/1 per I-block)
    uint8_t  ats[32];       // raw ATS as received
    uint8_t  ats_len;
    bool     active;
} iso_dep_t;

// Send RATS, parse the ATS, honour the start-up frame guard time. Returns
// ESP_OK when the card entered the ISO-DEP protocol.
esp_err_t iso_dep_activate(void);

// Read-only view of the negotiated parameters (valid after activate()).
const iso_dep_t *iso_dep_info(void);

// Exchange one APDU. `cmd`/`cmd_len` is the full C-APDU; the R-APDU (data +
// SW1 SW2) is written to `resp`, with capacity passed in *resp_len and the
// actual length returned there. Handles PCB block-number toggling, command and
// response chaining, S(WTX) extensions, and R(ACK)/R(NAK) with retransmission.
esp_err_t iso_dep_transceive_apdu(const uint8_t *cmd, size_t cmd_len,
                                  uint8_t *resp, size_t *resp_len);

// Send S(DESELECT) to leave the protocol cleanly.
esp_err_t iso_dep_deselect(void);
