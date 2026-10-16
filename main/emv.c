#include "emv.h"

#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include "esp_log.h"
#include "iso_dep.h"
#include "tlv.h"

static const char *TAG = "emv";

// Privacy switch: cardholder name (tag 5F20) is only logged when this is 1.
// Even then the PAN (5A / track 2 in 57) is always masked.
#define EMV_SHOW_CARDHOLDER   0

#define MAX_APDU_RESP   512     // assembled R-APDU after response chaining

// The ESP-IDF main task stack is only a few KB, so these per-step response
// buffers live at file scope rather than on the stack (the EMV flow is
// single-threaded and sequential, so they never overlap in use). s_rec is kept
// separate from s_gpo because the AFL pointer handed to read_records() points
// into s_gpo while records are read.
static uint8_t s_ppse[MAX_APDU_RESP];   // SELECT PPSE response
static uint8_t s_fci[MAX_APDU_RESP];    // SELECT AID (FCI) response
static uint8_t s_gpo[MAX_APDU_RESP];    // GET PROCESSING OPTIONS response
static uint8_t s_rec[MAX_APDU_RESP];    // READ RECORD response

// ---------------------------------------------------------------------------
// Hex logging
// ---------------------------------------------------------------------------
static void log_hex(const char *label, const uint8_t *data, size_t len)
{
    char line[200];
    int p = 0;
    for (size_t i = 0; i < len && p < (int)sizeof(line) - 4; i++) {
        p += snprintf(line + p, sizeof(line) - p, "%02X", data[i]);
    }
    ESP_LOGI(TAG, "%s [%u] %s", label, (unsigned)len, line);
}

// ---------------------------------------------------------------------------
// APDU helper: wraps the ISO-DEP transport and resolves the two status words
// that ask the terminal to re-issue the command.
//   61 xx -> more data available: issue GET RESPONSE with Le = xx.
//   6C xx -> wrong Le: resend the same command with Le = xx.
// ---------------------------------------------------------------------------
static esp_err_t apdu_exchange(const uint8_t *cmd, size_t cmd_len,
                               uint8_t *resp, size_t *resp_len)
{
    log_hex("C-APDU", cmd, cmd_len);

    size_t cap = *resp_len;
    size_t rl = cap;
    esp_err_t e = iso_dep_transceive_apdu(cmd, cmd_len, resp, &rl);
    if (e != ESP_OK) {
        ESP_LOGW(TAG, "APDU transport error: %d", e);
        *resp_len = 0;
        return e;
    }
    if (rl < 2) { *resp_len = rl; return ESP_FAIL; }

    uint8_t sw1 = resp[rl - 2];
    uint8_t sw2 = resp[rl - 1];

    if (sw1 == 0x61) {
        log_hex("R-APDU", resp, rl);
        ESP_LOGI(TAG, "  (61%02X: %u more bytes -> GET RESPONSE)", sw2, sw2);
        uint8_t gr[5] = { 0x00, 0xC0, 0x00, 0x00, sw2 };
        rl = cap;
        e = apdu_exchange(gr, sizeof(gr), resp, &rl);   // recurse (may 61 again)
        *resp_len = rl;
        return e;
    }
    if (sw1 == 0x6C) {
        log_hex("R-APDU", resp, rl);
        ESP_LOGI(TAG, "  (6C%02X: wrong Le -> resend with Le=%02X)", sw2, sw2);
        uint8_t buf[64];
        if (cmd_len == 0 || cmd_len > sizeof(buf)) { *resp_len = rl; return ESP_FAIL; }
        memcpy(buf, cmd, cmd_len);
        buf[cmd_len - 1] = sw2;     // our commands always end in the Le byte
        rl = cap;
        e = apdu_exchange(buf, cmd_len, resp, &rl);
        *resp_len = rl;
        return e;
    }

    log_hex("R-APDU", resp, rl);
    *resp_len = rl;
    return ESP_OK;
}

// Convenience: true if the last two bytes are 90 00.
static bool sw_ok(const uint8_t *resp, size_t len)
{
    return len >= 2 && resp[len - 2] == 0x90 && resp[len - 1] == 0x00;
}

// ---------------------------------------------------------------------------
// TLV tag names and sensitive-value handling
// ---------------------------------------------------------------------------
static const struct { uint32_t tag; const char *name; } TAG_NAMES[] = {
    { 0x6F,   "FCI Template" },
    { 0x84,   "DF Name" },
    { 0xA5,   "FCI Proprietary Template" },
    { 0xBF0C, "FCI Issuer Discretionary Data" },
    { 0x61,   "Application Template" },
    { 0x4F,   "AID (ADF Name)" },
    { 0x50,   "Application Label" },
    { 0x87,   "Application Priority Indicator" },
    { 0x9F38, "PDOL" },
    { 0x5F2D, "Language Preference" },
    { 0x9F11, "Issuer Code Table Index" },
    { 0x9F12, "Application Preferred Name" },
    { 0x77,   "Response Message Template Format 2" },
    { 0x80,   "Response Message Template Format 1" },
    { 0x82,   "Application Interchange Profile (AIP)" },
    { 0x94,   "Application File Locator (AFL)" },
    { 0x57,   "Track 2 Equivalent Data" },
    { 0x5A,   "Application PAN" },
    { 0x5F20, "Cardholder Name" },
    { 0x5F24, "Application Expiry Date" },
    { 0x5F25, "Application Effective Date" },
    { 0x5F28, "Issuer Country Code" },
    { 0x5F30, "Service Code" },
    { 0x5F34, "PAN Sequence Number" },
    { 0x9F07, "Application Usage Control" },
    { 0x9F08, "Application Version Number" },
    { 0x9F42, "Application Currency Code" },
    { 0x8C,   "CDOL1" },
    { 0x8D,   "CDOL2" },
    { 0x8E,   "CVM List" },
    { 0x9F0D, "Issuer Action Code - Default" },
    { 0x9F0E, "Issuer Action Code - Denial" },
    { 0x9F0F, "Issuer Action Code - Online" },
    { 0x9F36, "Application Transaction Counter (ATC)" },
    { 0x9F4A, "SDA Tag List" },
    { 0x9F46, "ICC Public Key Certificate" },
    { 0x9F47, "ICC Public Key Exponent" },
    { 0x9F48, "ICC Public Key Remainder" },
    { 0x90,   "Issuer Public Key Certificate" },
    { 0x9F32, "Issuer Public Key Exponent" },
    { 0x92,   "Issuer Public Key Remainder" },
    { 0x8F,   "Certification Authority Public Key Index" },
};

static const char *tag_name(uint32_t tag)
{
    for (size_t i = 0; i < sizeof(TAG_NAMES) / sizeof(TAG_NAMES[0]); i++) {
        if (TAG_NAMES[i].tag == tag) return TAG_NAMES[i].name;
    }
    return "?";
}

// Decode packed BCD nibbles (one digit per nibble) into a digit string, up to
// `max` digits, stopping at an 0xF nibble (padding) or the 0xD track separator.
// Returns the number of digits written (not NUL-terminated by caller's buffer
// size here -- caller provides room).
static int bcd_to_digits(const uint8_t *v, size_t len, char *out, int max, bool stop_on_d)
{
    int n = 0;
    for (size_t i = 0; i < len && n < max; i++) {
        for (int shift = 4; shift >= 0; shift -= 4) {
            uint8_t nib = (v[i] >> shift) & 0x0F;
            if (nib == 0x0F) return n;                 // padding -> end of PAN
            if (stop_on_d && nib == 0x0D) return n;    // track-2 field separator
            if (nib > 9) return n;                     // non-digit -> stop
            if (n < max) out[n++] = '0' + nib;
        }
    }
    return n;
}

// Print "123456******7890" style masking for a digit string in place.
static void print_masked_pan(const char *prefix, const char *digits, int ndig)
{
    char masked[32];
    int p = 0;
    for (int i = 0; i < ndig && p < (int)sizeof(masked) - 1; i++) {
        bool keep = (i < 6) || (i >= ndig - 4);
        masked[p++] = keep ? digits[i] : '*';
    }
    masked[p] = '\0';
    ESP_LOGI(TAG, "%s%s", prefix, masked);
}

// Print one primitive value, applying masking/suppression for sensitive tags.
static void print_value(uint32_t tag, const uint8_t *v, size_t len, int depth)
{
    char indent[24];
    int ind = depth * 2;
    if (ind > (int)sizeof(indent) - 1) ind = sizeof(indent) - 1;
    memset(indent, ' ', ind);
    indent[ind] = '\0';

    if (tag == 0x5A) {                          // PAN: mask middle digits
        char digits[24];
        int nd = bcd_to_digits(v, len, digits, (int)sizeof(digits), false);
        char pfx[48];
        snprintf(pfx, sizeof(pfx), "%s  = ", indent);
        print_masked_pan(pfx, digits, nd);
        return;
    }
    if (tag == 0x57) {                          // Track 2: mask the PAN portion
        char digits[24];
        int nd = bcd_to_digits(v, len, digits, (int)sizeof(digits), true);
        char pfx[48];
        snprintf(pfx, sizeof(pfx), "%s  = PAN ", indent);
        print_masked_pan(pfx, digits, nd);
        ESP_LOGI(TAG, "%s    (expiry/service code bytes present, not shown raw)", indent);
        return;
    }
    if (tag == 0x5F20 && !EMV_SHOW_CARDHOLDER) {
        ESP_LOGI(TAG, "%s  = <cardholder name suppressed>", indent);
        return;
    }

    // Generic hex + printable-ASCII rendering.
    char line[160];
    int p = snprintf(line, sizeof(line), "%s  = ", indent);
    for (size_t i = 0; i < len && p < (int)sizeof(line) - 4; i++) {
        p += snprintf(line + p, sizeof(line) - p, "%02X", v[i]);
    }
    p += snprintf(line + p, sizeof(line) - p, "  \"");
    for (size_t i = 0; i < len && p < (int)sizeof(line) - 2; i++) {
        line[p++] = isprint(v[i]) ? v[i] : '.';
    }
    if (p < (int)sizeof(line) - 1) line[p++] = '"';
    line[p] = '\0';
    ESP_LOGI(TAG, "%s", line);
}

// Recursively print a TLV tree with indentation and tag names.
static void tlv_print(const uint8_t *buf, size_t len, int depth)
{
    const uint8_t *p = buf;
    const uint8_t *end = buf + len;
    tlv_t t;
    char indent[24];
    int ind = depth * 2;
    if (ind > (int)sizeof(indent) - 1) ind = sizeof(indent) - 1;
    memset(indent, ' ', ind);
    indent[ind] = '\0';

    while ((p = tlv_next(p, end, &t)) != NULL) {
        ESP_LOGI(TAG, "%s%0*X  %-38s (%u)", indent,
                 t.tag > 0xFF ? 4 : 2, (unsigned)t.tag,
                 tag_name(t.tag), (unsigned)t.len);
        if (t.constructed) {
            tlv_print(t.val, t.len, depth + 1);
        } else {
            print_value(t.tag, t.val, t.len, depth);
        }
    }
}

// ---------------------------------------------------------------------------
// PDOL handling for GET PROCESSING OPTIONS
// ---------------------------------------------------------------------------
// Defaults for a few well-known PDOL tags so cards that gate GPO on them still
// answer during a read. Everything else is zero-filled. These are terminal-side
// values only -- nothing here authorises or values a transaction.
static size_t pdol_fill(uint32_t tag, size_t len, uint8_t *out)
{
    const uint8_t *val = NULL;
    static const uint8_t ttq[]  = { 0x36, 0x00, 0x00, 0x00 }; // 9F66: contactless, online-capable
    static const uint8_t ttype[] = { 0x22 };                  // 9F35: terminal type
    if (tag == 0x9F66 && len >= 4) val = ttq;
    else if (tag == 0x9F35 && len >= 1) val = ttype;

    for (size_t i = 0; i < len; i++) out[i] = (val && i < (val == ttq ? 4 : 1)) ? val[i] : 0x00;
    return len;
}

// Build the command data for GPO from the PDOL (tag 9F38) found in the AID's
// FCI. Returns the length written into `data` (the "83 <len> <values>" object).
static size_t build_gpo_data(const uint8_t *fci, size_t fci_len, uint8_t *data, size_t cap)
{
    tlv_t pdol;
    size_t vlen = 0;
    uint8_t values[64];

    if (tlv_find(fci, fci_len, 0x9F38, &pdol) && pdol.len > 0) {
        // PDOL is a concatenation of tag+length entries; fill each requested
        // value by length.
        const uint8_t *p = pdol.val;
        const uint8_t *end = pdol.val + pdol.len;
        while (p < end && vlen < sizeof(values)) {
            uint32_t tag = *p;
            if ((*p & 0x1F) == 0x1F) { p++; while (p < end && (*p & 0x80)) { tag = (tag << 8) | *p; p++; } if (p < end) { tag = (tag << 8) | *p; p++; } }
            else p++;
            if (p >= end) break;
            size_t len = *p++;
            if (vlen + len > sizeof(values)) break;
            vlen += pdol_fill(tag, len, &values[vlen]);
        }
    }

    // Wrap in Command Template tag 83.
    if (vlen + 2 > cap) return 0;
    size_t n = 0;
    data[n++] = 0x83;
    data[n++] = (uint8_t)vlen;
    memcpy(&data[n], values, vlen);
    n += vlen;
    return n;
}

// ---------------------------------------------------------------------------
// Flow steps
// ---------------------------------------------------------------------------
static esp_err_t select_by_name(const uint8_t *name, size_t name_len,
                                uint8_t *resp, size_t *resp_len)
{
    uint8_t cmd[5 + 16 + 1];
    if (name_len > 16) return ESP_FAIL;
    size_t n = 0;
    cmd[n++] = 0x00;            // CLA
    cmd[n++] = 0xA4;            // INS = SELECT
    cmd[n++] = 0x04;            // P1 = select by name
    cmd[n++] = 0x00;            // P2 = first/only occurrence
    cmd[n++] = (uint8_t)name_len;
    memcpy(&cmd[n], name, name_len);
    n += name_len;
    cmd[n++] = 0x00;           // Le
    return apdu_exchange(cmd, n, resp, resp_len);
}

static void read_records(const uint8_t *afl, size_t afl_len)
{
    // AFL is a list of 4-byte entries: SFI(<<3) | first record | last record |
    // number of records involved in offline data authentication.
    for (size_t i = 0; i + 4 <= afl_len; i += 4) {
        uint8_t sfi = afl[i] >> 3;
        uint8_t first = afl[i + 1];
        uint8_t last = afl[i + 2];
        ESP_LOGI(TAG, "-- AFL entry: SFI %u, records %u..%u --", sfi, first, last);

        for (uint8_t rec = first; rec <= last && rec != 0; rec++) {
            uint8_t cmd[5] = { 0x00, 0xB2, rec, (uint8_t)((sfi << 3) | 0x04), 0x00 };
            size_t rl = sizeof(s_rec);
            if (apdu_exchange(cmd, sizeof(cmd), s_rec, &rl) != ESP_OK) continue;
            if (!sw_ok(s_rec, rl)) {
                ESP_LOGW(TAG, "READ RECORD SFI %u rec %u -> SW %02X%02X",
                         sfi, rec, s_rec[rl - 2], s_rec[rl - 1]);
                continue;
            }
            ESP_LOGI(TAG, "Record SFI %u #%u:", sfi, rec);
            tlv_print(s_rec, rl - 2, 1);    // strip SW1 SW2
        }
    }
}

static void process_aid(const uint8_t *aid, size_t aid_len)
{
    char aidhex[48];
    int p = 0;
    for (size_t i = 0; i < aid_len && p < (int)sizeof(aidhex) - 3; i++)
        p += snprintf(aidhex + p, sizeof(aidhex) - p, "%02X", aid[i]);
    ESP_LOGI(TAG, "==== SELECT AID %s ====", aidhex);

    size_t fci_len = sizeof(s_fci);
    if (select_by_name(aid, aid_len, s_fci, &fci_len) != ESP_OK) return;
    if (!sw_ok(s_fci, fci_len)) {
        ESP_LOGW(TAG, "SELECT AID -> SW %02X%02X", s_fci[fci_len - 2], s_fci[fci_len - 1]);
        return;
    }
    ESP_LOGI(TAG, "FCI:");
    tlv_print(s_fci, fci_len - 2, 1);

    // GET PROCESSING OPTIONS
    uint8_t gpo_data[70];
    size_t gpo_data_len = build_gpo_data(s_fci, fci_len - 2, gpo_data, sizeof(gpo_data));
    uint8_t cmd[5 + sizeof(gpo_data) + 1];
    size_t n = 0;
    cmd[n++] = 0x80;           // CLA (proprietary)
    cmd[n++] = 0xA8;           // INS = GET PROCESSING OPTIONS
    cmd[n++] = 0x00;
    cmd[n++] = 0x00;
    cmd[n++] = (uint8_t)gpo_data_len;
    memcpy(&cmd[n], gpo_data, gpo_data_len);
    n += gpo_data_len;
    cmd[n++] = 0x00;           // Le

    size_t gpo_len = sizeof(s_gpo);
    ESP_LOGI(TAG, "---- GET PROCESSING OPTIONS ----");
    if (apdu_exchange(cmd, n, s_gpo, &gpo_len) != ESP_OK) return;
    if (!sw_ok(s_gpo, gpo_len)) {
        ESP_LOGW(TAG, "GPO -> SW %02X%02X", s_gpo[gpo_len - 2], s_gpo[gpo_len - 1]);
        return;
    }
    ESP_LOGI(TAG, "GPO response:");
    tlv_print(s_gpo, gpo_len - 2, 1);

    // Extract AIP + AFL. Format 1 (tag 80): AIP(2) || AFL. Format 2 (tag 77):
    // template with 82 (AIP) and 94 (AFL).
    tlv_t aip = {0}, afl = {0};
    tlv_t fmt1;
    const uint8_t *afl_ptr = NULL;
    size_t afl_len = 0;
    if (tlv_find(s_gpo, gpo_len - 2, 0x80, &fmt1)) {
        if (fmt1.len >= 2) {
            ESP_LOGI(TAG, "AIP = %02X%02X", fmt1.val[0], fmt1.val[1]);
            afl_ptr = fmt1.val + 2;
            afl_len = fmt1.len - 2;
        }
    } else {
        if (tlv_find(s_gpo, gpo_len - 2, 0x82, &aip) && aip.len >= 2)
            ESP_LOGI(TAG, "AIP = %02X%02X", aip.val[0], aip.val[1]);
        if (tlv_find(s_gpo, gpo_len - 2, 0x94, &afl)) {
            afl_ptr = afl.val;
            afl_len = afl.len;
        }
    }

    if (afl_ptr && afl_len) {
        ESP_LOGI(TAG, "---- READ RECORD (AFL) ----");
        read_records(afl_ptr, afl_len);
    } else {
        ESP_LOGW(TAG, "No AFL present; nothing to read");
    }
}

void emv_dump(void)
{
    ESP_LOGI(TAG, "==== ISO-DEP / EMV read (read-only) ====");
    if (iso_dep_activate() != ESP_OK) {
        ESP_LOGE(TAG, "ISO-DEP activation (RATS) failed");
        return;
    }

    // SELECT PPSE: "2PAY.SYS.DDF01"
    static const uint8_t PPSE[] = {
        '2','P','A','Y','.','S','Y','S','.','D','D','F','0','1'
    };
    size_t rl = sizeof(s_ppse);
    ESP_LOGI(TAG, "---- SELECT PPSE (2PAY.SYS.DDF01) ----");
    if (select_by_name(PPSE, sizeof(PPSE), s_ppse, &rl) != ESP_OK || !sw_ok(s_ppse, rl)) {
        ESP_LOGW(TAG, "PPSE select failed (SW %02X%02X) -- card may not be EMV contactless",
                 rl >= 2 ? s_ppse[rl - 2] : 0, rl >= 2 ? s_ppse[rl - 1] : 0);
        iso_dep_deselect();
        return;
    }
    ESP_LOGI(TAG, "PPSE FCI:");
    tlv_print(s_ppse, rl - 2, 1);

    // Collect AIDs from directory entries (tag 61 -> 4F AID, 50 label). Copy
    // them out first, because selecting an AID overwrites the shared buffers.
    uint8_t aids[8][16];
    uint8_t aid_lens[8];
    int naids = 0;

    const uint8_t *p = s_ppse;
    const uint8_t *end = s_ppse + (rl - 2);
    tlv_t dir;
    // The directory entries live under BF0C; search for each 61 template.
    tlv_t bf0c;
    if (tlv_find(s_ppse, rl - 2, 0xBF0C, &bf0c)) {
        p = bf0c.val;
        end = bf0c.val + bf0c.len;
    }
    while ((p = tlv_next(p, end, &dir)) != NULL && naids < 8) {
        if (dir.tag != 0x61) continue;
        tlv_t aid, label;
        if (tlv_find(dir.val, dir.len, 0x4F, &aid) && aid.len <= 16) {
            memcpy(aids[naids], aid.val, aid.len);
            aid_lens[naids] = (uint8_t)aid.len;
            if (tlv_find(dir.val, dir.len, 0x50, &label)) {
                char lbl[24];
                size_t ll = label.len < sizeof(lbl) - 1 ? label.len : sizeof(lbl) - 1;
                memcpy(lbl, label.val, ll);
                lbl[ll] = '\0';
                ESP_LOGI(TAG, "Found AID #%d: label \"%s\"", naids, lbl);
            } else {
                ESP_LOGI(TAG, "Found AID #%d (no label)", naids);
            }
            naids++;
        }
    }

    if (naids == 0) {
        ESP_LOGW(TAG, "No AIDs found in PPSE directory");
    }

    for (int i = 0; i < naids; i++) {
        process_aid(aids[i], aid_lens[i]);
    }

    iso_dep_deselect();
    ESP_LOGI(TAG, "==== EMV read complete ====");
}
