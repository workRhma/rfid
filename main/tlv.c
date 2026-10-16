#include "tlv.h"

const uint8_t *tlv_next(const uint8_t *p, const uint8_t *end, tlv_t *out)
{
    // Skip inter-object 0x00 padding (EMV records may be zero-padded).
    while (p < end && *p == 0x00) p++;
    if (p >= end) return NULL;

    // --- Tag ---
    uint32_t tag = *p;
    bool constructed = (*p & 0x20) != 0;
    if ((*p & 0x1F) == 0x1F) {          // multi-byte tag
        p++;
        while (p < end) {
            tag = (tag << 8) | *p;
            bool more = (*p & 0x80) != 0;
            p++;
            if (!more) break;
        }
    } else {
        p++;
    }
    if (p >= end) return NULL;

    // --- Length ---
    uint32_t len = *p++;
    if (len & 0x80) {                   // long form: low bits = number of length bytes
        int nbytes = len & 0x7F;
        len = 0;
        for (int i = 0; i < nbytes && p < end; i++) {
            len = (len << 8) | *p++;
        }
    }
    if ((size_t)(end - p) < len) {      // clamp a malformed length to the buffer
        len = (uint32_t)(end - p);
    }

    out->tag = tag;
    out->constructed = constructed;
    out->val = p;
    out->len = len;
    return p + len;
}

bool tlv_find(const uint8_t *buf, size_t len, uint32_t tag, tlv_t *out)
{
    const uint8_t *p = buf;
    const uint8_t *end = buf + len;
    tlv_t t;
    while ((p = tlv_next(p, end, &t)) != NULL) {
        if (t.tag == tag) {
            *out = t;
            return true;
        }
        if (t.constructed && tlv_find(t.val, t.len, tag, out)) {
            return true;
        }
    }
    return false;
}
