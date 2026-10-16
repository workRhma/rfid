#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Minimal hand-written BER-TLV parser (ISO 8825-1 / EMV Book 3). Supports
// multi-byte tags (0x1F continuation) and multi-byte lengths (0x81/0x82 forms).
// Values are referenced in place; nothing is copied or allocated.

typedef struct {
    uint32_t       tag;          // tag bytes packed big-endian (e.g. 0x9F38)
    bool           constructed;  // bit 6 of the first tag byte
    const uint8_t *val;          // pointer into the source buffer
    size_t         len;          // value length in bytes
} tlv_t;

// Parse the next TLV starting at `p` (stopping at `end`). Leading 0x00 padding
// bytes are skipped. Returns a pointer just past the value (feed it back in as
// `p` to iterate), or NULL when no more TLVs remain.
const uint8_t *tlv_next(const uint8_t *p, const uint8_t *end, tlv_t *out);

// Depth-first search for `tag` anywhere in the buffer, descending into
// constructed (template) objects. Returns true and fills `out` on the first
// match.
bool tlv_find(const uint8_t *buf, size_t len, uint32_t tag, tlv_t *out);
