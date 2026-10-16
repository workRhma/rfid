#pragma once

// Read-only EMV contactless exploration for a card you own. Assumes a card has
// already been activated with rc522_select() and is ISO-DEP capable (SAK bit
// 0x20). Performs: SELECT PPSE -> list AIDs -> SELECT AID -> GET PROCESSING
// OPTIONS -> READ RECORD over the AFL, printing a labelled TLV tree.
//
// Strictly read-only: no cryptogram generation, no GENERATE AC, no transaction.
// The PAN is masked in logs (first 6 + last 4); the cardholder name is only
// logged when EMV_SHOW_CARDHOLDER is set to 1 below.
void emv_dump(void);
