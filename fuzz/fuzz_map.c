// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* libFuzzer harness: THE CONTROL MAP A HOST BUILDS (src/mackie_map.c): mackie_map_check, the
 * reader of the one table every encoder and decoder trusts, and mackie_strerror.
 *
 * Input: one byte that chooses the map's base (0: all zero bytes, anything else a valid map
 * as fuzz_map_init builds it from the bytes after it), then edits until the input ends: a
 * field index and a value, written into the map's flat image before it is read back into a
 * struct mackie_map. The image holds every field in order (the 40 strip notes, 9 touch
 * notes, 16 global notes, 8 V-Pot CCs, 8 ring CCs, the fader channels, the assignment CC, the
 * timecode CC and digit count, the jog CC (two bytes), the key count, 8 key notes and the
 * mask of which keys have an id), so one edit breaks one rule. The key table is NULL when the
 * image says so. The last bytes of the input are an error code for mackie_strerror.
 *
 * The harness reads the map itself, from the rules in include/mackie/mackie.h (fuzz/spec.h
 * holds the limits), and every check holds the library to that reading. No expected value
 * comes from the library.
 *
 * Properties, each an abort() in a check_ function:
 *   - verdict: MACKIE_OK exactly for a map whose every note and CC is 7-bit, whose notes all
 *     differ, whose keys all have an id, whose assignment CC leaves room for the digit above
 *     it, whose display has 1..16 digits all with a 7-bit CC, whose jog CC is -1..127;
 *     MACKIE_E_RANGE for any other; MACKIE_E_ARG for a NULL map or a key count with no keys.
 *   - usable: a map it accepts makes only 7-bit bytes in the displays and rings, which is
 *     what "a map every encoder and decoder can use" says.
 *   - strerror: every status has its text and any other code "unknown error".
 */
#include <string.h>

#include <mackie/mackie_codec.h>

#include "fuzz.h"

/* the flat image of a map */
#define IMG_STRIP   0
#define IMG_TOUCH   40
#define IMG_GLOBAL  49
#define IMG_VPOT    65
#define IMG_RING    73
#define IMG_FADERS  81   /* two bytes */
#define IMG_ASSIGN  83
#define IMG_TC_CC   84
#define IMG_TC_DIG  85
#define IMG_JOG     86   /* two bytes, a signed 16-bit */
#define IMG_NKEYS   88
#define IMG_KEYS    89   /* eight notes */
#define IMG_IDMASK  97
#define IMG_SIZE    98

static void image_of(const struct fuzz_map *fm, uint8_t *img)
{
	const struct mackie_map *m = &fm->m;

	memset(img, 0, IMG_SIZE);
	for (unsigned b = 0; b < MACKIE_STRIP_BUTTONS; b++)
		memcpy(img + IMG_STRIP + b * SPEC_STRIPS, m->strip_note[b], SPEC_STRIPS);
	memcpy(img + IMG_TOUCH, m->touch_note, SPEC_STRIPS + 1);
	memcpy(img + IMG_GLOBAL, m->global_note, MACKIE_GLOBALS);
	memcpy(img + IMG_VPOT, m->vpot_cc, SPEC_STRIPS);
	memcpy(img + IMG_RING, m->ring_cc, SPEC_STRIPS);
	img[IMG_FADERS] = (uint8_t)m->fader_channels;
	img[IMG_FADERS + 1] = (uint8_t)(m->fader_channels >> 8);
	img[IMG_ASSIGN] = m->assignment_cc;
	img[IMG_TC_CC] = m->timecode_cc;
	img[IMG_TC_DIG] = m->timecode_digits;
	img[IMG_JOG] = (uint8_t)m->jog_cc;
	img[IMG_JOG + 1] = (uint8_t)((uint16_t)m->jog_cc >> 8);
	img[IMG_NKEYS] = (uint8_t)m->n_keys;
	for (size_t k = 0; k < m->n_keys; k++) {
		img[IMG_KEYS + k] = fm->keys[k].note;
		img[IMG_IDMASK] |= (uint8_t)(1u << k);
	}
}

/* the struct the image says; keys with no id in the mask have a NULL id, and a key count
 * past the eight there are room for reads as a table of eight (the image has no more) */
static void map_of(const uint8_t *img, struct fuzz_map *fm, int no_keys)
{
	struct mackie_map *m = &fm->m;

	memset(fm, 0, sizeof *fm);
	for (unsigned b = 0; b < MACKIE_STRIP_BUTTONS; b++)
		memcpy(m->strip_note[b], img + IMG_STRIP + b * SPEC_STRIPS, SPEC_STRIPS);
	memcpy(m->touch_note, img + IMG_TOUCH, SPEC_STRIPS + 1);
	memcpy(m->global_note, img + IMG_GLOBAL, MACKIE_GLOBALS);
	memcpy(m->vpot_cc, img + IMG_VPOT, SPEC_STRIPS);
	memcpy(m->ring_cc, img + IMG_RING, SPEC_STRIPS);
	m->fader_channels = (uint16_t)(img[IMG_FADERS] | img[IMG_FADERS + 1] << 8);
	m->assignment_cc = img[IMG_ASSIGN];
	m->timecode_cc = img[IMG_TC_CC];
	m->timecode_digits = img[IMG_TC_DIG];
	m->jog_cc = (int16_t)(img[IMG_JOG] | img[IMG_JOG + 1] << 8);
	m->n_keys = img[IMG_NKEYS] % (FUZZ_KEYS + 1);
	for (size_t k = 0; k < FUZZ_KEYS; k++) {
		fm->keys[k].note = img[IMG_KEYS + k];
		fm->keys[k].id = img[IMG_IDMASK] >> k & 1 ? fuzz_key_ids[k] : NULL;
	}
	m->keys = no_keys ? NULL : fm->keys;
}

/* Whether the rules of mackie.h accept the map, and as what. */
static int spec_check(const struct mackie_map *m)
{
	unsigned seen[256] = { 0 };

	if (m->n_keys && !m->keys)
		return SPEC_E_ARG;
	for (unsigned b = 0; b < MACKIE_STRIP_BUTTONS; b++)
		for (unsigned s = 0; s < SPEC_STRIPS; s++)
			seen[m->strip_note[b][s]]++;
	for (unsigned s = 0; s <= SPEC_STRIPS; s++)
		seen[m->touch_note[s]]++;
	for (unsigned g = 0; g < MACKIE_GLOBALS; g++)
		seen[m->global_note[g]]++;
	for (size_t k = 0; k < m->n_keys; k++) {
		if (!m->keys[k].id)
			return SPEC_E_RANGE;
		seen[m->keys[k].note]++;
	}
	for (unsigned n = 0; n < 256; n++)
		if (seen[n] > 1 || (seen[n] && n > 0x7f))
			return SPEC_E_RANGE;
	for (unsigned e = 0; e < SPEC_STRIPS; e++)
		if (m->vpot_cc[e] > 0x7f || m->ring_cc[e] > 0x7f)
			return SPEC_E_RANGE;
	if (m->assignment_cc > 0x7e)
		return SPEC_E_RANGE;
	if (m->timecode_digits < 1 || m->timecode_digits > 16 || m->timecode_cc > 0x7f ||
	    m->timecode_cc + m->timecode_digits - 1 > 0x7f)
		return SPEC_E_RANGE;
	if (m->jog_cc < -1 || m->jog_cc > 0x7f)
		return SPEC_E_RANGE;
	return SPEC_OK;
}

FUZZ_CHECK check_verdict(const struct fuzz_map *fm)
{
	int want = spec_check(&fm->m);
	int rc = mackie_map_check(&fm->m);

	/* A NULL map is an argument error, as is a key count with no key table.
	 * contract: include/mackie/mackie.h mackie_map_check ("MACKIE_E_ARG for NULL"); struct mackie_map keys ("NULL when n_keys is 0")
	 * mutant: src/mackie_map.c:34 `MACKIE_E_ARG` -> `MACKIE_E_RANGE`
	 * input: map-keys-null */
	if (mackie_map_check(NULL) != SPEC_E_ARG || (want == SPEC_E_ARG && rc != SPEC_E_ARG))
		abort();
	/* A map whose notes and CCs are 7-bit, whose notes differ, whose keys have ids and whose
	 * displays fit is accepted.
	 * contract: include/mackie/mackie.h mackie_map_check
	 * mutant: src/mackie_map.c:57 `m->jog_cc > 0x7f` -> `m->jog_cc > 0x3f`
	 * input: map-jog-127
	 * mutant: src/mackie_map.c:55 `m->timecode_cc + m->timecode_digits - 1 > 0x7f` -> `m->timecode_cc + m->timecode_digits > 0x7f`
	 * input: map-display-edge */
	if (want == SPEC_OK && rc != SPEC_OK)
		abort();
	/* Anything else is out of range.
	 * contract: include/mackie/mackie.h mackie_map_check ("MACKIE_E_RANGE otherwise")
	 * mutant: src/mackie_map.c:23 `note > 0x7f || seen[note]` -> `note > 0x7f`
	 * input: map-note-twice
	 * mutant: src/mackie_map.c:46 `!m->keys[k].id || ` -> ``
	 * input: map-key-no-id
	 * mutant: src/mackie_map.c:49 `m->vpot_cc[s] > 0x7f || m->ring_cc[s] > 0x7f` -> `m->vpot_cc[s] > 0x7f`
	 * input: map-ring-cc-128
	 * mutant: src/mackie_map.c:49 `m->vpot_cc[s] > 0x7f || ` -> ``
	 * input: map-vpot-cc-128
	 * mutant: src/mackie_map.c:52 `m->assignment_cc >= 0x7f` -> `m->assignment_cc > 0x7f`
	 * input: map-assign-127
	 * mutant: src/mackie_map.c:54 `m->timecode_digits < 1` -> `m->timecode_digits < 0`
	 * input: map-digits-0
	 * mutant: src/mackie_map.c:54 `m->timecode_digits > MACKIE_DISPLAY_MAX_DIGITS` -> `m->timecode_digits > MACKIE_DISPLAY_MAX_DIGITS + 1`
	 * input: map-digits-17
	 * mutant: src/mackie_map.c:57 `m->jog_cc < -1` -> `m->jog_cc < -2`
	 * input: map-jog-minus-2
	 * mutant: src/mackie_map.c:57 `m->jog_cc > 0x7f` -> `m->jog_cc > 0xff`
	 * input: map-jog-128 */
	if (want == SPEC_E_RANGE && rc != SPEC_E_RANGE)
		abort();
}

/* Whether every byte of the message is a 7-bit data byte after its status byte */
static int data7(const struct mackie_msg *g)
{
	for (unsigned i = 1; i < g->len; i++)
		if (g->bytes[i] > 0x7f)
			return 0;
	return g->len <= MACKIE_MSG_MAX;
}

FUZZ_CHECK check_usable(const struct fuzz_map *fm)
{
	struct mackie_msg out[MACKIE_DISPLAY_MAX_DIGITS], ring;
	size_t n = 0;

	if (mackie_map_check(&fm->m) != SPEC_OK)
		return;
	int bad = 0;
	for (unsigned e = 0; e < SPEC_STRIPS; e++)
		bad |= mackie_ring_encode(&fm->m, e, 5.5, MACKIE_RING_WRAP, 1, &ring) != SPEC_OK || !data7(&ring);
	/* A map the check accepts makes only 7-bit bytes: a ring for each encoder, the
	 * assignment display and the timecode display, whose CCs stay inside the map's own.
	 * contract: include/mackie/mackie.h mackie_map_check ("a map every encoder and decoder can use")
	 * mutant: src/mackie_codec.c:191 `m->ring_cc[encoder] & 0x7f` -> `m->ring_cc[encoder] | 0x80`
	 * input: map-display-edge */
	if (bad)
		abort();
	/* The assignment display's left digit is one CC above the map's.
	 * contract: include/mackie/mackie.h struct mackie_map assignment_cc; mackie_codec.h mackie_assignment_encode
	 * mutant: src/mackie_display.c:88 `m->assignment_cc + 1 - i` -> `m->assignment_cc + 2 - i`
	 * input: map-assign-126
	 * mutant: src/mackie_display.c:88 `m->assignment_cc + 1 - i` -> `m->assignment_cc`
	 * input: map-assign-126 */
	if (mackie_assignment_encode(&fm->m, "12", out) != SPEC_OK || !data7(&out[0]) || !data7(&out[1]) ||
	    out[0].bytes[1] != (uint8_t)(fm->m.assignment_cc + 1) || out[1].bytes[1] != fm->m.assignment_cc)
		abort();
	bad = mackie_timecode_encode(&fm->m, "01:02:03:04", out, MACKIE_DISPLAY_MAX_DIGITS, &n) != SPEC_OK ||
	      n != fm->m.timecode_digits;
	for (size_t i = 0; !bad && i < n; i++)
		bad = !data7(&out[i]) || out[i].bytes[1] != (uint8_t)(fm->m.timecode_cc + n - 1 - i);
	/* The timecode display writes one CC per digit, from the map's CC up by the digits, the
	 * leftmost digit on the highest.
	 * contract: include/mackie/mackie.h struct mackie_map timecode_cc; mackie_codec.h mackie_timecode_encode
	 * mutant: src/mackie_display.c:68 `m->timecode_cc + digits - 1 - i` -> `m->timecode_cc + digits - i`
	 * input: map-display-edge
	 * mutant: src/mackie_display.c:68 `m->timecode_cc + digits - 1 - i` -> `m->timecode_cc + digits - 1`
	 * input: map-display-edge */
	if (bad)
		abort();
}

FUZZ_CHECK check_strerror(int code)
{
	const char *want = code == 0 ? "ok" : code == -1 ? "invalid argument"
		: code == -2 ? "output buffer too small" : code == -3 ? "value out of range"
		: code == -4 ? "message of another kind" : "unknown error";

	/* Each status has its text and any other code is unknown.
	 * contract: include/mackie/mackie.h enum mackie_status, mackie_strerror
	 * mutant: src/mackie_map.c:14 `"value out of range"` -> `"value out of bounds"`
	 * input: strerror-range
	 * mutant: src/mackie_map.c:16 `"unknown error"` -> `"error"`
	 * input: strerror-unknown */
	if (strcmp(mackie_strerror(code), want))
		abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fuzz_in in;
	struct fuzz_map base, fm;
	uint8_t img[IMG_SIZE];
	int no_keys;

	if (size >= FUZZ_INPUT_MAX)
		return -1;
	in = fuzz_in(data, size);
	if (fuzz_u8(&in) == 0)
		memset(&base, 0, sizeof base);
	else
		fuzz_map_init(&base, &in);
	image_of(&base, img);
	no_keys = fuzz_u8(&in) & 1;
	while (in.n > 4) {
		uint8_t at = fuzz_u8(&in);
		uint8_t v = fuzz_u8(&in);
		img[at % IMG_SIZE] = v;
	}
	map_of(img, &fm, no_keys);
	check_verdict(&fm);
	check_usable(&fm);
	check_strerror((int8_t)fuzz_u8(&in));
	return 0;
}
