// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* libFuzzer harness: THE TEXT A HOST SENDS (src/mackie_text.c, src/mackie_display.c and the
 * scribble writers of src/mackie_sysex.c): UTF-8 read into the cells of the LCD scribble
 * strips and into the seven-segment displays, the decoder of every string the library takes.
 *
 * Input: the bytes that choose the map (fuzz_map_init in fuzz.h: the display widths and CCs
 * in it), then operations until the input ends. An operation is a selector byte, the
 * numbers it needs, and a text: a u16 length and that many bytes (or what is left) followed by
 * a NUL, in an allocation of exactly that, so a read past the NUL is a sanitizer report. A
 * NUL in the bytes ends the text there.
 *
 * The harness reads the text itself, from RFC 3629 and the UTF-16 slice and iteration the
 * header describes (fuzz/spec.h), and every check holds the library to that reading. No
 * expected value comes from the library.
 *
 * Properties, each an abort() in a check_ function:
 *   - scribble: a write at an offset is F0 00 00 66 <model> 12 <offset & 7f>, one byte for
 *     each of the text's first 112 characters that lies before cell 112 (a printable ASCII
 *     character as it is, anything else a space), and F7; a NULL text or result is
 *     MACKIE_E_ARG.
 *   - strip: a strip's cell is the same write at row * 56 + strip * 7 of the text cut to 7
 *     UTF-16 units and padded with spaces to 7, a row past the second MACKIE_E_RANGE with
 *     the result untouched.
 *   - timecode: the text cut to the map's digits, right-aligned with blanks, is one Control
 *     Change per character from the leftmost digit's CC down, the seven-segment code of the
 *     character as its data; MACKIE_E_SPACE when the room is short of them.
 *   - assignment: two Control Changes, the left digit's CC (one above) then the right's, the
 *     first two UTF-16 units of the text padded with blanks.
 *   - segment: a character's seven-segment code is the table of spec_seg.
 */
#include <mackie/mackie_codec.h>

#include "fuzz.h"


/* The cells of a write of `n` characters at `offset`: the characters before cell 112, a
 * printable ASCII one as it is and any other a space. */
static size_t expect_cells(unsigned offset, const uint32_t *cp, size_t n, uint8_t *cells)
{
	size_t room = offset < SPEC_LCD_CELLS ? SPEC_LCD_CELLS - offset : 0, k = 0;

	for (size_t i = 0; i < n && i < room; i++)
		cells[k++] = cp[i] >= 0x20 && cp[i] <= 0x7e ? (uint8_t)cp[i] : 0x20;
	return k;
}

/* The whole message a write makes. */
static size_t expect_write(unsigned offset, const uint32_t *cp, size_t n, uint8_t model,
			   uint8_t *msg)
{
	size_t k = 0;

	msg[k++] = SPEC_SYSEX; msg[k++] = 0; msg[k++] = 0; msg[k++] = 0x66; msg[k++] = model;
	msg[k++] = SPEC_SUB_LCD;
	msg[k++] = (uint8_t)(offset & 0x7f);
	k += expect_cells(offset, cp, n, msg + k);
	msg[k++] = SPEC_EOX;
	return k;
}

FUZZ_CHECK check_scribble(const char *text, unsigned offset, uint8_t model)
{
	struct mackie_msg out;
	uint32_t cp[SPEC_LCD_CELLS + 1];
	uint8_t want[MACKIE_MSG_MAX];
	const unsigned char *p = (const unsigned char *)text;
	size_t n = 0;
	uint32_t c;

	while (n < SPEC_LCD_CELLS && (c = spec_utf8(&p)) != 0)
		cp[n++] = c;
	size_t wn = expect_write(offset, cp, n, model, want);
	memset(&out, 0xa5, sizeof out);
	int rc = mackie_scribble_encode(offset, text, model, &out);

	/* A NULL text or result is an argument error.
	 * contract: include/mackie/mackie_codec.h, "MACKIE_E_ARG for a NULL pointer"; mackie.h
	 * mutant: src/mackie_sysex.c:57 `MACKIE_E_ARG` -> `MACKIE_E_RANGE`
	 * input: scribble-null */
	if (mackie_scribble_encode(offset, NULL, model, &out) != SPEC_E_ARG ||
	    mackie_scribble_encode(offset, text, model, NULL) != SPEC_E_ARG)
		abort();
	/* The write is the header, the offset's low 7 bits, the text's characters up to cell 112
	 * as printable ASCII or a space, and F7.
	 * contract: include/mackie/mackie_codec.h mackie_scribble_encode; mackie.h MACKIE_SYSEX_LCD
	 * mutant: src/mackie_sysex.c:33 `0x20 && cp <= 0x7e` -> `0x20 && cp <= 0x7f`
	 * input: scribble-del
	 * mutant: src/mackie_sysex.c:43 `put(out, offset & 0x7f)` -> `put(out, offset & 0xff)`
	 * input: scribble-offset-high
	 * mutant: src/mackie_sysex.c:40 `offset < LCD_CELLS ? LCD_CELLS - offset : 0` -> `LCD_CELLS`
	 * input: scribble-past-end
	 * mutant: src/mackie_sysex.c:58 `n < LCD_CELLS` -> `n < LCD_CELLS - 1`
	 * input: scribble-full
	 * mutant: src/mackie_sysex.c:45 `put(out, cell(chars[i]))` -> `put(out, chars[i] > 0x7e ? 0x3f : cell(chars[i]))`
	 * input: scribble-utf8 */
	if (rc != SPEC_OK || out.len != wn || memcmp(out.bytes, want, wn))
		abort();
}

FUZZ_CHECK check_strip(const char *text, unsigned strip, unsigned row, uint8_t model)
{
	struct mackie_msg out, was;
	uint16_t u[SPEC_CELL];
	uint32_t cp[SPEC_CELL];
	uint8_t want[MACKIE_MSG_MAX];

	memset(&out, 0xa5, sizeof out);
	was = out;
	int rc = mackie_strip_scribble_encode(strip, row, text, model, &out);

	/* A row other than the top or the bottom is out of range, and the result is left as it
	 * was.
	 * contract: include/mackie/mackie_codec.h mackie_strip_scribble_encode
	 * mutant: src/mackie_sysex.c:72 `row > 1` -> `row > 2`
	 * input: strip-row-2 */
	if (row > 1 && (rc != SPEC_E_RANGE || memcmp(&out, &was, sizeof out)))
		abort();
	if (row > 1)
		return;
	size_t got = spec_units(text, u, SPEC_CELL);
	for (size_t i = got; i < SPEC_CELL; i++)
		u[i] = ' ';
	size_t k = spec_chars(u, SPEC_CELL, cp);
	size_t wn = expect_write(row * SPEC_LCD_ROW + strip * SPEC_CELL, cp, k, model, want);
	/* The cell is the text cut to 7 UTF-16 units, padded with spaces to 7, written at the
	 * strip's slice of its row.
	 * contract: include/mackie/mackie_codec.h mackie_strip_scribble_encode
	 * mutant: src/mackie_sysex.c:79 `row * MACKIE_LCD_ROW_CHARS + strip * MACKIE_STRIP_CELL_CHARS` -> `row * MACKIE_LCD_ROW_CHARS + strip * 8`
	 * input: strip-4-bottom
	 * mutant: src/mackie_sysex.c:75 `got = mackie_utf16_head(text, u, MACKIE_STRIP_CELL_CHARS)` -> `got = mackie_utf16_head(text, u, MACKIE_STRIP_CELL_CHARS - 1)`
	 * input: strip-long
	 * mutant: src/mackie_sysex.c:77 `u[i] = ' '` -> `u[i] = '_'`
	 * input: strip-short
	 * mutant: src/mackie_text.c:71 `i++;` -> ``
	 * input: strip-astral */
	if (rc != SPEC_OK || out.len != wn || memcmp(out.bytes, want, wn))
		abort();
}

FUZZ_CHECK check_timecode(const struct fuzz_map *fm, const char *text, size_t cap)
{
	struct mackie_msg *out = cap ? (struct mackie_msg *)fuzz_alloc(cap * sizeof *out) : NULL;
	uint16_t u[MACKIE_DISPLAY_MAX_DIGITS], cut[MACKIE_DISPLAY_MAX_DIGITS];
	uint32_t cp[MACKIE_DISPLAY_MAX_DIGITS];
	unsigned d = fm->m.timecode_digits;
	size_t got = spec_units(text, cut, d), n = 99, k;

	/* the text right-aligned in d units */
	for (size_t i = 0; i < d; i++)
		u[i] = i < d - got ? ' ' : cut[i - (d - got)];
	k = spec_chars(u, d, cp);
	if (out)
		memset(out, 0xa5, cap * sizeof *out);
	int rc = mackie_timecode_encode(&fm->m, text, out, cap, &n);

	int bad = k <= cap && (rc != SPEC_OK || n != k);
	for (size_t i = 0; !bad && k <= cap && i < k; i++)
		bad = out[i].len != 3 || out[i].bytes[0] != SPEC_CC ||
		      out[i].bytes[1] != (uint8_t)(fm->m.timecode_cc + d - 1 - i) ||
		      out[i].bytes[2] != spec_seg(cp[i]);
	/* When the room is short of the characters the display needs, it is not written.
	 * contract: include/mackie/mackie_codec.h mackie_timecode_encode ("MACKIE_E_SPACE when cap is short of them")
	 * mutant: src/mackie_display.c:65 `return MACKIE_E_SPACE` -> `return MACKIE_E_RANGE`
	 * input: timecode-no-room
	 * mutant: src/mackie_display.c:65 `return MACKIE_E_SPACE` -> `return cap ? (out[0].len = 0, MACKIE_E_SPACE) : MACKIE_E_SPACE`
	 * input: timecode-no-room */
	if (k > cap && (rc != SPEC_E_SPACE || (out && !fuzz_all((const uint8_t *)out, cap * sizeof *out, 0xa5))))
		abort();
	/* The characters count and one Control Change is made for each, leftmost digit's CC
	 * first and going down, the seven-segment code of the character as its data.
	 * contract: include/mackie/mackie_codec.h mackie_timecode_encode; mackie.h struct mackie_map timecode_cc
	 * mutant: src/mackie_display.c:68 `m->timecode_cc + digits - 1 - i` -> `m->timecode_cc + digits - i`
	 * input: timecode-text
	 * mutant: src/mackie_display.c:69 `mackie_seven_segment_code(cp[i])` -> `mackie_seven_segment_code(cp[i]) & 0x1f`
	 * input: timecode-text
	 * mutant: src/mackie_display.c:60 `u[i + pad] = u[i]` -> `u[i + pad] = u[i] + 1`
	 * input: timecode-short
	 * mutant: src/mackie_display.c:62 `u[i] = ' '` -> `u[i] = '0'`
	 * input: timecode-short
	 * mutant: src/mackie_display.c:64 `k > cap` -> `k >= cap`
	 * input: timecode-exact-cap */
	if (bad)
		abort();
	free(out);
}

FUZZ_CHECK check_assignment(const struct fuzz_map *fm, const char *text)
{
	struct mackie_msg out[2];
	uint16_t u[2] = { ' ', ' ' };

	spec_units(text, u, 2);
	memset(out, 0xa5, sizeof out);
	int rc = mackie_assignment_encode(&fm->m, text, out);

	int bad = rc != SPEC_OK;
	for (unsigned i = 0; i < 2; i++)
		bad |= out[i].len != 3 || out[i].bytes[0] != SPEC_CC ||
		       out[i].bytes[1] != (uint8_t)(fm->m.assignment_cc + 1 - i) ||
		       out[i].bytes[2] != spec_seg(u[i]);
	/* Two Control Changes, the left digit's CC (one above the map's) then the right's, each
	 * the seven-segment code of one UTF-16 unit of the text padded with blanks.
	 * contract: include/mackie/mackie_codec.h mackie_assignment_encode
	 * mutant: src/mackie_display.c:88 `m->assignment_cc + 1 - i` -> `m->assignment_cc - i`
	 * input: assignment-text
	 * mutant: src/mackie_display.c:79 `u[2] = { ' ', ' ' }` -> `u[2] = { '0', ' ' }`
	 * input: assignment-empty */
	if (bad)
		abort();
}

FUZZ_CHECK check_segment(uint32_t cp)
{
	/* A character's seven-segment code folds lower case up, folds the few characters whose
	 * upper case begins with a letter, and is a blank for what the display cannot draw.
	 * contract: include/mackie/mackie_codec.h mackie_seven_segment_code
	 * mutant: src/mackie_display.c:29 `c >= 'a' && c <= 'z'` -> `c >= 'a' && c <= 'y'`
	 * input: segment-lower
	 * mutant: src/mackie_display.c:34 `FOLDS[i].cp == cp` -> `FOLDS[i].cp == (cp & 0xffff)`
	 * input: segment-astral
	 * mutant: src/mackie_display.c:39 `c <= 0x5f` -> `c <= 0x5e`
	 * input: segment-underscore */
	if (mackie_seven_segment_code(cp) != spec_seg(cp))
		abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fuzz_in in;
	struct fuzz_map fm;

	if (size >= FUZZ_INPUT_MAX)
		return -1;
	in = fuzz_in(data, size);
	fuzz_map_init(&fm, &in);
	while (in.n > 0) {
		uint8_t sel = fuzz_u8(&in);
		uint32_t num = fuzz_u32(&in);
		char *text = fuzz_text(&in);

		check_scribble(text, num, sel);
		check_strip(text, num & 0xff, num >> 8 & 3, sel);
		check_timecode(&fm, text, sel & 0x1f);
		check_assignment(&fm, text);
		check_segment(num);
		free(text);
	}
	return 0;
}
