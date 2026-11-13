// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* libFuzzer harness: THE SYSEX A SURFACE SENDS (src/mackie_sysex.c): the host-connection
 * handshake decoder, the version-reply decoder and the challenge-to-response transform.
 *
 * Input: one byte, the model id the host listens for, then operations until the input ends.
 * An operation is a selector byte, a length byte (at most 40) and that many bytes. With the
 * selector's high bit set the bytes are the body of a framed message, F0 00 00 66 <model> and
 * a sub-command, F7 around them, so an input reaches the decoders' body without first
 * guessing the frame; without it they are the message as they are. The low 5 bits of the
 * selector are the size of the text buffer the version decoder is given. Each message and
 * buffer is in an allocation of exactly its length, so a read or write past it is a
 * sanitizer report.
 *
 * The harness reads each message itself, from the layout captured live from an X-Touch (the
 * MACKIE_HS_* exchange in include/mackie/mackie.h), and every check holds the library to that
 * reading. No expected value comes from the library.
 *
 * Properties, each an abort() in a check_ function:
 *   - handshake: only F0 00 00 66 <model> <sub> ... F7 of at least six bytes is a handshake
 *     message, anything else MACKIE_E_NOT_MINE with *out as it was; a NULL result is
 *     MACKIE_E_ARG; the sub is the sixth byte, the serial the first 7 bytes of the body (the
 *     bytes between the sub and the F7), the challenge the next 4, each as many as there are.
 *   - version: a version reply is a handshake message with the sub 0x14; its text is the body
 *     as sent, NUL-terminated, the result its length, MACKIE_E_SPACE when the buffer cannot
 *     hold the text and the NUL.
 *   - response: the transform answers the challenge seen live, "0B8E", with 33 76 17 2A, every
 *     byte is 7-bit, a challenge shorter than 4 reads as if padded with zeros, and bytes past
 *     the fourth do not count.
 */
#include <mackie/mackie_codec.h>

#include "fuzz.h"

/* F0 00 00 66 <model> <sub> ... F7 of six bytes at least: a handshake message of this model,
 * read from the bytes alone */
static int spec_handshake_frame(const uint8_t *msg, size_t len, uint8_t model)
{
	return len >= 6 && msg[0] == SPEC_SYSEX && msg[len - 1] == SPEC_EOX && msg[1] == 0x00 &&
	       msg[2] == 0x00 && msg[3] == 0x66 && msg[4] == model;
}

/* the sub is msg[5]; the body is what is between it and the closing F7 */
static size_t body_len(size_t len)
{
	return len > 7 ? len - 7 : 0;
}

FUZZ_CHECK check_handshake(const uint8_t *msg, size_t len, uint8_t model)
{
	struct mackie_handshake h, was;
	int mine = spec_handshake_frame(msg, len, model);

	memset(&h, 0xa5, sizeof h);
	was = h;
	int rc = mackie_handshake_decode(msg, len, model, &h);

	/* A message that is not F0 00 00 66 <model> <sub> ... F7 of six bytes at least is of
	 * another kind, and the result is left as it was.
	 * contract: include/mackie/mackie_codec.h mackie_handshake_decode; mackie.h MACKIE_HS_*
	 * mutant: src/mackie_sysex.c:144 `msg[4] != model` -> `0`
	 * input: other-model
	 * mutant: src/mackie_sysex.c:144 `msg[3] != MACKIE_MANUFACTURER_2` -> `0`
	 * input: other-manufacturer
	 * mutant: src/mackie_sysex.c:141 `msg[len - 1] != MACKIE_SYSEX_END` -> `0`
	 * input: no-eox
	 * mutant: src/mackie_sysex.c:141 `len < 6` -> `len < 5`
	 * input: short-five */
	if (!mine && (rc != SPEC_E_NOT_MINE || memcmp(&h, &was, sizeof h)))
		abort();
	if (!mine)
		return;
	size_t blen = body_len(len), ns = blen < SPEC_SERIAL ? blen : SPEC_SERIAL;
	size_t nc = blen > SPEC_SERIAL ? blen - SPEC_SERIAL : 0;
	if (nc > SPEC_CHALLENGE)
		nc = SPEC_CHALLENGE;
	/* The sub is the sixth byte, F7 itself when the message ends there.
	 * contract: include/mackie/mackie.h, the handshake exchange; mackie_codec.h struct mackie_handshake
	 * mutant: src/mackie_sysex.c:148 `.sub = msg[5]` -> `.sub = msg[4]`
	 * input: query */
	if (rc != SPEC_OK || h.sub != msg[5])
		abort();
	/* The serial is the first 7 bytes of the body, as many as there are.
	 * contract: include/mackie/mackie_codec.h mackie_handshake_decode; mackie.h MACKIE_SERIAL_LEN
	 * mutant: src/mackie_sysex.c:149 `blen < MACKIE_SERIAL_LEN ? blen : MACKIE_SERIAL_LEN` -> `MACKIE_SERIAL_LEN`
	 * input: query
	 * mutant: src/mackie_sysex.c:150 `memcpy(h.serial, body, h.serial_len)` -> `memcpy(h.serial, body + 1, h.serial_len)`
	 * input: connection-query */
	if (h.serial_len != ns || memcmp(h.serial, msg + 6, ns))
		abort();
	/* The challenge is the next 4 bytes, as many as there are, and none when the body is no
	 * longer than the serial.
	 * contract: include/mackie/mackie_codec.h mackie_handshake_decode; mackie.h MACKIE_CHALLENGE_LEN
	 * mutant: src/mackie_sysex.c:151 `blen > MACKIE_SERIAL_LEN` -> `blen > 0`
	 * input: serial-only
	 * mutant: src/mackie_sysex.c:153 `c < MACKIE_CHALLENGE_LEN ? c : MACKIE_CHALLENGE_LEN` -> `MACKIE_CHALLENGE_LEN`
	 * input: serial-and-two
	 * mutant: src/mackie_sysex.c:154 `body + MACKIE_SERIAL_LEN` -> `body + MACKIE_SERIAL_LEN - 1`
	 * input: connection-query */
	if (h.challenge_len != nc || memcmp(h.challenge, msg + 6 + SPEC_SERIAL, nc))
		abort();
}

FUZZ_CHECK check_handshake_args(const uint8_t *msg, size_t len, uint8_t model)
{
	struct mackie_handshake h;

	/* A NULL result, or a NULL message with a length, is an argument error.
	 * contract: include/mackie/mackie_codec.h, "MACKIE_E_ARG for a NULL pointer"; mackie.h
	 * mutant: src/mackie_sysex.c:139 `MACKIE_E_ARG` -> `MACKIE_E_RANGE`
	 * input: args-null */
	if (mackie_handshake_decode(msg, len, model, NULL) != SPEC_E_ARG ||
	    (len && mackie_handshake_decode(NULL, len, model, &h) != SPEC_E_ARG))
		abort();
}

FUZZ_CHECK check_version(const uint8_t *msg, size_t len, uint8_t model, size_t cap)
{
	char *text = (char *)fuzz_alloc(cap);
	int reply = spec_handshake_frame(msg, len, model) && msg[5] == SPEC_SUB_VERSION_REPLY;
	size_t n = body_len(len);

	memset(text, 0xa5, cap);
	int rc = mackie_version_reply_decode(msg, len, model, text, cap);

	/* Only a handshake message with the sub 0x14 is a version reply; any other is of another
	 * kind and the buffer is not written.
	 * contract: include/mackie/mackie_codec.h mackie_version_reply_decode; mackie.h MACKIE_HS_VERSION_REPLY
	 * mutant: src/mackie_sysex.c:221 `h.sub != MACKIE_HS_VERSION_REPLY` -> `0`
	 * input: version-query-reply */
	if (!reply && (rc != SPEC_E_NOT_MINE || !fuzz_all((const uint8_t *)text, cap, 0xa5)))
		abort();
	if (!reply)
		goto out;
	/* A buffer that cannot hold the text and its NUL is too small, and is not written.
	 * contract: include/mackie/mackie_codec.h mackie_version_reply_decode ("MACKIE_E_SPACE when cap cannot hold it and the NUL")
	 * mutant: src/mackie_sysex.c:224 `n + 1 > cap` -> `n > cap`
	 * input: version-exact-cap */
	if (n + 1 > cap && (rc != SPEC_E_SPACE || !fuzz_all((const uint8_t *)text, cap, 0xa5)))
		abort();
	if (n + 1 > cap)
		goto out;
	/* The text is the body as sent, NUL-terminated, and the result is its length.
	 * contract: include/mackie/mackie_codec.h mackie_version_reply_decode; mackie.h MACKIE_HS_VERSION_REPLY
	 * mutant: src/mackie_sysex.c:226 `memcpy(text, msg + 6, n)` -> `memcpy(text, msg + 7, n)`
	 * input: version-reply
	 * mutant: src/mackie_sysex.c:227 `text[n] = '\0'` -> `text[n] = ' '`
	 * input: version-reply
	 * mutant: src/mackie_sysex.c:228 `(int)n` -> `(int)n + 1`
	 * input: version-reply */
	if (rc != (int)n || memcmp(text, msg + 6, n) || text[n] != '\0')
		abort();
out:
	free(text);
}

/* The 4-byte challenge-to-response transform of a spec-compliant surface, written here from
 * mackie_codec.h's description (each byte 7-bit) and the live exchange: the response is
 * computed on the challenge's bytes padded with zeros to 4. */
static void spec_response(const uint8_t *ch, size_t n, uint8_t r[4])
{
	int32_t c[4] = { 0, 0, 0, 0 };

	for (size_t i = 0; i < 4 && i < n; i++)
		c[i] = ch[i];
	r[0] = (uint8_t)((c[0] + (c[1] ^ 0x0a) - c[3]) & 0x7f);
	r[1] = (uint8_t)(((c[2] >> 4) ^ (c[0] + c[3])) & 0x7f);
	r[2] = (uint8_t)(((c[3] - (c[2] << 2)) ^ (c[0] | c[1])) & 0x7f);
	r[3] = (uint8_t)((c[1] - c[2] + (0xf0 ^ (c[3] << 4))) & 0x7f);
}

FUZZ_CHECK check_response(const uint8_t *ch, size_t n)
{
	uint8_t got[4], want[4];
	/* the challenge "0B8E" the X-Touch sent, and the response the host sent it: captured
	 * live (firmware V1.22, 2026-07-03) */
	static const uint8_t live[4] = { 0x30, 0x42, 0x38, 0x45 };
	static const uint8_t live_response[4] = { 0x33, 0x76, 0x17, 0x2a };

	memset(got, 0xa5, sizeof got);
	mackie_handshake_response(ch, n, got);
	spec_response(ch, n, want);
	/* The response is the transform of the challenge, every byte 7-bit; a challenge shorter
	 * than 4 reads as if padded with zeros, and bytes past the fourth are not read.
	 * contract: include/mackie/mackie_codec.h mackie_handshake_response
	 * mutant: src/mackie_sysex.c:167 `i < n && challenge` -> `i < 3 && challenge`
	 * input: response-live
	 * mutant: src/mackie_sysex.c:171 `0x7fu & ` -> ``
	 * input: response-high
	 * mutant: src/mackie_sysex.c:173 `(c[0] | c[1])` -> `(c[0] & c[1])`
	 * input: response-live
	 * mutant: src/mackie_sysex.c:171 `c[0] + (c[1] ^ 0x0a) - c[3]` -> `c[0] + (c[1] ^ 0x0b) - c[3]`
	 * input: response-short
	 * mutant: src/mackie_sysex.c:172 `(c[2] >> 4) ^ (c[0] + c[3])` -> `(c[2] >> 3) ^ (c[0] + c[3])`
	 * input: response-live */
	if (memcmp(got, want, 4) || (n == 4 && !memcmp(ch, live, 4) && memcmp(got, live_response, 4)))
		abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fuzz_in in;
	uint8_t model;

	if (size >= FUZZ_INPUT_MAX)
		return -1;
	in = fuzz_in(data, size);
	model = fuzz_u8(&in);
	while (in.n > 0) {
		uint8_t sel = fuzz_u8(&in);
		size_t n, len;
		uint8_t *body = fuzz_msg(&in, 40, &n);
		uint8_t *msg;

		if (sel & 0x80) {
			/* F0 00 00 66 <model> <body: the sub first> F7 */
			len = n + 6;
			msg = fuzz_alloc(len);
			msg[0] = SPEC_SYSEX; msg[1] = 0; msg[2] = 0; msg[3] = 0x66; msg[4] = model;
			if (n)
				memcpy(msg + 5, body, n);
			msg[len - 1] = SPEC_EOX;
		} else {
			msg = fuzz_dup(body, n);
			len = n;
		}
		check_handshake(msg, len, model);
		check_handshake_args(msg, len, model);
		check_version(msg, len, model, sel & 0x1f);
		check_response(msg, len);
		free(msg);
		free(body);
	}
	return 0;
}
