<!-- SPDX-License-Identifier: GPL-3.0-or-later
     Copyright (C) 2026 Pau Aliagas -->

# libmackie: threat model

## What it is and where it runs

libmackie is a C library (`libmackie.a`, and `libmackie.so` for the packages) that encodes and
decodes the Mackie Control (MCU) wire protocol: channel messages and SysEx between a host and a
control surface such as the Behringer X-Touch. It ships no command-line tool; `tools/gen-goldens.mjs`
is a development script that wrote `tests/golden/mcu_golden.h` and is not installed.

Every function works over caller memory. The library opens no MIDI port, file or socket, reads
no clock or environment, starts no thread, takes no lock and calls no allocator
(`README.md`, `src/`). Stack use is fixed: the largest local buffer is the 112-code-point array in
`mackie_scribble_encode` (`src/mackie_sysex.c`). Nothing in it blocks, so it can be called from a
real-time thread. It keeps no state between calls, apart from the constant colour table
`mackie_scribble_colours`, so calls are reentrant.

## Inputs

| Input | Read by | Who can write it | Trusted |
|---|---|---|---|
| MIDI channel messages (Note On/Off, Pitch Bend, Control Change) | `mackie_button_decode`, `mackie_fader_decode`, `mackie_vpot_decode`, `mackie_jog_decode` | the surface, or any device or client that can write to the MIDI port the host reads | no |
| SysEx (handshake, version reply) | `mackie_handshake_decode`, `mackie_version_reply_decode`, `mackie_handshake_response` | as above | no |
| Text for scribble strips and seven-segment displays (UTF-8) | `mackie_scribble_encode`, `mackie_strip_scribble_encode`, `mackie_timecode_encode`, `mackie_assignment_encode` | the host; often channel names that a remote user of the host can set | no |
| Colour names | `mackie_scribble_colour_index` | the host, possibly from user data | no |
| Control map (`struct mackie_map`) | every encoder and decoder; `mackie_map_check` | the host, from its own surface profile | yes, once `mackie_map_check` accepts it |
| Numbers passed to encoders (channel, strip, position, level, offset, model id) | the encoders in `src/mackie_codec.c`, `src/mackie_sysex.c` | the host | partly: ranges are clamped or refused |
| Caller buffers and their sizes (`cap`, `len`) | all functions | the host | yes |

The library reads no mapping file or configuration; the host builds the map. It has no network
transport. If the host carries MIDI over a network, those bytes reach the decoders as the MIDI
rows above.

## Trust boundary

Bytes from a surface are untrusted: anything that can write to the MIDI port the host listens
on can send any byte sequence, of any length. Text is untrusted as well, because hosts pass
on names that users choose. The control map, the buffer pointers and their lengths are the
caller's, and the library trusts them. A wrong `len` or `cap`, a text with no NUL terminator,
or a map with `n_keys` greater than the length of `keys` is a caller bug, and the library cannot
detect it.

## What the code assumes and enforces

- **Arguments.** A NULL pointer, or NULL with a nonzero length, returns `MACKIE_E_ARG`. Return codes
  are listed in `include/mackie/mackie.h` and `mackie_strerror` (`src/mackie_map.c`).
- **Decoders** (`src/mackie_codec.c`) never read past `len`. A missing data byte reads as 0. A
  message of another type, channel, note or CC returns `MACKIE_E_NOT_MINE` and leaves `*out`
  unchanged.
- **Data bytes are not checked to be 7-bit.** `mackie_fader_decode` combines the two bytes as
  they arrive, so a byte with the high bit set gives a value above 16383 (`fuzz/README.md`, "Not
  covered"). The V-Pot and jog decoders mask the data to 7 bits. The button decoder looks the
  note byte up as it arrives, and a byte above 0x7f matches nothing.
- **Handshake SysEx** (`mackie_handshake_decode`) requires `F0 00 00 66 <model> <sub> ... F7` of at
  least 6 bytes. It copies at most `MACKIE_SERIAL_LEN` (7) and `MACKIE_CHALLENGE_LEN` (4) bytes,
  whatever the length, and does not check the body bytes or the sub-command.
- **Version reply** (`mackie_version_reply_decode`) copies the body unchanged into the caller's
  buffer and returns `MACKIE_E_SPACE` when the body and its NUL do not fit in `cap`. The body is
  not checked: it may hold any byte value, including NUL or bytes at 0x80 and above. A caller that
  prints it has to treat it as untrusted text.
- **Outgoing messages** fit in `struct mackie_msg` (`MACKIE_MSG_MAX` = 128 bytes). The longest
  is a scribble write of 120 bytes, because the text is clamped to cell 111 (`scribble()` in
  `src/mackie_sysex.c`). The host-connection reply sends at most 7 + 4 body bytes. The timecode
  encoder returns `MACKIE_E_SPACE` when `cap` is too small.
- **Text** (`src/mackie_text.c`): an invalid, overlong or surrogate UTF-8 sequence, or a value past
  U+10FFFF, decodes as U+FFFD. A truncated sequence stops at the NUL and never reads past it.
  The library reads a bounded prefix of each text: 112 code points for a scribble write, 7
  UTF-16 units for a strip cell, the digit count for timecode, 2 units for the assignment
  display. A scribble cell keeps printable ASCII only and replaces anything else with a space.
  Seven-segment output is 7-bit (`mackie_seven_segment_code`).
- **Ranges** are clamped or refused. Positions and levels, NaN included, are clamped
  (`src/mackie_round.h`). `row > 1`, `encoder >= 8`, `value > 16383`, a colour count other than 8
  or a colour index above 7 return `MACKIE_E_RANGE`. The channel, strip, note and offset fields
  are masked to their wire width.
- **Map check.** `mackie_map_check` requires every note and CC to be 7-bit and every note to be
  distinct. Every key needs an id. The assignment CC needs room for the digit above it, the
  display needs 1..16 digits whose CCs fit in 7 bits, and the jog CC must be in -1..127.
  Otherwise it returns `MACKIE_E_RANGE`.

## Fuzz coverage

Each harness in `fuzz/` is built with clang, libFuzzer, ASan and UBSan, and runs for 60 s per
push and pull request (`.github/workflows/fuzz.yml`). The workflow also enforces sabotage
patches, mutant records and a coverage floor (`fuzz/README.md`).

| Untrusted input | Harness |
|---|---|
| MIDI channel messages | `fuzz/fuzz_decode.c` |
| Handshake and version SysEx | `fuzz/fuzz_sysex.c` |
| Scribble and display text | `fuzz/fuzz_text.c` |
| Colour names, encoder numbers | `fuzz/fuzz_encode.c` |
| Control map (caller data; checked by `mackie_map_check`) | `fuzz/fuzz_map.c` |

### Gaps

- The decoders are only fuzzed with maps that `mackie_map_check` accepts. Calling a decoder
  with an unchecked map is not enforced; the map check must come first.
- `mackie_fader_decode` accepts data bytes with the high bit set. Its value is fuzzed only when
  both bytes are 7-bit.
- `mackie_strip_scribble_encode` does not range-check `strip`. A strip past 7 cannot write past
  the message, but the cell lands at `row * 56 + strip * 7`, which can be in the other row. The
  header documents 0..7, but the function does not refuse other values.
- The version-reply text is not checked to be ASCII or free of NUL bytes.
- The library cannot detect a caller length that does not match the buffer, or a text with no
  NUL terminator. No fuzz harness covers either case.
- Each harness runs for 60 s in CI. There is no long-running fuzzing campaign.

## Reporting

Report vulnerabilities privately through GitHub private vulnerability reporting: open this
repository's Security tab and select "Report a vulnerability".
