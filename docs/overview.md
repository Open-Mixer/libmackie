# libmackie: overview

## Where it sits

libmackie is the wire layer under a surface behaviour layer (motor policy, touch, banking,
repaint) that is shared by MIDI surfaces and by DigiNet desks such as the Digidesign Control|24
([libdiginet](https://github.com/Open-Mixer/libdiginet)). MIDI bytes never cross into that
layer: libmackie encodes and decodes them, and the host carries them. The design is on
[libdiginet#29](https://github.com/FreeMixer/libdiginet/issues/29).

## The control map

Which note, CC or pitch-bend channel each control sits on is the surface's, not the
protocol's. The host fills a `struct mackie_map` from its own surface profile, the one source
of every address, and every encoder and decoder reads it. libmackie keeps no second table of
addresses beside the profile; `mackie_map_check()` refuses a map it cannot use, whole.

## Provenance

The codec is a port of a TypeScript MCU module (the X-Touch adapter's `mcu.ts`) that drives
X-Touches in production. It is held to that module byte for byte: `tools/gen-goldens.mjs` ran
every TypeScript encoder and decoder over a set of inputs and wrote what they returned into
`tests/golden/mcu_golden.h`, and `tests/test_golden.c` checks every C encoder and decoder
against it. The host-connection handshake is pinned to an exchange captured live on an X-Touch
(firmware V1.22).

