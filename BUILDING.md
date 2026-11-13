# Building libmackie

A hand-kept Makefile, no build system to configure. You need a C11 compiler and `make`.
Nothing else: no library outside libc, not even libm.

```
make                          # libmackie.a
make shared                   # libmackie.so.<version>, with its soname links
make test                     # the unit suite, the same command CI runs
make install PREFIX=/usr/local [DESTDIR=...]
make clean
```

The code is plain C11 built with `-Wall -Wextra -Werror`, so a warning is a build failure.
`CC` and `CFLAGS` can be overridden on the command line; the warning flags are kept even then.

`make install` copies the headers to `$(PREFIX)/include/mackie/`, the archive to
`$(PREFIX)/lib` (`LIBDIR=` to change it) and a pkg-config file, so a consumer builds with:

```
cc app.c $(pkg-config --cflags --libs libmackie)
```

## Tests

Every test runs through `tests/run-test.sh`, which gives it a timeout: a hang is a failure,
never a stalled build. A test that exits 77 proved this machine cannot host it and is reported
as SKIP, never as a pass.

- `test_mcu` is the TypeScript MCU suite ported case for case: faders, buttons, V-Pots,
  meters, scribble strips, the handshake ground truth and the scribble backlights, with the
  refusals a C API adds.
- `test_golden` holds every encoder and decoder to `tests/golden/mcu_golden.h`, the bytes the
  TypeScript encoders sent and what the TypeScript decoders read for the same inputs, and
  checks that what the encoders send decodes back to what they were given.
- `test_install.sh` installs into a scratch root and builds a consumer through pkg-config;
  `conformance-packaging.sh` holds the version and soname copies to one another;
  `test_workflows.sh` parses the CI workflows.

The checks on what this repository publishes, commit messages and private references, are
Open-Mixer/.github's, and CI runs them through its `public-sources-check` workflow; no copy is
kept here. `make public-sources` runs the private-refs check from a checkout of Open-Mixer/.github
(`OPENMIXER_DOTGITHUB`, else `../freemixer-dotgithub`). The commit-msg hook in `.githooks` is the
shared stub; enable it once per clone with `git config core.hooksPath .githooks`.

## Fuzzing

`fuzz/README.md` describes the libFuzzer harnesses (clang, `make fuzz`, `make fuzz-run`) and the
checks that hold them to their properties (`make fuzz-records`, `fuzz-sabotage`, `fuzz-coverage`).
None of them is part of `make test`; `.github/workflows/fuzz.yml` runs them.

## The golden bytes

`tests/golden/mcu_golden.h` is generated, and committed. To compare against a TypeScript MCU
module (compiled to `mcu.js`, with its dependencies resolvable from where it sits):

```
node tools/gen-goldens.mjs path/to/mcu.js > tests/golden/mcu_golden.h
git diff tests/golden/mcu_golden.h
```

A difference in the header is a change of wire bytes on one side or the other. The generator
draws its sampled inputs from a fixed seed, so the same module writes the same file.
