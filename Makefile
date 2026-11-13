# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# libmackie: the Mackie Control (MCU) wire protocol as libmackie.a. See BUILDING.md.
#
# `make shared` and `make install-shared` are what the packages build: the same objects as a
# shared library.

CC      ?= cc
AR      ?= ar
CFLAGS  ?= -O2 -g
LDFLAGS ?=
# -fPIC always: the same objects go into the archive and the shared library.
WARN    := -std=c11 -Wall -Wextra -Werror -fPIC
INC     := -Iinclude
PREFIX  ?= /usr/local
LIBDIR  ?= $(PREFIX)/lib
INCDIR  ?= $(PREFIX)/include
PCDIR   ?= $(LIBDIR)/pkgconfig
DESTDIR ?=

# The version is the VERSION file; the soname's major is MACKIE_ABI in mackie.h. The header's
# version string and the packaging copies are held to them by tests/conformance-packaging.sh.
VERSION := $(shell cat VERSION)
ABI     := $(shell sed -n 's/^\#define MACKIE_ABI  *\([0-9]*\)$$/\1/p' include/mackie/mackie.h)

OBJS := src/mackie_map.o src/mackie_text.o src/mackie_codec.o src/mackie_display.o \
	src/mackie_sysex.o

TESTS := tests/test_mcu tests/test_golden

RUN_TEST := tests/run-test.sh

all: libmackie.a

# -MMD -MP: a header edit rebuilds every object that includes it.
src/%.o: src/%.c
	$(CC) $(CFLAGS) $(WARN) -MMD -MP $(INC) -c $< -o $@

-include $(OBJS:.o=.d)

libmackie.a: $(OBJS)
	$(AR) rcs $@ $(OBJS)

tests/test_mcu: tests/test_mcu.c tests/check.h tests/golden/mcu_golden.h libmackie.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< libmackie.a -o $@

tests/test_golden: tests/test_golden.c tests/check.h tests/golden/mcu_golden.h libmackie.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< libmackie.a -o $@

# ---- shared library (the packages) ---------------------------------------------------------
# --no-undefined: a symbol nothing defines fails here, not at a consumer's link.
SO := libmackie.so.$(VERSION)

$(SO): $(OBJS)
	$(CC) $(LDFLAGS) -shared -Wl,-soname,libmackie.so.$(ABI) -Wl,--no-undefined -o $@ $(OBJS)
	ln -sf $@ libmackie.so.$(ABI)
	ln -sf libmackie.so.$(ABI) libmackie.so

shared: $(SO)

test: $(TESTS)
	$(RUN_TEST) tests/test_mcu
	$(RUN_TEST) tests/test_golden
	$(RUN_TEST) tests/test_install.sh
	$(RUN_TEST) tests/conformance-packaging.sh
	$(RUN_TEST) tests/test_workflows.sh

# No tracked file points into a private repository: Open-Mixer/.github's private-refs check, from a checkout of
# it (FREEMIXER_DOTGITHUB, else ../freemixer-dotgithub). CI runs it, with the commit message check, through the
# public-sources-check workflow; the packages' builds do not, so `make test` does not either.
FREEMIXER_DOTGITHUB ?= ../freemixer-dotgithub
public-sources:
	$(FREEMIXER_DOTGITHUB)/.github/actions/private-refs-check/check.sh .

# The pkg-config file is written at install time, from the install's own PREFIX and LIBDIR: a
# file kept from an earlier build would name that build's directories.
PCSED = sed -e 's|@PREFIX@|$(PREFIX)|' -e 's|@LIBDIR@|$(LIBDIR)|' -e 's|@INCDIR@|$(INCDIR)|' \
	    -e 's|@VERSION@|$(VERSION)|'

# What both installs carry: headers and the pkg-config file.
install-common:
	install -d $(DESTDIR)$(INCDIR)/mackie $(DESTDIR)$(PCDIR)
	install -m 644 include/mackie/*.h $(DESTDIR)$(INCDIR)/mackie/
	$(PCSED) packaging/libmackie.pc.in > $(DESTDIR)$(PCDIR)/libmackie.pc

install: libmackie.a install-common
	install -d $(DESTDIR)$(LIBDIR)
	install -m 644 libmackie.a $(DESTDIR)$(LIBDIR)/

# The packages: the shared library with its soname links.
install-shared: shared install-common
	install -d $(DESTDIR)$(LIBDIR)
	install -m 755 $(SO) $(DESTDIR)$(LIBDIR)/
	ln -sf $(SO) $(DESTDIR)$(LIBDIR)/libmackie.so.$(ABI)
	ln -sf libmackie.so.$(ABI) $(DESTDIR)$(LIBDIR)/libmackie.so

# ---- fuzzing (fuzz/README.md) ----------------------------------------------------------------
# One libFuzzer harness per reader of bytes or text in fuzz/, each linked against a library of
# its own: the same sources compiled with clang, AddressSanitizer, UndefinedBehaviorSanitizer
# and libFuzzer's coverage hooks into build/fuzz/obj, so the ordinary build above is never
# touched. None of these targets is part of `make test`.
#   make fuzz                   build every harness
#   make fuzz-run FUZZ_TIME=60  fuzz each for the budget; red on any crash, the input left in
#                               fuzz/findings/
#   make fuzz-sabotage          each patch of fuzz/sabotage/ must make its harness abort on a
#                               seed, in the property its header names
#   make fuzz-records           each check's mutant: and input: record, alone, must make that
#                               check abort on that seed; red on a check with no record and no
#                               not-a-property line
#   make fuzz-coverage          line coverage of each reader over its seed corpus, red below
#                               fuzz/coverage-floor.txt or on a property check no seed reaches
#   make fuzz-static            each harness linked fully static with a plain driver, over its
#                               corpus
#   make fuzz-corpus            write fuzz/corpus/ again from the control map and the encoders
#   make fuzz-corpus-check      red when fuzz/corpus/ is not what fuzz-corpus writes
FUZZ_CC        ?= clang
FUZZ_TIME      ?= 60
FUZZ_BUILD     := build/fuzz
FUZZ_HARNESSES := decode sysex text map encode
FUZZ_SAN       := -fsanitize=address,undefined -fno-sanitize-recover=all
FUZZ_CFLAGS    := -O1 -g -std=c11 -Wall -Wextra -Werror -fno-omit-frame-pointer
FUZZ_SRCS      := $(OBJS:.o=.c)
FUZZ_LIB       := $(FUZZ_BUILD)/libmackie-fuzz.a
FUZZ_BINS      := $(FUZZ_HARNESSES:%=$(FUZZ_BUILD)/fuzz_%)
FUZZ_HDRS      := fuzz/fuzz.h fuzz/spec.h

$(FUZZ_BUILD)/obj/%.o: %.c
	@mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(FUZZ_SAN) -fsanitize=fuzzer-no-link -MMD -MP $(INC) -c $< -o $@

$(FUZZ_LIB): $(FUZZ_SRCS:%.c=$(FUZZ_BUILD)/obj/%.o)
	$(AR) rcs $@ $^

$(FUZZ_BUILD)/fuzz_%: fuzz/fuzz_%.c $(FUZZ_HDRS) $(FUZZ_LIB)
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(FUZZ_SAN) -fsanitize=fuzzer -MMD -MP -MF $@.d $(INC) -Ifuzz $< $(FUZZ_LIB) -o $@

fuzz: $(FUZZ_BINS)

fuzz-run: fuzz
	FUZZ_BUILD=$(FUZZ_BUILD) FUZZ_TIME=$(FUZZ_TIME) fuzz/run.sh $(FUZZ_HARNESSES)

fuzz-sabotage:
	FUZZ_BUILD=$(FUZZ_BUILD) MAKE="$(MAKE)" fuzz/sabotage.sh

# Each record built plain and native with fuzz/standalone.c for its driver, no sanitizer, as the
# OSS Verify coverage build is.
fuzz-records:
	FUZZ_BUILD=$(FUZZ_BUILD) FUZZ_CC=$(FUZZ_CC) fuzz/records.sh $(FUZZ_HARNESSES)

# The same harnesses driven by fuzz/standalone.c instead of libFuzzer and linked fully static,
# each run over its corpus: the build a verifier that brings its own driver takes. Needs the
# static libc (glibc-static on Fedora, libc6-dev on Debian).
FUZZ_STATIC_BUILD := $(FUZZ_BUILD)/static
FUZZ_STATIC_FLAGS := -O2 -g -std=c11 -Wall -Wextra -Werror

$(FUZZ_STATIC_BUILD)/fuzz_%: fuzz/fuzz_%.c $(FUZZ_HDRS) fuzz/standalone.c $(FUZZ_SRCS)
	@mkdir -p $(@D)
	$(FUZZ_CC) $(FUZZ_STATIC_FLAGS) -static $(INC) -Ifuzz $< fuzz/standalone.c $(FUZZ_SRCS) -o $@

fuzz-static: $(FUZZ_HARNESSES:%=$(FUZZ_STATIC_BUILD)/fuzz_%)
	@for h in $(FUZZ_HARNESSES); do \
	  if readelf -lW $(FUZZ_STATIC_BUILD)/fuzz_$$h | grep -qE 'INTERP|DYNAMIC'; then \
	    echo "fuzz-static: fuzz_$$h is not static"; exit 1; fi; \
	  out=$$($(FUZZ_STATIC_BUILD)/fuzz_$$h fuzz/corpus/$$h/* 2>&1) || \
	    { echo "$$out"; echo "fuzz-static: fuzz_$$h failed on its own corpus"; exit 1; }; \
	  echo "fuzz_$$h, static: $$out"; done

# The coverage witness: the same harnesses without sanitizers, instrumented for llvm-cov, each
# run once over its seed corpus (-runs=0 executes the corpus and nothing else); the llvm-cov
# and llvm-profdata of FUZZ_CC's own LLVM.
FUZZ_COV_BUILD := $(FUZZ_BUILD)/cov
FUZZ_COV_FLAGS := -O0 -g -std=c11 -fprofile-instr-generate -fcoverage-mapping
FUZZ_COV_LIB   := $(FUZZ_COV_BUILD)/libmackie-cov.a
LLVM_COV       ?= llvm-cov
LLVM_PROFDATA  ?= llvm-profdata

$(FUZZ_COV_BUILD)/obj/%.o: %.c
	@mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_COV_FLAGS) -MMD -MP $(INC) -c $< -o $@

$(FUZZ_COV_LIB): $(FUZZ_SRCS:%.c=$(FUZZ_COV_BUILD)/obj/%.o)
	$(AR) rcs $@ $^

$(FUZZ_COV_BUILD)/fuzz_%: fuzz/fuzz_%.c $(FUZZ_HDRS) $(FUZZ_COV_LIB)
	$(FUZZ_CC) $(FUZZ_COV_FLAGS) -fsanitize=fuzzer $(INC) -Ifuzz $< $(FUZZ_COV_LIB) -o $@

fuzz-coverage: $(FUZZ_HARNESSES:%=$(FUZZ_COV_BUILD)/fuzz_%)
	@set -e; for h in $(FUZZ_HARNESSES); do \
	  rm -f $(FUZZ_COV_BUILD)/$$h.profraw; \
	  LLVM_PROFILE_FILE=$(FUZZ_COV_BUILD)/$$h.profraw $(FUZZ_COV_BUILD)/fuzz_$$h -runs=0 \
	      fuzz/corpus/$$h/ >$(FUZZ_COV_BUILD)/$$h.log 2>&1 || \
	    { cat $(FUZZ_COV_BUILD)/$$h.log; echo "fuzz-coverage: fuzz_$$h failed on its own corpus"; exit 1; }; \
	  $(LLVM_PROFDATA) merge -sparse $(FUZZ_COV_BUILD)/$$h.profraw -o $(FUZZ_COV_BUILD)/$$h.profdata; \
	done
	@LLVM_COV=$(LLVM_COV) fuzz/coverage.sh $(FUZZ_COV_BUILD) $(FUZZ_HARNESSES)

# The seed corpus is written from the control map and the library's own encoders, never from
# a network or a capture, and committed.
FUZZ_GEN := build/fuzz-gen-corpus
$(FUZZ_GEN): fuzz/gen-corpus.c $(FUZZ_HDRS) libmackie.a
	@mkdir -p build
	$(CC) $(CFLAGS) $(WARN) $(INC) -Ifuzz $< libmackie.a -o $@

fuzz-corpus: $(FUZZ_GEN)
	rm -rf fuzz/corpus
	$(FUZZ_GEN) fuzz/corpus

fuzz-corpus-check: $(FUZZ_GEN)
	@rm -rf build/fuzz-corpus-check
	@$(FUZZ_GEN) build/fuzz-corpus-check
	@diff -r build/fuzz-corpus-check fuzz/corpus && echo "fuzz/corpus is what fuzz-corpus writes"

-include $(FUZZ_SRCS:%.c=$(FUZZ_BUILD)/obj/%.d) $(FUZZ_BINS:=.d)

clean:
	rm -f $(OBJS) $(OBJS:.o=.d) libmackie.a libmackie.so* *.pc $(TESTS)
	rm -rf build

.PHONY: all test public-sources shared install install-common install-shared clean fuzz fuzz-run \
	fuzz-sabotage fuzz-records fuzz-static fuzz-coverage fuzz-corpus fuzz-corpus-check
