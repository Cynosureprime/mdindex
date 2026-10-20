# mdindex - a partial-hash index from digest to (file, offset) over very
# large wordlists, for several unsalted hash types at once.
#
# Platform detection follows hashpipe's, itself from PR #1 by @0xVavaldi.
#
# A clean clone does not build on its own: mdindex links the same hash
# libraries mdxfind does, and they are fetched and built by
#
#	make deps        # once, ~10 minutes
#	make             # thereafter
#
# `make deps` clones each dependency at a PINNED commit and refuses to
# continue if the clone's HEAD is anything else, so what it builds is what
# was tested rather than whatever upstream has moved to since.
#
# SQLite is the exception and is fetched by `make dep-sqlite`, which is
# part of `deps`: it ships as an amalgamation rather than a repository.
# mdindex uses it for ONE thing, the line-count cache it shares with
# mdxfind through $MDXFIND_CACHE, which lets a build projection reuse a
# count another run already paid for.

CC = cc
AR = ar
RANLIB = ranlib
TOPDIR := $(shell pwd)

# ---- Platform detection ----
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
MULTIARCH := $(shell $(CC) -print-multiarch 2>/dev/null)

ifeq ($(UNAME_M),x86_64)
  ARCHOPT = -DINTEL
else ifeq ($(UNAME_M),amd64)
  ARCHOPT = -DINTEL
else ifeq ($(UNAME_M),ppc64le)
  ARCHOPT = -DPOWERPC
else ifeq ($(UNAME_M),ppc64)
  ARCHOPT = -DPOWERPC
else
  ARCHOPT =
endif

ifeq ($(UNAME_S),Darwin)
  OSOPT = -DMACOSX=1
  LIBSEARCH = . /opt/local/lib /usr/local/lib /usr/lib
  LDEXTRA =
  INCEXTRA = -I/opt/local/include
else ifeq ($(UNAME_S),FreeBSD)
  OSOPT =
  LIBSEARCH = . /usr/local/lib /usr/lib
  LDEXTRA = -Wl,--allow-multiple-definition
  INCEXTRA = -I/usr/local/include
else
  OSOPT =
  LIBSEARCH = . /usr/lib/$(MULTIARCH) /usr/local/lib /usr/lib
  LDEXTRA = -ldl
  INCEXTRA = -I/usr/local/include
endif

ifneq ($(UNAME_S),Darwin)
  OSOPT += -fgnu89-inline
endif

CFLAGS  = -fomit-frame-pointer -pthread -O3 $(ARCHOPT) $(OSOPT) $(INCEXTRA) \
          -I. -I$(LIBDIR)
LDFLAGS = -pthread -O3

# Static is PREFERRED, not required: an archive staged in the tree first,
# then one in the system library directories, then the ordinary -l form.
# That makes a clean clone link while keeping the release build static.
# LIBDIR: where the static archives live, if not here.
#
# `make deps` is for a clean clone and builds them in this directory. A
# build HOST that already carries them -- every machine in the release
# fleet has them in ~/src/mdfind, shared with mdxfind -- should reuse
# those rather than spend ten minutes rebuilding what is already there:
#
#	mkdir ~/src/mdfind/mdindex-build && cd $_
#	make LIBDIR=.. mdindex
#
# Nothing is written outside this directory either way.
LIBDIR ?= .

pick_lib = $(firstword $(wildcard $(addsuffix /$(1),$(LIBSEARCH))) -l$(2))

COMPRESS = $(call pick_lib,libz.a,z)

# lm.a sits at the top of a build host's tree and under lm/ in a clean
# clone; take whichever is there before building one.
LM := $(firstword $(wildcard $(LIBDIR)/lm.a $(LIBDIR)/lm/lm.a) lm/lm.a)

# gost2012.a likewise: deps installs it under gosthash/gost2012/, a build
# host carries it at gosthash/ as well.
GOST := $(firstword $(wildcard $(LIBDIR)/gosthash/gost2012/gost2012.a \
                               $(LIBDIR)/gosthash/gost2012.a) \
                    gosthash/gost2012/gost2012.a)

LIBS = $(LIBDIR)/libssl.a $(LIBDIR)/libcrypto.a $(LIBDIR)/libsph.a \
       $(LIBDIR)/libmhash.a $(LIBDIR)/librhash.a $(LIBDIR)/md6.a \
       $(GOST) $(LIBDIR)/bcrypt-master/bcrypt.a \
       $(LIBDIR)/argon2/argon2.a $(LM) $(COMPRESS)

YESCRYPT_OBJS = $(LIBDIR)/yescrypt/yescrypt-common.o \
                $(LIBDIR)/yescrypt/yescrypt-opt.o \
                $(LIBDIR)/yescrypt/sha256.o \
                $(LIBDIR)/yescrypt/insecure_memzero.o

# hx: the expression language mdindex compiles every non-native type from.
# hx_func is built in its STANDALONE flavour -- mdindex has no Hashtypes[]
# table to register primitives from, as hashpipe does, so the registry is
# compiled in against OpenSSL directly and mdindex_bridge.c adds the rest.
HX_OBJS = hx_lib.o hx_ast.o hx_compile.o hx_vm.o hx_func_sa.o hx.tab.o hx.lex.o

ENCODING_OBJS = ruleproc32.o classify_utf8.o

SQLITE_OBJ = sqlite3.o

OBJS = mdindex.o mdindex_bridge.o userdef.o qsort_mt.o crypt-des.o \
       myprogress.o $(SQLITE_OBJ) $(HX_OBJS) $(ENCODING_OBJS)

ifeq ($(UNAME_M),x86_64)
  ARGON2_FILL_SRC = opt.c
  ARGON2_FILL_OBJ = opt.o
else ifeq ($(UNAME_M),amd64)
  ARGON2_FILL_SRC = opt.c
  ARGON2_FILL_OBJ = opt.o
else
  ARGON2_FILL_SRC = ref.c
  ARGON2_FILL_OBJ = ref.o
endif

all: mdindex

# -DHX_STANDALONE -DHX_HAS_KDF must match the flags hx_func_sa.o is built
# with, or the registry mdindex compiles against is not the one it links.
mdindex.o: mdindex.c mdindex_typeopts.h mdindex_hxcat.h john_map.h \
           hx_vm.h userdef.h codegen/maphashcat_data.h
	$(CC) $(CFLAGS) -DHX_STANDALONE -DHX_HAS_KDF \
	      -Wno-deprecated-declarations -c mdindex.c

mdindex_bridge.o: mdindex_bridge.c hx_vm.h md6.h
	$(CC) $(CFLAGS) -Wno-deprecated-declarations -c mdindex_bridge.c

userdef.o: userdef.c userdef.h hx_vm.h
	$(CC) $(CFLAGS) -c userdef.c

qsort_mt.o: qsort_mt.c
	$(CC) $(CFLAGS) -c qsort_mt.c

crypt-des.o: crypt-des.c
	$(CC) $(CFLAGS) -c crypt-des.c

myprogress.o: myprogress.c
	$(CC) $(CFLAGS) -c myprogress.c

sqlite3.o: sqlite3.c sqlite3.h
	$(CC) -O2 -DSQLITE_THREADSAFE=1 -DSQLITE_OMIT_LOAD_EXTENSION -c sqlite3.c

# Without this, a clean clone fails with make's own "No rule to make target
# 'sqlite3.c'", which says nothing about what to do next.
sqlite3.c sqlite3.h:
	@echo "$@ is not here yet. Run 'make deps' once (or just 'make dep-sqlite')." >&2
	@exit 1

# Same courtesy for the headers `make deps` installs. Without these, a tree
# whose deps step failed reports "No rule to make target 'md6.h'", which
# says nothing about what went wrong or what to do.
md6.h mhash.h rhash.h:
	@echo "$@ is missing: 'make deps' has not completed here." >&2
	@echo "Run 'make deps' and read its output -- do not discard it." >&2
	@exit 1

hx_lib.o: hx.c hx_ast.h hx_vm.h hx.tab.h
	$(CC) $(CFLAGS) -c hx.c -o hx_lib.o

hx_ast.o: hx_ast.c hx_ast.h
	$(CC) $(CFLAGS) -c hx_ast.c

hx_compile.o: hx_compile.c hx_ast.h hx_vm.h
	$(CC) $(CFLAGS) -c hx_compile.c

hx_vm.o: hx_vm.c hx_vm.h
	$(CC) $(CFLAGS) -c hx_vm.c

hx_func_sa.o: hx_func.c hx_vm.h
	$(CC) $(CFLAGS) -DHX_STANDALONE -DHX_HAS_KDF -c hx_func.c -o hx_func_sa.o

hx.tab.o: hx.tab.c hx_ast.h
	$(CC) $(CFLAGS) -c hx.tab.c

hx.lex.o: hx.lex.c hx.tab.h
	$(CC) $(CFLAGS) -c hx.lex.c

ruleproc32.o: ruleproc32.c ruleproc32.h rule_ops.h latin_case.h combining.h
	$(CC) $(CFLAGS) -c ruleproc32.c

classify_utf8.o: classify_utf8.c classify_utf8.h
	$(CC) $(CFLAGS) -std=gnu99 -c classify_utf8.c

mdindex: $(OBJS) $(LM)
	$(CC) $(LDFLAGS) -o mdindex $(OBJS) $(YESCRYPT_OBJS) $(LIBS) $(LDEXTRA)

# lm.a, the LAN Manager hash.  LGPL, Christopher R. Hertel -- see lm/ for
# its own notice.  Built here rather than fetched: it is eight small files
# and has had no upstream since 2004.
lm/lm.a:
	cd lm && $(CC) -O3 -w -c DES.c LMhash.c && $(AR) rcs lm.a DES.o LMhash.o

argon2/argon2.a:
	cd argon2 && $(CC) $(CFLAGS) -c argon2.c core.c encoding.c thread.c $(ARGON2_FILL_SRC) && \
	$(CC) $(CFLAGS) -c -o blake2b.o blake2/blake2b.c && \
	$(AR) rcs argon2.a argon2.o core.o encoding.o thread.o $(ARGON2_FILL_OBJ) blake2b.o

check: mdindex
	./mdindex selftest

clean:
	rm -f *.o mdindex lm/*.o lm/lm.a

distclean: clean
	rm -rf deps libssl.a libcrypto.a libsph.a libmhash.a librhash.a \
	       md6.a gosthash bcrypt-master yescrypt argon2/argon2.a \
	       argon2/*.o openssl mutils sph_*.h mhash.h rhash.h \
	       rhash_torrent.h md6.h.dep sqlite3.c sqlite3.h

# ---- Dependencies, pinned ----

DEPDIR = $(TOPDIR)/deps

# ---- Pinned versions ----
# OpenSSL 1.1.1w  -- last public release of the 1.1.1 LTS branch
OPENSSL_REPO   = https://github.com/openssl/openssl.git
OPENSSL_TAG    = OpenSSL_1_1_1w
OPENSSL_COMMIT = e04bd3433fd84e1861bf258ea37928d9845e6a86

# sphlib (Thomas Pornin) -- SHA-3 candidates and classic hashes
SPHLIB_REPO    = https://github.com/pornin/sphlib.git
SPHLIB_COMMIT  = 15b6b8d8f3e4a43c58ba102d712fa6b8a3317035

# libmhash 0.9.9.9 (Distrotech mirror of SourceForge canonical)
MHASH_REPO     = https://github.com/Distrotech/mhash.git
MHASH_BRANCH   = distrotech-mhash
MHASH_COMMIT   = d8cb1ed69b146d5001de1e083a44c12dc50d2e89

# RHash 1.4.6 -- latest stable release
RHASH_REPO     = https://github.com/rhash/RHash.git
RHASH_TAG      = v1.4.6
RHASH_COMMIT   = 6562de382954d9893442b89b0e8b5c513eea6a88

# MD6 reference implementation (Ron Rivest, MIT) via retter collection
MD6_REPO       = https://github.com/brandondahler/retter.git
MD6_COMMIT     = eaba612ef34c35ac6cce6a1778e91908ec62bd0e

# Streebog / GOST R 34.11-2012 (Markku-Juhani O. Saarinen)
# Core primitives from brutus (CAESAR test framework); streebog.c/streebog.h
# wrapper from stricat (not on GitHub) bundled in gosthash/gost2012/
STREEBOG_REPO  = https://github.com/mjosaarinen/brutus.git
STREEBOG_COMMIT = 04509d7c9009015fc13ffcc49324e4bbcaa569ec

# crypt_blowfish / bcrypt (Openwall) -- tag 1.3
BCRYPT_REPO    = https://github.com/openwall/crypt_blowfish.git
BCRYPT_TAG     = CRYPT_BLOWFISH_1_3
BCRYPT_COMMIT  = 3354bb81eea489e972b0a7c63231514ab34f73a0

# yescrypt 1.1.0 (Openwall -- Colin Percival / Alexander Peslyak)
YESCRYPT_REPO  = https://github.com/openwall/yescrypt.git
YESCRYPT_TAG   = YESCRYPT_1_1_0
YESCRYPT_COMMIT = 0731cce8fdd1636f0bd6b7ce742e0d2a2154c6e0
deps: dep-openssl dep-sphlib dep-mhash dep-rhash dep-md6 dep-streebog dep-bcrypt dep-yescrypt dep-sqlite

# ---- OpenSSL ----
dep-openssl:
	@echo "==> OpenSSL ($(OPENSSL_TAG))"
	@if [ -f $(TOPDIR)/libssl.a ] && [ -f $(TOPDIR)/libcrypto.a ]; then echo "  already built, skipping"; exit 0; fi; \
	set -e; \
	mkdir -p $(DEPDIR); \
	rm -rf $(DEPDIR)/openssl; \
	git clone --depth 1 --branch $(OPENSSL_TAG) $(OPENSSL_REPO) $(DEPDIR)/openssl; \
	GOT=$$(cd $(DEPDIR)/openssl && git rev-parse HEAD); \
	if [ "$$GOT" != "$(OPENSSL_COMMIT)" ]; then \
		echo "ERROR: OpenSSL HEAD $$GOT != expected $(OPENSSL_COMMIT)"; exit 1; \
	fi; \
	echo "  verified $$GOT"; \
	cd $(DEPDIR)/openssl && \
	./config no-shared no-dso no-engine no-tests && \
	$(MAKE) build_libs; \
	cp $(DEPDIR)/openssl/libssl.a $(TOPDIR)/; \
	cp $(DEPDIR)/openssl/libcrypto.a $(TOPDIR)/; \
	mkdir -p $(TOPDIR)/openssl; \
	cp -r $(DEPDIR)/openssl/include/openssl/* $(TOPDIR)/openssl/; \
	echo "  libssl.a + libcrypto.a installed"

# ---- sphlib ----
dep-sphlib:
	@echo "==> sphlib ($(SPHLIB_COMMIT))"
	@if [ -f $(TOPDIR)/libsph.a ]; then echo "  already built, skipping"; exit 0; fi; \
	set -e; \
	mkdir -p $(DEPDIR); \
	rm -rf $(DEPDIR)/sphlib; \
	git clone $(SPHLIB_REPO) $(DEPDIR)/sphlib; \
	GOT=$$(cd $(DEPDIR)/sphlib && git rev-parse HEAD); \
	if [ "$$GOT" != "$(SPHLIB_COMMIT)" ]; then \
		echo "ERROR: sphlib HEAD $$GOT != expected $(SPHLIB_COMMIT)"; exit 1; \
	fi; \
	echo "  verified $$GOT"; \
	cd $(DEPDIR)/sphlib/c && \
	SPH_SRCS=$$(ls *.c | grep -v '^test_' | grep -v '^hsum' | grep -v '^speed' \
		| grep -v 'sha3nist' | grep -v '^utest' | grep -v '_helper\.c') && \
	$(CC) -O3 -w -fno-strict-aliasing -c $$SPH_SRCS && \
	$(AR) rcs libsph.a *.o; \
	cp $(DEPDIR)/sphlib/c/libsph.a $(TOPDIR)/; \
	cp $(DEPDIR)/sphlib/c/sph_*.h $(TOPDIR)/; \
	echo "  libsph.a installed"

# ---- libmhash ----
dep-mhash:
	@echo "==> libmhash ($(MHASH_COMMIT))"
	@if [ -f $(TOPDIR)/libmhash.a ]; then echo "  already built, skipping"; exit 0; fi; \
	set -e; \
	mkdir -p $(DEPDIR); \
	rm -rf $(DEPDIR)/mhash; \
	git clone --branch $(MHASH_BRANCH) $(MHASH_REPO) $(DEPDIR)/mhash; \
	GOT=$$(cd $(DEPDIR)/mhash && git rev-parse HEAD); \
	if [ "$$GOT" != "$(MHASH_COMMIT)" ]; then \
		echo "ERROR: libmhash HEAD $$GOT != expected $(MHASH_COMMIT)"; exit 1; \
	fi; \
	echo "  verified $$GOT"; \
	cd $(DEPDIR)/mhash && \
	libtoolize --force --copy --install && \
	autoreconf -i && \
	CFLAGS="-O2 -w -std=gnu89" ./configure --enable-static --disable-shared && \
	$(MAKE); \
	cp $(DEPDIR)/mhash/lib/.libs/libmhash.a $(TOPDIR)/; \
	cp $(DEPDIR)/mhash/include/mhash.h $(TOPDIR)/; \
	cp -r $(DEPDIR)/mhash/include/mutils $(TOPDIR)/; \
	echo "  libmhash.a installed"

# ---- librhash ----
dep-rhash:
	@echo "==> RHash ($(RHASH_TAG))"
	@if [ -f $(TOPDIR)/librhash.a ]; then echo "  already built, skipping"; exit 0; fi; \
	set -e; \
	mkdir -p $(DEPDIR); \
	rm -rf $(DEPDIR)/rhash; \
	git clone --depth 1 --branch $(RHASH_TAG) $(RHASH_REPO) $(DEPDIR)/rhash; \
	GOT=$$(cd $(DEPDIR)/rhash && git rev-parse HEAD); \
	if [ "$$GOT" != "$(RHASH_COMMIT)" ]; then \
		echo "ERROR: RHash HEAD $$GOT != expected $(RHASH_COMMIT)"; exit 1; \
	fi; \
	echo "  verified $$GOT"; \
	cd $(DEPDIR)/rhash && \
	./configure --enable-lib-static && \
	cd librhash && \
	$(MAKE) lib-static; \
	cp $(DEPDIR)/rhash/librhash/librhash.a $(TOPDIR)/; \
	cp $(DEPDIR)/rhash/librhash/rhash.h $(TOPDIR)/; \
	cp $(DEPDIR)/rhash/librhash/rhash_torrent.h $(TOPDIR)/; \
	echo "  librhash.a installed"

# ---- md6 ----
dep-md6:
	@echo "==> MD6 (Rivest reference impl)"
	@if [ -f $(TOPDIR)/md6.a ]; then echo "  already built, skipping"; exit 0; fi; \
	set -e; \
	mkdir -p $(DEPDIR); \
	rm -rf $(DEPDIR)/retter; \
	git clone $(MD6_REPO) $(DEPDIR)/retter; \
	GOT=$$(cd $(DEPDIR)/retter && git rev-parse HEAD); \
	if [ "$$GOT" != "$(MD6_COMMIT)" ]; then \
		echo "ERROR: MD6/retter HEAD $$GOT != expected $(MD6_COMMIT)"; exit 1; \
	fi; \
	echo "  verified $$GOT"; \
	cd $(DEPDIR)/retter/MD6 && \
	$(CC) -O3 -w -fcommon -c md6_compress.c md6_mode.c && \
	$(AR) rcs md6.a md6_compress.o md6_mode.o; \
	cp $(DEPDIR)/retter/MD6/md6.a $(TOPDIR)/; \
	cp $(DEPDIR)/retter/MD6/md6.h $(TOPDIR)/; \
	echo "  md6.a installed"

dep-streebog:
	@echo "==> Streebog ($(STREEBOG_COMMIT))"
	@if [ -f $(TOPDIR)/gosthash/gost2012/gost2012.a ]; then echo "  already built, skipping"; exit 0; fi; \
	set -e; \
	mkdir -p $(DEPDIR); \
	rm -rf $(DEPDIR)/brutus; \
	git clone $(STREEBOG_REPO) $(DEPDIR)/brutus; \
	GOT=$$(cd $(DEPDIR)/brutus && git rev-parse HEAD); \
	if [ "$$GOT" != "$(STREEBOG_COMMIT)" ]; then \
		echo "ERROR: brutus HEAD $$GOT != expected $(STREEBOG_COMMIT)"; exit 1; \
	fi; \
	echo "  verified $$GOT"; \
	mkdir -p $(TOPDIR)/gosthash/gost2012; \
	cp $(DEPDIR)/brutus/crypto_aead_round1/stribob192r1/ref/sbob_pi64.c $(TOPDIR)/gosthash/gost2012/; \
	cp $(DEPDIR)/brutus/crypto_aead_round1/stribob192r1/ref/sbob_tab64.c $(TOPDIR)/gosthash/gost2012/; \
	cp $(DEPDIR)/brutus/crypto_aead_round1/stribob192r1/ref/stribob.h $(TOPDIR)/gosthash/gost2012/; \
	cd $(TOPDIR)/gosthash/gost2012 && \
	$(CC) -O3 -w -c sbob_pi64.c sbob_tab64.c streebog.c && \
	$(AR) rcs gost2012.a sbob_pi64.o sbob_tab64.o streebog.o; \
	echo "  gost2012.a built"

# ---- bcrypt (Openwall crypt_blowfish) ----
dep-bcrypt:
	@echo "==> crypt_blowfish ($(BCRYPT_TAG))"
	@if [ -f $(TOPDIR)/bcrypt-master/bcrypt.a ]; then echo "  already built, skipping"; exit 0; fi; \
	set -e; \
	mkdir -p $(DEPDIR); \
	rm -rf $(DEPDIR)/crypt_blowfish; \
	git clone --depth 1 --branch $(BCRYPT_TAG) $(BCRYPT_REPO) $(DEPDIR)/crypt_blowfish; \
	GOT=$$(cd $(DEPDIR)/crypt_blowfish && git rev-parse HEAD); \
	if [ "$$GOT" != "$(BCRYPT_COMMIT)" ]; then \
		echo "ERROR: crypt_blowfish HEAD $$GOT != expected $(BCRYPT_COMMIT)"; exit 1; \
	fi; \
	echo "  verified $$GOT"; \
	cd $(DEPDIR)/crypt_blowfish && \
	$(CC) -O3 -w -c crypt_blowfish.c crypt_gensalt.c wrapper.c && \
	$(AR) rcs bcrypt.a crypt_blowfish.o crypt_gensalt.o wrapper.o; \
	mkdir -p $(TOPDIR)/bcrypt-master; \
	cp $(DEPDIR)/crypt_blowfish/bcrypt.a $(TOPDIR)/bcrypt-master/; \
	echo "  bcrypt.a installed"

# ---- yescrypt ----
dep-yescrypt:
	@echo "==> yescrypt ($(YESCRYPT_TAG))"
	@if [ -f $(TOPDIR)/yescrypt/yescrypt-opt.o ]; then echo "  already built, skipping"; exit 0; fi; \
	set -e; \
	mkdir -p $(DEPDIR); \
	rm -rf $(DEPDIR)/yescrypt; \
	git clone --depth 1 --branch $(YESCRYPT_TAG) $(YESCRYPT_REPO) $(DEPDIR)/yescrypt; \
	GOT=$$(cd $(DEPDIR)/yescrypt && git rev-parse HEAD); \
	if [ "$$GOT" != "$(YESCRYPT_COMMIT)" ]; then \
		echo "ERROR: yescrypt HEAD $$GOT != expected $(YESCRYPT_COMMIT)"; exit 1; \
	fi; \
	echo "  verified $$GOT"; \
	cd $(DEPDIR)/yescrypt && \
	$(CC) -O3 -w -DSKIP_MEMZERO -c yescrypt-opt.c yescrypt-common.c sha256.c insecure_memzero.c; \
	mkdir -p $(TOPDIR)/yescrypt; \
	cp $(DEPDIR)/yescrypt/yescrypt-opt.o $(TOPDIR)/yescrypt/; \
	cp $(DEPDIR)/yescrypt/yescrypt-common.o $(TOPDIR)/yescrypt/; \
	cp $(DEPDIR)/yescrypt/sha256.o $(TOPDIR)/yescrypt/; \
	cp $(DEPDIR)/yescrypt/insecure_memzero.o $(TOPDIR)/yescrypt/; \
	cp $(DEPDIR)/yescrypt/yescrypt.h $(TOPDIR)/yescrypt/; \
	echo "  yescrypt objects installed"

# ---- SQLite amalgamation ----
# A download rather than a pinned clone, because it ships as an
# amalgamation and not as a repository -- so this is the one dependency
# `deps` cannot pin by commit the way the others are pinned.  It is the
# same URL mdxfind's Makefile names.
SQLITE_URL  = https://www.sqlite.org/2025/sqlite-amalgamation-3490100.zip

dep-sqlite:
	@echo "==> SQLite amalgamation"
	@if [ -f $(TOPDIR)/sqlite3.c ] && [ -f $(TOPDIR)/sqlite3.h ]; then \
	    echo "  already present, skipping"; exit 0; fi; \
	set -e; \
	mkdir -p $(DEPDIR); \
	cd $(DEPDIR) && \
	curl -fsSL -o sqlite.zip "$(SQLITE_URL)" && \
	unzip -oq sqlite.zip && \
	cp sqlite-amalgamation-*/sqlite3.c sqlite-amalgamation-*/sqlite3.h $(TOPDIR)/; \
	echo "  sqlite3.c + sqlite3.h installed"

install-man:
	@d=$${DESTDIR:-/usr/local}/share/man/man1; \
	mkdir -p "$$d" && cp man/man1/mdindex.1 "$$d/" && \
	echo "installed $$d/mdindex.1"

.PHONY: all check clean distclean deps install-man \
        dep-openssl dep-sphlib dep-mhash dep-rhash dep-md6 \
        dep-streebog dep-bcrypt dep-yescrypt dep-sqlite
