/*
 * mdindex - a partial-hash index from digest to (file, offset) over very
 * large wordlists, for several unsalted hash types at once.
 *
 * Answers "what word hashes to this" across files far larger than mdfind.c
 * can address.  mdfind.c carries a 32-bit offset and a 32-bit line counter;
 * a 31.8 GB source file leaves 87% of itself unreachable and three files
 * already total 4.146 billion lines against a 4.295 billion ceiling.
 *
 * THE INDEX IS DELIBERATELY LOSSY, AND THAT IS WHAT MAKES IT SMALL.
 *
 * A record stores 96 bits of digest, not the whole thing, and does not
 * record WHICH hash function produced it.  Both are recovered rather than
 * stored: a hit is answered by reading the line, regenerating every
 * configured digest of it, and comparing against the full digest the caller
 * supplied.  So the index is only a filter.  A key collision costs one
 * wasted read and prints nothing -- it can never produce a wrong answer.
 * Nothing in the record, the sort, the merge or the wrapper decoding knows
 * which function made a key, so adding a hash type is a table entry and a
 * rebuild, not a format change.
 *
 * Record, 15 bytes, big-endian throughout so that memcmp() over a whole
 * record is the sort order and the files are portable between hosts:
 *
 *     [0..8]   digest bytes 3..11          residue, 72 bits
 *     [9..14]  (file << 37) | offset       locator, 48 bits
 *
 * Digest bytes 0..2 are not stored; they are implied by which of the 2^24
 * buckets the record sits in, so the key is 96 bits in all.  The locator
 * sorts ascending exactly when (file, offset) does, and the manifest is in
 * priority order, so sorting by the whole record puts the winning duplicate
 * first and dedup is "drop a record whose key equals its predecessor's".
 *
 * WHY 96 BITS.  The key is NOT sized for lookup -- 64 bits already selects
 * about one record and a half-MD5 is free to search, which is why MINQHEX
 * is 16 hex characters and not KEYBITS/4.  It is sized for DEDUP, which is
 * the one place a bit too few loses data outright.
 *
 * Dedup compares keys and never sees the plaintext, so it cannot tell a
 * repeated word from two distinct words whose keys collide, and it drops
 * one of the pair.  At 64 bits that was an expected 2.7 losses across the
 * old index and 6.2 across a six-type one (n^2/2^65), and the loss was
 * invisible twice over: a half-MD5 could not return both words, and a FULL
 * digest query for the loser returned nothing, with no staleness ALERT
 * because that check only fires at or below KEYBITS.  96 bits puts the
 * expectation at 1.4e-9 and costs 4 bytes a record, 60 GB at this scale.
 * 56 bits, for contrast, would have lost 698 records.
 *
 * THE OLD INDEX IS MERGED, NOT RE-SORTED.  Both a build's fresh records
 * and the existing index are sorted on the whole scratch record, which is
 * (key, file, offset), so emit_index takes the smaller of the two heads
 * and gets exactly the order a combined sort produced -- including which
 * record of an equal-key pair survives dedup.  Sorting the union meant
 * sorting 59 million records per partition to absorb 30 of them, and
 * expanding every old record into scratch form first.
 *
 * The scratch key must EQUAL the stored key, or an update cannot expand the
 * existing index back into scratch form and dedup the new lines against it;
 * with the two equal, update runs the identical code path as build and
 * re-appearances of an indexed word cost nothing and add nothing.  That
 * equality is why widening the dedup key widened the RECORD: a 12-byte
 * scratch key read back out of a 5-byte residue would leave an update
 * unable to match its own records, and it would duplicate every word it
 * re-read instead of dropping it.
 *
 * Partial lookup falls out of the sorted array for free.  A query of q bits
 * selects a contiguous run of buckets and, inside them, a contiguous run of
 * records; the caller decides the cost by how many digits they supply.  A
 * 16-character query is exactly the stored key and returns one candidate; 4
 * characters return about 153,000.  Every candidate is regenerated and
 * compared against all q bits before anything is printed.
 *
 * THE INDEX IS WRITTEN IN TWO PIECES.
 *
 * index.rec is a packed sorted array, so inserting into it shifts every
 * record after the insertion point: absorbing one new word costs a read
 * and a write of the whole thing.  Measured on the real database, a
 * night's new words were 1,197 lines holding 164 records the index did not
 * already have, and taking them cost 452 GB of I/O and 36 minutes.
 *
 * So update does not touch index.rec at all.  New records go to add.rec,
 * the overlay: a plain sorted array of 18-byte scratch records -- whole
 * key, then locator -- with no directory, searched by binary search.  A
 * lookup answers from both.  An update costs the lines it reads.
 *
 * What makes the overlay stay small is that update drops a record whose
 * key index.rec already holds, so the overlay tracks NEW WORDS and not
 * lines read: 7,404 of those 7,568 records were already held.  The cost of
 * the arrangement is one extra binary search per query, and `compact`
 * folds the overlay back in when that stops being a good trade.  compact
 * is the only command that rewrites index.rec.
 *
 * A word re-appearing in a higher-priority file keeps the record it
 * already has rather than being re-attributed.  That is the one way the
 * result differs from a full build, and it is not observable: both records
 * name a line yielding the same plaintext, and output is TYPE hash:plain.
 *
 * Every one of those properties rests on index.rec actually being sorted,
 * so the `check` command verifies it: inside a bucket the records must be
 * STRICTLY increasing on the key, because dedup removed every repeat.  A
 * descending pair means the sort failed, an equal pair means dedup did --
 * and a sort that drops a work item produces both, since the dedup compares
 * only adjacent records.  The check lives in here, not in a tool beside it,
 * because a verifier carrying its own copy of the record size is worth
 * nothing: the standalone one still read 11-byte records after the format
 * went to v3, and called all 16,777,216 buckets unsorted on a good index.
 *
 *
 * $Revision: 1.37 $
 * $Log: mdindex.c,v $
 * Revision 1.37  2026/10/23 17:46:08  dlr
 * sel_expand_iters: -i N now reaches every native arm, at depths mdxfind agrees with. A native arm only ever picked up a deeper round that Defsix literally carried, and Defsix carries exactly one (MD5x02), so -i silently did nothing for SHA1, SHA256, SQL5 and NTLM: "-H e10 -i 2" built SHA256x01 and no SHA256x02 while the hx types named in the same -H got theirs, and the gap reads as a clean 0-hit lookup. The depths the table cannot supply now come from the catalog expression, the same path the non-native types already take, which reproduces mdxfind for MD5, SHA1 and SHA256. Two arms do not fit that rule and are handled explicitly. NTLM (e369) does not iterate at all: JOB_NTLM calls checkhash(..., 1, job) with a literal 1 and has no Maxiter loop, so NTLMx02 is a digest mdxfind never computes; the guard sits ahead of the native/catalog split because -H all reached the same type by the other route and built md4(md4(utf16le(pass))), dropping the encoding the second round needs and labelling it NTLMx02. That digest already has a correct home in e496 MD4UTF16, which declares the step md4(utf16le(PREV)). SQL5 (e259) iterates but carries forward a value it does not report: it reports sha1(sha1_bin(cur)) while setting the next cur to prmd5UC of the INNER digest, uppercased, so the printed round cannot be fed back and the step mechanism cannot restructure its inside; the chain is unrolled instead as C(1)=pass, C(k)=upper(sha1(C(k-1))), reported sha1(sha1_bin(C(n))). The catalog is no help there either, holding MySQL display form. Verified against mdxfind -z for 4 words x depths 1-5 across all five native arms: 84 of 84 digests found under identical type names, all 84 re-verified by hashpipe, -H all unchanged but for NTLMx02, non-ASCII NTLM three-codepage variants intact, selftest passes
 *
 * Revision 1.36  2026/10/21 20:08:44  dlr
 * Define getentropy locally so a build from the 2.27 host runs on the 2.19 hosts. OpenSSL 1.1.1s CSPRNG carries a WEAK undefined getentropy and glibc supplies it only from 2.25, so an unresolved one survives the link as a versioned import and the loader on an older host refuses the binary whole: gp, gp1 and gp2 are EGLIBC 2.19 and reported version GLIBC_2.25 not found before main ran, on a binary that had built and selftested clean on the build host. mdxfind never showed this although it is built on the same host against the same libcrypto.a, because mymd5.c has carried the same shim for months and mdxfind links mymd5.o. mdindex does not, and mymd5.o cannot be added to this link: its procsaltbb references checkhashbb and NoMarkSalt, both mdxfind internals, and the link fails. So the definition is repeated here rather than shared, guarded away from macOS and Windows which have their own mechanisms. mymd5.c pairs it with explicit_bzero for argon2s secure wipe and nothing in this link references that one, so it is not repeated and the comment records where its twin would go. Measured on the build host: the symbol goes from w DF UND GLIBC_2.25 to g DF .text Base, the binarys highest glibc requirement drops from 2.25 to 2.17 which is exactly where mdxfind sits, and selftest passes on the build host and on all three 2.19 hosts, where the previous build would not start at all. The alternative tried first was a -static link, which worked but treated a one-symbol gap with a whole-binary change. No behaviour change on macOS or Windows, where the preprocessor removes the block.
 *
 * Revision 1.35  2026/10/21 16:07:32  dlr
 * Find the hash in a noisy line instead of demanding the whole token be one. The stdin filter required the first whitespace-delimited token to be entirely hex and MINQHEX to the longest loaded digest long, which is true of almost nothing in somebody else's list: a 63,042-line hashmob unsolved file is hash colon salt on every line and read as 63,042 lines ignored, 0 of 0 hashes, no hits. That is the worst shape a diagnostic can have, because a wholly-skipped input is indistinguishable from an index with nothing in it. New first_hex_run finds the FIRST maximal run of ASCII hex at least MINQHEX long and extends it to the first non-hex byte, which is how mdxfind reads its hex, so no separator can be inside the run. A run SHORTER than the minimum is stepped over rather than failing the line, and that is what lets a login through: the a of alice colon is a hex run of length one and the digest after the colon is the first run long enough to be a digest. Interior whitespace is no longer cut either, only the line ending, so a digest in a later column is found; cutting at the first space is what used to hide it. A run longer than the longest digest the open index holds is counted as ignored rather than TRUNCATED to fit, because a truncated run is a query nobody asked for and at fifteen billion records it would occasionally match and be reported as a hit. Deliberately literal about first, too: scanning on to a later shorter run after rejecting an over-long one would make which field gets looked up depend on the index contents rather than on the line. Measured on the file that prompted this: 62,964 of 63,042 lines now parse against 0 before, 1,983 hits over 1,026 distinct hashes in 123 seconds at 511 lookups per second. The 78 ignored are accounted for exactly: 77 lines have no hex run of 16 or more at all, ETL colon being one, and one line leads with a 128-character run which this index cannot answer for since its longest digest is 64. Checked rather than assumed that the repeated output lines are input multiplicity and not double emission: the input holds 56,587 distinct hashes across 62,964 parsed lines, one hash appears 5 times and the output repeats each hit exactly as often as the input asks for it, which is the existing contract that lines printed and hashes answered are two numbers. The diagnostic said not 16 to 64 hex characters, which named a test the program no longer makes, and now says no run of 16 to 64 hex characters. skip_leadin is left in place and now serves the ARGUMENT path only, where a partial query typed by hand is deliberate and runs at any length. Its stdin consequence has changed and the comment says so: a salted dollar dynamic_1 line used to keep its trailing salt, fail the hex test and be COUNTED as ignored, and now its digest is found and looked up as if unsalted, so it reads as an ordinary miss. That is the price of reading a noisy list at all and it is the same trade every hash colon salt line in such a list already makes. Seven selftest checks cover the run extraction, including the one case where the first long run is NOT the hash: a phpass MCF in field one is not hex, so field two is what gets looked up, 4 lines in the 63,042-line sample. The terminal path is untouched and still takes one typed token. selftest passes.
 *
 * Revision 1.34  2026/10/20 17:21:08  dlr
 * Three reproduced traps: a lost word, a raw plaintext, and a stale overlay. Reported against 1.32 by Waffle, all three reproduced here before being touched. FIRST, a word was lost whenever an update met a source whose last line had no terminator. consumed was set to the file SIZE, which asserts that the final partial line is finished, so the next update began in the middle of a word: a file ending bet, with a-newline-gamma-newline appended, indexed bet and then a and never beta. Two words were unreachable, not one -- bet had a record too, naming an offset that now reads beta and fails its re-hash. consumed_to now stops at the byte after the last newline, so an unterminated tail is re-read until it is terminated, which costs a few re-hashed lines that dedup drops. The tail is still INDEXED at build, so a file that simply ends without a newline keeps its last word. The fingerprint had to move with it: it was taken over size while files_check recomputes over consumed, and the mismatch made every source read as rewritten. SECOND, plaintexts were printed raw. needs_hex was correct and matched mdxfinds own dohex rule, but emit_hit never reached it: every type sets verbatim, and that branch printed the source line and returned. A colon made the line ambiguous, a high byte went out unwrapped, and a NUL TRUNCATED the plaintext -- printf stops at a NUL whatever precision it is given -- so the line claimed a word that does not produce its hash. All output now goes through emit_line, which writes with fwrite rather than a precision conversion and wraps on mdxfinds rule: any byte below 0x20 or above 0x7e, or a colon. The verbatim path applies only the BYTE test, never the wrapper-prefix test, because an already-wrapped line is plain ASCII and re-wrapping would double it. THIRD, a build left the previous overlay in place. add.rec describes words at locators in the OLD sources; at best its records are rejected one at a time, and at worst its locator names a source the new manifest does not have, which is fatal at the first lookup -- FATAL record names file index 1 of 1, on a database build had just reported as finished. check calls such an overlay clean, because every record in it is well formed; what is wrong is that it belongs to a database that no longer exists. build now unlinks it. Verified: beta resolves and so do its neighbours, a file ending without a newline keeps its last word, a colon, a high byte and an embedded NUL all emit as $HEX[] and pass hashpipe -c, a rebuild after an update leaves no overlay and no FATAL, selftest passes, and both live databases read and check unchanged.
 *
 * Revision 1.33  2026/10/20 17:03:56  dlr
 * Index the HUM families: a second enumerated domain, and a reported salt that differs from the bound one. The seven HUM types were absent from every index because they carried no hx expression; with hx.8 1.98 supplying one they need the enumeration machinery to generalise. enumsalt was a flag meaning walk the 256 two-hex salts and is now enumdom, naming a domain, with hex2 and humsep behind edom_count and edom_value. humsep is eight line-ending sequences held as HEX because the first is a NUL byte, which the expressions decode with fromhex. The substantive change is that the value BOUND to salt in the expression and the value REPORTED in the output line are no longer the same thing. For hex2 they coincide. For humsep mdxfind prints the separator followed by the inner-iteration index, 0d0a- x 1, and reporting the bound value instead would emit a line hashpipe cannot verify. hout.salt grows from 8 bytes to 24 to hold it; at 8 it could not have held 0d0a- x 1 at all, and the %s would have run past the array. An unknown domain in a manifest is fatal rather than ignored, because a domain this build cannot walk would index one digest per word where the database holds sixteen and answer for a fraction of itself without saying so. N, the inner iteration, is not indexed: mdxfind emits x 1 by default and that is what all 112 vectors are, so a deeper N would multiply the set again. -H all goes from 544 types to 551 and from 4,884 records per word to 5,026, a 2.9 percent rise. Verified: 112 of 112 digests found, all 112 emitted lines byte-identical to mdxfinds including the salt field, all 112 verified by hashpipe, HEXSALT unchanged, selftest passing, and the live index still reads and checks clean through the old hex2 manifest row.
 *
 * Revision 1.32  2026/10/20 15:04:00  dlr
 * Clear hout.salt before a variant slot is filled. emit_hit chooses between hash colon plain and hash colon salt colon plain by testing salt[0], and the six native arms never wrote that field: h_md5 and the rest set dig, plain, plen and verbatim and nothing else, while the hx path always set it because slen is zero for a type that enumerates nothing. hv is a per-thread heap buffer reused for every word, so an ordinary type read whatever was left there. Undefined behaviour, and platform-dependent in the worst way: macOS hands back zeroed pages so the branch never fired and the defect was invisible to every test run here, including the full selftest, the Windows selftest under wine, and 1081 types cross-checked against mdxfind. On Linux a plain MD5 lookup printed MD5x01 5f4dcc3b...cf99 colon 09cb7 tab ba! colon password -- a salt field full of debris in front of a correct answer, on a type that has no salt -- and the %s ran past the eight-byte array as well, nothing having terminated it. Cleared for every slot at the top of type_hash rather than in each of the six arms, so both paths are covered and a seventh arm cannot reintroduce it. Found by building the published tree from a clean clone in Docker on 192.168.22.213, which is the only configuration that could see it. Verified on Linux: the same lookup now gives cf99 colon password byte for byte, natively and through the container, the enumerated SHA1HEXSALT still reports its salt as 476649c6...:0a:098765, and the selftest passes on Linux, macOS and Windows.
 *
 * Revision 1.31  2026/10/20 13:52:55  dlr
 * Windows port. mdindex now builds and passes its whole selftest as a native x86_64 Windows binary, verified under wine on the cross-compile host: 78 lines, 0 failures, exit 0, identical to the macOS run, plus build, lookup, update and compact exercised by hand including the new LM and SQL3 bridges. mdindex_win32.h carries the shims and is included only under _WIN32. pread is the one that matters: the obvious _lseeki64-then-_read is WRONG here because sixteen scatter threads share one descriptor per source and a lookup shares Srcfd, so seek-then-read is two operations against one shared pointer and the result is not a crash but a correct-looking index built from the wrong bytes; OVERLAPPED carries the offset into the read so the pointer is never consulted, which is the guarantee POSIX pread makes and the only reason sharing a descriptor is allowed. mmap is CreateFileMapping plus MapViewOfFile, read-only and shared, which is the only form used. statvfs is GetDiskFreeSpaceEx for the projections free-space check. Also stat as _stat64 since every file here is past 2GB by design, mkdir, realpath as _fullpath, sysconf as GetSystemInfo, nanosleep as Sleep, mkdtemp, and open through CreateFileA with FILE_SHARE_DELETE so an open descriptor does not block a rename or unlink as it does not on POSIX -- carrying the mode flags onto the descriptor, _O_BINARY above all, because _open_osfhandle defaults to TEXT and a translated byte in index.rec is a corrupted record. FOUR DEFECTS THE PORT EXPOSED, three of them platform-independent and live on every platform. First and worst: a CRLF wordlist was indexed with the carriage return as part of the word. mdxfind strips it, so mdindex was indexing digests of password-CR that mdxfind never produces and no query could match, on Linux and macOS as much as on Windows; both the scatter and fetch_line now strip it, and they must agree because the lookup re-hashes the line it fetched. Second: index_map leaked the previous mapping every time it was called again, which update and the selftest both do; harmless-looking on POSIX and fatal on Windows, where the stale mapping holds index.rec and compacts rename over it fails after the entire merge is done. index_map now releases first, and index_unmap exists for that and for compact. Third: emit_index renamed index.rec.new over an index.rec the caller still had open; POSIX replaces an open file and Windows refuses, and not for want of sharing -- MoveFileEx with MOVEFILE_REPLACE_EXISTING returns ERROR_ACCESS_DENIED on an open target even when the handle carries FILE_SHARE_DELETE, confirmed with a standalone test. emit_index now consumes oldfd and closes it before the rename. Fourth, in the selftest: freopen of /dev/null and /dev/tty around the silenced commands lost stderr entirely on Windows and was wrong on Unix too, since /dev/tty reopens the terminal rather than restoring, so mdindex selftest redirected to a file sent everything after the first silenced block to the tty instead. Replaced by st_hush and st_speak, which save and restore the descriptor and put back a pipe, a file or a tty alike. The two-pass getopt also went, replaced by collecting -H and resolving it after the loop: rewinding getopt needs optreset, which glibc spells as optind = 0 and mingw does not declare at all, and one pass has no state to rewind. renames are MoveFileEx with REPLACE_EXISTING rather than remove-then-rename, which would compile and appear to work while destroying the atomicity every write here depends on. Windows ARM64 is not built yet although the toolchain is present.
 *
 * Revision 1.30  2026/10/20 13:06:09  dlr
 * Accept John dynamic labels in -H, and skip a non-hex lead-in on input. john_map.h maps a dynamic label to the hashpipe type name, which is the same namespace as a canonical name here, so the label resolves through the path already built rather than needing one of its own; the mapped name carries its iteration, dynamic_2 being MD5x02, so the xNN is split off and takes the same route md5:2 takes. Of the 132 portable labels 96 are indexable and 36 are refused for the ordinary reason, a salt or a userid they cannot supply. JohnMap only, never JohnMapLocal: the local table is read from whatever dynamic.conf sat on the machine that ran the generator and its numbering is machine-local, so selecting a builds types through it would mean one -H line naming different types on two machines; john_map.h says the same of john_label_for, and the reason is recorded at the site. Diagnostics now report the label the OPERATOR typed rather than the catalog name it mapped to -- an error naming MD5PASSSALT when the command line said dynamic_1 sends the reader looking in the wrong place. The input side needed the other half, because a John hash is not a bare digest: the line is $dynamic_0$<hex>, sometimes with a login in front of that, and both forms were counted as ignored. The digest begins after the SECOND dollar in every $tag$ form whatever precedes the first, so that is where skip_leadin resumes, and it is applied only when the lead-in was the reason the line did not parse, so a line that already read as a digest is never re-read as something else. A TRAILING field is deliberately left attached: in a John line it is the salt, and a salted digest is not something this index holds, so leaving it makes the line fail the hex test and be counted as ignored rather than looked up as if it were unsalted and reported as an ordinary miss. Four selftest checks cover the lead-in, the login in front of it, the bare digest and the trailing salt. Verified against the live index: $dynamic_0$ with an md5 and with a sha1, alice:$dynamic_0$ with an md5, and a bare digest all resolve identically, and a salted dynamic_1 line is reported as one input line ignored.
 *
 * Revision 1.29  2026/10/20 12:56:48  dlr
 * Bridge lm, mysql3 and murmur64a, and refuse a digest narrower than the index key. lm is a library, lm.a, which mdxfind already links and mdindex now links too; it does not upper-case or truncate, so the bridge does both before calling exactly as mdxfind does. mysql3 and murmur64a are static inside mdxfind.c with no library behind them and are transcribed, the only two primitives in the bridge file that are not a call into someone elses code; both are frozen legacy algorithms, MySQL pre-4.1 OLD_PASSWORD and MurmurHash64A, so there is no moving target, and each was checked against mdxfinds own output before use. That is the last of the unbridged primitives. The bare forms of two of them cannot be indexed and are now refused rather than silently mis-keyed. mysql3 and murmur64a are EIGHT bytes and the index key is twelve: the scatter copies KEYSZ bytes out of every digest, so a shorter one is read past into whatever the probe left in the struct, the keys do not reproduce between runs, and the type simply stops being found after a rebuild with nothing saying why. The selftest has asserted that invariant over the selected set since the key went to 96 bits, but nothing enforced it at selection, so it was an assertion about types that happened not to exist yet. It is enforced in sel_add_hx now and MYSQL3, MURMUR64A and MURMUR64AZERO fall out of -H all by that rule rather than by a list. This is also the structural form of Waffles caution that mysql3 will false-match many hashes: 64 bits of digest against an index keyed on 96. The types that NEST these are unaffected and are indexed, md5 of mysql3 of pass being an ordinary 16-byte MD5, which is why the primitive is bridged and only the bare form refused. -H all goes from 532 types to 544. Verified against mdxfind -z over LM MD5LM MD5LMUC MD5-LMNTLM MD4SQL3 MD5SQL3 SHA1SQL3 RADMIN2SQL3 MD4UTF16SQL3 and MD5SQL3SQL5MD5MD5: 40 of 40 digests identical under the same names. The LM family reports the source word where mdxfind reports the upper-cased one, because mdxfind upper-cases in place and then prints what it hashed; both verify through hashpipe, and the source word is what the wordlist actually holds.
 *
 * Revision 1.28  2026/10/20 12:43:35  dlr
 * Percentages in the two build phases and the update probe, and nowhere else. Plan step 0 had a progress half that was never built: the scatter poller and the emit_index partition line printed raw counts with no denominator in view, and the update probe printed nothing at all. The probe is the one that matters, being the slow half of an update at one random seek per new word against an index far too large to cache -- a measured 145 a second, 279 of one nights 279.3 seconds, with an empty terminal throughout. Percent is integer and written only when it changes, so a loop over billions of records costs at most 100 writes, the same discipline as rling.c:1414. Deliberately NOT on the query path. Waffle: we do not want progress indicators during lookup, ever; only during build or update. A lookups stdout carries solutions and is meant to be piped, and a progress line scrolling past in the middle of that is noise to a pipeline with no use for it. checks existing bucket counter is left as it is, being a maintenance command rather than a query and predating this. The scatter poller already ran at 4 Hz off the workers volatile done counters so the percentage went there rather than into the workers, one writer to stderr as before.
 *
 * Revision 1.27  2026/10/20 12:34:09  dlr
 * Project the build cost before writing anything, and refuse when it will not fit. Plan step 0, which was never built: with a user-chosen type set the index size is user-chosen too, e183 alone over 4.1 billion lines being about 3.2 trillion records and 47 TB, and until now nothing said so. A build filled the filesystem and found out at the first write that failed, with scratch spread over 256 partition files. Two cheap measurements decide it. Lines come from count_newlines, taken from mdxfind rather than reimplemented so the two tools cannot disagree about the same file, with AVX2 behind a runtime check, NEON on ARM and a scalar tail; only the unindexed tail is counted, because a nightly update that appends 422 KB must not pay for a pass over 53.5 GB. The count is looked up in and written to mdxfinds own SQLite line cache keyed on path, size and mtime, so the pass usually costs nothing; MDXFIND_CACHE is the only input, there is no default path and no search, and a row is stored only for a file counted to its end because a partial count persisted from an interrupted run poisons every later session and looks exactly like a good row. Records per line is observed rather than assumed, by hashing a sample of the real input through the selected types, because the ratio depends on the non-ASCII share and on whether an enumerated type is selected. Peak is scratch plus the new index plus the old one, which survives until the rename. The threshold is a tenth of free space rather than a fixed size, because a build runs for hours while other things write to the same volume and the reading is a moment in time rather than a reservation; -y proceeds. Verified on a 1 GB volume: the refusal fires, exits 1 and writes nothing, and -y proceeds and then genuinely fills the disk. Accuracy against the 1059-type build is 48,925,829 projected against 48,924,912 actual before dedup, and exact at 60,006 for the default six. Two defects found and fixed while testing. The sampler gated on md_unwraps return, which says whether a WRAPPER was decoded and is 0 for a plain literal line having already pointed at the line itself, so every unwrapped word was skipped and the ratio fell back to one record per type -- a number that is right for a six-type build, which is why the first test agreed, and wrong by 4.6x the moment an enumerated type is selected. And the sample was budgeted in lines, which costs 4,892 times more against the identification set than against the default six and put 17s of sampling in front of an 8s build; it is budgeted in digests now, with a line floor so the non-ASCII share is still visible, and the overhead is 1.2s.
 *
 * Revision 1.26  2026/10/20 12:11:53  dlr
 * Add -C for user-defined hash types, u<id> selection, and -V. A -C file is a stanza file in the format mdxfind reads as userdef.txt, and the shared loader now has an explicit-path entry point, userdef_load_file, so both tools parse the same file with the same code rather than mdindex carrying a second parser that could drift. The file is named outright: no search path, no default, MDXFIND_CACHE not consulted, because this file decides what an index MEANS and a different file answering to the same name later would reinterpret records already on disk. For the same reason -H u47 writes the expression into the manifest as an ordinary hxtype row, plus an hxuser row recording the id and the file it came from, so -C is needed to build and never to read: lookup, update, info and compact all take their types from the manifest. Verified by changing the expression under a built index, and by deleting the file entirely, both of which leave lookup answering exactly as built. Two places where a user type is NOT a catalog type. First, an expression naming salt is refused permanently rather than provisionally: the catalog HEXSALT family has an mdxfind arm enumerating its own salt and a user type has no arm at all, so the two refusals carry different messages and a comment at the site says not to reconcile them. Second, iteration runs the opposite way. A catalog type repeats its OUTERMOST call over the previous digest; a user type has no arm, so mdxfinds generic loop re-runs the WHOLE expression with pass bound to the previous digest. Building it the catalog way gave an index that self-tested clean and matched nothing mdxfind emits. expr_subst_pass rewrites standalone pass outside string literals and expr_iterate_user chains the rounds through temp bindings so an expression naming pass several times still computes each round once. Verified against mdxfind -z -i 3 for two user types: 24 of 24 digests identical under the same names. -C and -H are order-independent, so option parsing is now two passes. -V prints the version the way mdxfind does. Diagnostics print a user type as its own u-id rather than a synthetic e-number that matches no catalog entry. Selftest unchanged and passing; the live 1059-type index still reads, checks clean and answers identically.
 *
 * Revision 1.25  2026/10/20 04:36:17  dlr
 * Choose which of a duplicate pair is reported by job and iteration, not by selection order. Two types that differ only in an output form are one digest once it is stored as bytes, and one of them has to go quiet; which one was decided by whichever the selection reached first, and that is not mdxfind's order. mdxfind runs its types in job order and the first to solve wins, so the lower job, and within a job the lower iteration, is the name it prints. Selection order is not that order, because -H all adds every type at x01 before any at x02: MD5x02 arrived to find MD5UCMD5x01 already in the table and went quiet, leaving md5_uc of md5 of pass to report a digest that is plainly MD5x02. The scan now looks for the REPORTED member of the equivalence class rather than the first match, since a class may already hold several quiet members, and flips it when the newcomer is lower. The suppressed set is now eleven and every one is a higher-numbered alias of the type that reports it: MD5UCx01 to MD5x01, SHA1UCx01 to SHA1x01, SHA256UCx01 to SHA256x01, MD4UTF16x01 and NTLMH to NTLMx01, MYSQL5MD5x01 to SHA1SHA1RAWMD5x01, MD5UCMD5x01 to MD5x02.
 *
 * Revision 1.24  2026/10/20 04:32:59  dlr
 * Dedup on the word, not on the digest alone, so two words whose digests collide both survive. md5(md5(password)) and md5(md5(rev(drowssap))) are the same 128 bits. Keying dedup on the digest kept one record, and the loss was unrecoverable: lookup regenerates types only for the line the surviving record names, so a full-digest query for MD5x02 answered MD5revpx02 with a different password -- true, and useless. Dedup now compares the whole scratch record, and on an equal key with differing locators it reads the two source lines and lets the TEXT decide: identical text is the same word met twice, which priority says to keep once and which is what holds the index to its size when sources overlap, while differing text is a collision and both records are kept. Collisions and overlaps are the only paths that read a line, so the two seeks are rare by construction. The same rule now governs the overlay's main-index filter, which previously dropped a new word whenever the main index held its key under a different word. check follows: the invariant is strictly increasing on the whole record, since an equal key with a higher locator is now legitimate and ascending, and what must never repeat is a whole record. Also fixes a latent hazard the work exposed -- Srcfd is reset to -1 at the end of index_map, but build calls emit_index BEFORE index_map, so a zeroed array meant descriptor 0 and a fetch on that path would have pread stdin; it is now initialised where it is used. And -i now reaches a native type's deeper round, so MD5x02 is selectable beside MD5x01. Selftest 57 checks; the equal-key case was rewritten to the new invariant and two cases added, an identical record and an equal key with a lower locator. Verified: the colliding pair now returns both words under both types, a word in two files still indexes once, the live six-type database still answers and its overlay checks clean.
 *
 * Revision 1.23  2026/10/20 04:15:29  dlr
 * Iterate the final statement of a multi-statement type, and add hxeval. A type written as h=md5(pass); md5(h . h) computes a seed in its prelude and hashes it in the final statement, and mdxfind then falls into the ordinary loop: JOB_MD5_2xMD5 builds the doubled hex and goes to MDstart. So the round repeats the FINAL statement's outer call and the prelude is computed once; iterating the whole expression recomputes the seed every round and gives a different hash. That alone took the depth-2 shortfall from 81 labels to 57, and with the step declarations now in hx.8 it is 1 of 1044, the remainder being the enumerated HEXSALT family, which has its own loop and is not yet iterated, and SHA1lsb32, whose outermost construct is a concatenation and so has no step to repeat. tools/hxeval evaluates an hx expression with mdindex's full primitive set, which the standalone hx cannot do because it lacks the bridges; it exists so a candidate step can be compared against mdxfind generate mode, which is how all 39 new steps were found.
 *
 * Revision 1.22  2026/10/20 03:38:12  dlr
 * Index enumerated types, and add -i. The HEXSALT family supplies its own salt rather than taking one, so its digests stay a function of the password alone and it is indexable at 768 per word: 256 two-hex salts over three shapes. A type whose expression reads salt is still refused unless the catalog declares the domain, because an externally supplied salt is not known at build time and never will be. The shapes, the domain and the per-word enumeration are carried through the manifest alongside the expression, since an index built over 768 digests per word and read back as one would answer for a fraction of what it holds. The matching salt is reported in the output line as hash colon salt colon plain, which is the shape mdxfind prints and the only one that re-verifies; hashpipe accepts it. Separately, -i depth indexes iterations 1 to depth. mdxfind iterates by applying a type's OUTERMOST function again to the previous round's output, so iteration 2 of md5 of sha1 of pass is md5 of md5 of sha1 of pass, not the whole expression nested; the two readings agree for one-call types and disagree for every composite, which is why the old substitution passed MD5x02's vector and was wrong everywhere else. Checked against mdxfind for MD5SHA1 at x02 and x03 and for SHA1UC, whose uppercase hex is what gets carried. A chain carrying something other than its printed output declares a STEP; a type with no single outermost call has no step and stays at depth 1; an enumerated type has its own loop and is not iterated. Depth is absolute in the xNN, so a chain whose first round is x02 yields x02 and x03 at -i 3. Verified: 768 of 768 digests found for each of e183, e184 and e185, and -i 3 over e178, e182 and e383 reproduces exactly the seven labels mdxfind emits.
 *
 * Revision 1.21  2026/10/20 03:24:29  dlr
 * Honour a type's admission guard, at build and at lookup alike. e732 SHA1UTF7 is SHA-1 of the UTF-7 encoding, and mdxfind skips any word whose UTF-7 form is the word itself -- every ASCII word -- because the digest would be a plain SHA-1 wearing another name. mdindex built the type from its expression alone and so reported 7,176 SHA1UTF7 answers over a ten-thousand-word ASCII list, none of which mdxfind would ever produce. The condition is not visible in the expression or the bytecode, so hx.8 now declares it as a GUARD comment beside the row and gen_hxcat carries it through; the guard is compiled with the type, runs per word before the digest, and a word it rejects yields no record. It is written into the manifest as its own row and compiled back on read, because a database that answers differently from the way it was built is worse than one that answers less -- without that, build excluded the records and lookup reported the type anyway. A guard that no longer compiles is fatal for the same reason.
 *
 * Revision 1.20  2026/10/20 03:17:16  dlr
 * Refuse two classes of type that were being indexed with wrong or redundant digests. A type whose expression reads salt, salt2, pepper or userid is one mdxfind supplies those values for, and for the f-only types that reach here it supplies them by ENUMERATING them: e184 SHA1HEXSALT walks all 256 two-hex salts over three shapes and emits 768 digests for one word. mdindex bound every slot but pass to the empty string, so it indexed sha1 of pass concatenated with nothing, which is not a member of the family, duplicates SHA1x01 and matches no real SHA1HEXSALT hash. Six types were affected, the five HEXSALT families and e283. They are refused until the enumeration is implemented; TypeOpts remains the authority on what is indexable in principle, and these are, at 256 times the records. Separately, two expressions differing only in an output role compute the same BINARY digest, because mdindex hex-decodes whatever hx returns and keys on the bytes: sha1_uc and sha1 are the same index content at x01 and diverge only from x02, where the uppercase hex is what gets rehashed. Those are now indexed once, under the first name. The test needs both halves, because AICH reduces to SHA-1 for any message short enough to be a password but is a different algorithm that mdxfind does report, so it is kept: a duplicate must match on two probe digests AND on its bytecode once roles are ignored. Fifteen types left the default selection and index.rec did not change by a byte, which is the check that they were contributing only duplicates.
 *
 * Revision 1.19  2026/10/20 02:29:21  dlr
 * Register the hash primitives hx's own registry leaves to the caller, lifting the indexable catalog from 334 types to 534. hx_func built standalone implements md5, md4, sha1, sha256 and sha512 against OpenSSL and nothing else; hashpipe supplies the rest by registering its compute_ functions, but those read a thread-local workspace only hashpipe has, so mdindex registers its own against the same libraries mdxfind calls -- libsph for the blake, bmw, cubehash, echo, fugue, groestl, hamsi, haval, jh, keccak, luffa, shabal, shavite, simd, skein, md2, panama, radiogatun, ripemd, sha0, tiger and whirlpool families, librhash for has160, tth, ed2k, aich, gost, snefru, edon-r and sha3, mhash for the two wide RIPEMDs, OpenSSL EVP for sm3, blake2s256 and mdc2, md6.h for md6, and mdxfind's own gost2012 entry points for Streebog so the byte order is settled by construction. Registration runs before any expression is compiled, because hx resolves a function name to a table entry at compile time. Also fixes two defects the verification found: the manifest types line outgrew the 8 KB read buffer at 534 types, so a wide manifest was split by fgets and its tail parsed as a source row, reporting a good database as malformed -- the buffer is now sized for the whole catalog and a line that still does not fit is fatal rather than silently split; and radiogatun32 was declared 32 bytes where mdxfind passes checkhash a length of 32 HEX CHARACTERS, so the type is the first 16 bytes truncated. Verified against both oracles: every one of 532 emitted lines re-verifies through hashpipe, and cross-checked against mdxfind's own generated vectors for all 533 selected types, mdindex reproduces every type mdxfind names except six whose mdxfind line label carries no iteration suffix and one whose output is hash colon salt colon plain.
 *
 * Revision 1.18  2026/10/20 02:15:39  dlr
 * User-selectable hash types through hx. The six native arms stay exactly as they are and an hx type is added ALONGSIDE them, so an existing database keeps byte-identical behaviour by construction rather than by a test; replacing them is a separate change. Htype is now a runtime table instead of a static array with a 32-bit Tmask, because the catalog is far wider than a machine word. -H names a type by canonical name, by mdxfind eN, by hashcat mode or as all, with a trailing colon N for the iteration; a native arm wins for the same type and iteration so e259, 300 and SQL5 all still give SQL5x01, whose catalog expression is MySQL's display form and not a digest. Eligibility is a predicate over two generated tables, mdxfind's TypeOpts and a slimmed catalog, so a corrected flag makes a type indexable with nothing here to edit: 620 of 1061 are a function of the password alone and 334 of those compile and probe clean in this build. Every type is proved before a record is written, by running it over two words and requiring a fixed-width hex digest that changes with the password; that rejects stored forms and parameterised entries, and a type that will not compile is fatal on build and update alike. Each worker gets its own hx_vm array over the shared read-only programs, and the variant buffer leaves the stack. The manifest records each hx type's expression in full, so update reconstructs the type rather than trusting the catalog to still agree. Verified: all 55 selftest checks, the live six-type database still answers all six vectors, and every one of 334 types round-trips through hashpipe.
 *
 * Revision 1.17  2026/10/19 17:19:07  dlr
 * $TESTVEC[] gets its own buffer, so UNWRAPBUF no longer bounds an expansion.
 *
 * 1.16 shrank UNWRAPBUF to 131,136 and left $TESTVEC[] expanding into the same
 * buffer, so md_unwrap refused any vector over that size although TESTVECSIZE
 * is 2 MB and hashpipe expands it. That was a divergence between the two tools
 * introduced by sharing one buffer for two unrelated jobs, and the diagnostic
 * was incoherent with it: the refusal prints TESTVECSIZE while the condition
 * that fired was the outmax arm, so a 200,000 byte vector was reported as over
 * a 2,097,152 byte limit.
 *
 * The two caps are now independent, which is what mdxfind.c and hashpipe.c
 * already do. UNWRAPBUF bounds the HEX decode only, where it is derived from
 * LINECAP and so unreachable for an accepted line. A vector expands into a
 * TESTVECSIZE buffer that md_unwrap allocates on first sight of one and never
 * again, held by the caller and freed with its other per-thread buffers. Only
 * one vector is ever in flight per thread, so one buffer is enough, and a
 * wordlist containing no vector never allocates it at all. TESTVECSIZE is
 * again the only bound, and over it the refusal stands: a shortened vector
 * hashes to a well-formed digest for a word that was never presented.
 *
 * Verified end to end on the case 1.16 refused. A source holding
 * $TESTVEC[41 x 200000] between two short words indexes 17 records -- three
 * lines, six types, less the NTLM reading that declines a 200,000 byte
 * password -- and the digest resolves to the line in its stored wrapped form.
 * That digest equals an independent python md5 of 200,000 A bytes, and the
 * emitted line round-trips through hashpipe, which is the parity the shared
 * buffer had broken. 1.16 on the same input exits FATAL. Selftest gains four
 * checks: the buffer is NULL until a vector is met and non-NULL after, and a
 * 500,000 byte vector expands while the decode buffer passed alongside it is
 * 256 bytes, which fails on any build where outmax still reaches the
 * expansion.
 *
 * mdindex.1: correct the paragraph that documented the divergence.
 *
 * Revision 1.16  2026/10/19 17:13:19  dlr
 * LINECAP 256 KB, and a line past it is dropped rather than fatal.
 *
 * LINECAP was 16 MB and UNWRAPBUF derived from it at 8 MB, which made pass a
 * value of up to 8 MB rather than the 13-byte average these sources actually
 * hold. Every buffer sized from those constants was sized for a case that does
 * not occur: per thread the read buffer was CHUNK+16 MB and the decode buffer
 * 8 MB, so sixteen workers reserved about 640 MB. At 256 KB the same workers
 * reserve about 262 MB. UNWRAPBUF still derives as LINECAP/2+64, now 131,136,
 * so the relationship a HEX line of full length denotes half its length is
 * unchanged and the payload-too-large branch stays unreachable for accepted
 * HEX input, which is the position hashpipe.c is in.
 *
 * A line longer than LINECAP was FATAL. One malformed record in a four billion
 * line source should not end a two-hour build, so it is now dropped: the
 * buffered bytes are discarded and the reader scans forward to the newline
 * that ends the line. Dropping is not silent in aggregate. Each worker counts
 * its drops, scatter_file sums them and prints the total per source, because a
 * word that was skipped cannot be told at lookup time from one the index never
 * held, and a drop that left no trace would read as data loss. Two sites: the
 * no-newline-in-buffer path, and the tail of a region where the last line has
 * no newline at all and was previously accepted at any length.
 *
 * One deliberate divergence. A TESTVEC expands independently of the length of
 * the line that writes it, so UNWRAPBUF now binds it before TESTVECSIZE does
 * and a vector denoting more than 131,136 bytes is refused here although
 * hashpipe would expand it. TESTVECSIZE stays at 2 MB because it is the
 * hashpipe parity constant; the divergence begins at 128 KB of password and is
 * noted at the definition.
 *
 * Verified: a source holding two 300,000-byte lines interleaved with alpha,
 * omega and zeta indexes 3 lines and reports 2 dropped, gives 18 records for
 * 3 lines times 6 types, scans clean, and all three words answer -- including
 * omega between two dropped lines and zeta after one, which is the resume path
 * the change turns on. Selftest passes. solved.words measured: longest line
 * 438 bytes.
 *
 * mdindex.1: document the cap, the drop and its count, and the TESTVEC
 * divergence.
 *
 * Revision 1.15  2026/10/19 02:23:45  dlr
 * Probe the main index once per source line, not once per record. Keeping an already-indexed word out of the overlay is the entire cost of an update: the first live run spent 279 of its 279.3 seconds on 32,442 probes, at a measured 145 random probes a second on this volume. Those 32,442 records were 4,448 lines. A line yields one record per type and every one is the same word, and a build indexes every configured type of every line, so if any one of a lines keys is in the index then all of them are and one probe decides the group. Group by locator, filter, then sort back into key order for the merge. The merge itself no longer probes at all: a record already in the overlay cannot be in the main index, since that is the invariant the filter maintains and compact empties the overlay rather than merging the two sets. That removed a probe per existing overlay record per night, which is nothing today and grows with every night without a compact. Verified: 30,000 probes for 30,000 appended lines where the old code made 116,994, overlay identical at 116,994 records, lookup output over 5,514 queries identical to a full-rewrite update both before and after compact, and compact still reproduces the reference record count, directory and key sequence exactly. Measured alternative rejected: 8 threads raise the probe rate to 280 a second and 16 and 32 do not improve on that, so parallelism was worth 1.9x against the 7.3x here. The selftest appends the repeated word FIRST, so it is the line a too-coarse grouping would probe, and losing the two new words behind it fails four checks; confirmed against a build with the grouping removed.
 *
 * Revision 1.14  2026/10/19 02:12:05  dlr
 * Two-way merge in emit_index, and an overlay so update stops rewriting the index. emit_index sorted the union of the old index and the new records, which meant sorting 59 million records per partition to absorb 30 and expanding every old record into scratch form to do it. Both sides are already sorted on the whole scratch record, so they are merged instead: byte-identical output, verified against 1.13 on a plain build and across two update generations including a new lowest-priority file and 156,246 cross-file dedup drops. The larger problem is that index.rec is a packed sorted array, so absorbing one word costs a read and a write of all of it: the measured night was 1,197 lines holding 164 records not already indexed, at 452 GB and 36 minutes. update now writes only add.rec, a sorted array of 18-byte scratch records with no directory, binary-searched; lookup answers from both. It drops any record whose key index.rec already holds, so the overlay tracks new words rather than lines read, which on that night was 164 against 7,568. compact folds it back in through the merge and is the only command that rewrites index.rec. Verified: lookup output over 5,514 queries is identical to a full-rewrite update, and compacting gives the same record count, a byte-identical directory and a byte-identical key sequence. check takes index, overlay or all, because an update cannot have changed index.rec and a nightly 226 GB re-read to prove it is a check that gets switched off. Manifest v4; v3 is read unchanged since index.rec is untouched, and the first write upgrades it so that a v3 binary refuses the database rather than silently ignoring the overlay. Selftest covers the overlay and compact, and both new checks were confirmed to fail against a build with the overlay probe removed and one with the main-index test removed.
 *
 * Revision 1.13  2026/10/18 12:53:09  dlr
 * Fold the sort-order scan into mdindex as a check command. The index rests on index.rec being sorted, and the only verifier of that was a standalone binary with the record size compiled into it: after the v3 widening it still read 11-byte records and reported all 16,777,216 buckets unsorted on a good index, which is a checker disagreeing with the writer rather than a finding. check is built from the same RECSZ and RESID as emit_index, so it cannot drift again. It also tests the stronger invariant: inside a bucket the records are STRICTLY increasing on the key, because dedup removed every repeat, so a descending pair is a sort failure and an equal pair is a dedup escape. The old scanner compared whole records and so could not see a dedup escape at all. Validated before being trusted, both ways: the width tests fail on a deliberately narrowed and a deliberately widened comparison, and a real 359,484-record index with 3,818 multi-record buckets scans clean, then reports the right bucket and the right fault class when one pair is swapped and when one key is duplicated. The whole-index pass in the selftest is marked as the vacuous test it is on an index that small.
 *
 * Revision 1.12  2026/10/18 05:33:30  dlr
 * Print a partial-query hit once per query, not once per matching record. One LINE can answer one query through several records, because the query is a prefix and the line carries a key per type: the query 5 matches password by its MD5, SHA-1 and SHA-256 keys at once, three candidates at a single locator. The line is read once and every type regenerated from it, so each repeat produced a byte-identical output line -- the query 5 printed 10 hits where 4 are real, and the duplicates also inflated Ncand and the fetch rate. Collapsed in the candidate array after the sort, where a repeated locator-and-query pair is meaningless by construction, rather than guarded at emit_hit, so the statistics count work actually done. A full digest never reached this, since only one record's key can match it; it took a query short enough for two of one line's keys to match, which is argv and terminal input only. Selftest asserts that no answer appears twice, and was confirmed to FAIL against a build with the collapse removed.
 *
 * Revision 1.11  2026/10/18 05:14:36  dlr
 * Widen the key to 96 bits so two words that collide in 64 both survive the build. Format v3, no upgrade path; a v2 index is refused with the rebuild instruction. Dedup compares keys and never sees the plaintext, so at 64 bits it could not tell a repeated word from two distinct words whose digests collide, and it dropped one of the pair -- an expected 6.2 losses in a six-type index. The loss was invisible twice: a half-MD5 could not return both words, and a full-digest query for the loser returned nothing, with no staleness ALERT because that check only fires at or below KEYBITS. The probe side was always right and emits every record in range, measured at 2,466,495 hits for one short query, so the fix belongs in emit_index and not in the lookup. Widening the dedup key forced the record to 15 bytes: the scratch key must equal the stored key or an update cannot expand the index back into scratch form, and it would then duplicate every word it re-reads. Cost is 4 bytes a record, 60 GB at this scale, against an expected loss of 1.4e-9. MINQHEX replaces KEYBITS/4 as the piped-query floor so a half-MD5 stays searchable now that the key is wider than a query needs. Static asserts tie the three layout constants together, and the selftest checks that no type's digest is shorter than the key.
 *
 * Revision 1.10  2026/10/18 04:36:18  dlr
 * Take a piped query from the index key width up, so a half-MD5 can be searched from a file. The floor was the shortest digest, 32 hex characters, which refused a 16-character half-MD5 on the stdin path although argv and a terminal took it. KEYBITS is 64, so a 16-character query resolves one bucket and one key and probes exactly as cheaply as a full digest -- measured one candidate fetched per query, no waste. hashcat mode 5100 therefore needs no type of its own; the index is already keyed on precisely those bits. The guard keeps its purpose: below the key width cost climbs as 16 to the minus n, and beef, 19 and 123456 are still refused, while a 16-character hex plaintext meets a record with probability about 8e-10 and is free. Selftest asserts the window.
 *
 * Revision 1.9  2026/10/18 04:23:48  dlr
 * Add SHA1x01, plain sha1(pass), as a sixth indexable type. The index held no plain SHA1 at all, so a lookup of 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 missed every time while the MD5x01, MD5x02 and NTLMx01 digests of the same word all hit -- a type-coverage gap that reads exactly like data loss. Appended to Htype so no existing type changes its Tmask bit. Records carry no type tag, so this is additive to the format: only a build that includes sha1 writes the new records. Self-test vectors are hashcat mode 100's published pair, verified against mdxfind -h SHA1 and an independent implementation.
 *
 * Revision 1.8  2026/10/17 18:11:06  dlr
 * Add SQL5x01, sha1(sha1_bin(pass)), the MySQL 4.1+ password hash.
 *
 * Strictly additive: appended to the end of the type table, so no existing
 * type changes op or bit position, the record format is untouched, and an
 * existing index stays readable (the manifest records type NAMES, not
 * indices).  Selectable as -H sql5; the default is still every type, so the
 * next build indexes it without being asked.
 *
 * The inner digest is consumed as sha1's 20 RAW BYTES.  That is the opposite
 * of MD5x02 immediately above it, which consumes md5's 32 hex characters, and
 * getting either one backwards builds an index that passes its own self-test
 * and never matches anything the suite emits.  The authority is mdxfind
 * -m e259, which prints
 *
 *   SQL5x01 2470c0c06dee42fd1618bb99005adca2ec9d1e19:password
 *
 * and is marked hashcat mode 300 in the type table.  mdxfind does NOT load
 * the *-prefixed form MySQL displays, and accepts either hex case; this
 * matches both, so no input handling changed.
 *
 * Self-test gains two vectors from outside this code -- the published MySQL
 * 4.1 hash of password, and hashcat's own -m 300 example hash of hashcat --
 * plus an end-to-end lookup against the temporary index.  Verified further by
 * round-tripping 500 real words from solved.words through a built index: 500
 * of 500 answered, and every output line re-verified by hashpipe, wrappers
 * and all.  Note those 500 are all $HEX[] lines, so the query side has to
 * unwrap before hashing -- hashing the wrapper text scores 0 of 500 and looks
 * exactly like a broken type.
 *
 * Cost, measured over a 500 MB slice of hibp.pass: 76,345,426 records becomes
 * 95,172,439, so plus 24.7 percent.  On the full three-source build that is
 * about 12.6 billion records, an index.rec near 138 GB against 111 GB, and
 * roughly 292 GB of scratch against 234 GB.  One extra sha1 pair per line is
 * nothing next to that; the build is write-bound.
 *
 * mdindex.1: document the type, the mode 300 equivalence, the raw-bytes
 * contrast with MD5x02 and the leading star.
 *
 * Revision 1.7  2026/10/17 14:52:39  dlr
 * Raise our own descriptor limit before opening the partition scratch.
 *
 * A build holds all 256 partition files open at once.  The ambient limit is
 * not a property of the machine: an interactive shell on this iMac allows
 * 1,048,576, while launchd hands its own default of 256 to anything IT
 * starts.  So a build that is routine from a terminal dies at partition 253
 * with "Too many open files" under at(1), cron or a LaunchAgent.  That is
 * exactly what killed the 2026-10-17 01:00 rebuild, one second in, with the
 * old index correctly left in place.
 *
 * part_open now asks for NPART + 32 before the first open.  The hard limit
 * here is unlimited, so the request succeeds; where it cannot, the shortfall
 * is named on stderr before the work starts rather than discovered a second
 * later as an open failure.
 *
 * Proved by A/B under ulimit -S -n 256, hard unlimited, which is what
 * launchd supplies: 1.6 fails at partition 253, this revision completes and
 * the index answers.  Note that bash ulimit -n without -S lowers the HARD
 * limit too, which no process can raise back -- that form tests a different
 * and unfixable case.
 *
 * Revision 1.6  2026/10/17 04:15:47  dlr
 * Piped input: skip anything that is not a hash, and do it silently.
 *
 * From a pipe or a file, a line is taken as a query only if it is hex and its
 * length lies between the shortest and the longest digest the database holds.
 * Anything else is skipped without a per-line message and counted, and the
 * total is printed after the summary line.  An argument, or a line typed at a
 * terminal, is unchanged: taken exactly as asked however short, with a
 * malformed one still named.
 *
 * Two complaints, one cause.  A mixed file (hash:plain pairs, salts, blanks)
 * drew a not-a-hash message for every line that was not a query, burying the
 * answers.  Worse, a plaintext that happens to be hex was accepted as a
 * partial query.  Over a found-file, cut -c 42- then cut -c 1-40 piped in 22
 * one-character and 41 two-character lines; those select a 16th and a 256th
 * of the keyspace, about 15.5 billion candidate records against the full
 * index, each one a seek into a source file to verify.  It was not hung, it
 * was working, and would have been for years.  The same pipeline now answers
 * in 14ms.
 *
 * Nothing in the lookup path itself changed, so a deliberate partial query
 * still costs what the manual says it costs.
 *
 * mdindex.1: document both, and add the 1- and 2-character rows to the
 * partial-hash cost table, which is what makes the reason obvious.
 *
 * Revision 1.5  2026/10/17 00:11:38  dlr
 * Record the measurement that rejected a larger scatter burst. A bigger PARTBUF was tried over a 4 GB slice of hibp.pass: at 512 KB the scatter phase was unchanged, 42.9s against 42.6s, and the whole build was slower, 160.7s against 141.6s; at 1 MB scatter gained 5.7s and the build still lost 6s. Buffer memory comes out of the page cache that emit_index wants for reading the scratch back, so the next phase pays for what this one saves. The fixture also never reached the write-bound regime it was aimed at, writing 17 GB of scratch at 375 MB/s, above this devices 299 MB/s single-stream rate. Code is unchanged from 1.4; the comment names the real remedy, one scratch file per thread and partition.
 *
 * Revision 1.4  2026/10/16 18:42:43  dlr
 * Rewrite as a multi-type partial-hash index.  Format v2, no upgrade path
 * from v1: the manifest version is checked explicitly and a v1 database is
 * refused with the rebuild instruction rather than mis-parsed.
 *
 * The record is now 11 bytes -- 5 bytes of digest residue plus a 48-bit
 * locator packing an 11-bit file index and a 37-bit offset -- with the other
 * 24 key bits implied by the bucket, everything big-endian so memcmp over a
 * record IS the sort order and the files are portable.  A record no longer
 * says which function made it.  Both the missing digest bits and the type are
 * recovered at lookup by reading the line, regenerating every configured
 * digest and comparing against the whole hash supplied, so the index is a
 * filter and the verification is exact: a key collision costs a read and
 * prints nothing.  That is also what makes partial hashes first-class -- a
 * q-bit query selects a run of buckets and a run of records, every candidate
 * is checked against all the digits given, and every match prints.
 *
 * The key is 64 bits rather than something narrower for two reasons, both
 * recorded in the header: dedup cannot tell a repeated word from a key
 * collision so it silently drops one of the pair, and 64 bits puts the
 * expected loss at 2.7 records across the whole index where 56 bits puts it
 * at 698; and the scratch key must EQUAL the stored key or an update cannot
 * expand the existing index back into scratch form.  With them equal, update
 * runs the identical path as build and a re-appearing word adds nothing --
 * measured, adding a file whose only new word was already indexed grew the
 * index by exactly the 4 records of the genuinely new word.
 *
 * Types are md5, md5x02, sha256, ntlm and sql5, selectable with -H, named with
 * the mdxfind designators so a printed line feeds hashpipe.  The two nested
 * types read their inner digest the OPPOSITE way round and the distinction is
 * the whole type: MD5x02 consumes it as 32-character hex, which is what hx
 * and mdxfind -i 2 do, while SQL5x01 consumes sha1's 20 RAW BYTES.  Either
 * one read the other way builds an index that passes its own self-test and
 * never matches the suite.  A type may now yield SEVERAL (digest, reported
 * plaintext) pairs for one word, because NTLM must: per Waffle the UTF-8 and
 * code-page conversions are LIFTED from ruleproc32.c and called the way
 * JOB_NTLM calls them, so a word is read as UTF-8, CP1251 and CP1252, and for
 * the code-page readings the reported plaintext is the UTF-8 spelling of the
 * codepoints actually hashed rather than the wordlist bytes.  Printing the
 * wordlist bytes there emits a line that does not re-verify.  Verified
 * byte-identical to mdxfind for 636166c3a9 on all three readings including
 * the reported plaintexts, and for 618062 where ill-formed UTF-8 drops the
 * UTF-8 reading and keeps the two code-page ones.  My own reimplementation of
 * the conversion got that second case wrong, which is the argument for
 * lifting.
 *
 * Lookup is now batched.  A pipe or file is read whole, sorted, deduped and
 * answered together; a terminal stays line-at-a-time.  Above a crossover
 * derived from the measured device the whole index is scanned once instead of
 * probed per query -- random 4 KB reads on this volume plateau at about 340
 * IOPS from queue depth 8 (165 at QD1) while one sequential stream runs at
 * 299 MB/s, so the scan wins past about 125,000 queries on a full-size index.
 * The scan is deliberately single-threaded: four parallel streams measured
 * 157 MB/s between them against 299 for one.  Candidates are sorted by
 * locator before fetching so the source reads are monotone too.
 *
 * Staleness is now reported rather than inferred.  The manifest records size,
 * mtime and MD5s of the first AND last megabyte of the indexed region; a
 * truncate, rewrite or reorder changes at least one and is reported as an
 * ALERT naming the file and what moved.  An edit in the middle of a large
 * file changes none of them and is caught instead per hit, where a candidate
 * whose query is no shorter than the key MUST regenerate to it.
 *
 * Timing per Waffle, in mdxfind style: format_rate is lifted from mdxfind.c,
 * lookup always prints hits, hashes answered, lookup time and seconds per
 * hash, -v adds the per-phase breakdown, and build/update report lines/sec
 * and bytes/sec.  needs_hex is lifted from hashpipe.c so a reported line
 * wraps on exactly the bytes hashpipe would wrap on.
 *
 * Verified: selftest 25 checks, all digests against RFC 1321, FIPS 180-4, the
 * standard NTLM vector and mdxfind.  A real 30,252,037-line build produced
 * 121,392,143 records in 9.0s; 6,000 digests of 1,500 sampled real lines
 * across all four types round-trip 6,000 of 6,000 against an independent
 * python implementation, with zero wrong words and zero wrong types.  A
 * 20,000-digest batch took the scan path and reported 16,017 hits -- the
 * 3,983 that missed were exactly the 3,983 $HEX[] lines in the sample, whose
 * digest is of the bytes they denote and not of their literal text.
 *
 * Revision 1.3  2026/10/16 13:11:14  dlr
 * lookup is now the default command: mdindex with no arguments reads
 * digests from stdin, so "md5 <<<word | mdindex" works without naming
 * lookup.  Usage text updated.
 *
 * Revision 1.2  2026/10/16 06:44:30  dlr
 * Bounded reads, one read per partition on update, and verify every lookup. The whole-file mmap drove RSS to 16.8 GB on a 31.8 GB input and the machine to 15 MB free, with the compressor and swap thrashing: throughput decayed 93 to 24 MB/s and kept falling while the interactive session competed for what was left. Workers now pread in 16 MB chunks with 16 MB of line slack, so the footprint is fixed regardless of input size; measured peak RSS 963 MB against 16,800, and the line count now agrees with wc -l exactly where the mmap version was one short. Also: the update merge expanded the old index with one pread per record, which is 4.15 billion syscalls on a full index and was invisible in a four-record test, now one read per partition and a 30.2 M-record update takes 5.3s. Review fixes from Waffle. lookup_one re-hashes the line it fetched and index_open runs the same prefix fingerprint check cmd_update already did: a source rewritten between update and lookup previously produced whatever bytes sat at the offset, with no diagnostic and exit 0, which is a confident wrong answer from the one tool whose job is answering correctly. An oversized HEX payload now falls through to literal as decode_hex_password does in hashpipe, since literal is a different well-defined word rather than a shortened one and is exactly what hashpipe computes, and UNWRAPBUF is derived from LINECAP so the branch is unreachable for an accepted line anyway; the TESTVEC refusal stays, because there the alternative really is truncation. md_unwrap refuses a line past INT_MAX rather than casting it negative. update now accepts new source files, appended at lowest priority. manifest_read grows Files in blocks instead of reserving 273 MB. The progress counter is volatile and the native-endian layout is documented. Verified: full build of 4,146,418,069 lines to 2,507,187,474 records in 2012s, both large files matching wc -l exactly; 1500 sampled real lines round-trip on the decoded word; 400 absent digests report absent; a rewritten prefix is refused up front and an in-place edit past the prefix is caught per hit.
 *
 * Revision 1.1  2026/10/16 05:03:43  dlr
 * Initial revision
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <limits.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/mman.h>
#include <sys/resource.h>
#endif
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include "ruleproc32.h"
#include "hx_vm.h"
/* mdindex_bridge.c registers the primitives hx_func.c leaves to the
 * caller -- the libsph, librhash, mhash, md6 and gosthash families
 * hashpipe supplies through its workspace-bound compute_* functions,
 * which mdindex cannot use.  Without them 220 of 571 indexable
 * expressions do not compile. */
extern int mdindex_bridges_register(void);
/* Generated, never checked in: tools/gen_typeopts.sh extracts mdxfind's
 * TypeOpts[] and tools/gen_hxcat.py slims codegen/hx_specs_data.c down to
 * eN, name and expression.  Eligibility is then a PREDICATE over those two
 * tables -- a type whose flags are corrected in mdxfind.c becomes eligible
 * on the next build with nothing here to edit. */
#include "mdindex_typeopts.h"
#include "mdindex_hxcat.h"
#include "codegen/maphashcat_data.h"
#include "john_map.h"
#include "userdef.h"
#include "sqlite3.h"
#ifdef _WIN32
#include "mdindex_win32.h"
#else
#include <sys/statvfs.h>
#endif

/* OpenSSL 1.1.1's CSPRNG carries a WEAK undefined getentropy, which glibc
 * supplies only from 2.25.  Left unresolved it survives the link as a
 * versioned import and the loader on an older host refuses the binary
 * whole: gp, gp1 and gp2 are EGLIBC 2.19 and report "version `GLIBC_2.25'
 * not found" before main() runs, on a binary that built and selftested
 * clean on the build host.  A local definition binds the weak reference at
 * link time and the import never appears, which is why mdxfind -- built on
 * the same host against the same libcrypto.a -- tops out at GLIBC_2.17.
 * mdxfind gets this from mymd5.c, and mdindex cannot: mymd5.o's procsaltbb
 * references checkhashbb and NoMarkSalt, both mdxfind internals, so linking
 * it here fails.  Repeated rather than shared for that reason.  mymd5.c
 * pairs it with explicit_bzero for argon2's secure wipe; nothing in this
 * link references that one, so it is not repeated -- if argon2 ever pulls
 * it in, this is where its twin goes.  macOS and Windows have their own
 * mechanisms and are excluded. */
#if !defined(__APPLE__) && !defined(_WIN32)
int getentropy(void *buf, size_t buflen)
{
    int     fd = open("/dev/urandom", O_RDONLY);
    ssize_t n;

    if (fd < 0)
        return -1;
    n = read(fd, buf, buflen);
    close(fd);
    return (n == (ssize_t)buflen) ? 0 : -1;
}
#endif

/* Windows opens in TEXT mode by default, which translates CRLF on read and
 * stops at 0x1A. Every file mdindex touches is binary -- the index, the
 * partitions, and a wordlist that may hold any byte -- so every open() here
 * carries O_BINARY. It is 0 everywhere else, so the Unix builds are
 * unchanged. mdxfind learned this the hard way: a text-mode read corrupted
 * an LZMA stream before the decoder ever saw it. */
#ifndef O_BINARY
#define O_BINARY 0
#endif

#ifdef _WIN32
#define DEVNULL "NUL"
#else
#define DEVNULL "/dev/null"
#endif

static char *Version = "$Header: /Users/dlr/src/mdfind/RCS/mdindex.c,v 1.37 2026/10/23 17:46:08 dlr Exp dlr $";
static const char *Prog = "mdindex";

extern void qsort_mt(void *a, size_t n, size_t es,
                     int (*cmp)(const void *, const void *),
                     int maxthreads, int forkelem);

#define DBDIR_DEFAULT   "/usr/local/share/mdfind"

#define BUCKBITS        24
#define NBUCK           (1u << BUCKBITS)
#define NPART           256             /* partition = digest byte 0        */
#define RECSZ           15              /* 9 residue + 6 locator            */
#define RESID           9               /* digest bytes 3..11 stored        */
#define KEYSZ           12              /* digest bytes 0..11 = the key     */
#define KEYBITS         (KEYSZ * 8)     /* 24 implied by bucket + 72 stored */
#define LOCSZ           6
#define SRECSZ          18              /* scratch: 12 key + 6 locator      */
/* The narrowest PIPED query, in hex characters.  Deliberately NOT KEYBITS/4:
 * the key is 96 bits so that the build can tell two colliding words apart,
 * but 64 bits already selects about one record (Nrec/2^64 is 8e-10 on a
 * 15-billion-record index), so a half-MD5 stays free to search and the
 * index needs no Half-MD5 type of its own.  Below this the cost climbs as
 * 16^-n and the filter earns its place -- see hexlen_range(). */
#define ADDWARN         (256ULL << 20)  /* overlay size that suggests compact */
#define MINQHEX         16

/* The layout is three constants that MUST agree, and nothing at runtime
 * notices when they stop.  The scratch key has to equal the stored key or
 * an update cannot expand the index back into scratch form, and it then
 * duplicates every word it re-reads instead of dropping it -- a silent,
 * compounding corruption that no lookup reports. */
_Static_assert(KEYSZ == RESID + 3,      "key = 3 bucket bytes + residue");
_Static_assert(RECSZ == RESID + LOCSZ,  "stored record is residue + locator");
_Static_assert(SRECSZ == KEYSZ + LOCSZ, "scratch record is key + locator");
_Static_assert(KEYSZ > 8, "dedup narrower than 72 bits silently drops one "
                          "of every colliding pair; see WHY 96 BITS");

/* The locator packs both halves into 48 bits.  Splitting file from offset
 * rather than using one global position is what keeps a record valid when
 * an earlier file grows: a global offset would shift every later file. */
#define FILEBITS        11
#define OFFBITS         37
#define MAXFILES        (1 << FILEBITS)         /* 2,048 source files       */
#define MAXOFF          (1ULL << OFFBITS)       /* 137.4 GB per file        */

#define TESTVECSIZE     (2048 * 1024)   /* matches hashpipe.c               */
/* Per-thread, per-partition scatter burst.  A bigger burst was tried and
 * rejected on measurement, 2026-10-16, over a 4 GB slice of hibp.pass: at
 * 512 KB the scatter phase was unchanged (42.9s against 42.6s) and the
 * whole build was SLOWER, 160.7s against 141.6s; at 1 MB scatter gained
 * 5.7s and the build still lost 6s.  Buffer memory is not free -- it comes
 * out of the page cache that emit_index then wants for reading the scratch
 * back, so the next phase pays for what this one saves.
 *
 * That fixture never reached the regime the change was aimed at: it wrote
 * 17 GB of scratch at 375 MB/s, above this device's 299 MB/s single-stream
 * rate, so the writes stayed in page cache.  The real interleaving cost is
 * only visible on a full build -- 233 GB of scratch at 44.5 MB/s and 27.8%
 * CPU, entirely write-bound, while one sequential stream runs at 299 MB/s
 * and four parallel ones manage 39 MB/s each.  A larger burst is NOT the
 * remedy for that.  If it is ever worth attacking, write one scratch file
 * per (thread, partition): a single writer each, no mutex and no
 * interleaving, with emit_index reading Nthreads files per partition. */
#define PARTBUF         (128 * 1024)    /* per-thread, per-partition        */
#define CHUNK           (16ULL << 20)   /* bytes a worker reads at a time   */
#define LINECAP         (256ULL << 10)  /* longest single line accepted     */
/* Big enough that ANY $HEX[] line the reader accepts can be decoded: a line
 * of LINECAP bytes denotes LINECAP/2 bytes, so the "payload too large"
 * branch is unreachable for accepted HEX input, which is the position
 * hashpipe.c is in and keeps the two tools agreeing on a legal line.
 *
 * $TESTVEC[] is NOT bounded by the line length -- the notation is compact
 * and the expansion is not -- so it does NOT share this buffer.  It expands
 * into its own TESTVECSIZE buffer, allocated once per thread and only if a
 * vector is actually met, which is how mdxfind.c and hashpipe.c do it and
 * is what keeps TESTVECSIZE the only bound on a vector in any of the
 * three.  Only one vector is ever in flight per thread, so one buffer
 * suffices. */
#define UNWRAPBUF       ((size_t)(LINECAP / 2 + 64))
#define PREFIXCHK       (1024 * 1024)   /* bytes fingerprinted at each end  */
#define FORKELEM        4096            /* qsort_mt hand-off threshold      */
#define MAXDIG          64              /* longest digest handled, bytes    */
#define QBATCH          4000000         /* queries held in memory at once   */

/* Measured on this volume, 2026-10-16: random 4 KB reads plateau at about
 * 340 IOPS from queue depth 8 upwards (165 at QD1), and a single-stream
 * sequential read runs at 299 MB/s.  Four parallel sequential streams
 * managed 157 MB/s between them, so the scan below is deliberately not
 * threaded.  Scanning the whole index beats probing it once the batch is
 * larger than Nrec * RECSZ * IOPS / SEQBW queries. */
#define RND_IOPS        340.0
#define SEQ_BYTES_SEC   299.0e6

#define FATAL(...) do {                                                   \
        fprintf(stderr, "FATAL %s:%d: ", __FILE__, __LINE__);             \
        fprintf(stderr, __VA_ARGS__);                                     \
        fputc('\n', stderr);                                              \
        exit(1);                                                          \
    } while (0)

static int   Verbose;
static char  Cfgfile[4096];    /* -C: see cfg_load() */
static int   Nthreads;
static char  Dbdir[4096];


/* ------------------------------------------------------------------ */
/* source files                                                        */
/* ------------------------------------------------------------------ */

struct srcfile {
    char               path[4096];
    unsigned long long consumed;        /* bytes already indexed        */
    unsigned long long size;
    long long          mtime;
    unsigned long long lines;
    char               hmd5[33];        /* MD5 of the first PREFIXCHK   */
    char               tmd5[33];        /* MD5 of the last PREFIXCHK    */
};

static struct srcfile *Files;
static int             Nfiles;

/* Reserving MAXFILES up front is megabytes of address space for a
 * three-file index, charged to every one-digest lookup. */
static void files_reserve(int n)
{
    static int cap;
    if (n <= cap) return;
    cap = n + 16;
    Files = realloc(Files, sizeof(*Files) * (size_t)cap);
    if (Files == NULL) FATAL("out of memory for %d source files", cap);
}

static void *xmalloc(size_t n)
{
    void *p = malloc(n);
    if (p == NULL) FATAL("out of memory allocating %zu bytes", n);
    return p;
}

static void *xrealloc(void *o, size_t n)
{
    void *p = realloc(o, n);
    if (p == NULL) FATAL("out of memory allocating %zu bytes", n);
    return p;
}

static char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char  *p = xmalloc(n);
    memcpy(p, s, n);
    return p;
}

/* Four slots: rename(pathcat(a), pathcat(b)) with one static buffer passes
 * the same pointer twice and renames a file onto itself. */
static char *pathcat(const char *tail)
{
    static char buf[4][8192];
    static int  slot;
    slot = (slot + 1) & 3;
    snprintf(buf[slot], sizeof(buf[0]), "%s/%s", Dbdir, tail);
    return buf[slot];
}

static char *commify(unsigned long long v)
{
    static char out[4][64];
    static int  slot;
    char  tmp[32];
    char *o;
    int   n, i, j;

    slot = (slot + 1) & 3;
    o = out[slot];
    n = snprintf(tmp, sizeof(tmp), "%llu", v);
    for (i = 0, j = 0; i < n; i++) {
        if (i > 0 && (n - i) % 3 == 0) o[j++] = ',';
        o[j++] = tmp[i];
    }
    o[j] = 0;
    return o;
}

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode hexlen hex characters.  An odd count leaves the final nibble in
 * the high half of the last byte, which is what a partial query needs. */
static int hex2bin(const char *hex, int hexlen, unsigned char *bin)
{
    int i, n = 0;
    for (i = 0; i + 1 < hexlen; i += 2) {
        int h = hexval(hex[i]), l = hexval(hex[i + 1]);
        if (h < 0 || l < 0) return -1;
        bin[n++] = (unsigned char)((h << 4) | l);
    }
    if (i < hexlen) {
        int h = hexval(hex[i]);
        if (h < 0) return -1;
        bin[n++] = (unsigned char)(h << 4);
    }
    return n;
}

static void bin2hex(const unsigned char *b, int n, char *out)
{
    static const char hx[] = "0123456789abcdef";
    int i;
    for (i = 0; i < n; i++) {
        out[i * 2]     = hx[b[i] >> 4];
        out[i * 2 + 1] = hx[b[i] & 15];
    }
    out[n * 2] = 0;
}

/* Big-endian accessors.  Everything on disk is big-endian so that memcmp
 * over a record IS the sort order and the files move between hosts. */
static void be_put(unsigned char *p, unsigned long long v, int n)
{
    int i;
    for (i = n - 1; i >= 0; i--) { p[i] = (unsigned char)(v & 0xFF); v >>= 8; }
}

static unsigned long long be_get(const unsigned char *p, int n)
{
    unsigned long long v = 0;
    int i;
    for (i = 0; i < n; i++) v = (v << 8) | p[i];
    return v;
}
/* ------------------------------------------------------------------ */
/* $HEX[] and $TESTVEC[] -- semantics copied from hashpipe.c 1.226.    */
/*                                                                      */
/* These are duplicated rather than shared because hashpipe.c and       */
/* mdxfind.c each already carry their own copy and neither exports one. */
/* ponytail: lift all three into a shared header the next time either   */
/* of those files is opened; a wrapper parsed differently by two tools  */
/* in the suite is exactly the drift hx_drift_audit.sh exists to catch. */
/*                                                                      */
/* A malformed wrapper falls through to literal, which is what keeps a  */
/* word that merely resembles one safe.  Being too LARGE is not         */
/* malformed, so it is fatal rather than silently literal or truncated: */
/* a shortened vector hashes to a well-formed digest for a word that    */
/* was never presented.                                                 */
/* ------------------------------------------------------------------ */

static int md_unwrap(const unsigned char *s, size_t slen,
                     unsigned char *out, size_t outmax,
                     unsigned char **tvbuf,
                     const unsigned char **pp, int *pl,
                     const char *where, unsigned long long off)
{
    const unsigned char *p, *end;
    unsigned char pat[256];
    int patbytes, hexlen, count;
    unsigned long long total;

    if (slen > (size_t)INT_MAX)
        FATAL("%s offset %llu: line is %zu bytes, past the %d byte limit",
              where, off, slen, INT_MAX);
    *pp = s;
    *pl = (int)slen;

    if (slen >= 6 && memcmp(s, "$HEX[", 5) == 0 && s[slen - 1] == ']') {
        hexlen = (int)slen - 6;
        /* A payload too large for the buffer falls through to literal, as
         * decode_hex_password does in hashpipe.c.  Literal is not a
         * SHORTENED word, it is a different well-defined one, and it is
         * exactly the word hashpipe computes a digest for, so indexing it
         * literally keeps the two tools in agreement.  With UNWRAPBUF sized
         * from LINECAP this cannot fire for an accepted line anyway, and
         * aborting would let one pathological line kill a multi-hour build
         * from inside a worker thread, mid-write to 256 scratch files.  The
         * $TESTVEC[] case below stays fatal: there the alternative really is
         * truncation, and a shortened vector hashes to a well-formed digest
         * for a word that was never presented.  It has its own buffer, so
         * outmax does not reach it. */
        if (hexlen > 0 && (size_t)(hexlen / 2) > outmax) return 0;
        if (hexlen > 0 && hex2bin((const char *)s + 5, hexlen, out) > 0) {
            *pp = out;
            *pl = hexlen / 2;
            return 1;
        }
        return 0;                       /* malformed: literal */
    }

    if (slen < 15 || memcmp(s, "$TESTVEC[", 9) != 0) return 0;

    p   = s + 9;
    end = (s[slen - 1] == ']') ? s + slen - 1 : s + slen;

    hexlen = 0;
    while (p + hexlen < end && hexval(p[hexlen]) >= 0) hexlen++;
    if (hexlen < 2 || hexlen > (int)sizeof(pat) * 2) return 0;
    patbytes = hex2bin((const char *)p, hexlen, pat);
    if (patbytes <= 0) return 0;

    p += hexlen;
    while (p < end && (*p < '0' || *p > '9')) p++;
    if (p >= end) return 0;

    count = 0;
    for (; p < end; p++) {
        if (*p < '0' || *p > '9') return 0;
        if (count > 99999999) return 0;
        count = count * 10 + (*p - '0');
    }
    if (count <= 0) return 0;

    total = (unsigned long long)patbytes * (unsigned long long)count;
    if (total > TESTVECSIZE)
        FATAL("%s offset %llu: $TESTVEC[] expands to %llu bytes, over the %d "
              "byte limit; refusing to truncate it",
              where, off, total, TESTVECSIZE);

    /* One buffer per caller, allocated the first time a vector is actually
     * met and never again -- mdxfind.c and hashpipe.c allocate theirs the
     * same way, on first sight of a type that needs one.  A wordlist with
     * no $TESTVEC[] in it never pays for this at all. */
    if (*tvbuf == NULL) *tvbuf = xmalloc(TESTVECSIZE);
    out = *tvbuf;

    if (patbytes == 1) {
        memset(out, pat[0], (size_t)total);
    } else {
        unsigned long long pos;
        for (pos = 0; pos < total; pos += patbytes)
            memcpy(out + pos, pat, patbytes);
    }
    *pp = out;
    *pl = (int)total;
    return 1;
}

/* ------------------------------------------------------------------ */
/* hash types                                                          */
/*                                                                      */
/* Names are the mdxfind designators, verified against                  */
/* "mdxfind -z -m eN -i 1", so a line this tool prints can be fed       */
/* straight to hashpipe.  Adding a type here and rebuilding is the      */
/* whole cost of adding a type; the record format does not change.      */
/* ------------------------------------------------------------------ */

/* A type can yield SEVERAL (digest, reported plaintext) pairs for one word.
 * NTLM is why: Windows mapped the user's code page into UTF-16LE through the
 * OS tables rather than zero-extending, so mdxfind reads a candidate as
 * UTF-8, as CP1251 and as CP1252, and for the two code-page readings it
 * reports the UTF-8 spelling of the codepoints it actually hashed, which is
 * NOT the bytes in the wordlist.  Printing the wordlist line for those would
 * emit a line that does not re-verify.
 *
 * The conversions are mdxfind's own, from ruleproc32.c, called the same way
 * JOB_NTLM calls them -- lifted rather than reimplemented so the two cannot
 * drift.  ruleproc32.o links with nothing but libc.
 *
 * Ill-formed UTF-8 loses the UTF-8 reading and keeps the two code-page
 * ones: those bytes are still a legal CP1251 or CP1252 password, and
 * mdxfind emits both.  An all-ASCII word collapses to a single reading
 * because all three coincide. */

#define MAXVAR          3
/* A type may emit several digests for one word from several SHAPES, and
 * may walk an enumerated variable domain.  The HEXSALT family does both:
 * 256 two-hex salts over three shapes is 768 digests from one word, which
 * is what mdxfind emits and therefore what the index must hold. */
#define MDX_MAXSHAPE    4
#define MDX_HEXSALTS    256

/* ENUMERATED DOMAINS.
 *
 * A type in one of these supplies its own salt values instead of taking
 * one with the hash, so it stays a function of the password alone and
 * can be indexed -- at one record per member per shape.
 *
 *   hex2    the HEXSALT family: all 256 two-hex salts
 *   humsep  the HUM family: eight line-ending sequences
 *
 * The HUM separators are written as HEX and the expressions decode them
 * with fromhex(), because the first of them is a NUL byte -- mdxfind's
 * table is NUL-delimited and an empty entry is taken as one NUL
 * (`if (i == 0) i = 1`), which its own output confirms by reporting that
 * member as salt "00".  A string literal cannot carry it, and hx takes
 * "\r\n" literally rather than as CR LF, so fromhex() is the only form
 * that reproduces mdxfind here. */
enum { EDOM_NONE = 0, EDOM_HEX2, EDOM_HUMSEP };

static const char *const Humsep[] = {
    "00", "20", "0d", "0d0a", "0a", "0d0d", "0a0a", "0a0d"
};
#define MDX_HUMSEPS ((int)(sizeof(Humsep) / sizeof(Humsep[0])))

static int edom_by_name(const char *d)
{
    if (d == NULL)                   return EDOM_NONE;
    if (strcmp(d, "hex2") == 0)      return EDOM_HEX2;
    if (strcmp(d, "humsep") == 0)    return EDOM_HUMSEP;
    FATAL("unknown enumerated domain '%s' -- this build carries hex2 and "
          "humsep", d);
    return EDOM_NONE;
}

static const char *edom_name(int d)
{
    return d == EDOM_HEX2 ? "hex2" : d == EDOM_HUMSEP ? "humsep" : "none";
}

static int edom_count(int d)
{
    return d == EDOM_HEX2 ? MDX_HEXSALTS : d == EDOM_HUMSEP ? MDX_HUMSEPS : 1;
}

/* The value BOUND to `salt` in the expression, and the value REPORTED in
 * the output line.  Identical for hex2; different for humsep, where
 * mdxfind prints "<hex>- x 1" -- the separator and the inner-iteration
 * index, which is 1 for every digest this indexes.  Reporting the bound
 * value there would emit a line hashpipe cannot verify. */
static void edom_value(int d, int i, char *bound, size_t bsz,
                       char *reported, size_t rsz)
{
    static const char hexd[] = "0123456789abcdef";

    switch (d) {
    case EDOM_HEX2:
        snprintf(bound, bsz, "%c%c", hexd[(i >> 4) & 0xf], hexd[i & 0xf]);
        snprintf(reported, rsz, "%s", bound);
        break;
    case EDOM_HUMSEP:
        snprintf(bound, bsz, "%s", Humsep[i]);
        snprintf(reported, rsz, "%s- x 1", Humsep[i]);
        break;
    default:
        bound[0] = 0;
        reported[0] = 0;
        break;
    }
}
#define NTLM_MAXLEN     MAXLINE         /* ruleproc32.h; mdxfind's own cap  */

struct hout {
    unsigned char        dig[MAXDIG];
    const unsigned char *plain;         /* what to report as the password  */
    int                  plen;
    int                  verbatim;      /* plain IS the line's own bytes   */
    /* An enumerated type found the digest with one particular member of
     * its domain, and nothing can re-verify the line without knowing
     * which: mdxfind prints SHA1HEXSALT <hash>:0a:<pass>, so this does
     * too.  Empty for every type that enumerates nothing. */
    char                 salt[24];
};

typedef int (*hfn)(const unsigned char *p, int n, struct hout *o);

struct htype {
    const char *name;       /* mdxfind designator, e.g. "MD5x01"      */
    const char *key;        /* what -H accepts                         */
    int         dlen;       /* digest bytes                            */
    hfn         fn;         /* native arm, or NULL for an hx type      */
    int         maxvar;     /* digests this type yields for one word   */
    int         job;        /* catalog eN, 0 for a native-only type    */
    int         iters;      /* mdxfind iteration count, the xNN suffix */
    char       *expr;       /* hx source, NULL for a native type       */
    hx_program *prog;       /* compiled once, shared read-only         */
    hx_program *shape[MDX_MAXSHAPE];  /* extra shapes past prog        */
    char       *sexpr[MDX_MAXSHAPE];  /* their source, for the manifest */
    int         nshape;     /* 1 = prog alone                          */
    int         enumdom;    /* EDOM_*: the domain this type walks, if any */
    int         quiet;      /* indexed, but never reported: at THIS
                             * depth it is another type's stored-form
                             * variant and the label would be noise     */
    int         vmbase;     /* first VM slot this type owns            */
    hx_program *guard;      /* admission test, NULL when unconditional */
    char       *gexpr;      /* its source, for the manifest            */
    char       *uid;        /* -C stanza id, NULL unless user-defined  */
    char       *ufile;      /* the -C file that defined it             */
    unsigned char pd[MAXDIG * 2];  /* digests of the two probe words    */
};

static int h_md5(const unsigned char *p, int n, struct hout *o)
{
    MD5(p, (size_t)n, o[0].dig);
    o[0].plain = p; o[0].plen = n; o[0].verbatim = 1;
    return 1;
}

/* md5(md5(pass)) hashes the 32-character LOWERCASE HEX of the first digest,
 * not its 16 raw bytes.  Both hx and mdxfind agree -- hx's md5() yields hex
 * and md5_bin() yields bytes, and "mdxfind -i 2" prints MD5x02
 * 696d29e0940a4957748fe3fc9efd22a3 for "password".  The raw-byte reading
 * gives 9bf4b361... and would build an index that passes its own self-test
 * and never matches anything the suite emits. */
static int h_md5x02(const unsigned char *p, int n, struct hout *o)
{
    static const char hx[] = "0123456789abcdef";
    unsigned char d[16];
    char          hex[32];
    int i;

    MD5(p, (size_t)n, d);
    for (i = 0; i < 16; i++) {
        hex[i * 2]     = hx[d[i] >> 4];
        hex[i * 2 + 1] = hx[d[i] & 15];
    }
    MD5((const unsigned char *)hex, 32, o[0].dig);
    o[0].plain = p; o[0].plen = n; o[0].verbatim = 1;
    return 1;
}

static int h_sha256(const unsigned char *p, int n, struct hout *o)
{
    SHA256(p, (size_t)n, o[0].dig);
    o[0].plain = p; o[0].plen = n; o[0].verbatim = 1;
    return 1;
}

static int h_sha1(const unsigned char *p, int n, struct hout *o)
{
    SHA1(p, (size_t)n, o[0].dig);
    o[0].plain = p; o[0].plen = n; o[0].verbatim = 1;
    return 1;
}

/* SQL5x01 is sha1(sha1_bin(pass)): the inner digest is consumed as its 20
 * RAW BYTES.  That is the opposite of MD5x02 just above, which consumes the
 * inner digest as hex, and the difference is the whole type -- reading these
 * the wrong way round gives a digest nothing in the suite will ever emit.
 * mdxfind -m e259 is the authority and prints
 *   SQL5x01 2470c0c06dee42fd1618bb99005adca2ec9d1e19:password
 * which is hashcat mode 300, the MySQL 4.1+ password hash.  MySQL displays
 * it with a leading '*' that is NOT part of the digest; mdxfind will not
 * load that form either, so neither does this. */
static int h_sql5(const unsigned char *p, int n, struct hout *o)
{
    unsigned char inner[20];

    SHA1(p, (size_t)n, inner);
    SHA1(inner, 20, o[0].dig);
    o[0].plain = p; o[0].plen = n; o[0].verbatim = 1;
    return 1;
}

/* One u8 slot PER VARIANT.  The reported plaintext has to stay valid until
 * the caller has printed it, and the caller sees all the variants at once;
 * a single shared buffer leaves every reading but the last pointing at the
 * last one's bytes. */
struct ntlmbuf {
    unsigned char w[NTLM_MAXLEN * 2 + 16];
    unsigned char u8[MAXVAR][NTLM_MAXLEN * 3 + 16];
    unsigned char cp[NTLM_MAXLEN + 16];
    uint32_t      u32[NTLM_MAXLEN + 16];
};

static int h_ntlm(const unsigned char *p, int n, struct hout *o)
{
    static __thread struct ntlmbuf *b;
    int nout = 0, L, R, nv, i, ascii = 1;

    if (n > NTLM_MAXLEN) return 0;          /* mdxfind breaks here too */
    if (b == NULL) b = xmalloc(sizeof(*b));
    for (i = 0; i < n; i++) if (p[i] >= 0x80) { ascii = 0; break; }

    /* Reading 1, as UTF-8.  Ill-formed input is REFUSED, not shortened. */
    L = utf8_to_utf16(p, n, b->w, (int)sizeof(b->w), b->u32,
                      NTLM_MAXLEN + 16, UTF16_LE);
    if (L >= 0) {
        MD4(b->w, (size_t)L, o[nout].dig);
        o[nout].plain = p; o[nout].plen = n; o[nout].verbatim = 1;
        nout++;
    }
    if (ascii) return nout;     /* all three readings coincide */

    /* Readings 2 and 3.  Copied aside because the re-encode writes into a
     * buffer the caller may be reading from. */
    memcpy(b->cp, p, (size_t)n);
    nv = cp_tables_agree(b->cp, n, CP_1251, CP_1252) ? 1 : 2;
    for (i = 0; i < nv && nout < MAXVAR; i++) {
        L = cp_to_utf16(b->cp, n, b->w, (int)sizeof(b->w),
                        i ? CP_1252 : CP_1251, UTF16_LE);
        if (L < 0) continue;
        R = utf16_to_utf8(b->w, L, b->u8[nout], (int)sizeof(b->u8[0]), b->u32,
                          NTLM_MAXLEN + 16, UTF16_LE);
        if (R < 0) continue;
        MD4(b->w, (size_t)L, o[nout].dig);
        o[nout].plain = b->u8[nout]; o[nout].plen = R; o[nout].verbatim = 0;
        nout++;
    }
    return nout;
}

/* The six native arms.  They stay native deliberately.  Every one of them
 * is reproduced exactly by an hx expression -- verified against the live
 * vectors -- but the production index was built by this code, and swapping
 * the hashing path underneath it is the one step in the plan with a real
 * risk attached.  Opening the catalog does not need it: an hx type is added
 * ALONGSIDE these, not in place of them, so an existing database keeps
 * byte-identical behaviour by construction rather than by a test I have to
 * pass.  Replacing them is a separate, independently verifiable change. */
static const struct htype Defsix[] = {
    { "MD5x01",    "md5",    16, h_md5,    1, 1,   1, NULL, NULL },
    { "MD5x02",    "md5x02", 16, h_md5x02, 1, 1,   2, NULL, NULL },
    { "SHA256x01", "sha256", 32, h_sha256, 1, 10,  1, NULL, NULL },
    { "NTLMx01",   "ntlm",   16, h_ntlm,   3, 369, 1, NULL, NULL },
    { "SQL5x01",   "sql5",   20, h_sql5,   1, 259, 1, NULL, NULL },
    { "SHA1x01",   "sha1",   20, h_sha1,   1, 8,   1, NULL, NULL },
};
#define NDEFSIX ((int)(sizeof(Defsix) / sizeof(Defsix[0])))

/* The selected set IS the table: there is no mask any more, because the
 * catalog is far wider than a machine word and a bitmask over 620 types
 * would have been the first thing to go wrong. */
static struct htype *Htype;
static int           Nhtype;
static int           Maxvar = MAXVAR;   /* over the SELECTED types          */

/* ---- eligibility, as a predicate over the two generated tables ---- */

#define TYPEOPT_NOT_INDEXABLE (1 | 32 | 64 | 128)   /* NEEDSJ|SALT|USER|PEPPER */

static int job_indexable(int job)
{
    unsigned f;

    if (job < 0 || job > MDX_MAXJOB) return 0;
    f = Typeopt_flags[job];
    /* 'f' and nothing else.  A type needing a salt, a userid, a pepper or
     * the structured channel is not a function of the password alone, so
     * the index cannot key on it.  Structured-load forms (bcrypt and
     * family) carry NEEDSJ and fall out here for free -- no reject-list. */
    return (f & 2) && !(f & TYPEOPT_NOT_INDEXABLE);
}

static const struct hxcat *cat_by_job(int job)
{
    int i;
    for (i = 0; i < NHXCAT; i++) if (Hxcat[i].job == job) return &Hxcat[i];
    return NULL;
}

static const struct hxcat *cat_by_name(const char *name)
{
    int i;
    for (i = 0; i < NHXCAT; i++)
        if (strcasecmp(Hxcat[i].name, name) == 0) return &Hxcat[i];
    return NULL;
}

static int job_for_hashcat(unsigned mode)
{
    int i;
    for (i = 0; i < (int)(sizeof(hx_maphashcat) / sizeof(hx_maphashcat[0])); i++)
        if (hx_maphashcat[i].hc == mode) return (int)hx_maphashcat[i].mdx;
    return 0;
}

/* mdxfind iterates a type by applying its OUTERMOST function again to the
 * previous round's output string -- that is what the MDstart and
 * SHA1_start loops do: hash `cur`, re-render the digest as hex in the
 * type's own case convention, and go round.  The seed is whatever came
 * before that outer call and is computed once.
 *
 * So iteration 2 of md5(sha1(pass)) is md5(md5(sha1(pass))), NOT
 * md5(sha1(md5(sha1(pass)))).  Both readings agree for the one-call types
 * and disagree for every composite, which is why substituting the whole
 * expression into its own `pass` passed MD5x02's vector and was wrong
 * everywhere else.  Checked against mdxfind for MD5SHA1 at x02 AND x03,
 * and for SHA1UC, whose uppercase hex is what gets carried.
 *
 * A type whose chain carries something other than its printed output
 * cannot be derived this way -- MD5RAWUC re-uppercases between rounds --
 * and declares its own step in hx.8 with PREV standing for the previous
 * round. */
/* The step is the outermost call TOGETHER WITH any non-digest transforms
 * it wraps, stopping at the first digest below it.  mdxfind re-renders the
 * previous digest as hex and applies the round function, and for a type
 * like md4(utf16le(pass)) that round function includes the encoding: x02
 * is md4(utf16le(md4(utf16le(pass)))), not md4(md4(utf16le(pass))).  For
 * md5(sha1(pass)) the sha1 is a digest, so the step stops at md5 and x02
 * is md5(md5(sha1(pass))).  Both verified against mdxfind.
 *
 * hx's registry already distinguishes the two: a digest function declares
 * its width in max_out, a transform declares 0. */
static int fn_is_digest(const char *name)
{
    hx_func_entry *fe = hx_func_lookup(name);
    char b[128];
    int  len = (int)strlen(name);

    if (fe == NULL && len > 4 && name[len - 4] == '_' && len < (int)sizeof(b)) {
        memcpy(b, name, (size_t)len + 1);
        b[len - 4] = 0;
        fe = hx_func_lookup(b);
    }
    return fe != NULL && fe->max_out > 0;
}

static int expr_outer(const char *e, char *fn, size_t fnlen)
{
    size_t n = strlen(e), i, j;
    int depth = 0;

    for (i = 0; i < n; i++) if (e[i] == '(') break;
    if (i == 0 || i >= n) return 0;                 /* no call at all */
    for (j = 0; j < i; j++)
        if (!isalnum((unsigned char)e[j]) && e[j] != '_' &&
            e[j] != '^') return 0;                  /* not a bare name */
    /* the opening paren must close exactly at the end, or the outermost
     * construct is a concatenation and not a call */
    for (; i < n; i++) {
        if (e[i] == '"') { do { i++; } while (i < n && e[i] != '"'); continue; }
        if (e[i] == '(') depth++;
        else if (e[i] == ')' && --depth == 0) break;
    }
    if (i != n - 1) return 0;
    if (j >= fnlen) return 0;
    memcpy(fn, e, j);
    fn[j] = 0;
    return 1;
}

/* A multi-statement type -- h=md5(pass); md5(h . h) -- computes a seed in
 * the prelude and hashes it in the final statement, and mdxfind then falls
 * into the ordinary loop: JOB_MD5_2xMD5 builds hex(h) . hex(h) and goes to
 * MDstart.  So the round repeats the FINAL statement's outer call, and the
 * prelude is computed once.  Iterating the whole expression instead would
 * recompute the seed every round, which is a different hash. */
static size_t expr_prelude(const char *e)
{
    size_t i, last = 0;
    int    inq = 0;

    for (i = 0; e[i]; i++) {
        if (e[i] == '"') { inq = !inq; continue; }
        if (!inq && e[i] == ';') last = i + 1;
    }
    while (e[last] == ' ' || e[last] == '\t') last++;
    return last;
}

/* Replace every standalone `pass` with `repl`, leaving string literals
 * alone.  Returns NULL when the expression never names pass.
 *
 * This exists only for user-defined types, and they iterate by a DIFFERENT
 * rule than the catalog does.  A catalog type has a C arm in mdxfind and
 * its loop repeats the OUTERMOST call over the previous digest.  A user
 * type has no arm, so mdxfind's generic loop re-runs the WHOLE program
 * with pass bound to the previous round's output.  Verified against
 * mdxfind -z -i 2 -m u47 for sha1(md5(pass)."register"), which gives
 * 230964f3... = the whole expression re-run, not e3fd2626... = the
 * outermost sha1 repeated.  Using the catalog rule here builds an index
 * that self-tests clean and matches nothing mdxfind emits. */
static char *expr_subst_pass(const char *expr, const char *repl)
{
    size_t rl = strlen(repl), occ = 0, n;
    const char *p;
    char *out, *q;
    char quote;

#define MDX_ISPASS(p) \
    (strncmp((p), "pass", 4) == 0 && \
     !((p) > expr && (isalnum((unsigned char)(p)[-1]) || (p)[-1] == '_')) && \
     !(isalnum((unsigned char)(p)[4]) || (p)[4] == '_'))

    for (p = expr, quote = 0; *p; ) {
        if (quote) {
            if (*p == '\\' && p[1]) { p += 2; continue; }
            if (*p == quote) quote = 0;
            p++; continue;
        }
        if (*p == '"' || *p == '\'') { quote = *p; p++; continue; }
        if (MDX_ISPASS(p)) { occ++; p += 4; continue; }
        p++;
    }
    if (occ == 0) return NULL;

    n = strlen(expr) + occ * (rl > 4 ? rl - 4 : 0) + 1;
    out = xmalloc(n);
    for (p = expr, q = out, quote = 0; *p; ) {
        if (quote) {
            if (*p == '\\' && p[1]) { *q++ = *p++; *q++ = *p++; continue; }
            if (*p == quote) quote = 0;
            *q++ = *p++; continue;
        }
        if (*p == '"' || *p == '\'') { quote = *p; *q++ = *p++; continue; }
        if (MDX_ISPASS(p)) { memcpy(q, repl, rl); q += rl; p += 4; continue; }
        *q++ = *p++;
    }
    *q = 0;
#undef MDX_ISPASS
    return out;
}

/* Depth `iters` of a user-defined type, as a chain of temp bindings:
 *
 *   mdxi1 = EXPR ; mdxi2 = EXPR[pass:=mdxi1] ; ... ; EXPR[pass:=mdxi(n-1)]
 *
 * A binding rather than textual nesting, so an expression naming pass
 * several times still computes each round once instead of 2^n times.
 * Returns NULL when the type cannot be iterated: one that never names
 * pass has no round to repeat, and one that already carries its own
 * prelude would have its variables redefined by the chain. */
static char *expr_iterate_user(const char *expr, int iters)
{
    char  prev[32], *acc, *cur;
    int   n;

    if (iters <= 1) return xstrdup(expr);
    if (expr_prelude(expr) > 0) return NULL;     /* own prelude; leave it */
    {
        char *t = expr_subst_pass(expr, "x");
        if (t == NULL) return NULL;              /* never names pass */
        free(t);
    }
    acc = xstrdup("");
    cur = xstrdup(expr);
    for (n = 1; n < iters; n++) {
        char  *nx, *tmp;
        size_t ln;

        snprintf(prev, sizeof(prev), "mdxi%d", n);
        ln = strlen(acc) + strlen(prev) + strlen(cur) + 4;
        tmp = xmalloc(ln);
        snprintf(tmp, ln, "%s%s=%s;", acc, prev, cur);
        free(acc); acc = tmp;

        nx = expr_subst_pass(expr, prev);
        free(cur); cur = nx;
    }
    {
        size_t ln = strlen(acc) + strlen(cur) + 1;
        char  *full = xmalloc(ln);
        snprintf(full, ln, "%s%s", acc, cur);
        free(acc); free(cur);
        return full;
    }
}

static char *expr_iterate(const char *expr, int iters, const char *step,
                          const char *name)
{
    size_t pre = expr_prelude(expr);
    char *cur = xstrdup(expr + pre);
    char  fn[128];
    int   n;

    if (iters <= 1) { free(cur); return xstrdup(expr); }
    if (step == NULL && !expr_outer(expr + pre, fn, sizeof(fn)))
        FATAL("%s cannot be iterated: its outermost construct is not a "
              "single function call, so there is no step to repeat (%s). "
              "Declare one in hx.8 as a STEP line if the type really does "
              "iterate.", name, expr);
    for (n = 1; n < iters; n++) {
        char *out;
        if (step != NULL) {
            const char *pv = strstr(step, "PREV");
            size_t pre, post;
            if (pv == NULL)
                FATAL("%s: its declared step names no PREV: %s", name, step);
            pre  = (size_t)(pv - step);
            post = strlen(pv + 4);
            out = xmalloc(pre + strlen(cur) + post + 1);
            memcpy(out, step, pre);
            memcpy(out + pre, cur, strlen(cur));
            memcpy(out + pre + strlen(cur), pv + 4, post + 1);
        } else {
            size_t ln = strlen(fn) + strlen(cur) + 3;
            out = xmalloc(ln);
            snprintf(out, ln, "%s(%s)", fn, cur);
        }
        free(cur);
        cur = out;
    }
    if (pre > 0) {                       /* put the prelude back in front */
        char  *full = xmalloc(pre + strlen(cur) + 1);
        memcpy(full, expr, pre);
        memcpy(full + pre, cur, strlen(cur) + 1);
        free(cur);
        cur = full;
    }
    return cur;
}

/* hx_compile.c:380 calls exit(1) on a function it cannot resolve, which is
 * right for a one-expression tool and fatal for "compile all 571 of these
 * and tell me which ones work".  So the names are checked FIRST, against
 * the same registry and the same role-suffix rule resolve_func uses
 * (hx_compile.c:207): longest-match on _bin/_hex/_b64/_mcf, then _uc, then
 * the whole name.  A miss here means the function is one hashpipe supplies
 * through a bridge and mdindex does not -- 220 of the 571, all of them
 * libsph/libmhash/librhash primitives.
 *
 * This duplicates a rule that lives in the compiler, which is the kind of
 * restatement that eventually disagrees with the thing it restates.  It is
 * bounded: the only cost of disagreeing is that a type is skipped by -H all
 * or reported unavailable, never that a wrong digest is computed, because
 * every type still has to pass hx_probe afterwards. */
static int expr_funcs_available(const char *expr, const char *banned,
                                char *miss, size_t misslen)
{
    const char *r = expr;
    int inq = 0;

    for (; *r; r++) {
        char name[128];
        const char *b;
        size_t n;
        int len;

        if (*r == '"') { inq = !inq; continue; }
        if (inq) continue;
        if (!isalpha((unsigned char)*r) && *r != '_') continue;
        if (r > expr && (isalnum((unsigned char)r[-1]) || r[-1] == '_')) continue;
        b = r;
        while (isalnum((unsigned char)*r) || *r == '_') r++;
        n = (size_t)(r - b);
        /* a name is a CALL only if a ( or an ^N iteration follows it */
        if (*r != '(' && *r != '^') { r--; continue; }
        r--;
        if (n >= sizeof(name)) continue;
        memcpy(name, b, n);
        name[n] = 0;
        /* emit() writes the value to stdout and suppresses the program's
         * own result, so a multi-emit type would print digests into the
         * middle of a build and hand back nothing to index.  Three catalog
         * types do this; capturing their several digests properly is the
         * multi-emit work in the plan, not something to half-do here. */
        if (banned && strcmp(name, banned) == 0) {
            snprintf(miss, misslen, "%s", name);
            return 0;
        }
        if (hx_func_lookup(name)) continue;
        len = (int)n;
        if (len > 4 && name[len - 4] == '_') {
            const char *sfx = name + len - 3;
            if (memcmp(sfx, "bin", 3) == 0 || memcmp(sfx, "hex", 3) == 0 ||
                memcmp(sfx, "b64", 3) == 0 || memcmp(sfx, "mcf", 3) == 0) {
                name[len - 4] = 0;
                if (hx_func_lookup(name)) continue;
                name[len - 4] = '_';
            }
        }
        if (len > 3 && name[len - 3] == '_' &&
            memcmp(name + len - 2, "uc", 2) == 0) {
            name[len - 3] = 0;
            if (hx_func_lookup(name)) continue;
            name[len - 3] = '_';
        }
        snprintf(miss, misslen, "%s", name);
        return 0;
    }
    return 1;
}

/* A type whose expression reads salt, salt2, pepper or userid is one
 * mdxfind supplies those values for -- and for the f-only types that reach
 * here, it supplies them by ENUMERATING them itself.  e184 SHA1HEXSALT
 * walks all 256 two-hex salts over three shapes and emits 768 digests for
 * one word.  mdindex binds every slot but pass to the empty string, so it
 * would compute sha1(pass . "") -- a digest that is not a member of the
 * family at all, that duplicates SHA1x01, and that no real SHA1HEXSALT
 * hash will ever equal.  Indexing it costs records and answers nothing,
 * and a type reported under a name whose digests it does not hold reads
 * exactly like data loss.
 *
 * So it is refused until the enumeration is implemented.  This is NOT the
 * eligibility test that was considered and rejected: TypeOpts is still the
 * authority on what is indexable IN PRINCIPLE, and these types are -- at
 * 256 times the records, which is the operator's choice to make.  This
 * says only that THIS build cannot compute them correctly yet, which is a
 * statement about the implementation, not about the type.  Six catalog
 * types are affected: the five HEXSALT families and e283 MD52SALTMD5. */
static int prog_reads_supplied_var(const hx_program *prog, int *slot)
{
    int i;

    for (i = 0; i < prog->ncode; i++)
        if (prog->code[i].op == OP_PUSH_VAR &&
            prog->code[i].u.slot >= HX_SLOT_SALT &&
            prog->code[i].u.slot <= HX_SLOT_USERID) {
            *slot = prog->code[i].u.slot;
            return 1;
        }
    return 0;
}

static const char *slotname(int slot)
{
    switch (slot) {
    case HX_SLOT_SALT:   return "salt";
    case HX_SLOT_SALT2:  return "salt2";
    case HX_SLOT_PEPPER: return "pepper";
    case HX_SLOT_USERID: return "userid";
    }
    return "?";
}

/* Compile, then PROVE the type is one the index can key on, by running it
 * over two different words.  Three things have to hold and each has bitten
 * something in this suite before:
 *
 *   fixed width   -- a variable-length output is a stored form, not a
 *                    digest, and there is nothing to key on.
 *   hex           -- e259 SQL5's expression is the MySQL display form,
 *                    "*" . upper(...), which is not a digest either.
 *   password-dependent -- a type whose output does not change with the
 *                    word is broken; eleven parameterised catalog entries
 *                    (sha1(cut(sha256(pass), 0, N)) and family) are caught
 *                    by exactly this, because N is unbound here.
 *
 * Rejection is loud and the caller decides whether it is fatal: a type
 * named explicitly must be an error, while "give me everything indexable"
 * must skip it. */
static int hx_probe(hx_program *prog, int *dlen, const char **why,
                    unsigned char *pd, const char *salt)
{
    static const char *w1 = "password", *w2 = "hashcat";
    int slen = salt ? (int)strlen(salt) : 0;
    char   a[MAXDIG * 2 + 2];
    hx_vm  vm;
    hx_val r;
    int    alen, i;

    hx_vm_init(&vm, prog);
    r = hx_vm_run(&vm, w1, (int)strlen(w1), salt, slen, "", 0, "", 0, "", 0);
    if (r.data == NULL || r.len <= 0 || r.len > MAXDIG * 2) {
        *why = "produced no digest, or one wider than the index holds";
        hx_vm_free(&vm); return 0;
    }
    alen = r.len;
    memcpy(a, r.data, (size_t)alen);
    r = hx_vm_run(&vm, w2, (int)strlen(w2), salt, slen, "", 0, "", 0, "", 0);
    if (r.data == NULL || r.len != alen) {
        *why = "digest width depends on the password";
        hx_vm_free(&vm); return 0;
    }
    if (memcmp(a, r.data, (size_t)alen) == 0) {
        *why = "output does not depend on the password";
        hx_vm_free(&vm); return 0;
    }
    if (alen & 1) { *why = "output is an odd number of characters, so not hex";
                    hx_vm_free(&vm); return 0; }
    for (i = 0; i < alen; i++)
        if (hexval((unsigned char)a[i]) < 0 ||
            hexval((unsigned char)r.data[i]) < 0) {
            *why = "output is not hex -- a stored form, not a digest";
            hx_vm_free(&vm); return 0;
        }
    /* Hand both probe digests back: the caller uses them to recognise a
     * type that is another one's stored-form variant. */
    if (pd != NULL) {
        hex2bin(a, alen, pd);
        hex2bin(r.data, alen, pd + alen / 2);
    }
    hx_vm_free(&vm);
    *dlen = alen / 2;
    return 1;
}

/* Two expressions that differ only in an output ROLE compute the same
 * BINARY digest, because mdindex hex-decodes whatever hx returns and keys
 * on the bytes.  sha1_uc(pass) and sha1(pass) are the same index content:
 * identical at x01, and only diverging from x02, where the uppercase hex
 * is what gets rehashed.  mdxfind suppresses the duplicate label at x01
 * for exactly this reason and so does this.
 *
 * The role test alone is not enough, and the digest test alone is not
 * either.  AICH is a different algorithm that happens to reduce to SHA-1
 * for any message short enough to be a password, so its digests match but
 * its bytecode does not -- and mdxfind DOES report it, so it is kept.  A
 * stored-form variant has to satisfy both: same digests on two different
 * probe words, and the same program once roles are ignored. */
static int progs_same_but_role(const hx_program *a, const hx_program *b)
{
    int i;

    if (a == NULL || b == NULL || a->ncode != b->ncode) return 0;
    for (i = 0; i < a->ncode; i++) {
        const hx_inst *x = &a->code[i], *y = &b->code[i];
        if (x->op != y->op) return 0;
        switch (x->op) {
        case OP_CALL:
            /* entry and arity must match; the role deliberately need not */
            if (x->u.call.entry != y->u.call.entry ||
                x->u.call.nargs != y->u.call.nargs) return 0;
            break;
        case OP_PUSH_VAR: case OP_STORE: case OP_INC:
            if (x->u.slot != y->u.slot) return 0;
            break;
        case OP_PUSH_INT:
            if (x->u.ival != y->u.ival) return 0;
            break;
        case OP_PUSH_STR:
            if (x->u.stridx != y->u.stridx) return 0;
            if (a->strlens[x->u.stridx] != b->strlens[y->u.stridx]) return 0;
            if (memcmp(a->strings[x->u.stridx], b->strings[y->u.stridx],
                       (size_t)a->strlens[x->u.stridx]) != 0) return 0;
            break;
        default:
            break;
        }
    }
    return 1;
}

static void sel_reserve(int n)
{
    static int cap;
    if (n <= cap) return;
    cap = cap ? cap * 2 : 16;
    while (cap < n) cap *= 2;
    Htype = xrealloc(Htype, sizeof(*Htype) * (size_t)cap);
}

static int sel_have(const char *name)
{
    int i;
    for (i = 0; i < Nhtype; i++)
        if (strcasecmp(Htype[i].name, name) == 0) return 1;
    return 0;
}

/* fatal: the type was named, so refusing it quietly would build a database
 * that silently does not hold what was asked for.  Not fatal: the caller
 * said "everything indexable" and a type hx cannot express is simply not
 * one of them. */
/* The xNN in a type name is mdxfind's iteration count, and it does not
 * always start at 1: JOB_MD5RAWUC enters the iterator at x = 2 because
 * iteration 1 would be exactly MD5x01, so MD5RAWUCx01 is a label mdxfind
 * never prints.  Emitting it anyway would produce a line that does not
 * round-trip, which is the one property section 7 of the plan requires.
 * hx.8 declares the exception as `.\" FIRSTITER eN: M`. */
/* An admission guard is part of the type, not an optimisation.  e732
 * SHA1UTF7 is SHA-1 of the UTF-7 encoding, and mdxfind skips any word
 * whose UTF-7 form IS the word -- every ASCII word -- because the digest
 * would be a plain SHA-1 wearing another name.  hx's utf7() is an encoder
 * and applies unconditionally, which is correct for the function and wrong
 * for a type built from the expression alone: without this, an index of
 * ten thousand ASCII passwords reports 7,176 SHA1UTF7 answers that mdxfind
 * would never produce.  hx.8 declares the condition as
 * `.\" GUARD eN: <expr>`; the word is admitted only where <expr> differs
 * from the password itself. */
/* How a job prints in a diagnostic.  A user-defined type has a synthetic
 * op well above the catalog's range, and printing that as "e1147" sends
 * the reader looking for a catalog entry that does not exist; its own -C
 * id is what identifies it. */
static const char *jobdesig(int job)
{
    static char buf[64];
    struct userdef_type *u;

    if (userdef_is_userop(job) && (u = userdef_get(job)) != NULL) {
        snprintf(buf, sizeof(buf), "u%s", u->idstr);
        return buf;
    }
    snprintf(buf, sizeof(buf), "e%d", job);
    return buf;
}

static int sel_add_hx(int job, const char *catname, const char *expr,
                      int iters, int first_iter, const char *guard,
                      const char *enum_dom, const char *const *also,
                      int nalso, const char *step, int fatal)
{
    char        name[64];
    char       *full;
    hx_program *prog;
    const char *why = "";
    int         dlen = 0, quiet = 0;

    if (first_iter < 1) first_iter = 1;
    snprintf(name, sizeof(name), "%sx%02d", catname, first_iter + iters - 1);
    if (sel_have(name)) return 1;

    /* An iterated catalog type is NOT verified against mdxfind.  mdxfind
     * re-hashes the HEX of the previous digest, carrying any case
     * transform with it -- MD5RAWUCx03 is md5(upper(md5(upper(hex(
     * md5_bin^2(pass)))))), not the x02 expression wrapped around itself.
     * Substituting the expression into its own `pass` happens to be right
     * for MD5x02, which is why it passes its vector, and happens to be
     * wrong for every chain type.  Computing it anyway is the operator's
     * call; doing so without saying this would not be. */
    /* An enumerated type is not iterated: mdxfind's HEXSALT arm has its
     * own loop and does not pass through MDstart at all. */
    if (iters > 1 && enum_dom != NULL)
        return 0;

    if (userdef_is_userop(job)) {
        full = expr_iterate_user(expr, iters);
        if (full == NULL) {
            if (fatal)
                FATAL("type %s (%s) cannot be iterated: a user-defined type "
                      "repeats by re-running its whole expression with pass "
                      "bound to the previous digest, so it must name pass "
                      "and must not carry a prelude of its own: %s",
                      name, jobdesig(job), expr);
            return 0;
        }
    } else {
        full = expr_iterate(expr, iters, step, name);
    }
    {
        char miss[128] = "";
        if (!expr_funcs_available(full, "emit", miss, sizeof(miss))) {
            if (fatal && strcmp(miss, "emit") == 0)
                FATAL("type %s (%s) emits several digests per word, which "
                      "this build does not index: %s", name, jobdesig(job), full);
            if (fatal)
                FATAL("type %s (%s) needs the hash function '%s', which "
                      "this build of mdindex does not carry: %s",
                      name, jobdesig(job), miss, full);
            free(full);
            return 0;
        }
    }
    hx_diag_count = 0;
    prog = hx_compile_expr(full, NULL);
    if (prog == NULL) {
        if (fatal) FATAL("type %s (%s): hx cannot compile %s", name, jobdesig(job), full);
        free(full);
        return 0;
    }
    {
        int slot = 0;
        /* An enumerated domain is the exception: the type supplies its own
         * values, so it stays a function of the password alone.  An
         * externally supplied salt is still refused -- it is not known at
         * build time and never will be. */
        if (enum_dom == NULL && prog_reads_supplied_var(prog, &slot)) {
            /* Same test, opposite reason, depending on who wrote the
             * expression.  A CATALOG type that reads salt may have an
             * mdxfind arm enumerating it -- the HEXSALT family does --
             * so the refusal is provisional and names the missing
             * enumeration.  A USER type has no arm at all, so the salt
             * can only come from outside and the refusal is permanent.
             * Neither message should be "fixed" to match the other. */
            if (fatal && userdef_is_userop(job))
                FATAL("type %s (%s) reads %s, which has to be supplied "
                      "with each hash and is not known when the index is "
                      "built. A user-defined type is indexable only if it "
                      "is a function of the password alone: %s",
                      name, jobdesig(job), slotname(slot), full);
            if (fatal)
                FATAL("type %s (%s) reads %s, which mdxfind enumerates "
                      "itself -- 256 values over three shapes for the "
                      "HEXSALT family. mdindex would bind it empty and "
                      "index one digest the type never produces. Refused "
                      "until the enumeration is implemented: %s",
                      name, jobdesig(job), slotname(slot), full);
            hx_program_free(prog);
            free(full);
            return 0;
        }
    }
    {
        unsigned char pd[MAXDIG * 2];
        int k;

        if (!hx_probe(prog, &dlen, &why, pd, enum_dom ? "00" : "")) {
            if (fatal) FATAL("type %s (%s): %s -- %s", name, jobdesig(job), why, full);
            hx_program_free(prog);
            free(full);
            return 0;
        }
        /* A digest narrower than the key cannot be indexed at all.  The
         * scatter copies KEYSZ bytes out of every digest, so a shorter
         * one is read past, into whatever the probe left in the struct:
         * the keys are not reproducible between runs and the type simply
         * stops being found after a rebuild, with nothing saying why.
         * The selftest asserts the invariant over the SELECTED set; this
         * is what keeps it true, and it is the reason MYSQL3, MURMUR64A
         * and MURMUR64AZERO are absent from -H all.
         *
         * Those three are 8 bytes, and that is also why they would false
         * match: 64 bits of digest against an index keyed on 96.  The
         * types that nest them are unaffected and are indexed -- md5 of
         * mysql3 of pass is an ordinary 16-byte MD5 -- so the primitive
         * is bridged and only the bare form is refused. */
        if (dlen < KEYSZ) {
            if (fatal)
                FATAL("type %s (%s) yields a %d-byte digest, shorter than "
                      "the %d-byte index key. It cannot be indexed: the key "
                      "would be padded with whatever follows the digest in "
                      "memory, so it would not reproduce between builds. A "
                      "type that nests it inside a full-width digest is "
                      "fine and is indexed.",
                      name, jobdesig(job), dlen, KEYSZ);
            hx_program_free(prog);
            free(full);
            return 0;
        }
        /* Already selected under another name, differing only in an output
         * role?  Then it is the same index content and the second label is
         * noise.  Both tests must hold -- see progs_same_but_role.
         *
         * WHICH of the pair is the noise is decided by (job, iteration),
         * not by which was reached first.  mdxfind runs its types in job
         * order and the first to solve wins, so the lower pair is the
         * name it would print.  Selection order is not that order: -H all
         * adds every type at x01 before any at x02, so MD5x02 (e1) met
         * MD5UCMD5x01 (e558) already in the table and went quiet, leaving
         * md5_uc(md5(pass)) to report a digest that is plainly MD5x02. */
        {
            int canon = -1, matched = 0;

            for (k = 0; k < Nhtype; k++) {
                if (Htype[k].prog == NULL || Htype[k].dlen != dlen) continue;
                if (memcmp(Htype[k].pd, pd, (size_t)dlen * 2) != 0) continue;
                if (!progs_same_but_role(Htype[k].prog, prog)) continue;
                matched = 1;
                if (!Htype[k].quiet) { canon = k; break; }
            }
            if (matched) {
                /* Suppressed on OUTPUT -- not dropped.  The digests are
                 * identical, so the records dedup away and the type costs
                 * the index nothing; keeping it in the table is what lets
                 * -i reach it, since sha1_uc coincides with sha1 at x01
                 * and diverges at x02 where the uppercase hex is rehashed. */
                int beats = canon >= 0 &&
                            (job < Htype[canon].job ||
                             (job == Htype[canon].job &&
                              first_iter + iters - 1 < Htype[canon].iters));
                if (beats) {
                    if (fatal)
                        fprintf(stderr, "note: %s and %s are one digest in "
                                "different output forms; reported as %s\n",
                                name, Htype[canon].name, name);
                    Htype[canon].quiet = 1;        /* the newcomer is lower */
                } else {
                    if (fatal)
                        fprintf(stderr, "note: %s is %s with a different "
                                "output form, so the same digest; reported "
                                "as %s\n", name,
                                canon >= 0 ? Htype[canon].name : "another type",
                                canon >= 0 ? Htype[canon].name : "that one");
                    quiet = 1;
                }
            }
        }
        sel_reserve(Nhtype + 1);
        memset(&Htype[Nhtype], 0, sizeof(Htype[0]));
        memcpy(Htype[Nhtype].pd, pd, (size_t)dlen * 2);
    }
    Htype[Nhtype].name   = xstrdup(name);
    Htype[Nhtype].key    = xstrdup(catname);
    Htype[Nhtype].dlen   = dlen;
    Htype[Nhtype].fn     = NULL;
    Htype[Nhtype].maxvar = 1;
    Htype[Nhtype].job    = job;
    Htype[Nhtype].nshape   = 1;
    Htype[Nhtype].quiet    = quiet;
    Htype[Nhtype].enumdom  = edom_by_name(enum_dom);
    {
        int k;
        for (k = 0; k < nalso; k++) {
            hx_program *sp;
            if (k + 1 >= MDX_MAXSHAPE)
                FATAL("type %s (%s) declares more shapes than %d",
                      name, jobdesig(job), MDX_MAXSHAPE);
            hx_diag_count = 0;
            sp = hx_compile_expr(also[k], NULL);
            if (sp == NULL)
                FATAL("type %s (%s): shape %d will not compile: %s",
                      name, jobdesig(job), k + 2, also[k]);
            Htype[Nhtype].sexpr[Htype[Nhtype].nshape] = xstrdup(also[k]);
            Htype[Nhtype].shape[Htype[Nhtype].nshape++] = sp;
        }
    }
    if (guard != NULL) {
        hx_diag_count = 0;
        Htype[Nhtype].guard = hx_compile_expr(guard, NULL);
        if (Htype[Nhtype].guard == NULL)
            FATAL("type %s (%s): its admission guard will not compile: %s",
                  name, jobdesig(job), guard);
        Htype[Nhtype].gexpr = xstrdup(guard);
    }
    Htype[Nhtype].iters  = first_iter + iters - 1;
    Htype[Nhtype].expr   = full;
    Htype[Nhtype].prog   = prog;
    /* Every round of a user type carries its provenance, not just the
     * first: -i adds x02 and x03 through this same path, and an info
     * that named only x01 would read as if the deeper rounds came from
     * somewhere else. */
    if (userdef_is_userop(job)) {
        struct userdef_type *u = userdef_get(job);
        if (u != NULL) {
            Htype[Nhtype].uid   = xstrdup(u->idstr);
            Htype[Nhtype].ufile = xstrdup(Cfgfile);
        }
    }
    Nhtype++;
    return 1;
}

static void sel_add_native(const struct htype *proto)
{
    if (sel_have(proto->name)) return;
    sel_reserve(Nhtype + 1);
    Htype[Nhtype++] = *proto;
}

static int Maxiter = 1;

/* The native arms mdxfind does not iterate the generic way.  The generic
 * rule -- re-hash the LOWERCASE hex of the previous digest -- is what
 * expr_iterate() builds from a catalog expression, and it reproduces
 * mdxfind exactly for MD5, SHA1 and SHA256.  The other two do not fit it:
 *
 *   NTLM (e369) does not iterate AT ALL.  mdxfind.c's JOB_NTLM arm calls
 *   checkhash(&md5buf, 32, 1, job) with a literal 1 and carries no
 *   `for (x = 1; x <= Maxiter; x++)` loop, so NTLMx02 is a digest mdxfind
 *   never computes and hashpipe never verifies.  Generating one here would
 *   put a hash in the index that nothing else in the suite agrees with,
 *   which is worse than the gap it would fill.
 *
 *   SQL5 (e259) iterates, but the value it carries forward is NOT the one
 *   it reports.  JOB_SQL5 reports sha1(sha1_bin(cur)) while setting the
 *   next cur to prmd5UC(sha1_bin(cur)) -- the INNER digest, uppercased.
 *   The reported hash is a further sha1 of that inner digest, so the
 *   printed round cannot be fed back into anything, and expr_iterate's
 *   step mechanism (which substitutes PREV for the whole previous
 *   expression) cannot restructure its inside.  The chain is unrolled
 *   explicitly below instead.  The catalog expression is no help either:
 *   e259 holds MySQL's DISPLAY form, "*" . upper(...), which is not even a
 *   digest -- mdindex indexes the bare sha1(sha1_bin(pass)) that mdxfind
 *   prints, so the unrolled form has to start from that and not from the
 *   catalog.
 */
#define JOB_E_SQL5 259
#define JOB_E_NTLM 369

/* SQL5 unrolled to depth n:  C(1) = pass,  C(k) = upper(sha1(C(k-1))),
 * and the digest reported at depth n is sha1(sha1_bin(C(n))).  Checked
 * against mdxfind -z for x01..x05. */
static char *sql5_iter_expr(int n)
{
    char *inner = xstrdup("pass");
    char *out;
    int   k;

    for (k = 1; k < n; k++) {
        size_t ln = strlen(inner) + sizeof("upper(sha1())");
        out = xmalloc(ln);
        snprintf(out, ln, "upper(sha1(%s))", inner);
        free(inner);
        inner = out;
    }
    {
        size_t ln = strlen(inner) + sizeof("sha1(sha1_bin())");
        out = xmalloc(ln);
        snprintf(out, ln, "sha1(sha1_bin(%s))", inner);
    }
    free(inner);
    return out;
}

/* -i N: index iterations 1..N of every selected type.  Done after the
 * selection is complete so that -i and -H are order-independent, and so a
 * type that cannot be iterated is skipped rather than refused -- asking
 * for depth across the whole catalog should not fail on the one type
 * whose outermost construct is a concatenation. */
static void sel_expand_iters(void)
{
    int base = Nhtype, i, k;

    if (Maxiter < 2) return;
    for (i = 0; i < base; i++) {
        const struct hxcat *c;
        int first;

        /* NTLM does not iterate -- see above.  The test sits HERE, ahead of
         * the native/catalog split, because the two selection routes reach
         * this loop differently: `-H e369` brings in the native arm, while
         * `-H all` brings in the catalog entry, and neither may grow an
         * x02.  Through the catalog it was doubly wrong -- the generic rule
         * built md4(md4(utf16le(pass))), dropping the encoding the second
         * round needs, and labelled it NTLMx02, which mdxfind never prints.
         * The digest that form should have produced already has a correct
         * home: e496 MD4UTF16 declares the step md4(utf16le(PREV)) and
         * computes it right, and hashpipe verifies it under that name. */
        if (Htype[i].job == JOB_E_NTLM) continue;

        if (Htype[i].fn != NULL) {
            /* A native arm is not iterated from an expression, but the
             * table may carry the deeper round itself -- MD5x02 is there
             * beside MD5x01 -- and -i should reach it. */
            int d, k2, njob = Htype[i].job;

            for (k2 = 2; k2 <= Maxiter; k2++)
                for (d = 0; d < NDEFSIX; d++)
                    if (Defsix[d].job == njob &&
                        Defsix[d].iters == k2)
                        sel_add_native(&Defsix[d]);

            /* Defsix carries exactly ONE deeper round -- MD5x02 -- so
             * until now every other native arm stopped right here and -i
             * silently did nothing for it: `-H e10 -i 2` built SHA256x01
             * and no SHA256x02, while the hx types named in the same -H
             * got theirs.  The depths the table cannot supply come from
             * the catalog expression instead, which is the same path the
             * non-native types already take.  SQL5 cannot: */
            if (njob == JOB_E_SQL5) {
                for (k2 = 2; k2 <= Maxiter; k2++) {
                    char *e = sql5_iter_expr(k2);
                    sel_add_hx(JOB_E_SQL5, "SQL5", e, 1, k2, NULL, NULL,
                               NULL, 0, NULL, 0);
                    free(e);
                }
                continue;
            }
            /* MD5, SHA1, SHA256: the generic rule is right, fall through. */
        }
        if (Htype[i].enumdom) continue;             /* own loop, no MDstart */
        if (userdef_is_userop(Htype[i].job)) {
            /* A user type does NOT iterate the way a catalog type does.
             * It has no C arm in mdxfind, so mdxfind's generic loop
             * re-runs the whole expression with pass bound to the
             * previous digest; see expr_subst_pass.  sel_add_hx builds
             * that form and declines the types it does not fit. */
            struct userdef_type *u = userdef_get(Htype[i].job);
            if (u == NULL) continue;
            for (k = 2; k <= Maxiter; k++)
                sel_add_hx(Htype[i].job, u->dispname, u->hx, k, 1,
                           NULL, NULL, NULL, 0, NULL, 0);
            continue;
        }
        c = cat_by_job(Htype[i].job);
        first = Htype[i].iters;
        if (c == NULL || c->expr == NULL) continue;
        for (k = 2; first - 1 + k <= Maxiter; k++) {
            char fn[128];
            if (c->step == NULL &&
                !expr_outer(c->expr + expr_prelude(c->expr), fn, sizeof(fn)))
                break;                              /* no step to repeat */
            sel_add_hx(c->job, c->name, c->expr, k, c->first_iter, c->guard,
                       c->enum_dom, c->also, c->nalso, c->step, 0);
        }
    }
}

static void sel_default(void)
{
    int i;
    for (i = 0; i < NDEFSIX; i++) sel_add_native(&Defsix[i]);
}

/* -C: the stanza file that defines user types, named outright.
 *
 * It is NOT derived from MDXFIND_CACHE and there is no search path, because
 * this file decides what the database MEANS: a type selected from it is
 * built into the index under its own name, and a different file answering
 * to the same name tomorrow would reinterpret records already on disk.  The
 * expression is copied into the manifest for exactly that reason, so once
 * an index exists the manifest is what defines its types and this file is
 * no longer consulted.  See manifest_write().
 *
 * Loaded before any -H is resolved, so -C and -H are order-independent the
 * way every other mdindex option is. */
static void cfg_load(void)
{
    int n;

    if (Cfgfile[0] == 0) return;
    n = userdef_load_file(Cfgfile, 1);
    if (n < 0)
        FATAL("-C %s: %s", Cfgfile, strerror(errno));
    if (n == 0)
        FATAL("-C %s: no usable type definitions in it", Cfgfile);
    if (Verbose)
        fprintf(stderr, "%d user-defined type(s) from %s\n", n, Cfgfile);
}

/* u<id>: a type from the -C file rather than the catalog.  The id is the
 * stanza's own `id =` value, which is what mdxfind -m u<id> takes, so one
 * spelling selects the same type in both tools. */
static void sel_add_user(const char *spec, int iters)
{
    const struct userdef_type *u;
    int op;

    if (Cfgfile[0] == 0)
        FATAL("-H %s names a user-defined type, but no -C file was given",
              spec);
    op = userdef_lookup_by_id(spec + 1);
    if (op < 0) {
        const char *why = userdef_skip_reason(spec + 1);
        if (why != NULL)
            FATAL("-H %s: %s defines that id but it was rejected: %s",
                  spec, Cfgfile, why);
        FATAL("-H %s: %s defines no type with id = %s",
              spec, Cfgfile, spec + 1);
    }
    u = userdef_get(op);
    if (u == NULL) FATAL("-H %s: id resolved to no type", spec);
    /* A user expression that reads salt genuinely needs one -- no mdxfind
     * arm is enumerating it, unlike the catalog's HEXSALT family -- so
     * sel_add_hx's refusal is the right verdict here and is left to it. */
    sel_add_hx(op, u->dispname, u->hx, iters, 1,
               NULL, NULL, NULL, 0, NULL, 1);
}

/* -H: five namespaces, disjoint by grammar, so nothing is tried in turn.
 *
 *   e<digits>      mdxfind catalog type        e259
 *   u<digits>      user-defined type, -C file  u47
 *   <digits>       hashcat mode                300
 *   all            every indexable catalog type
 *   anything else  canonical name              SQL5, MD5MD5PASS, md5
 *
 * A trailing :N selects mdxfind iteration N, which is the xNN in the type
 * name; the default is 1.  The six native names (md5, md5x02, sha256,
 * ntlm, sql5, sha1) resolve to the native arms first so that naming the
 * default set explicitly reproduces it exactly. */
static void sel_from_list(const char *list)
{
    char  copy[65536];
    char *p, *save = NULL;

    snprintf(copy, sizeof(copy), "%s", list);
    for (p = strtok_r(copy, ",", &save); p; p = strtok_r(NULL, ",", &save)) {
        const struct hxcat *c = NULL;
        char *colon;
        const char *spelt;
        int   iters = 1, i, job = 0, had_colon = 0;

        while (*p == ' ' || *p == '\t') p++;
        if (*p == 0) continue;
        /* What the OPERATOR typed, for diagnostics.  A John label is
         * rewritten to the catalog name it maps to, and an error naming
         * MD5PASSSALT when the command line said dynamic_1 sends the
         * reader looking in the wrong place. */
        spelt = p;
        colon = strrchr(p, ':');
        if (colon && colon[1]) {
            iters = atoi(colon + 1);
            if (iters < 1 || iters > 16)
                FATAL("-H %s: iteration count must be 1..16", p);
            *colon = 0;
            had_colon = 1;
        }

        if (strcasecmp(p, "all") == 0) {
            int added = 0;
            for (i = 0; i < NHXCAT; i++) {
                if (!job_indexable(Hxcat[i].job) || Hxcat[i].expr == NULL)
                    continue;
                added += sel_add_hx(Hxcat[i].job, Hxcat[i].name,
                                    Hxcat[i].expr, iters,
                                    Hxcat[i].first_iter, Hxcat[i].guard,
                                    Hxcat[i].enum_dom, Hxcat[i].also,
                                    Hxcat[i].nalso, Hxcat[i].step, 0);
            }
            if (added == 0) FATAL("-H all selected no types at all");
            continue;
        }

        if (!had_colon) {
            for (i = 0; i < NDEFSIX; i++)
                if (strcasecmp(p, Defsix[i].key) == 0 ||
                    strcasecmp(p, Defsix[i].name) == 0) {
                    sel_add_native(&Defsix[i]);
                    break;
                }
            if (i < NDEFSIX) continue;
        }

        /* A John dynamic label.  john_map.h maps it to the hashpipe type
         * name, which is the same namespace as a canonical name here, so
         * it resolves through the path already built rather than needing
         * one of its own.
         *
         * JohnMap only, never JohnMapLocal: the local table is read from
         * whatever dynamic.conf sat on the machine that ran the generator
         * and its NUMBERING is machine-local, so selecting a build's types
         * through it would mean one -H line naming different types on two
         * machines.  john_map.h says the same of john_label_for(). */
        if (strncasecmp(p, "dynamic_", 8) == 0) {
            static char base[80];
            const char *mapped = NULL;
            char       *xs;
            int         k;

            if (had_colon)
                FATAL("-H %s:%d names an iteration twice -- a John label "
                      "already carries one (dynamic_2 is MD5x02)", p, iters);
            for (k = 0; k < JOHN_MAP_COUNT; k++)
                if (strcasecmp(p, JohnMap[k].john) == 0) {
                    mapped = JohnMap[k].hptype;
                    break;
                }
            if (mapped == NULL)
                FATAL("-H %s: not a John dynamic format this build carries. "
                      "john_map.h holds %d, each one confirmed by "
                      "recomputing John's own test vector; a format whose "
                      "vector did not verify is absent rather than guessed.",
                      p, JOHN_MAP_COUNT);
            snprintf(base, sizeof(base), "%s", mapped);
            /* The mapped name carries its iteration -- dynamic_2 is
             * MD5x02 -- so split the xNN off and let it take the same
             * path md5:2 takes. */
            xs = strrchr(base, 'x');
            if (xs != NULL && isdigit((unsigned char)xs[1]) &&
                strspn(xs + 1, "0123456789") == strlen(xs + 1)) {
                iters = atoi(xs + 1);
                *xs = 0;
                had_colon = 1;
            }
            p = base;
        }

        if ((p[0] == 'u' || p[0] == 'U') && isdigit((unsigned char)p[1])) {
            sel_add_user(p, iters);
            continue;
        }

        if ((p[0] == 'e' || p[0] == 'E') && isdigit((unsigned char)p[1]))
            job = atoi(p + 1);
        else if (isdigit((unsigned char)p[0]))
            job = job_for_hashcat((unsigned)atoi(p));
        else {
            c = cat_by_name(p);
            if (c) job = c->job;
        }
        if (job == 0)
            FATAL("-H %s: not a catalog name, not eN, not u<id>, not a hashcat "
                  "mode", spelt);
        /* A native arm wins over the catalog for the same (type,
         * iteration).  It matters for e259 SQL5, whose catalog expression
         * is MySQL's DISPLAY form -- "*" . upper(...) -- and so is not a
         * digest at all; mdindex indexes the bare sha1(sha1_bin(pass))
         * under the name mdxfind prints.  Routing e259, hashcat 300 and
         * the name SQL5 to the native arm keeps all three spellings
         * giving the one answer. */
        for (i = 0; i < NDEFSIX; i++)
            if (Defsix[i].job == job && Defsix[i].iters == iters) {
                sel_add_native(&Defsix[i]);
                break;
            }
        if (i < NDEFSIX) continue;

        if (c == NULL) c = cat_by_job(job);
        if (c == NULL)
            FATAL("-H %s: e%d has no entry in the hx catalog", spelt, job);
        if (!job_indexable(job))
            FATAL("-H %s: e%d %s needs a salt, userid, pepper or the "
                  "structured channel, so it is not a function of the "
                  "password alone and cannot be indexed", spelt, job, c->name);
        if (c->expr == NULL)
            FATAL("-H %s: e%d %s carries no hx expression in the catalog "
                  "(it is one of the %d outliers)", spelt, job, c->name, 100);
        sel_add_hx(job, c->name, c->expr, iters, c->first_iter, c->guard,
                   c->enum_dom, c->also, c->nalso, c->step, 1);
    }
    if (Nhtype == 0) FATAL("no hash types selected");
}

/* ---- per-thread hx context ----
 *
 * The hx_program is shared and read-only; an hx_vm is NOT -- it carries a
 * private arena and stack, so every worker keeps its own array, one VM per
 * selected type, allocated once at thread start.  hashpipe's bridges also
 * need a thread-local workspace pointer set before any run; mdindex needs
 * no such thing, because it registers no bridges and hx_func.c's own
 * functions are self-contained.  If bridges are ever added here, the
 * workspace has to be set up in this same place or every thread will
 * compute digests from another thread's buffers -- which does not fail
 * loudly, it just builds a plausible, wrong index. */
/* Assign each type a contiguous run of VM slots and return the total.
 * Called once the selection is final, before any thread starts. */
static int Nvm;

static void vms_layout(void)
{
    int i;

    Nvm = 0;
    for (i = 0; i < Nhtype; i++) {
        Htype[i].vmbase = Nvm;
        if (Htype[i].prog == NULL) continue;      /* native arm */
        Nvm += Htype[i].nshape + (Htype[i].guard != NULL);
    }
}

static hx_vm *vms_new(void)
{
    hx_vm *v;
    int    i, n = 0;

    for (i = 0; i < Nhtype; i++) if (Htype[i].prog) n++;
    if (n == 0 || Nvm == 0) return NULL;
    /* Every program a type owns needs its own VM, because an hx_vm
     * carries a private arena and stack: one per shape, plus one for the
     * admission guard.  Slots are laid out contiguously per type from
     * vmbase, which sel_* assigned when the type was selected. */
    v = xmalloc(sizeof(*v) * (size_t)Nvm);
    memset(v, 0, sizeof(*v) * (size_t)Nvm);
    for (i = 0; i < Nhtype; i++) {
        int k;
        for (k = 0; k < Htype[i].nshape; k++) {
            hx_program *pr = k ? Htype[i].shape[k] : Htype[i].prog;
            if (pr) hx_vm_init(&v[Htype[i].vmbase + k], pr);
        }
        if (Htype[i].guard)
            hx_vm_init(&v[Htype[i].vmbase + Htype[i].nshape], Htype[i].guard);
    }
    return v;
}

static void vms_free(hx_vm *v)
{
    int i;
    if (v == NULL) return;
    for (i = 0; i < Nhtype; i++) {
        int k;
        for (k = 0; k < Htype[i].nshape; k++) {
            hx_program *pr = k ? Htype[i].shape[k] : Htype[i].prog;
            if (pr) hx_vm_free(&v[Htype[i].vmbase + k]);
        }
        if (Htype[i].guard)
            hx_vm_free(&v[Htype[i].vmbase + Htype[i].nshape]);
    }
    free(v);
}

/* Returns how many digests this type yielded for this word.  The variant
 * count is checked against the table rather than trusted: a type that
 * produced more than it declared would overrun hv[], and one that silently
 * filled to the brim and stopped would build an index that passes check,
 * answers most queries, and is missing the rest with no diagnostic. */
static int type_hash(int t, hx_vm *vms, const unsigned char *p, int n,
                     struct hout *o)
{
    hx_val r;
    int    nv, sl;

    /* CLEAR THE SALT FIELD BEFORE ANYTHING FILLS THIS SLOT.
     *
     * hout.salt is written only by the enumerated branch below, and
     * emit_hit decides between "hash:plain" and "hash:salt:plain" by
     * testing salt[0].  hv[] is a per-thread heap buffer reused for every
     * word, so for an ORDINARY type that field holds whatever the last
     * enumerated type left there -- or, on the first use, whatever malloc
     * returned.  That is an uninitialised read: undefined behaviour, and
     * it behaves differently per platform.  On macOS the fresh pages are
     * zero and the bug is invisible; on Linux an md5 lookup printed
     *
     *     MD5x01 5f4dcc3b...cf99:09cb7<TAB>ba!:password
     *
     * -- a salt field full of debris in front of a correct answer, on a
     * type that has no salt.  The %s also ran past the 8-byte array,
     * because nothing had terminated it either. */
    for (sl = 0; sl < Htype[t].maxvar; sl++) o[sl].salt[0] = 0;

    if (Htype[t].fn != NULL) {
        nv = Htype[t].fn(p, n, o);
        if (nv > Htype[t].maxvar)
            FATAL("type %s yielded %d digests, over its declared %d",
                  Htype[t].name, nv, Htype[t].maxvar);
        return nv;
    }
    /* The guard decides whether this type applies to THIS word at all.
     * Returning 0 means no record, which the caller already handles --
     * h_ntlm does the same for an over-length word.  The guard runs first
     * so a word it rejects costs one cheap transform, not a digest. */
    if (Htype[t].guard != NULL) {
        hx_val g = hx_vm_run(&vms[Htype[t].vmbase + Htype[t].nshape],
                             (const char *)p, n, "", 0, "", 0, "", 0, "", 0);
        if (g.data == NULL) return 0;
        if (g.len == n && memcmp(g.data, p, (size_t)n) == 0) return 0;
    }

    /* shapes x enumerated domain.  The HEXSALT family walks all 256
     * two-hex salts over three shapes: 768 digests for one word, which is
     * exactly what mdxfind emits, so it is what the index must hold. */
    {
        char  saltbuf[24], saltrep[24];
        int   nsalt = edom_count(Htype[t].enumdom);
        int   sh, si, nv = 0;
        for (si = 0; si < nsalt; si++) {
            const char *salt = "";
            int slen = 0;
            saltrep[0] = 0;
            if (Htype[t].enumdom) {
                edom_value(Htype[t].enumdom, si, saltbuf, sizeof(saltbuf),
                           saltrep, sizeof(saltrep));
                salt = saltbuf; slen = (int)strlen(saltbuf);
            }
            for (sh = 0; sh < Htype[t].nshape; sh++) {
                r = hx_vm_run(&vms[Htype[t].vmbase + sh], (const char *)p, n,
                              salt, slen, "", 0, "", 0, "", 0);
                if (r.data == NULL || r.len != Htype[t].dlen * 2)
                    FATAL("type %s shape %d returned %d characters, "
                          "expected %d -- the expression is not the one "
                          "this database was built with",
                          Htype[t].name, sh + 1, r.data ? r.len : -1,
                          Htype[t].dlen * 2);
                if (nv >= Htype[t].maxvar)
                    FATAL("type %s yielded more than its declared %d "
                          "digests", Htype[t].name, Htype[t].maxvar);
                if (hex2bin(r.data, r.len, o[nv].dig) != Htype[t].dlen)
                    FATAL("type %s returned a non-hex digest", Htype[t].name);
                o[nv].plain = p; o[nv].plen = n; o[nv].verbatim = 1;
                snprintf(o[nv].salt, sizeof(o[nv].salt), "%s", saltrep);
                nv++;
            }
        }
        return nv;
    }
}

static void maxvar_set(void)
{
    int i;

    Maxvar = 1;
    for (i = 0; i < Nhtype; i++) {
        /* The variant space is shapes times the enumerated domain: the
         * HEXSALT family is 3 x 256 = 768 digests for one word.  The
         * bound is asserted at use, never trusted -- a type that filled
         * hv[] to the brim and stopped would build an index that passes
         * check, answers most queries and is missing the rest. */
        int mv = Htype[i].fn ? Htype[i].maxvar
                             : Htype[i].nshape *
                               edom_count(Htype[i].enumdom);
        Htype[i].maxvar = mv;
        if (mv > Maxvar) Maxvar = mv;
    }
    vms_layout();
}


/* ------------------------------------------------------------------ */
/* manifest                                                            */
/*                                                                      */
/* Every offset in the index names a byte position in these files, so   */
/* the manifest is what makes a stale index detectable instead of       */
/* quietly wrong.  Size and mtime are recorded, and so are MD5s of the  */
/* first and last megabyte of the region that was indexed.  Appending   */
/* changes neither fingerprint; truncating, rewriting or reordering     */
/* changes at least one.  An edit in the middle of a large file changes */
/* nothing here and is caught instead at lookup, where every hit is     */
/* re-hashed before it is printed.                                      */
/* ------------------------------------------------------------------ */

static void region_md5(const char *path, unsigned long long at,
                       unsigned long long upto, char *hex)
{
    unsigned char *buf;
    unsigned char  h[16];
    size_t want = upto < PREFIXCHK ? (size_t)upto : PREFIXCHK;
    int    fd;

    if (want == 0) { strcpy(hex, "-"); return; }
    fd = open(path, O_RDONLY | O_BINARY);
    if (fd < 0) FATAL("open %s: %s", path, strerror(errno));
    buf = xmalloc(want);
    {
        unsigned char *p = buf;
        size_t n = want;
        off_t  o = (off_t)at;
        while (n > 0) {
            ssize_t r = pread(fd, p, n, o);
            if (r <= 0) FATAL("read %s at %lld: %s", path, (long long)o,
                              r < 0 ? strerror(errno) : "short");
            p += r; n -= (size_t)r; o += r;
        }
    }
    close(fd);
    MD5(buf, want, h);
    bin2hex(h, 16, hex);
    free(buf);
}

static void file_fingerprint(struct srcfile *sf, unsigned long long upto)
{
    unsigned long long tailat;
    region_md5(sf->path, 0, upto, sf->hmd5);
    tailat = upto > PREFIXCHK ? upto - PREFIXCHK : 0;
    region_md5(sf->path, tailat, upto - tailat, sf->tmd5);
}

/* Returns 0 clean, or the number of problems reported.  Fatal is the
 * caller's decision: lookup cannot proceed, info can. */
static int files_check(int fatal)
{
    int i, bad = 0;

    for (i = 0; i < Nfiles; i++) {
        struct srcfile *s = &Files[i];
        struct stat sb;
        char hm[33], tm[33];
        unsigned long long tailat;

        if (stat(s->path, &sb) != 0) {
            fprintf(stderr, "ALERT source %d %s: %s. The index addresses "
                    "byte offsets in this file.\n", i, s->path, strerror(errno));
            bad++;
            continue;
        }
        if ((unsigned long long)sb.st_size < s->consumed) {
            fprintf(stderr, "ALERT source %d %s shrank from %s to %s bytes. "
                    "Every offset into it is stale.\n", i, s->path,
                    commify(s->consumed), commify((unsigned long long)sb.st_size));
            bad++;
            continue;
        }
        if (s->consumed == 0) continue;

        region_md5(s->path, 0, s->consumed, hm);
        if (strcmp(hm, s->hmd5) != 0) {
            fprintf(stderr, "ALERT source %d %s was rewritten, not appended "
                    "to: its first %s bytes now hash to %s, not %s.\n",
                    i, s->path,
                    commify(s->consumed < PREFIXCHK ? s->consumed : PREFIXCHK),
                    hm, s->hmd5);
            bad++;
            continue;
        }
        tailat = s->consumed > PREFIXCHK ? s->consumed - PREFIXCHK : 0;
        region_md5(s->path, tailat, s->consumed - tailat, tm);
        if (strcmp(tm, s->tmd5) != 0) {
            fprintf(stderr, "ALERT source %d %s changed inside the indexed "
                    "region: the %s bytes ending at %s now hash to %s, not "
                    "%s. Lines were reordered or rewritten.\n", i, s->path,
                    commify(s->consumed - tailat), commify(s->consumed),
                    tm, s->tmd5);
            bad++;
            continue;
        }
        if ((long long)sb.st_mtime != s->mtime &&
            (unsigned long long)sb.st_size == s->size)
            fprintf(stderr, "note: source %d %s has a new mtime but the same "
                    "size and fingerprints; treating it as unchanged.\n",
                    i, s->path);
    }
    if (bad && fatal)
        FATAL("%d source file%s no longer matches the index. Offsets into "
              "%s meaningless; run 'mdindex build'.",
              bad, bad == 1 ? "" : "s", bad == 1 ? "it are" : "them are");
    return bad;
}

static void manifest_write(void)
{
    char *tmp = pathcat("manifest.new");
    FILE *f;
    int   i, first = 1;

    f = fopen(tmp, "w");
    if (f == NULL) FATAL("open %s: %s", tmp, strerror(errno));
    fprintf(f, "# mdindex manifest v4\n");
    fprintf(f, "types\t");
    for (i = 0; i < Nhtype; i++) { fprintf(f, "%s%s", first ? "" : ",",
                                           Htype[i].name); first = 0; }
    fprintf(f, "\n");
    /* A name is enough to find a native arm again, but not to reconstruct
     * an hx type: the expression IS the type, and an index whose manifest
     * records only "SHA1MD5PASSx01" could be re-opened by a build whose
     * catalog had since changed that expression, with nothing to notice.
     * The expression is therefore written out in full, and update rebuilds
     * from these rows rather than from the catalog. */
    for (i = 0; i < Nhtype; i++) {
        if (Htype[i].fn != NULL) continue;
        fprintf(f, "hxtype\t%s\t%s\t%d\t%d\t%d\t%s\n",
                Htype[i].name, Htype[i].key, Htype[i].job, Htype[i].iters,
                Htype[i].dlen, Htype[i].expr);
    }
    /* An admission guard is part of the type: without it the same database
     * answers differently on lookup than it was built with, reporting a
     * type for words it holds no records for.  Its own row, so the hxtype
     * row keeps the shape an older build can still parse. */
    for (i = 0; i < Nhtype; i++)
        if (Htype[i].guard != NULL)
            fprintf(f, "hxguard\t%s\t%s\n", Htype[i].name, Htype[i].gexpr);
    /* Where a user-defined type came from.  The hxtype row above already
     * carries its expression, which is what the index was built on and
     * what every later read uses, so this row changes no behaviour: it
     * exists so `info` can name the -C file and id behind a type long
     * after that file has moved or changed.  The manifest, not the -C
     * file, is what an existing database means. */
    for (i = 0; i < Nhtype; i++)
        if (Htype[i].uid != NULL)
            fprintf(f, "hxuser\t%s\t%s\t%s\n", Htype[i].name,
                    Htype[i].uid, Htype[i].ufile ? Htype[i].ufile : "");
    /* A type's shapes and its enumerated domain are as much the type as
     * its expression: an index built over 768 digests per word that was
     * read back as one would answer for a fraction of what it holds. */
    for (i = 0; i < Nhtype; i++) {
        int k;
        if (Htype[i].enumdom)
            fprintf(f, "hxenum\t%s\t%s\n", Htype[i].name,
                    edom_name(Htype[i].enumdom));
        if (Htype[i].quiet)
            fprintf(f, "hxquiet\t%s\n", Htype[i].name);
        for (k = 1; k < Htype[i].nshape; k++)
            fprintf(f, "hxshape\t%s\t%s\n", Htype[i].name, Htype[i].sexpr[k]);
    }
    fprintf(f, "# idx\tconsumed\tsize\tmtime\tlines\theadmd5\ttailmd5\tpath\n");
    for (i = 0; i < Nfiles; i++)
        fprintf(f, "%d\t%llu\t%llu\t%lld\t%llu\t%s\t%s\t%s\n",
                i, Files[i].consumed, Files[i].size, Files[i].mtime,
                Files[i].lines, Files[i].hmd5, Files[i].tmd5, Files[i].path);
    if (fclose(f) != 0) FATAL("write %s: %s", tmp, strerror(errno));

    /* rename last: a torn manifest cannot be told from a good one */
    if (rename(tmp, pathcat("manifest")) != 0)
        FATAL("rename manifest: %s", strerror(errno));
}

/* The manifest's own `types` line, read back.  Only the native names are
 * resolved here; an hx type arrives on its own `hxtype` row, which carries
 * the expression and therefore does not depend on the catalog still
 * agreeing.  A name that is neither is left for the hxtype rows to supply,
 * and manifest_types_done() is what notices if one never arrives. */
static int Mtypes_wanted;
static char Mtypes[4096];

static void manifest_types(const char *list)
{
    char  copy[4096];
    char *p, *save = NULL;

    snprintf(Mtypes, sizeof(Mtypes), "%s", list);
    snprintf(copy, sizeof(copy), "%s", list);
    for (p = strtok_r(copy, ",", &save); p; p = strtok_r(NULL, ",", &save)) {
        int i;
        Mtypes_wanted++;
        for (i = 0; i < NDEFSIX; i++)
            if (strcasecmp(p, Defsix[i].key) == 0 ||
                strcasecmp(p, Defsix[i].name) == 0) {
                sel_add_native(&Defsix[i]);
                break;
            }
    }
}

static void manifest_hxtype(const char *row)
{
    char name[64], key[64], expr[8192];
    int  job, iters, dlen;
    const char *why = "";
    hx_program *prog;
    int probed = 0;

    if (sscanf(row, "%63[^\t]\t%63[^\t]\t%d\t%d\t%d\t%8191[^\n]",
               name, key, &job, &iters, &dlen, expr) != 6)
        FATAL("malformed hxtype row in manifest: %s", row);
    if (sel_have(name)) return;
    hx_diag_count = 0;
    prog = hx_compile_expr(expr, NULL);
    if (prog == NULL)
        FATAL("type %s in this database no longer compiles: %s\n"
              "The database cannot be read or updated until it does. "
              "This is a hard error on purpose -- computing a different "
              "digest under the same name would corrupt the index silently.",
              name, expr);
    /* An enumerated type reads salt, so probe it with a member of the
     * domain; the hxenum row that says so has not been read yet, but a
     * concrete salt is harmless for a type that ignores it. */
    probed = hx_probe(prog, &dlen, &why, NULL, "00");
    if (!probed) FATAL("type %s in this database no longer probes clean: "
                       "%s -- %s", name, why, expr);
    sel_reserve(Nhtype + 1);
    memset(&Htype[Nhtype], 0, sizeof(Htype[0]));
    Htype[Nhtype].name   = xstrdup(name);
    Htype[Nhtype].key    = xstrdup(key);
    Htype[Nhtype].dlen   = dlen;
    Htype[Nhtype].maxvar = 1;
    Htype[Nhtype].job    = job;
    Htype[Nhtype].iters  = iters;
    Htype[Nhtype].expr   = xstrdup(expr);
    Htype[Nhtype].prog   = prog;
    Htype[Nhtype].nshape = 1;
    Nhtype++;
}

/* hxenum and hxshape rows follow the hxtype rows, so the type exists. */
static int manifest_find(const char *name, const char *what)
{
    int i;
    for (i = 0; i < Nhtype; i++)
        if (strcmp(Htype[i].name, name) == 0) return i;
    FATAL("manifest has a %s for %s, which it does not hold", what, name);
    return -1;
}

static void manifest_hxenum(const char *row)
{
    char name[64], dom[32];

    if (sscanf(row, "%63[^\t]\t%31s", name, dom) != 2)
        FATAL("malformed hxenum row in manifest: %s", row);
    /* edom_by_name is fatal on an unknown name, which is what this
     * needs: a domain this build cannot walk would index one digest per
     * word where the database holds many, and answer for a fraction of
     * what it contains without saying so. */
    Htype[manifest_find(name, "domain")].enumdom = edom_by_name(dom);
}

/* Provenance only.  The type itself was already rebuilt from its hxtype
 * row, expression and all, so a -C file that has since changed or gone
 * away cannot alter what this database holds; these two fields just let
 * `info` say where the name came from. */
static void manifest_hxuser(const char *row)
{
    char name[64], uid[128], file[4096];
    int  i, n;

    n = sscanf(row, "%63[^\t]\t%127[^\t]\t%4095[^\n]", name, uid, file);
    if (n < 2) FATAL("malformed hxuser row in manifest: %s", row);
    if (n < 3) file[0] = 0;
    i = manifest_find(name, "user id");
    Htype[i].uid   = xstrdup(uid);
    Htype[i].ufile = xstrdup(file);
}

static void manifest_hxshape(const char *row)
{
    char name[64], expr[8192];
    hx_program *sp;
    int i;

    if (sscanf(row, "%63[^\t]\t%8191[^\n]", name, expr) != 2)
        FATAL("malformed hxshape row in manifest: %s", row);
    i = manifest_find(name, "shape");
    if (Htype[i].nshape >= MDX_MAXSHAPE)
        FATAL("manifest gives %s more shapes than %d", name, MDX_MAXSHAPE);
    hx_diag_count = 0;
    sp = hx_compile_expr(expr, NULL);
    if (sp == NULL)
        FATAL("type %s: one of its shapes no longer compiles: %s", name, expr);
    Htype[i].sexpr[Htype[i].nshape] = xstrdup(expr);
    Htype[i].shape[Htype[i].nshape++] = sp;
}

/* The guard rows follow the hxtype rows, so the type already exists. */
static void manifest_hxguard(const char *row)
{
    char name[64], expr[8192];
    int  i;

    if (sscanf(row, "%63[^\t]\t%8191[^\n]", name, expr) != 2)
        FATAL("malformed hxguard row in manifest: %s", row);
    for (i = 0; i < Nhtype; i++)
        if (strcmp(Htype[i].name, name) == 0) break;
    if (i == Nhtype)
        FATAL("manifest has a guard for %s, which it does not hold", name);
    hx_diag_count = 0;
    Htype[i].guard = hx_compile_expr(expr, NULL);
    if (Htype[i].guard == NULL)
        FATAL("type %s: its admission guard no longer compiles: %s\n"
              "Without it this build would report %s for words the index "
              "holds no records for.", name, expr, name);
    Htype[i].gexpr = xstrdup(expr);
}

/* A type named on the types line that no row ever supplied means the index
 * holds records this build cannot reproduce.  That is exactly the shape of
 * data loss -- a digest the index DOES hold, which nothing can now verify
 * -- so it is fatal rather than a warning. */
static void manifest_types_done(void)
{
    if (Mtypes_wanted && Nhtype < Mtypes_wanted)
        FATAL("manifest lists %d hash types (%s) but only %d could be "
              "reconstructed; the index holds records this build cannot "
              "verify", Mtypes_wanted, Mtypes, Nhtype);
}

static int manifest_read(int quiet)
{
    /* The types line carries every selected type's name, so it grows with
     * the type count: 534 types is about 9 KB and the whole catalog would
     * be over 20 KB.  At the old 8 KB a wide manifest was split by fgets
     * and the tail parsed as a source row, which reported a perfectly good
     * database as malformed.  Sized for the catalog, and a line that still
     * does not fit is a hard error rather than a silent split -- half a
     * types line would otherwise look like a database holding half as many
     * types as it does. */
    char  line[262144];
    FILE *f = fopen(pathcat("manifest"), "r");

    if (f == NULL) {
        if (quiet) return 0;
        FATAL("no manifest in %s -- run 'mdindex build' first", Dbdir);
    }
    Nfiles = 0;
    Mtypes_wanted = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        struct srcfile *s;
        char *p, *tab;
        int   idx;

        p = strchr(line, '\n');
        if (p) *p = 0;
        else if (strlen(line) == sizeof(line) - 1)
            FATAL("manifest line longer than %zu bytes in %s; the database "
                  "was written by a build that allowed more types than this "
                  "one can read back", sizeof(line) - 1, Dbdir);
        /* Check the version explicitly.  A v1 row has one field fewer and
         * sscanf happily reads the path into the missing fingerprint, so
         * inferring the version from the field count mis-reports it as a
         * malformed row. */
        if (strncmp(line, "# mdindex manifest v", 20) == 0) {
            /* v3 is READ but not written.  v4 added the overlay, which is
             * a separate file and leaves index.rec byte-for-byte what v3
             * wrote, so a v3 database needs no conversion -- the first
             * build, update or compact rewrites the manifest as v4 and a
             * v3 binary then refuses it, which is the point: that binary
             * would read index.rec correctly and silently ignore every
             * record in the overlay. */
            int v = atoi(line + 20);
            if (v != 3 && v != 4)
                FATAL("%s holds a version %d index; this mdindex writes "
                      "version 4, whose record is 15 bytes and whose key is "
                      "96 bits, so that two words colliding in 64 bits both "
                      "survive the build. The old index cannot be converted "
                      "-- run 'mdindex build' to rebuild it, or use -d to "
                      "point at a version 4 database.",
                      Dbdir, v);
            continue;
        }
        if (line[0] == '#' || line[0] == 0) continue;
        if (strncmp(line, "types\t", 6) == 0) { manifest_types(line + 6); continue; }
        if (strncmp(line, "hxtype\t", 7) == 0) { manifest_hxtype(line + 7); continue; }
        if (strncmp(line, "hxguard\t", 8) == 0) { manifest_hxguard(line + 8); continue; }
        if (strncmp(line, "hxenum\t", 7) == 0)  { manifest_hxenum(line + 7); continue; }
        if (strncmp(line, "hxquiet\t", 8) == 0) {
            Htype[manifest_find(line + 8, "quiet flag")].quiet = 1; continue; }
        if (strncmp(line, "hxshape\t", 8) == 0) { manifest_hxshape(line + 8); continue; }
        if (strncmp(line, "hxuser\t", 7) == 0)  { manifest_hxuser(line + 7); continue; }
        if (Nfiles >= MAXFILES) FATAL("manifest holds more than %d files", MAXFILES);
        files_reserve(Nfiles + 1);
        s = &Files[Nfiles];
        memset(s, 0, sizeof(*s));
        if (sscanf(line, "%d\t%llu\t%llu\t%lld\t%llu\t%32s\t%32s",
                   &idx, &s->consumed, &s->size, &s->mtime,
                   &s->lines, s->hmd5, s->tmd5) != 7)
            FATAL("malformed manifest row (v1 index? rebuild): %s", line);
        if (idx != Nfiles) FATAL("manifest row %d is out of order", idx);
        /* the path is the last field and may contain anything but a tab */
        tab = line;
        for (idx = 0; idx < 7; idx++) {
            tab = strchr(tab, '\t');
            if (tab == NULL) FATAL("malformed manifest row: %s", line);
            tab++;
        }
        snprintf(s->path, sizeof(s->path), "%s", tab);
        Nfiles++;
    }
    fclose(f);
    manifest_types_done();
    maxvar_set();
    return Nfiles;
}

/* ------------------------------------------------------------------ */
/* stage 1: scatter source lines into 256 partitions by digest byte 0  */
/*                                                                      */
/* One pass over the sources produces one scratch record per (line,     */
/* type).  A line's four digests land in four different partitions,     */
/* which is exactly what we want: the partitions stay balanced and      */
/* nothing downstream has to know a record's type.                      */
/* ------------------------------------------------------------------ */

static int             Partfd[NPART];
static pthread_mutex_t Partmtx[NPART];

/* Padded to 128 bytes, and the hot counters are kept in locals inside the
 * worker.  Unpadded, sixteen of these sit in 56-byte slots sharing cache
 * lines, and a per-line write to lines/done invalidates every other core on
 * every line: measured 63 MB/s on a PCIe NVMe that does gigabytes. */
struct scatter {
    int                  fd;
    int                  fidx;
    int                  tid;
    int                  unused;
    unsigned long long   start, end;    /* line-aligned region, absolute */
    const char          *path;
    unsigned long long   lines;         /* out                           */
    unsigned long long   recs;          /* out                           */
    volatile unsigned long long done;   /* out, read by the -v poller    */
    unsigned long long   drops;         /* out, lines past LINECAP       */
    char                 pad[128 - 72];
};

static void part_write(int p, const unsigned char *b, size_t n)
{
    pthread_mutex_lock(&Partmtx[p]);
    while (n > 0) {
        ssize_t w = write(Partfd[p], b, n);
        if (w <= 0) FATAL("write partition %d: %s", p, strerror(errno));
        b += w;
        n -= (size_t)w;
    }
    pthread_mutex_unlock(&Partmtx[p]);
}

/* Read up to want bytes at `at`, never past `end`.  A whole-file mmap of a
 * 31.8 GB input drove this process to 16.8 GB resident and the machine to
 * 15 MB free; bounded reads keep the footprint fixed whatever the input. */
static size_t fill_at(int fd, unsigned char *p, unsigned long long at,
                      unsigned long long end, size_t want, const char *path)
{
    size_t got = 0;
    if (at >= end) return 0;
    if ((unsigned long long)want > end - at) want = (size_t)(end - at);
    while (got < want) {
        ssize_t n = pread(fd, p + got, want - got, (off_t)(at + got));
        if (n < 0) FATAL("pread %s at %llu: %s", path, at + got, strerror(errno));
        if (n == 0) break;
        got += (size_t)n;
    }
    return got;
}

static void *scatter_thread(void *arg)
{
    struct scatter *sc  = arg;
    unsigned char  *buf = xmalloc((size_t)NPART * PARTBUF);
    unsigned char  *dec = xmalloc(UNWRAPBUF);
    unsigned char  *tv  = NULL;         /* $TESTVEC[], on first sight only */
    size_t         *fil = xmalloc(sizeof(size_t) * NPART);
    unsigned char  *rb  = xmalloc((size_t)(CHUNK + LINECAP));
    hx_vm          *vms = vms_new();
    struct hout    *hv  = xmalloc(sizeof(struct hout) * (size_t)Maxvar);
    unsigned long long base = sc->start;    /* file offset of rb[0] */
    unsigned long long lines = 0, recs = 0, drops = 0;
    size_t filled = 0, off = 0;
    int i;

    memset(fil, 0, sizeof(size_t) * NPART);
    filled = fill_at(sc->fd, rb, base, sc->end,
                     (size_t)(CHUNK + LINECAP), sc->path);

    while (off < filled) {
        const unsigned char *lp = rb + off;
        const unsigned char *nl = memchr(lp, '\n', filled - off);
        const unsigned char *mp;
        unsigned long long lineoff, loc;
        size_t llen;
        int ml, t, k, nv;

        if (nl == NULL && base + filled < sc->end) {
            /* partial line at the tail: slide it down and read more */
            size_t keep = filled - off;
            if (keep > LINECAP) {
                /* Past LINECAP with no newline in sight.  DROP the line
                 * rather than abort: one malformed record in a four
                 * billion line source must not kill a multi-hour build.
                 * Discard what is buffered and read forward to the
                 * newline that ends it.  Counted, and the total is
                 * reported -- a drop that left no trace would be
                 * indistinguishable from a word the index never held. */
                unsigned long long p = base + off + keep;
                size_t got;

                drops++;
                for (;;) {
                    if (p >= sc->end) { off = filled; break; }
                    got = fill_at(sc->fd, rb, p, sc->end,
                                  (size_t)(CHUNK + LINECAP), sc->path);
                    if (got == 0) { off = filled; break; }
                    nl = memchr(rb, '\n', got);
                    if (nl != NULL) {
                        base   = p;
                        filled = got;
                        off    = (size_t)(nl - rb) + 1;
                        break;
                    }
                    p += got;
                }
                if (off >= filled) break;       /* region exhausted */
                continue;
            }
            memmove(rb, rb + off, keep);
            base  += off;
            filled = keep;
            off    = 0;
            filled += fill_at(sc->fd, rb + filled, base + filled, sc->end,
                              (size_t)(CHUNK + LINECAP) - filled, sc->path);
            if (filled == keep)
                FATAL("%s: short read before end of region at %llu",
                      sc->path, base + filled);
            continue;
        }

        llen    = nl ? (size_t)(nl - lp) : (filled - off);
        /* A CRLF line ends "...\r\n", and the \r is a line TERMINATOR
         * here, not a character of the word.  mdxfind strips it -- see the
         * f[-1] == '\r' test in its reader -- so mdindex must too, or a
         * wordlist saved on Windows indexes digests of "password\r" that
         * mdxfind will never produce and no query will ever match.  Both
         * ends have to agree: fetch_line strips it on the way back out,
         * because the lookup re-hashes the line it fetched and a mismatch
         * there reads as a stale index rather than as a CRLF file. */
        if (llen > 0 && lp[llen - 1] == '\r') llen--;
        if (llen > LINECAP) {       /* tail of a region, no newline */
            drops++;
            off += llen + (nl ? 1 : 0);
            continue;
        }
        lineoff = base + off;
        loc     = ((unsigned long long)sc->fidx << OFFBITS) | lineoff;

        md_unwrap(lp, llen, dec, UNWRAPBUF, &tv, &mp, &ml, sc->path, lineoff);

        /* One line can yield several records for one type: NTLM reads a
         * non-ASCII word as UTF-8, CP1251 and CP1252, and all three are
         * digests mdxfind can produce for it, so all three are indexed. */
        for (t = 0; t < Nhtype; t++) {
            nv = type_hash(t, vms, mp, ml, hv);
            for (k = 0; k < nv; k++) {
                unsigned char *r;
                int p = hv[k].dig[0];

                if (fil[p] + SRECSZ > PARTBUF) {
                    part_write(p, buf + (size_t)p * PARTBUF, fil[p]);
                    fil[p] = 0;
                }
                r = buf + (size_t)p * PARTBUF + fil[p];
                memcpy(r, hv[k].dig, KEYSZ);
                be_put(r + KEYSZ, loc, LOCSZ);
                fil[p] += SRECSZ;
                recs++;
            }
        }

        off += llen + (nl ? 1 : 0);
        if ((++lines & 0xFFFF) == 0) sc->done = base + off - sc->start;

        if (off >= filled && base + filled < sc->end) {
            base  += filled;
            filled = fill_at(sc->fd, rb, base, sc->end,
                             (size_t)(CHUNK + LINECAP), sc->path);
            off    = 0;
        }
    }

    for (i = 0; i < NPART; i++)
        if (fil[i] > 0) part_write(i, buf + (size_t)i * PARTBUF, fil[i]);

    sc->lines = lines;
    sc->recs  = recs;
    sc->drops = drops;
    sc->done  = base + off - sc->start;
    free(buf);
    free(dec);
    free(tv);
    free(fil);
    free(rb);
    free(hv);
    vms_free(vms);
    return NULL;
}

/* Scatter one source file from its watermark to EOF.  Returns lines added. */
/* Progress, for build and update ONLY -- never on the query path.  A
 * lookup's stdout carries solutions and is meant to be piped; its stderr
 * carries the counts that go with them.  A progress line scrolling past
 * in the middle of that is noise to a pipeline that has no use for it,
 * and `check` is fast enough not to need one either.
 *
 * Integer percent, written only when it changes, so a loop over billions
 * of records costs at most 100 writes.  rling.c:1414 does the same. */
static void pct_line(const char *what, unsigned long long at,
                     unsigned long long of, int *last, double t0)
{
    int p;

    if (!Verbose || of == 0) return;
    p = (int)((at * 100ULL) / of);
    if (p == *last) return;
    *last = p;
    fprintf(stderr, "\r  %-30s %3d%%  %.0fs   ", what, p, now() - t0);
    fflush(stderr);
}

static unsigned long long scatter_file(struct srcfile *sf, int fidx)
{
    struct scatter *sc;
    pthread_t      *th;
    unsigned long long span, added = 0, drops = 0, *bound;
    double t0 = now();
    int fd, i;

    if (sf->size <= sf->consumed) return 0;
    if (sf->size > MAXOFF)
        FATAL("%s is %s bytes, past the %s byte per-file ceiling that the "
              "%d-bit offset field allows.", sf->path, commify(sf->size),
              commify(MAXOFF), OFFBITS);

    fd = open(sf->path, O_RDONLY | O_BINARY);
    if (fd < 0) FATAL("open %s: %s", sf->path, strerror(errno));

    /* Split the unread region into Nthreads line-aligned pieces. */
    span  = (sf->size - sf->consumed) / (unsigned)Nthreads + 1;
    bound = xmalloc(sizeof(*bound) * (size_t)(Nthreads + 1));
    bound[0] = sf->consumed;
    for (i = 1; i < Nthreads; i++) {
        unsigned long long at = sf->consumed + span * (unsigned)i;
        unsigned char b[65536];
        if (at >= sf->size) { bound[i] = sf->size; continue; }
        for (;;) {
            ssize_t n = pread(fd, b, sizeof(b), (off_t)at);
            unsigned char *nl;
            if (n <= 0) { at = sf->size; break; }
            nl = memchr(b, '\n', (size_t)n);
            if (nl) { at += (unsigned long long)(nl - b) + 1; break; }
            at += (unsigned long long)n;
            if (at >= sf->size) { at = sf->size; break; }
        }
        bound[i] = at < sf->size ? at : sf->size;
    }
    bound[Nthreads] = sf->size;
    for (i = 1; i <= Nthreads; i++)
        if (bound[i] < bound[i - 1]) bound[i] = bound[i - 1];

    sc = xmalloc(sizeof(*sc) * (size_t)Nthreads);
    th = xmalloc(sizeof(*th) * (size_t)Nthreads);
    memset(sc, 0, sizeof(*sc) * (size_t)Nthreads);
    for (i = 0; i < Nthreads; i++) {
        sc[i].fd    = fd;
        sc[i].fidx  = fidx;
        sc[i].tid   = i;
        sc[i].start = bound[i];
        sc[i].end   = bound[i + 1];
        sc[i].path  = sf->path;
        if (pthread_create(&th[i], NULL, scatter_thread, &sc[i]) != 0)
            FATAL("pthread_create: %s", strerror(errno));
    }
    if (Verbose) {
        unsigned long long total = sf->size - sf->consumed, seen;
        for (;;) {
            struct timespec ts = { 0, 250 * 1000 * 1000 };
            nanosleep(&ts, NULL);
            seen = 0;
            for (i = 0; i < Nthreads; i++) seen += sc[i].done;
            fprintf(stderr, "\r  %s  %s of %s bytes  %3d%%  %.0fs   ",
                    sf->path, commify(seen), commify(total),
                    (int)((seen * 100ULL) / (total ? total : 1)),
                    now() - t0);
            if (seen >= total) break;
        }
    }
    for (i = 0; i < Nthreads; i++) {
        pthread_join(th[i], NULL);
        added += sc[i].lines;
        drops += sc[i].drops;
    }
    if (Verbose) fputc('\n', stderr);
    fprintf(stderr, "  %-40s %18s lines  %6.1fs\n",
            sf->path, commify(added), now() - t0);
    /* Never silent in aggregate.  A line past LINECAP is skipped, and a
     * word that was skipped is indistinguishable at lookup time from one
     * the index never held, so the count has to surface somewhere. */
    if (drops)
        fprintf(stderr, "  %-40s %18s lines over %s bytes, DROPPED\n",
                sf->path, commify(drops), commify(LINECAP));
    close(fd);
    free(bound);
    free(sc);
    free(th);
    return added;
}

/* ------------------------------------------------------------------ */
/* stage 2: sort each partition and emit the index                     */
/* ------------------------------------------------------------------ */

/* The scratch key is byte-for-byte the stored key, so memcmp over a whole
 * scratch record is (key, file, offset) -- and the manifest is in priority
 * order, so the first record of an equal-key run is the one to keep. */
static int srec_cmp(const void *a, const void *b)
{
    return memcmp(a, b, SRECSZ);
}

/* Order by LOCATOR first.  Every record of one source line carries the
 * same locator, so this groups a line's records together whatever their
 * keys -- which is what lets one probe answer for all of them. */
static int loc_cmp(const void *a, const void *b)
{
    int c = memcmp((const unsigned char *)a + KEYSZ,
                   (const unsigned char *)b + KEYSZ, LOCSZ);
    return c ? c : memcmp(a, b, KEYSZ);
}

struct outbuf {
    int            fd;
    unsigned char *b;
    size_t         fill, cap;
};

static void ob_open(struct outbuf *o, const char *path, size_t cap)
{
    o->fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
    if (o->fd < 0) FATAL("open %s: %s", path, strerror(errno));
    o->b = xmalloc(cap);
    o->cap = cap;
    o->fill = 0;
}

static void writeall(int fd, const unsigned char *p, size_t n)
{
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) FATAL("write index: %s", strerror(errno));
        p += w;
        n -= (size_t)w;
    }
}

static void ob_flush(struct outbuf *o)
{
    writeall(o->fd, o->b, o->fill);
    o->fill = 0;
}

static void ob_put(struct outbuf *o, const unsigned char *r, size_t n)
{
    /* Anything too large for the buffer goes straight to the file. */
    if (n >= o->cap) { ob_flush(o); writeall(o->fd, r, n); return; }
    if (o->fill + n > o->cap) ob_flush(o);
    memcpy(o->b + o->fill, r, n);
    o->fill += n;
}

static void ob_close(struct outbuf *o)
{
    ob_flush(o);
    if (close(o->fd) != 0) FATAL("close index: %s", strerror(errno));
    free(o->b);
}

static unsigned long long fsize(const char *path)
{
    struct stat sb;
    if (stat(path, &sb) != 0) FATAL("stat %s: %s", path, strerror(errno));
    return (unsigned long long)sb.st_size;
}

static void preadall(int fd, void *buf, size_t n, off_t off, const char *what)
{
    unsigned char *p = buf;
    while (n > 0) {
        ssize_t r = pread(fd, p, n, off);
        if (r <= 0) FATAL("pread %s: %s", what, r < 0 ? strerror(errno) : "short");
        p += r; n -= (size_t)r; off += r;
    }
}

static void readall(int fd, void *buf, size_t n, const char *what)
{
    unsigned char *p = buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r <= 0) FATAL("read %s: %s", what, r < 0 ? strerror(errno) : "short");
        p += r; n -= (size_t)r;
    }
}

/* Sort the partitions and write index.dir + index.rec.
 *
 * olddir/oldfd, when present, are the index being replaced.  Its records
 * expand back into scratch form WITHOUT LOSS -- the stored key is the whole
 * scratch key and the three implied bytes come back from the bucket -- so an
 * update sorts and dedups the old and new records together on exactly the
 * same terms as a build.  That is the property that makes a re-appearance of
 * an already-indexed word cost nothing and add nothing.
 *
 * ponytail: the old index is already sorted, so a streaming two-way merge
 * would halve the I/O and skip the re-sort.  Worth writing when an update
 * stops finishing inside a coffee break; until then this is one code path
 * instead of two, and the one that cannot disagree with itself. */
static int fetch_line(int fidx, unsigned long long off, char **out,
                      size_t *outlen);

/* Two records with one key and two locators are EITHER the same word read
 * from two files -- which priority says to keep once, and which is what
 * holds the index to its size when sources overlap -- OR two different
 * words whose digests collide, which must both survive.  Nothing in the
 * record distinguishes them, so the only honest test is to read the two
 * lines and compare them.  That costs two seeks, and is reached only on
 * an equal key, which is rare by construction: it is the collision rate,
 * plus however much the sources overlap.
 *
 * Returns 1 when the two locators name the same text, i.e. a duplicate
 * word rather than a collision. */
static int same_line(unsigned long long la, unsigned long long lb)
{
    char   *p, *tmp;
    size_t  na, nb;
    int     eq;

    if (la == lb) return 1;
    if (!fetch_line((int)(la >> OFFBITS), la & (MAXOFF - 1), &p, &na))
        return 0;                      /* unreadable: assume distinct */
    tmp = xmalloc(na + 1);             /* fetch_line reuses one buffer */
    memcpy(tmp, p, na);
    if (!fetch_line((int)(lb >> OFFBITS), lb & (MAXOFF - 1), &p, &nb)) {
        free(tmp);
        return 0;
    }
    eq = (na == nb) && memcmp(tmp, p, na) == 0;
    free(tmp);
    return eq;
}

static int same_word(const unsigned char *a, const unsigned char *b)
{
    return same_line(be_get(a + KEYSZ, LOCSZ), be_get(b + KEYSZ, LOCSZ));
}

static void emit_index(uint64_t *olddir, int oldfd)
{
    uint64_t      *dir = xmalloc(sizeof(uint64_t) * (NBUCK + 1));
    unsigned char *arr = NULL, *oldbuf = NULL;
    size_t         arrcap = 0, oldcap = 0;
    unsigned long long total = 0, dropped = 0;
    struct outbuf  ob;
    double t0 = now();
    int p;
    uint32_t b;

    memset(dir, 0, sizeof(uint64_t) * (NBUCK + 1));
    ob_open(&ob, pathcat("index.rec.new"), 8 * 1024 * 1024);

    for (p = 0; p < NPART; p++) {
        char partpath[8192];
        unsigned long long nnew, nold = 0;
        int fd;

        snprintf(partpath, sizeof(partpath), "%s/part/%03d", Dbdir, p);
        nnew = fsize(partpath) / SRECSZ;
        if (olddir) nold = olddir[(uint64_t)(p + 1) << 16] -
                           olddir[(uint64_t)p << 16];

        /* arr holds the NEW records only.  The old index is already sorted
         * -- that is the whole point of having written it -- so it is
         * merged in rather than re-sorted with them.  Sorting the union
         * meant sorting 59 million records to absorb 30, and expanding
         * every old record into 18-byte scratch form to do it. */
        if (nnew * SRECSZ > arrcap) {
            free(arr);
            arrcap = (size_t)(nnew * SRECSZ) + (16 << 20);
            arr = xmalloc(arrcap);
        }

        fd = open(partpath, O_RDONLY | O_BINARY);
        if (fd < 0) FATAL("open %s: %s", partpath, strerror(errno));
        readall(fd, arr, (size_t)(nnew * SRECSZ), partpath);
        close(fd);

        if (nnew > 1)
            qsort_mt(arr, (size_t)nnew, SRECSZ, srec_cmp, Nthreads, FORKELEM);

        if (olddir && nold > 0) {
            /* One read for the whole partition, not one per record.  The
             * slice is contiguous because the index is sorted and a
             * partition is a prefix of it; record by record is billions of
             * syscalls on a full-size index and is invisible in a test. */
            if (nold * RECSZ > oldcap) {
                free(oldbuf);
                oldcap = (size_t)(nold * RECSZ) + (16 << 20);
                oldbuf = xmalloc(oldcap);
            }
            preadall(oldfd, oldbuf, (size_t)(nold * RECSZ),
                     (off_t)(olddir[(uint64_t)p << 16] * RECSZ), "index.rec");
        }

        /* The two-way merge.  Both sides are sorted on the whole scratch
         * record, which is (key, file, offset), so taking the smaller of
         * the two heads yields exactly the order the combined sort used to
         * produce -- including which record of an equal-key pair comes
         * first, and so which one dedup keeps.  The locator carries the
         * file in its high bits and the manifest is in priority order, so
         * that is still the highest-priority copy of the word, whether it
         * arrived in this run or years ago. */
        {
        unsigned long long inew = 0, iold = 0;
        uint64_t  obase = olddir ? olddir[(uint64_t)p << 16] : 0;
        uint32_t  obk   = (uint32_t)p << 16;
        const unsigned char *orec = oldbuf;
        unsigned char oldscr[SRECSZ], prev[SRECSZ];
        int have_old = 0, haveprev = 0;

        for (;;) {
            const unsigned char *r;
            unsigned char  out[RECSZ];

            /* Expand the old side one record at a time, and only when it
             * is actually needed.  The three bytes the record does not
             * store come from the bucket it sits in, which is why the
             * bucket cursor walks forward with the read cursor. */
            if (!have_old && iold < nold) {
                while (obase + iold >= olddir[obk + 1]) obk++;
                oldscr[0] = (unsigned char)(obk >> 16);
                oldscr[1] = (unsigned char)(obk >> 8);
                oldscr[2] = (unsigned char)(obk);
                memcpy(oldscr + 3, orec, RESID);              /* digest 3..11 */
                memcpy(oldscr + KEYSZ, orec + RESID, LOCSZ);  /* locator     */
                have_old = 1;
            }
            if (inew >= nnew && !have_old) break;

            if (!have_old)
                r = arr + inew++ * SRECSZ;
            else if (inew >= nnew)
                r = oldscr;
            else if (memcmp(arr + inew * SRECSZ, oldscr, SRECSZ) <= 0)
                r = arr + inew++ * SRECSZ;
            else
                r = oldscr;

            if (r == oldscr) { have_old = 0; iold++; orec += RECSZ; }

            /* Dedup on the WHOLE key, which is why the key is 96 bits and
             * not the 64 a query needs.  This comparison never sees the
             * plaintext, so at 64 bits it could not tell "the same word from
             * two source files" -- the 6.5 billion drops this is for -- from
             * "two different words whose digests collide in 64 bits", and it
             * silently discarded the second.  About 6 such pairs exist in a
             * 15-billion-record index (n^2/2^65), and each cost two lookups:
             * a half-MD5 could never return both, and a FULL digest query
             * for the losing word returned nothing at all, with no ALERT
             * because that check only fires at or below KEYBITS.  At 96 bits
             * the expectation is 1.4e-9 and both records survive. */
            /* The predecessor is now the one the MERGE last emitted, not
             * the one that happens to sit behind r in an array -- the two
             * heads come from different buffers.  Same rule, same result,
             * and it is the merge order above that guarantees equal keys
             * are still adjacent for it to see. */
            /* Dedup on the WHOLE scratch record -- key AND locator --
             * not on the key alone.  Two records with one key and two
             * locators are two different WORDS whose digests collide:
             * md5(md5("password")) and md5(md5(rev("drowssap"))) are the
             * same 128 bits, and keying on the digest threw one of them
             * away.  The loss was unrecoverable, because the surviving
             * record names the other line and lookup can only regenerate
             * types for the line it found -- so a full-digest query for
             * MD5x02 answered MD5revpx02 with a different password, which
             * is true and useless.  Same-word aliases still collapse,
             * since MD5x01 and MD5UCx01 of one line share a locator too;
             * only genuine cross-word collisions are kept. */
            if (haveprev && memcmp(r, prev, KEYSZ) == 0) {
                /* Same key.  An exact repeat of the whole record is the
                 * same word met twice; otherwise read both lines and let
                 * the TEXT decide, because a collision between two
                 * different words must keep both records -- keying on the
                 * digest alone threw one away, and the loss was
                 * unrecoverable: lookup can only regenerate types for the
                 * line the surviving record names, so a full-digest query
                 * answered with a different password under a different
                 * type, which is true and useless. */
                if (memcmp(r + KEYSZ, prev + KEYSZ, LOCSZ) == 0 ||
                    same_word(r, prev)) { dropped++; continue; }
            }
            memcpy(prev, r, SRECSZ);
            haveprev = 1;

            memcpy(out, r + 3, RESID);
            memcpy(out + RESID, r + KEYSZ, LOCSZ);
            ob_put(&ob, out, RECSZ);
            dir[(((uint32_t)r[0] << 16) | ((uint32_t)r[1] << 8) | r[2]) + 1]++;
            total++;
        }
        }

        if (Verbose)
            fprintf(stderr, "\r  partition %3d/%d %3d%%  %s records kept  "
                            "%.0fs   ",
                    p + 1, NPART, ((p + 1) * 100) / NPART,
                    commify(total), now() - t0);
    }
    if (Verbose) fputc('\n', stderr);
    ob_close(&ob);

    for (b = 0; b < NBUCK; b++) dir[b + 1] += dir[b];
    if (dir[NBUCK] != total) FATAL("directory sums to %llu, emitted %llu",
                                   (unsigned long long)dir[NBUCK], total);

    {
        struct outbuf  db;
        unsigned char *be = xmalloc(8 * (size_t)(NBUCK + 1));
        uint64_t       k;
        for (k = 0; k <= NBUCK; k++) be_put(be + k * 8, dir[k], 8);
        ob_open(&db, pathcat("index.dir.new"), 8 * 1024 * 1024);
        ob_put(&db, be, 8 * (size_t)(NBUCK + 1));
        ob_close(&db);
        free(be);
    }

    /* The merge is finished with oldfd, and it must be CLOSED before the
     * rename below rather than by the caller after it.  POSIX replaces an
     * open file happily; Windows refuses, and not for want of sharing --
     * MoveFileEx with MOVEFILE_REPLACE_EXISTING returns ERROR_ACCESS_DENIED
     * on an open target even when the handle was opened FILE_SHARE_DELETE.
     * So this function CONSUMES oldfd; compact must not close it again. */
    if (oldfd >= 0) close(oldfd);

    /* rename only after both files are complete */
    if (rename(pathcat("index.rec.new"), pathcat("index.rec")) != 0)
        FATAL("rename index.rec: %s", strerror(errno));
    if (rename(pathcat("index.dir.new"), pathcat("index.dir")) != 0)
        FATAL("rename index.dir: %s", strerror(errno));

    fprintf(stderr, "%s records, %s duplicates dropped, %.1fs\n",
            commify(total), commify(dropped), now() - t0);
    free(dir);
    free(arr);
    free(oldbuf);
}

/* ------------------------------------------------------------------ */
/* partition scratch                                                   */
/* ------------------------------------------------------------------ */

/* A build holds all NPART scratch files open at once.  The ambient
 * descriptor limit is not a property of the machine: an interactive shell
 * on this iMac allows 1,048,576, while launchd hands its own default of
 * 256 to anything IT starts -- at(1), cron, a LaunchAgent.  The same
 * build that works from a terminal then dies at partition 253 with
 * "Too many open files", one second in, which is what happened to the
 * 2026-10-17 01:00 rebuild.  The hard limit is unlimited, so ask for what
 * the code actually needs rather than inheriting a number nobody chose. */
#ifdef _WIN32
/* Windows has no rlimit.  The CRT caps open descriptors at 512 by default
 * and _setmaxstdio raises it to 8192, which is the same question asked a
 * different way: a build needs one descriptor per partition plus the
 * sources, and 256 partitions against a 512 default is close enough to
 * the edge to be worth raising rather than discovering at partition 253. */
static void want_fds(unsigned want)
{
    int have = _getmaxstdio();

    if (have >= (int)want) return;
    if (_setmaxstdio((int)want) == -1 || _getmaxstdio() < (int)want)
        fprintf(stderr, "warning: %d file descriptors available, %u needed "
                "for %d partitions -- the build will fail part way\n",
                _getmaxstdio(), want, NPART);
}
#else
static void want_fds(unsigned want)
{
    struct rlimit rl;

    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) return;
    if (rl.rlim_cur >= (rlim_t)want) return;
    rl.rlim_cur = (rl.rlim_max == RLIM_INFINITY || rl.rlim_max > (rlim_t)want)
                  ? (rlim_t)want : rl.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0 || rl.rlim_cur < (rlim_t)want)
        fprintf(stderr, "warning: %llu file descriptors available, %u needed "
                "for %d partitions -- the build will fail part way\n",
                (unsigned long long)rl.rlim_cur, want, NPART);
}
#endif

static void part_open(void)
{
    char path[8192];
    int  p;

    want_fds(NPART + 32);               /* partitions, plus the usual few */

    snprintf(path, sizeof(path), "%s/part", Dbdir);
    if (mkdir(path, 0755) != 0 && errno != EEXIST)
        FATAL("mkdir %s: %s", path, strerror(errno));
    for (p = 0; p < NPART; p++) {
        snprintf(path, sizeof(path), "%s/part/%03d", Dbdir, p);
        Partfd[p] = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
        if (Partfd[p] < 0) FATAL("open %s: %s", path, strerror(errno));
        pthread_mutex_init(&Partmtx[p], NULL);
    }
}

static void part_close(void)
{
    int p;
    for (p = 0; p < NPART; p++)
        if (close(Partfd[p]) != 0)
            FATAL("close partition %d: %s", p, strerror(errno));
}

static void part_remove(void)
{
    char path[8192];
    int  p;
    for (p = 0; p < NPART; p++) {
        snprintf(path, sizeof(path), "%s/part/%03d", Dbdir, p);
        unlink(path);
    }
    snprintf(path, sizeof(path), "%s/part", Dbdir);
    rmdir(path);
}

/* ------------------------------------------------------------------ */
/* lookup                                                              */
/* ------------------------------------------------------------------ */

static const unsigned char *Dir;        /* mmap, big-endian uint64      */
static const unsigned char *Rec;        /* mmap, RECSZ records          */
static unsigned long long   Nrec;
static int                  Srcfd[MAXFILES];

/* ---- the overlay ----
 *
 * add.rec is a plain sorted array of SRECSZ scratch records -- the whole
 * 12-byte key and then the locator -- and it has NO directory, because it
 * is searched by binary search over the key rather than by bucket.  It
 * holds records whose keys are not in index.rec, and a lookup answers from
 * both.
 *
 * WHY IT EXISTS.  index.rec is a packed sorted array, so inserting into it
 * shifts everything after the insertion point: absorbing one new word costs
 * an index-sized read and an index-sized write.  Measured on the real
 * database, a night's solved.words was 1,197 lines, of which 164 were
 * records not already held -- and taking them cost 452 GB of I/O and 36
 * minutes.  Appending them here instead costs their own size.
 *
 * The price is paid at lookup: every query also binary-searches the
 * overlay.  That is why `compact` exists, and why update reports the
 * overlay's size -- the arrangement is only cheap while the overlay stays
 * small relative to the index.  compact folds it in with the same two-way
 * merge an update used to run, and is the ONLY thing that rewrites
 * index.rec. */
static const unsigned char *Add;        /* mmap, SRECSZ records, sorted */
static unsigned long long   Nadd;

static uint64_t dirget(uint32_t b)
{
    return be_get(Dir + (size_t)b * 8, 8);
}

/* Map the index files.  Split out of index_open so that update, which has
 * already read the manifest and checked the sources, can get at the index
 * for its own probes without repeating either. */
static void index_unmap(void);

/* Re-mapping RELEASES first.  update and the selftest both call this more
 * than once in a process, and without the release each call leaked the
 * previous mapping: invisible on POSIX, where a leaked read-only mapping
 * costs only address space and a file may be replaced while mapped, and
 * fatal on Windows, where the stale mapping keeps a handle on index.rec
 * and compact's rename over it fails with a sharing violation after the
 * whole merge has been done. */
static void index_map(void)
{
    unsigned long long dsz;
    int fd;

    index_unmap();

    dsz = fsize(pathcat("index.dir"));
    if (dsz != 8ULL * (NBUCK + 1))
        FATAL("index.dir is %llu bytes, expected %llu -- rebuild",
              dsz, 8ULL * (NBUCK + 1));
    fd = open(pathcat("index.dir"), O_RDONLY | O_BINARY);
    if (fd < 0) FATAL("open index.dir: %s", strerror(errno));
    Dir = mmap(NULL, (size_t)dsz, PROT_READ, MAP_SHARED, fd, 0);
    if (Dir == MAP_FAILED) FATAL("mmap index.dir: %s", strerror(errno));
    close(fd);

    Nrec = fsize(pathcat("index.rec")) / RECSZ;
    if (Nrec != dirget(NBUCK))
        FATAL("index.rec holds %llu records, index.dir expects %llu -- rebuild",
              Nrec, (unsigned long long)dirget(NBUCK));
    fd = open(pathcat("index.rec"), O_RDONLY | O_BINARY);
    if (fd < 0) FATAL("open index.rec: %s", strerror(errno));
    Rec = mmap(NULL, (size_t)(Nrec * RECSZ), PROT_READ, MAP_SHARED, fd, 0);
    if (Rec == MAP_FAILED) FATAL("mmap index.rec: %s", strerror(errno));
    close(fd);

    /* The overlay is optional: a database that has only ever been built,
     * or has just been compacted, has none. */
    Add = NULL;
    Nadd = 0;
    if (access(pathcat("add.rec"), R_OK) == 0) {
        unsigned long long asz = fsize(pathcat("add.rec"));
        if (asz % SRECSZ)
            FATAL("add.rec is %llu bytes, not a whole number of %d-byte "
                  "records -- remove it and run 'update'", asz, SRECSZ);
        Nadd = asz / SRECSZ;
        if (Nadd) {
            fd = open(pathcat("add.rec"), O_RDONLY | O_BINARY);
            if (fd < 0) FATAL("open add.rec: %s", strerror(errno));
            Add = mmap(NULL, (size_t)asz, PROT_READ, MAP_SHARED, fd, 0);
            if (Add == MAP_FAILED) FATAL("mmap add.rec: %s", strerror(errno));
            close(fd);
        }
    }

    memset(Srcfd, -1, sizeof(Srcfd));
}

/* Release the mappings before replacing or deleting what they map.
 *
 * On POSIX this is housekeeping: a file may be renamed over or unlinked
 * while it is mapped, and the mapping stays valid until the process
 * exits, which is why nothing called this before.  On Windows a mapped
 * file CANNOT be replaced or deleted -- compact's rename over index.rec
 * and its unlink of add.rec both fail with a sharing violation -- so the
 * release is not optional there.
 *
 * Called immediately before the write that would otherwise be refused,
 * never earlier: anything still reading through Dir/Rec/Add after this
 * is reading freed address space. */
static void index_unmap(void)
{
    if (Dir != NULL) { munmap((void *)Dir, (size_t)(8ULL * (NBUCK + 1)));
                       Dir = NULL; }
    if (Rec != NULL) { munmap((void *)Rec, (size_t)(Nrec * RECSZ));
                       Rec = NULL; }
    if (Add != NULL) { munmap((void *)Add, (size_t)(Nadd * SRECSZ));
                       Add = NULL; }
}

static void index_open(void)
{
    manifest_read(0);
    files_check(1);
    index_map();
}

/* ---- queries ---- */

struct query {
    unsigned char d[MAXDIG];            /* the digest, as far as supplied */
    unsigned char klo[KEYSZ], khi[KEYSZ];
    int           nbits;
};

/* Build the inclusive key range a q-bit prefix selects.  Below KEYBITS the
 * range spans many records; above it the index filters on the first KEYBITS
 * and the rest of the digest is checked after the line is read. */
static void query_bounds(struct query *q)
{
    int i;
    for (i = 0; i < KEYSZ; i++) {
        int left = q->nbits - i * 8;
        if (left >= 8) { q->klo[i] = q->d[i]; q->khi[i] = q->d[i]; }
        else if (left <= 0) { q->klo[i] = 0x00; q->khi[i] = 0xFF; }
        else {
            unsigned mask = (0xFFu << (8 - left)) & 0xFF;
            q->klo[i] = (unsigned char)(q->d[i] & mask);
            q->khi[i] = (unsigned char)((q->d[i] & mask) | (~mask & 0xFF));
        }
    }
}

/* Do the first nbits of a regenerated digest equal the query's? */
static int digest_prefix_eq(const unsigned char *a, const unsigned char *b,
                            int nbits)
{
    int whole = nbits / 8, rest = nbits & 7;
    if (whole && memcmp(a, b, (size_t)whole) != 0) return 0;
    if (rest) {
        unsigned mask = (0xFFu << (8 - rest)) & 0xFF;
        if (((a[whole] ^ b[whole]) & mask) != 0) return 0;
    }
    return 1;
}

static int qcmp(const void *a, const void *b)
{
    const struct query *x = a, *y = b;
    int c = memcmp(x->klo, y->klo, KEYSZ);
    if (c) return c;
    return (x->nbits > y->nbits) - (x->nbits < y->nbits);
}

/* ---- candidates ---- */

struct cand {
    unsigned long long loc;
    uint32_t           qi;
};

static struct cand *Cand;
static size_t       Ncand, Ccap;

static void cand_push(unsigned long long loc, uint32_t qi)
{
    if (Ncand == Ccap) {
        Ccap = Ccap ? Ccap * 2 : 4096;
        Cand = realloc(Cand, sizeof(*Cand) * Ccap);
        if (Cand == NULL) FATAL("out of memory for %zu candidates", Ccap);
    }
    Cand[Ncand].loc = loc;
    Cand[Ncand].qi  = qi;
    Ncand++;
}

static int ccmp(const void *a, const void *b)
{
    const struct cand *x = a, *y = b;
    if (x->loc != y->loc) return x->loc < y->loc ? -1 : 1;
    return (x->qi > y->qi) - (x->qi < y->qi);
}

/* Probe one query: one directory reference per bucket it spans, then a
 * binary search inside each. */
static void probe_query(const struct query *q, uint32_t qi)
{
    uint32_t blo = ((uint32_t)q->klo[0] << 16) | ((uint32_t)q->klo[1] << 8) | q->klo[2];
    uint32_t bhi = ((uint32_t)q->khi[0] << 16) | ((uint32_t)q->khi[1] << 8) | q->khi[2];
    uint32_t b;

    for (b = blo; ; b++) {
        uint64_t lo = dirget(b), hi = dirget(b + 1), a, z, m;

        a = lo; z = hi;
        while (a < z) {
            m = a + (z - a) / 2;
            if (memcmp(Rec + m * RECSZ, q->klo + 3, RESID) < 0) a = m + 1;
            else z = m;
        }
        for (m = a; m < hi; m++) {
            const unsigned char *r = Rec + m * RECSZ;
            if (memcmp(r, q->khi + 3, RESID) > 0) break;
            cand_push(be_get(r + RESID, LOCSZ), qi);
        }
        if (b == bhi) break;
    }
}

/* Is this key already in the MAIN index?  One bucket reference and a
 * binary search, used by update to keep words it has already indexed out
 * of the overlay -- without it the overlay grows with every re-appearance
 * of a word rather than with new ones, and the measured night was 7,404
 * re-appearances to 164 new records. */
/* Does the main index already hold this WORD at this key?  Holding the
 * key at another locator is either the same word met at another offset --
 * already indexed, so the new record is redundant -- or a different word
 * whose digest collides, which must be kept.  Only the line text tells
 * them apart, so the run of equal keys is walked and each candidate's
 * line compared.  The key is no longer unique in index.rec, which is why
 * the run has to be walked at all. */
static int main_has_record(const unsigned char *k)
{
    uint32_t b = ((uint32_t)k[0] << 16) | ((uint32_t)k[1] << 8) | k[2];
    uint64_t a = dirget(b), z = dirget(b + 1), m, lo;

    while (a < z) {
        int c;
        m = a + (z - a) / 2;
        c = memcmp(Rec + m * RECSZ, k + 3, RESID);
        if (c < 0) a = m + 1;
        else if (c > 0) z = m;
        else {
            lo = m;
            while (lo > dirget(b) &&
                   memcmp(Rec + (lo - 1) * RECSZ, k + 3, RESID) == 0) lo--;
            for (; lo < dirget(b + 1) &&
                   memcmp(Rec + lo * RECSZ, k + 3, RESID) == 0; lo++)
                if (same_line(be_get(Rec + lo * RECSZ + RESID, LOCSZ),
                              be_get(k + KEYSZ, LOCSZ)))
                    return 1;
            return 0;
        }
    }
    return 0;
}

/* The overlay has no directory, so the whole key is compared and the
 * search is over the whole file.  It is one binary search per query on
 * top of the main probe. */
static void probe_overlay(const struct query *q, uint32_t qi)
{
    unsigned long long a = 0, z = Nadd, m;

    if (Nadd == 0) return;
    while (a < z) {
        m = a + (z - a) / 2;
        if (memcmp(Add + m * SRECSZ, q->klo, KEYSZ) < 0) a = m + 1;
        else z = m;
    }
    for (m = a; m < Nadd; m++) {
        const unsigned char *r = Add + m * SRECSZ;
        if (memcmp(r, q->khi, KEYSZ) > 0) break;
        cand_push(be_get(r + KEYSZ, LOCSZ), qi);
    }
}

/* Fold the scratch partitions into the overlay, and report what landed.
 *
 * Three things are dropped rather than written: a key already in the main
 * index, a key already in the overlay, and a repeat within this run.  All
 * three are the same rule as emit_index's -- one record per key, the one
 * with the lowest (file, offset) -- applied across three sorted streams
 * instead of one array.  Dropping the first is what keeps the overlay
 * proportional to NEW words rather than to lines read: the night this was
 * written, 1,197 lines produced 7,568 records of which 7,404 were already
 * held.
 *
 * A word re-appearing in a HIGHER-priority file keeps the record it
 * already has rather than being re-attributed, which is the one way this
 * differs from a full build.  Both records name a line that yields the
 * same plaintext, and output is TYPE hash:plain, so nothing observable
 * changes -- and compact preserves whichever one is held. */
static void overlay_absorb(void)
{
    unsigned char *nw;
    unsigned long long nnew = 0, kept = 0, already = 0, repeat = 0, probes = 0;
    unsigned long long inew = 0, iold = 0;
    unsigned char prev[SRECSZ];
    int haveprev = 0, p;
    struct outbuf ob;
    double t0 = now();
    char path[8192];

    for (p = 0; p < NPART; p++) {
        snprintf(path, sizeof(path), "%s/part/%03d", Dbdir, p);
        nnew += fsize(path) / SRECSZ;
    }

    nw = xmalloc((size_t)(nnew ? nnew * SRECSZ : 1));
    {
        unsigned char *w = nw;
        for (p = 0; p < NPART; p++) {
            unsigned long long k;
            int fd;
            snprintf(path, sizeof(path), "%s/part/%03d", Dbdir, p);
            k = fsize(path) / SRECSZ;
            if (k == 0) continue;
            fd = open(path, O_RDONLY | O_BINARY);
            if (fd < 0) FATAL("open %s: %s", path, strerror(errno));
            readall(fd, w, (size_t)(k * SRECSZ), path);
            close(fd);
            w += k * SRECSZ;
        }
    }
    /* ONE PROBE PER LINE, NOT PER RECORD.  Asking the main index whether
     * it already holds a key is the entire cost of an update -- 32,442
     * probes took 279 of the 279.3 seconds the first live run spent, at a
     * measured 145 random probes a second on this volume.  But those
     * 32,442 records were only 4,448 lines: a line yields one record per
     * type, every one of them the same WORD, and a build indexes every
     * configured type of every line it reads.  So if any one of a line's
     * keys is in the index, all of them are, and one probe decides the
     * whole group.
     *
     * (The exception is a 96-bit key collision, which could leave one
     * type's record absent while its siblings are present -- an expected
     * 1.4e-9 of them in this index, and a word already unreachable by
     * that type whatever this code does.)
     *
     * Group by locator to find the lines, then sort back into key order
     * for the merge.  Two sorts of the new records, which are thousands,
     * to avoid tens of thousands of seeks. */
    if (nnew > 1)
        qsort_mt(nw, (size_t)nnew, SRECSZ, loc_cmp, Nthreads, FORKELEM);
    {
        unsigned long long i = 0, w = 0;
        int                lastp = -1;
        double             tp = now();

        /* The probe is the slow half of an update: one random seek per
         * new word against an index far too large to cache, measured at
         * 145 a second, and it was 279 of one night's 279.3 seconds with
         * nothing on the terminal for any of it. */
        while (i < nnew) {
            unsigned long long j = i;
            while (j < nnew &&
                   memcmp(nw + j * SRECSZ + KEYSZ,
                          nw + i * SRECSZ + KEYSZ, LOCSZ) == 0) j++;
            pct_line("probing the index", i, nnew, &lastp, tp);
            probes++;
            if (main_has_record(nw + i * SRECSZ)) { already += j - i; i = j; continue; }
            if (w != i) memmove(nw + w * SRECSZ, nw + i * SRECSZ,
                                (size_t)((j - i) * SRECSZ));
            w += j - i;
            i = j;
        }
        if (Verbose && lastp >= 0) fputc('\n', stderr);
        nnew = w;
    }
    if (nnew > 1)
        qsort_mt(nw, (size_t)nnew, SRECSZ, srec_cmp, Nthreads, FORKELEM);

    ob_open(&ob, pathcat("add.rec.new"), 1 << 20);
    for (;;) {
        const unsigned char *r;

        if (inew >= nnew && iold >= Nadd) break;
        if (iold >= Nadd)
            r = nw + inew++ * SRECSZ;
        else if (inew >= nnew)
            r = Add + iold++ * SRECSZ;
        else if (memcmp(nw + inew * SRECSZ, Add + iold * SRECSZ, SRECSZ) <= 0)
            r = nw + inew++ * SRECSZ;
        else
            r = Add + iold++ * SRECSZ;

        if (haveprev && memcmp(r, prev, SRECSZ) == 0) { repeat++; continue; }
        memcpy(prev, r, SRECSZ);
        haveprev = 1;
        /* No probe here.  The new side was filtered above, and a record
         * already IN the overlay cannot be in the main index -- that is
         * the invariant the filter maintains, and compact empties the
         * overlay rather than merging the two sets.  Probing here as well
         * cost Nadd seeks a night, which is nothing today and grows with
         * every night that passes without a compact. */
        ob_put(&ob, r, SRECSZ);
        kept++;
    }
    ob_close(&ob);
    if (rename(pathcat("add.rec.new"), pathcat("add.rec")) != 0)
        FATAL("rename add.rec: %s", strerror(errno));
    free(nw);

    /* commify() rotates four static buffers, so five of them in one
     * fprintf silently overwrites the first.  Two calls. */
    fprintf(stderr, "%s new records, %s already indexed, %s repeated, "
                    "%s probes; ",
            commify(kept - Nadd), commify(already), commify(repeat),
            commify(probes));
    fprintf(stderr, "overlay holds %s records (%s bytes), %.1fs\n",
            commify(kept), commify(kept * SRECSZ), now() - t0);

    /* The overlay is only cheap while it stays small against the index.
     * Every query binary-searches it, and compact is what puts it back to
     * nothing. */
    if (kept * SRECSZ > ADDWARN)
        fprintf(stderr, "note: the overlay is over %s bytes; "
                        "'mdindex compact' folds it into the index\n",
                commify(ADDWARN));
}

/* One sequential pass over the whole index, merged against the sorted
 * queries.  Above the crossover this beats probing: measured on this volume
 * a random 4 KB read runs at about 340/s while a single sequential stream
 * runs at 299 MB/s, so the whole index costs the same as Nrec * RECSZ *
 * 340 / 299e6 probes.  Deliberately one thread: four parallel streams
 * measured 157 MB/s between them against 299 MB/s for one. */
static void scan_all(const struct query *q, size_t nq)
{
    size_t bufrecs = (8u << 20) / RECSZ;
    unsigned char *buf = xmalloc(bufrecs * RECSZ);
    size_t have = 0, pos = 0, cur = 0;
    uint32_t b;
    int fd = open(pathcat("index.rec"), O_RDONLY | O_BINARY);

    if (fd < 0) FATAL("open index.rec: %s", strerror(errno));
    for (b = 0; b < NBUCK; b++) {
        uint64_t lo = dirget(b), hi = dirget(b + 1), m;
        for (m = lo; m < hi; m++) {
            unsigned char key[KEYSZ];
            const unsigned char *r;
            size_t j;

            if (pos == have) {
                ssize_t n = read(fd, buf, bufrecs * RECSZ);
                if (n <= 0) FATAL("read index.rec: %s",
                                  n < 0 ? strerror(errno) : "short");
                have = (size_t)n / RECSZ;
                pos  = 0;
            }
            r = buf + pos * RECSZ;
            pos++;

            key[0] = (unsigned char)(b >> 16);
            key[1] = (unsigned char)(b >> 8);
            key[2] = (unsigned char)(b);
            memcpy(key + 3, r, RESID);

            while (cur < nq && memcmp(q[cur].khi, key, KEYSZ) < 0) cur++;
            for (j = cur; j < nq && memcmp(q[j].klo, key, KEYSZ) <= 0; j++)
                if (memcmp(q[j].khi, key, KEYSZ) >= 0)
                    cand_push(be_get(r + RESID, LOCSZ), (uint32_t)j);
        }
    }
    close(fd);
    free(buf);
}

/* ---- fetching and reporting ---- */

/* Read the line the locator points at.  Length is not stored: the line runs
 * to the next newline, and a $TESTVEC[] line is short in the file however
 * large it expands. */
static int fetch_line(int fidx, unsigned long long off, char **out, size_t *outlen)
{
    static char  *buf;
    static size_t cap;
    size_t want = 65536;

    /* Srcfd is reset to -1 at the end of index_map, but build calls
     * emit_index BEFORE index_map, and a zeroed Srcfd means descriptor 0:
     * a fetch on that path would have pread() stdin and compared whatever
     * came back.  Initialise where the array is USED, so no caller has to
     * know the order. */
    static int inited;
    if (!inited) {
        int i;
        for (i = 0; i < MAXFILES; i++) Srcfd[i] = -1;
        inited = 1;
    }
    if (fidx >= Nfiles) FATAL("record names file index %d of %d", fidx, Nfiles);
    if (Srcfd[fidx] < 0) {
        Srcfd[fidx] = open(Files[fidx].path, O_RDONLY | O_BINARY);
        if (Srcfd[fidx] < 0)
            FATAL("open %s: %s", Files[fidx].path, strerror(errno));
    }
    for (;;) {
        ssize_t n;
        char   *nl;
        if (want + 1 > cap) {
            cap = want + 1;
            buf = realloc(buf, cap);
            if (buf == NULL) FATAL("realloc %zu: %s", cap, strerror(errno));
        }
        n = pread(Srcfd[fidx], buf, want, (off_t)off);
        if (n < 0) FATAL("pread %s: %s", Files[fidx].path, strerror(errno));
        if (n == 0) return 0;
        nl = memchr(buf, '\n', (size_t)n);
        /* Strip a CRLF's \r here too -- see scatter_thread.  The two must
         * agree exactly: this line is re-hashed before it is printed. */
        if (nl != NULL) {
            size_t l = (size_t)(nl - buf);
            if (l > 0 && buf[l - 1] == '\r') l--;
            *out = buf; *outlen = l; return 1;
        }
        if ((size_t)n < want) {
            size_t l = (size_t)n;
            if (l > 0 && buf[l - 1] == '\r') l--;
            *out = buf; *outlen = l; return 1;
        }
        if ((unsigned long long)want >= LINECAP)
            FATAL("no newline within %llu bytes at %s offset %llu",
                  LINECAP, Files[fidx].path, off);
        want *= 4;
    }
}

/* hashpipe.c 1.226 needs_hex, so a line this prints is wrapped on exactly
 * the same bytes hashpipe would wrap it on. */
/* mdxfind's rule for the PASSWORD field, from the dohex loop in
 * checkhashkeylen: any byte below 0x20 or above 0x7e, or a colon.
 *
 * The colon is deliberately here and deliberately NOT in mdxfind's
 * fmt_saltfield, which tests only the byte range: a salt field is
 * positionally delimited, while a colon inside a password makes the
 * whole line ambiguous to anything that splits on one. */
static int hex_bytes_needed(const unsigned char *p, int n)
{
    int i;
    for (i = 0; i < n; i++)
        if ((signed char)(p[i] + 1) < '!' || p[i] == ':') return 1;
    return 0;
}

static int needs_hex(const unsigned char *pass, int passlen)
{
    if (hex_bytes_needed(pass, passlen)) return 1;
    /* A password that merely STARTS with a wrapper is re-wrapped, so its
     * spelling cannot be read back as the wrapper it is not.  mdxfind
     * tests clen > 5 strictly, leaving a password that is exactly
     * "$HEX[" alone, and this matches it. */
    if (passlen > 5 && memcmp(pass, "$HEX[", 5) == 0) return 1;
    if (passlen > 9 && memcmp(pass, "$TESTVEC[", 9) == 0) return 1;
    return 0;
}

/* Print "<name> <hex>[:<salt>]:<plain>", wrapping the plaintext when it
 * cannot be written raw.  Everything goes through here so no path can
 * emit an unwrapped byte that breaks the line. */
static void emit_line(const char *name, const char *hex, const char *salt,
                      const unsigned char *plain, int plen, int wrap)
{
    int i;

    printf("%s %s:", name, hex);
    if (salt != NULL && salt[0]) printf("%s:", salt);
    if (wrap) {
        printf("$HEX[");
        for (i = 0; i < plen; i++) printf("%02x", plain[i]);
        printf("]\n");
        return;
    }
    /* fwrite, not %.*s: printf stops at a NUL whatever precision it is
     * given, which silently truncated a plaintext and emitted a line
     * claiming a word that does not produce the hash. */
    fwrite(plain, 1, (size_t)plen, stdout);
    putchar('\n');
}

/* TYPE hash:plain, the mdxfind shape, so the line pipes into hashpipe.
 *
 * A verbatim variant reports the stored line unchanged, wrapper and all,
 * because that is the spelling the file holds and it already round-trips.
 * NTLM's code-page readings are NOT verbatim: mdxfind reports the UTF-8
 * spelling of the codepoints it hashed, which is not the bytes in the
 * wordlist, and printing the wordlist bytes there would emit a line that
 * does not re-verify. */
static unsigned long long Emitted;

static void emit_hit(const struct htype *t, const struct hout *v,
                     const char *line, size_t llen)
{
    char hex[MAXDIG * 2 + 1];
    int  i;

    if (t->quiet) return;
    Emitted++;
    bin2hex(v->dig, t->dlen, hex);
    /* A VERBATIM hit reports the source line as the file spells it, so a
     * line already stored as $HEX[...] round-trips unchanged -- that is
     * what the flag is for.  But the line still has to be WRITABLE: one
     * carrying a colon, a NUL, a control character or a high byte cannot
     * be printed raw, because the colon splits the field and everything
     * past a NUL is lost.  Only the byte test applies here, never the
     * wrapper-prefix test: an already-wrapped line is plain ASCII and
     * passes it, and re-wrapping would double the wrapper. */
    if (v->verbatim)
        emit_line(t->name, hex, v->salt, (const unsigned char *)line,
                  (int)llen,
                  hex_bytes_needed((const unsigned char *)line, (int)llen));
    else
        emit_line(t->name, hex, v->salt, v->plain, v->plen,
                  needs_hex(v->plain, v->plen));
}

/* Timing, reported the way mdxfind reports it: a rate with a magnitude
 * suffix rather than a bare float nobody can scale by eye. */
static void format_rate(double val, double *out, const char **suffix)
{
    *suffix = "";
    if (val < 0.0) val = 0.0;
    if (val > 1000.0) { *suffix = "K"; val /= 1000.0; }
    if (val > 1000.0) { *suffix = "M"; val /= 1000.0; }
    if (val > 1000.0) { *suffix = "G"; val /= 1000.0; }
    if (val > 1000.0) { *suffix = "T"; val /= 1000.0; }
    *out = val;
}

static void rate_line(const char *what, unsigned long long n, double secs)
{
    double r; const char *m;
    format_rate(secs > 0 ? (double)n / secs : 0.0, &r, &m);
    fprintf(stderr, "  %-14s %8.3fs  %s  %.2f%s/s\n", what, secs, commify(n), r, m);
}

/* ---- the batch ---- */

static unsigned long long Hits, Asked, Nhashcalc, Nstale, Nskip;
static double             Tsort, Tprobe, Tfetch;
static int                Didscan;

static void run_batch(struct query *q, size_t nq)
{
    unsigned char *qmatched;
    double t0;
    size_t i;

    if (nq == 0) return;

    t0 = now();
    if (nq > 1) qsort(q, nq, sizeof(*q), qcmp);
    Tsort += now() - t0;

    Ncand = 0;
    t0 = now();
    /* Scan once rather than probe nq times when the batch is big enough to
     * pay for the whole index.  The crossover is derived from the measured
     * device, not guessed: see RND_IOPS / SEQ_BYTES_SEC above. */
    if (nq > 1 && (double)nq >
        (double)Nrec * RECSZ * RND_IOPS / SEQ_BYTES_SEC) {
        Didscan = 1;
        scan_all(q, nq);
    } else {
        for (i = 0; i < nq; i++) probe_query(&q[i], (uint32_t)i);
    }
    /* Both paths above read index.rec only.  The overlay is searched here
     * so neither can forget it -- a lookup that silently skipped it would
     * report "not found" for every word added since the last compact. */
    if (Nadd)
        for (i = 0; i < nq; i++) probe_overlay(&q[i], (uint32_t)i);
    Tprobe += now() - t0;

    t0 = now();
    if (Ncand > 1) qsort(Cand, Ncand, sizeof(*Cand), ccmp);

    /* One LINE can answer one query through several records, because the
     * query is a prefix and the line has a key per type: "5" matches
     * password by its MD5, its SHA-1 AND its SHA-256 key, three records at
     * one locator.  The answer is the same each time -- the line is read
     * once and every type regenerated from it -- so a repeated (locator,
     * query) pair carries no information and printed the hit once per
     * record.  Collapse here rather than guarding emit_hit, so that Ncand
     * and the fetch rate count work actually done. */
    if (Ncand > 1) {
        size_t w = 1, r;
        for (r = 1; r < Ncand; r++)
            if (Cand[r].loc != Cand[w - 1].loc || Cand[r].qi != Cand[w - 1].qi)
                Cand[w++] = Cand[r];
        Ncand = w;
    }

    qmatched = calloc(nq, 1);
    if (qmatched == NULL) FATAL("out of memory");

    for (i = 0; i < Ncand; ) {
        static unsigned char *vb, *tvb;
        static hx_vm         *lvms;
        static struct hout   *v;
        unsigned char *cm;
        unsigned long long loc = Cand[i].loc;
        unsigned long long off = loc & (MAXOFF - 1);
        int    fidx = (int)(loc >> OFFBITS);
        char  *line;
        size_t llen, j = i, c;
        const unsigned char *mp;
        int ml, t, k;

        while (j < Ncand && Cand[j].loc == loc) j++;
        if (!fetch_line(fidx, off, &line, &llen)) { i = j; continue; }
        if (vb == NULL) vb = xmalloc(UNWRAPBUF);
        if (v  == NULL) { v = xmalloc(sizeof(*v) * (size_t)Maxvar);
                          lvms = vms_new(); }
        md_unwrap((const unsigned char *)line, llen, vb, UNWRAPBUF, &tvb,
                  &mp, &ml, Files[fidx].path, off);

        cm = calloc(j - i, 1);
        if (cm == NULL) FATAL("out of memory");
        for (t = 0; t < Nhtype; t++) {
            int nv;
            nv = type_hash(t, lvms, mp, ml, v);
            Nhashcalc += (unsigned)nv;
            for (k = 0; k < nv; k++)
                for (c = i; c < j; c++) {
                    struct query *qq = &q[Cand[c].qi];
                    if (qq->nbits > Htype[t].dlen * 8) continue;
                    if (!digest_prefix_eq(v[k].dig, qq->d, qq->nbits)) continue;
                    emit_hit(&Htype[t], &v[k], line, llen);
                    cm[c - i] = 1;
                    qmatched[Cand[c].qi] = 1;
                }
        }
        /* The index matched the first KEYBITS of this query, so for a query
         * no longer than that the line MUST regenerate to it.  If it does
         * not, the line at that offset is not the line that was indexed. */
        for (c = i; c < j; c++)
            if (!cm[c - i] && q[Cand[c].qi].nbits <= KEYBITS) {
                char nowhex[MAXDIG * 2 + 1];
                bin2hex(q[Cand[c].qi].d, (q[Cand[c].qi].nbits + 7) / 8, nowhex);
                fprintf(stderr, "ALERT %s offset %llu no longer hashes to "
                        "anything matching %s. The index does not match the "
                        "file; rebuild.\n", Files[fidx].path, off, nowhex);
                Nstale++;
            }
        free(cm);
        i = j;
    }
    for (i = 0; i < nq; i++) if (qmatched[i]) Hits++;
    free(qmatched);
    Tfetch += now() - t0;
}

/* The hex-character window a piped line must fall in to be taken as a
 * query.  The floor is MINQHEX, not the shortest digest: 64 bits already
 * selects about one record, so a half-MD5 (hashcat mode 5100) is the
 * narrowest query that costs nothing, and it needs no type of its own
 * because the index is keyed on a superset of exactly those bits.
 *
 * Below that the cost climbs as 16^-n and the filter earns its place:
 * "ab" selects 1/256 of the keyspace, tens of millions of records on a
 * full index, each one a seek into a source file to verify, which is what
 * made a piped wordlist look like a hang.  Plaintexts that happen to be
 * hex ("beef", "123456", "19") are common in any list, so that is not a
 * rare input, while a 16-character hex plaintext is both rare and almost
 * free: it meets a record with probability Nrec/2^64, about 8e-10 on a
 * 15-billion-record index.
 *
 * Only the stdin path filters; a partial query typed as an argument, or
 * typed at a terminal, is deliberate and runs at any length. */
static void hexlen_range(int *lo, int *hi)
{
    int t, mx = 0;
    for (t = 0; t < Nhtype; t++)
        if (Htype[t].dlen > mx) mx = Htype[t].dlen;
    *lo = MINQHEX;
    *hi = mx * 2;
}

static int all_hex(const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) if (hexval((unsigned char)s[i]) < 0) return 0;
    return 1;
}

/* Find the first maximal run of ASCII hex digits at least `lo` long, and
 * report where it starts and how long it is.
 *
 * This is what makes a NOISY file usable.  The input to this program is
 * normally somebody else's list, and the digest is rarely the whole line:
 * it arrives as `hash:salt`, as `user:hash`, as `$dynamic_0$hash`, or in
 * some column further along.  Requiring the whole token to be hex rejected
 * every one of those, and a 63,042-line list read as 63,042 lines ignored
 * and no hits -- a wholly-skipped input that looks exactly like an index
 * with nothing in it.
 *
 * A run SHORTER than `lo` is stepped over rather than failing the line,
 * which is what lets a login through: the `a` of `alice:` is a hex run of
 * length 1, and the digest after the colon is the first run long enough to
 * be one.  The run then extends to the first non-hex byte, as mdxfind reads
 * its hex, so no separator can end up inside it.
 *
 * `lo` is the shortest query worth making and the caller's `hi` the longest
 * digest the open index actually holds.  A run longer than `hi` is not a
 * digest this index can answer for, and the line is counted as ignored
 * rather than TRUNCATED to fit: a truncated run is a query nobody asked
 * for, and at these volumes it would occasionally match something and be
 * reported as a hit.  Deliberately literal about "first", too -- scanning
 * on to a later, shorter run after rejecting an over-long one would make
 * which field gets looked up depend on the index's contents.
 *
 * Returns NULL when the line has no such run. */
static char *first_hex_run(char *s, int lo, int *lenp)
{
    char *p = s;

    while (*p != 0) {
        char *b;
        int   n;

        if (hexval((unsigned char)*p) < 0) { p++; continue; }
        b = p;
        while (hexval((unsigned char)*p) >= 0) p++;
        n = (int)(p - b);
        if (n >= lo) { *lenp = n; return b; }
    }
    return NULL;
}

/* A John line carries its format in front of the digest, and some carry a
 * login in front of that:
 *
 *     $dynamic_0$0cc175b9c0f1b6a831c399e269772661
 *     user:$dynamic_0$0cc175b9c0f1b6a831c399e269772661
 *
 * The digest begins after the SECOND '$' in every $tag$ form, whatever
 * precedes the first, so that is where to resume.  A trailing field is
 * deliberately NOT stripped: in a John line it is the salt, and a salted
 * digest is not something this index holds, so leaving it makes the line
 * fail the hex test and be counted as ignored rather than looked up and
 * silently missed.
 *
 * Returns the original pointer when there is no such lead-in. */
static char *skip_leadin(char *p)
{
    char *d1 = strchr(p, '$');
    char *d2;

    if (d1 == NULL) return p;
    d2 = strchr(d1 + 1, '$');
    if (d2 == NULL) return p;
    return d2 + 1;
}

static int parse_query(const char *hex, struct query *q)
{
    size_t n = strlen(hex);
    if (n == 0 || n > MAXDIG * 2) {
        fprintf(stderr, "not a hash: %s (1 to %d hex characters)\n",
                hex, MAXDIG * 2);
        return 0;
    }
    memset(q->d, 0, sizeof(q->d));
    if (hex2bin(hex, (int)n, q->d) < 0) {
        fprintf(stderr, "not a hash: %s\n", hex);
        return 0;
    }
    q->nbits = (int)n * 4;
    query_bounds(q);
    return 1;
}

static void cmd_lookup(int argc, char **argv)
{
    struct query *q;
    size_t cap, nq = 0;
    double t0;
    int    i;

    index_open();
    t0 = now();

    if (argc > 0 && !(argc == 1 && strcmp(argv[0], "-") == 0)) {
        cap = (size_t)argc;
        q = xmalloc(sizeof(*q) * cap);
        for (i = 0; i < argc; i++) {
            char *a = skip_leadin(argv[i]);
            Asked++;
            if (a != argv[i] && !all_hex(a, strlen(a))) a = argv[i];
            if (parse_query(a, &q[nq])) nq++;
        }
        run_batch(q, nq);
        free(q);
    } else {
        /* A terminal gets an answer per line; a pipe or a file is batched,
         * because sorting the whole batch is what makes the index scan and
         * the ordered fetch possible. */
        size_t blk = isatty(0) ? 1 : QBATCH;
        int    lo = 0, hi = 0;          /* 0 = take every line */
        char   line[1024];

        if (!isatty(0)) hexlen_range(&lo, &hi);
        cap = blk < 4096 ? blk : 4096;
        q = xmalloc(sizeof(*q) * cap);
        while (fgets(line, sizeof(line), stdin) != NULL) {
            char *p = line + strspn(line, " \t");

            /* Only the line ending is cut.  Interior whitespace STAYS,
             * because the digest may be in a later column and cutting at
             * the first space would hide it. */
            p[strcspn(p, "\r\n")] = 0;
            /* Not a hash: skip it without a word.  Feeding a mixed file
             * in is the normal way to use this, so a per-line complaint
             * would bury the answers.  The count is reported at the end
             * -- silence about a wholly-skipped input is how a pipeline
             * with the wrong column reads as "no hits". */
            if (lo) {
                int   n = 0;
                char *h = first_hex_run(p, lo, &n);

                if (h == NULL || n > hi) {
                    if (*p != 0) Nskip++;   /* a blank line is not "ignored" */
                    continue;
                }
                h[n] = 0;                   /* overwrite the byte that ended it */
                p = h;
            } else {
                /* A terminal gets what was typed, one token. */
                p[strcspn(p, " \t")] = 0;
                if (*p == 0) continue;
            }
            if (nq == cap) {
                cap = cap * 2 < blk ? cap * 2 : blk;
                q = realloc(q, sizeof(*q) * cap);
                if (q == NULL) FATAL("out of memory for %zu queries", cap);
            }
            Asked++;
            if (parse_query(p, &q[nq])) nq++;
            if (nq >= blk) { run_batch(q, nq); nq = 0; }
        }
        run_batch(q, nq);
        free(q);
    }

    fflush(stdout);
    {
        double total = now() - t0;
        double r; const char *m;
        format_rate(Asked > 0 ? (double)Asked / total : 0.0, &r, &m);
        /* Lines printed AND hashes answered: a partial query can match
         * many records, so one number cannot say both. */
        fprintf(stderr, "%s hit%s for %s of %s hashes, lookup time %.3fs, "
                        "%.6fs per hash (%.2f%s lookups/sec)\n",
                commify(Emitted), Emitted == 1 ? "" : "s",
                commify(Hits), commify(Asked), total,
                Asked ? total / (double)Asked : 0.0, r, m);
        if (Verbose) {
            rate_line("sort", (unsigned long long)Asked, Tsort);
            rate_line(Didscan ? "index scan" : "index probe",
                      (unsigned long long)Asked, Tprobe);
            rate_line("fetch+verify", (unsigned long long)Ncand, Tfetch);
            fprintf(stderr, "  %-14s %8s   %s hash computations\n",
                    "regenerated", "", commify(Nhashcalc));
        }
        if (Nskip) {
            int lo, hi;
            hexlen_range(&lo, &hi);
            fprintf(stderr, "%s input line%s ignored: no run of %d to %d "
                    "hex characters\n", commify(Nskip), Nskip == 1 ? "" : "s",
                    lo, hi);
        }
        if (Nstale)
            fprintf(stderr, "%s hit%s did NOT re-hash to the key asked for; "
                    "the index is stale. Run 'build'.\n",
                    commify(Nstale), Nstale == 1 ? "" : "s");
    }
}

/* ------------------------------------------------------------------ */
/* build / update                                                      */
/* ------------------------------------------------------------------ */

static void stat_file(struct srcfile *sf)
{
    struct stat sb;
    if (stat(sf->path, &sb) != 0) FATAL("stat %s: %s", sf->path, strerror(errno));
    sf->size  = (unsigned long long)sb.st_size;
    sf->mtime = (long long)sb.st_mtime;
}

static void say_types(void)
{
    int i, first = 1;
    fprintf(stderr, "hash types:");
    for (i = 0; i < Nhtype; i++)
        if (1) { fprintf(stderr, "%s %s", first ? "" : ",",
                                         Htype[i].name); first = 0; }
    fprintf(stderr, "\n");
}

static void hashed_report(unsigned long long lines, unsigned long long bytes,
                          double secs, const char *what)
{
    double lr, br; const char *lm, *bm;
    format_rate(secs > 0 ? (double)lines / secs : 0.0, &lr, &lm);
    format_rate(secs > 0 ? (double)bytes / secs : 0.0, &br, &bm);
    fprintf(stderr, "%s %s lines (%s bytes) in %.1fs -- %.2f%s lines/sec, "
                    "%.2f%sB/sec\n",
            what, commify(lines), commify(bytes), secs, lr, lm, br, bm);
}

/* ------------------------------------------------------------------ */
/* build-cost projection                                               */
/*                                                                      */
/* With a user-chosen type set, index size and build time are chosen    */
/* too: e183 alone over 4.1 billion lines is ~3.2 trillion records and  */
/* ~47 TB.  Both are knowable before the first record is written, from  */
/* two cheap measurements -- how many lines there are, and how many     */
/* records a line of THIS input yields through THESE types.            */
/*                                                                      */
/* This is the one place mdindex refuses rather than reports.  Every-   */
/* where else -- an unusual type, a pathological line, a vast selection */
/* -- it says so loudly and computes anyway.  Here the alternative is   */
/* discovering at hour six that the filesystem is full with scratch     */
/* spread over 256 partition files, which costs the whole build and     */
/* leaves nothing usable behind.                                        */
/* ------------------------------------------------------------------ */

static int Yes;                  /* -y: proceed past the space alert   */

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
static int have_avx2(void)
{
    static int known = -1;
    if (known < 0) known = __builtin_cpu_supports("avx2");
    return known;
}
__attribute__((target("avx2")))
static unsigned long long count_nl_avx2(const unsigned char *buf, size_t len)
{
    __m256i nl = _mm256_set1_epi8('\n');
    unsigned long long n = 0;
    size_t i = 0;
    for (; i + 32 <= len; i += 32) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(buf + i));
        n += (unsigned)__builtin_popcount(
                 (unsigned)_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, nl)));
    }
    for (; i < len; i++) if (buf[i] == '\n') n++;
    return n;
}
#elif defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#endif

/* Newline counter, the same one mdxfind uses: AVX2 where the CPU has it,
 * NEON on ARM, scalar otherwise.  Taken rather than linked because it is
 * static inside mdxfind.c, and taken rather than reimplemented because a
 * line count that disagrees with mdxfind's would make the two tools
 * disagree about the same file. */
static unsigned long long count_newlines(const unsigned char *buf, size_t len)
{
    unsigned long long n = 0;
    size_t i = 0;

#if defined(__x86_64__) || defined(__i386__)
    if (have_avx2()) return count_nl_avx2(buf, len);
#elif defined(__ARM_NEON) || defined(__aarch64__)
    {
        uint8x16_t nl = vdupq_n_u8('\n');
        for (; i + 16 <= len; i += 16) {
            uint8x16_t v = vld1q_u8(buf + i);
            uint8x16_t m = vandq_u8(vceqq_u8(v, nl), vdupq_n_u8(1));
            n += vaddlvq_u8(m);
        }
    }
#endif
    for (; i < len; i++) if (buf[i] == '\n') n++;
    return n;
}

/* ---- mdxfind's line-count cache, read and written ----
 *
 * Keyed on (path, size, mtime), so a file that has grown misses rather
 * than returning a stale count.  These are the same wordlists both tools
 * read, so the count is usually already there and the pre-pass costs
 * nothing.  MDXFIND_CACHE is the only input: there is no default path and
 * no search, matching mdxfind.
 *
 * A count is stored only for a file counted to its end.  mdxfind learned
 * that the hard way -- a partial count persisted from an interrupted run
 * poisons every later session, and the row looks exactly like a good one. */
static sqlite3 *lc_open(void)
{
    const char *env = getenv("MDXFIND_CACHE");
    sqlite3    *db  = NULL;

    if (env == NULL || env[0] == 0) return NULL;
    if (sqlite3_open(env, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return NULL;
    }
    sqlite3_exec(db, "PRAGMA busy_timeout=5000;", NULL, NULL, NULL);
    return db;
}

static long long lc_lookup(sqlite3 *db, const char *path,
                           long long size, long long mtime)
{
    sqlite3_stmt *st = NULL;
    long long     r  = -1;

    if (db == NULL) return -1;
    if (sqlite3_prepare_v2(db, "SELECT lines FROM linecount WHERE "
                               "filepath=? AND filesize=? AND mtime=?",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, size);
    sqlite3_bind_int64(st, 3, mtime);
    if (sqlite3_step(st) == SQLITE_ROW) r = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return r;
}

static void lc_store(sqlite3 *db, const char *path, long long size,
                     long long mtime, long long lines)
{
    sqlite3_stmt *st = NULL;

    if (db == NULL) return;
    if (sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS linecount ("
            "  filepath TEXT NOT NULL,"
            "  filesize INTEGER NOT NULL,"
            "  mtime INTEGER NOT NULL,"
            "  lines INTEGER NOT NULL,"
            "  cached_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),"
            "  PRIMARY KEY (filepath, filesize, mtime));",
            NULL, NULL, NULL) != SQLITE_OK)
        return;
    if (sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO linecount "
                               "(filepath,filesize,mtime,lines) "
                               "VALUES (?,?,?,?)", -1, &st, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_text(st, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, size);
    sqlite3_bind_int64(st, 3, mtime);
    sqlite3_bind_int64(st, 4, lines);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

/* Count the UNINDEXED TAIL, not the file.  Counting is free; reading is
 * not, and a nightly update that appends 422 KB must not pay for a pass
 * over 53.5 GB. */
static unsigned long long src_count_lines(const struct srcfile *sf,
                                          unsigned long long from)
{
    static unsigned char buf[4 << 20];
    unsigned long long   n = 0, off = from;
    int                  fd;

    if (from >= sf->size) return 0;
    fd = open(sf->path, O_RDONLY | O_BINARY);
    if (fd < 0) FATAL("open %s: %s", sf->path, strerror(errno));
    while (off < sf->size) {
        ssize_t got = pread(fd, buf, sizeof(buf), (off_t)off);
        if (got < 0) FATAL("read %s: %s", sf->path, strerror(errno));
        if (got == 0) break;
        n += count_newlines(buf, (size_t)got);
        off += (unsigned long long)got;
    }
    /* A final line with no terminator is still a line. */
    if (sf->size > from) {
        unsigned char last = 0;
        if (pread(fd, &last, 1, (off_t)(sf->size - 1)) == 1 && last != '\n')
            n++;
    }
    close(fd);
    return n;
}

/* Records per line, OBSERVED rather than assumed.  It is not a constant:
 * six types give about 6.02 because NTLM emits up to three readings of a
 * non-ASCII word, and an enumerated type gives 768.  The sample has to
 * come off the real input, because the ratio depends on how many of its
 * lines are non-ASCII. */
#define PROJ_SAMPLE  4096      /* lines, at most                       */
#define PROJ_MINLINE   64      /* lines, at least: the non-ASCII share  */
#define PROJ_DIGESTS 200000    /* digests, the real budget              */

static double sample_rpl(const struct srcfile *sf, unsigned long long from)
{
    static unsigned char buf[1 << 20];
    unsigned char       *dec = xmalloc(UNWRAPBUF);
    unsigned char       *tvb = NULL;
    struct hout         *hv  = xmalloc(sizeof(*hv) * (size_t)Maxvar);
    hx_vm               *vms = vms_new();
    unsigned long long   recs = 0;
    int                  fd, lines = 0;
    ssize_t              got;
    size_t               at = 0;

    fd = open(sf->path, O_RDONLY | O_BINARY);
    if (fd < 0) FATAL("open %s: %s", sf->path, strerror(errno));
    got = pread(fd, buf, sizeof(buf), (off_t)from);
    close(fd);
    if (got <= 0) { free(dec); free(hv); return (double)Nhtype; }

    /* Budget the sample in DIGESTS, not lines.  A line costs one digest
     * per type, so a fixed line count is 4,892 times dearer against the
     * 1,059-type identification set than against the default six: it put
     * 17 s of sampling in front of an 8 s build.  The floor keeps enough
     * lines to see the non-ASCII share, which is what the ratio turns on. */
    while (at < (size_t)got && lines < PROJ_SAMPLE &&
           (lines < PROJ_MINLINE || recs < PROJ_DIGESTS)) {
        unsigned char *nl = memchr(buf + at, '\n', (size_t)got - at);
        size_t         ll = nl ? (size_t)(nl - (buf + at)) : (size_t)got - at;
        const unsigned char *mp;
        int                  ml, t;

        if (nl == NULL && (size_t)got == sizeof(buf))
            break;                       /* truncated tail, not a line */
        if (ll > 0 && buf[at + ll - 1] == '\r') ll--;
        /* md_unwrap's RETURN says whether a wrapper was decoded, not
         * whether the line is usable: a plain literal returns 0 having
         * already pointed mp/ml at the line itself.  Gating on it skips
         * every unwrapped word, which is nearly all of them, and leaves
         * the ratio at one record per type -- a number that looks right
         * for a six-type build because it IS right there, and is wrong
         * by 4.6x the moment an enumerated type is selected. */
        md_unwrap(buf + at, ll, dec, UNWRAPBUF, &tvb, &mp, &ml, sf->path, 0);
        if (ml > 0) {
            for (t = 0; t < Nhtype; t++)
                recs += (unsigned long long)type_hash(t, vms, mp, ml, hv);
            lines++;
        }
        if (nl == NULL) break;
        at = (size_t)(nl - buf) + 1;
    }
    free(dec);
    free(hv);
    if (lines == 0) return (double)Nhtype;
    return (double)recs / (double)lines;
}

static unsigned long long fs_free(const char *dir)
{
    struct statvfs v;
    char           probe[8192];

    if (statvfs(dir, &v) == 0)
        return (unsigned long long)v.f_bavail * (unsigned long long)v.f_frsize;
    /* The directory may not exist yet on a fresh build; ask its parent. */
    snprintf(probe, sizeof(probe), "%s", dir);
    {
        char *slash = strrchr(probe, '/');
        if (slash != NULL && slash != probe) *slash = 0;
        else snprintf(probe, sizeof(probe), ".");
    }
    if (statvfs(probe, &v) == 0)
        return (unsigned long long)v.f_bavail * (unsigned long long)v.f_frsize;
    return 0;
}

static const char *human(unsigned long long b)
{
    static char buf[4][40];
    static int  k;
    char       *o = buf[k = (k + 1) & 3];
    const char *u[] = { "bytes", "KB", "MB", "GB", "TB", "PB" };
    double      v = (double)b;
    int         i = 0;

    while (v >= 1024.0 && i < 5) { v /= 1024.0; i++; }
    if (i == 0) snprintf(o, 40, "%llu bytes", b);
    else        snprintf(o, 40, "%.1f %s", v, u[i]);
    return o;
}

/* Projected peak, printed before anything is written, and the refusal.
 *
 * The threshold is a SHARE of free space rather than a fixed size: a
 * build runs for hours while other things write to the same filesystem,
 * and on a shared or snapshotting volume the reading is a moment in time
 * and not a reservation.  A tenth, not a half, for that reason. */
static void project_build(int updating)
{
    unsigned long long lines = 0, scratch, newrec, oldrec = 0, peak, freeb;
    double             rpl;
    sqlite3           *db = lc_open();
    double             t0 = now();
    int                i, counted = 0;

    for (i = 0; i < Nfiles; i++) {
        unsigned long long from = updating ? Files[i].consumed : 0;
        long long          c;

        if (from >= Files[i].size) continue;
        c = (from == 0)
          ? lc_lookup(db, Files[i].path, (long long)Files[i].size,
                      (long long)Files[i].mtime)
          : -1;
        if (c >= 0) { lines += (unsigned long long)c; continue; }
        {
            unsigned long long n = src_count_lines(&Files[i], from);
            lines += n;
            counted++;
            if (from == 0)
                lc_store(db, Files[i].path, (long long)Files[i].size,
                         (long long)Files[i].mtime, (long long)n);
        }
    }
    if (db != NULL) sqlite3_close(db);

    if (lines == 0) return;              /* nothing to add; nothing to say */

    rpl = sample_rpl(&Files[0], updating ? Files[0].consumed : 0);
    scratch = (unsigned long long)((double)lines * rpl) * SRECSZ;
    newrec  = (unsigned long long)((double)lines * rpl) * RECSZ;
    if (access(pathcat("index.rec"), R_OK) == 0)
        oldrec = fsize(pathcat("index.rec"));
    /* The old index survives until the rename, so it is part of the peak.
     * An update writes only the overlay and never rewrites index.rec, so
     * for an update the old copy is not doubled. */
    peak  = updating ? scratch + oldrec
                     : scratch + newrec + oldrec;
    freeb = fs_free(Dbdir);

    fprintf(stderr,
            "projection  %s lines x %.2f records/line = %s records\n",
            commify(lines), rpl,
            commify((unsigned long long)((double)lines * rpl)));
    fprintf(stderr,
            "            scratch %s, new index %s, peak %s; %s free%s\n",
            human(scratch), human(newrec), human(peak), human(freeb),
            counted ? "" : " (line counts from cache)");
    if (counted && Verbose)
        fprintf(stderr, "            counted %d file(s) in %.1fs\n",
                counted, now() - t0);

    if (freeb != 0 && peak > freeb / 10 && !Yes) {
        fprintf(stderr,
"\n"
"REFUSING: the projected peak of %s is more than a tenth of the %s free\n"
"on %s.  Nothing has been written.\n"
"\n"
"A build runs for hours while other things write to the same filesystem, so\n"
"a tenth rather than a half, and the free-space reading is a moment in time\n"
"and not a reservation.  Either free space, pick a -d on a larger volume,\n"
"index fewer types, or pass -y to proceed anyway.\n",
                human(peak), human(freeb), Dbdir);
        exit(1);
    }
}

/* How far a source may be marked CONSUMED: the byte after its last
 * newline, which is its size when the file ends with one.
 *
 * A file whose last line has no terminator is still indexed to the end --
 * the word is there and the index should hold it -- but recording the
 * whole size as consumed assumes that line is finished, and the next
 * update then starts in the MIDDLE of a word.  Appending "a\ngamma\n" to
 * a file ending "bet" indexed "bet" and then "a", and never "beta": the
 * word the file actually contains was unreachable, and so was "bet",
 * whose record now named an offset that reads "beta" and fails its
 * re-hash.  Two words lost to one unterminated line.
 *
 * Stopping at the last newline means an unterminated tail is re-read on
 * every update until it is terminated.  That costs a few re-hashed lines
 * and the dedup drops them; the alternative costs words. */
static unsigned long long consumed_to(const struct srcfile *sf)
{
    static unsigned char buf[65536];
    unsigned long long at = sf->size;
    int fd;

    if (sf->size == 0) return 0;
    fd = open(sf->path, O_RDONLY | O_BINARY);
    if (fd < 0) FATAL("open %s: %s", sf->path, strerror(errno));
    while (at > 0) {
        size_t want = at > sizeof(buf) ? sizeof(buf) : (size_t)at;
        ssize_t n;
        unsigned char *nl;

        n = pread(fd, buf, want, (off_t)(at - want));
        if (n <= 0) break;
        for (nl = buf + n; nl > buf; nl--)
            if (nl[-1] == '\n') {
                close(fd);
                return at - want + (unsigned long long)(nl - buf);
            }
        at -= (unsigned long long)n;
    }
    close(fd);
    /* No newline anywhere: nothing is complete, so nothing is consumed
     * and the whole file is re-read next time. */
    return 0;
}

static void cmd_build(int argc, char **argv)
{
    unsigned long long lines = 0, bytes = 0;
    double t0 = now(), thash;
    int i;

    if (argc < 1) FATAL("build needs at least one source file");
    if (argc > MAXFILES) FATAL("at most %d source files", MAXFILES);

    /* A build REPLACES the database, so any overlay from the previous one
     * has to go with it.  An add.rec left behind describes words at
     * locators in the OLD sources: at best its records are rejected one
     * by one when the line they name no longer re-hashes, and at worst
     * its locator names a source the new manifest does not have, which
     * is fatal at the first lookup --
     *
     *     FATAL record names file index 1 of 1
     *
     * on a database that build had just reported as finished. `check`
     * calls such an overlay clean, because every record in it is
     * internally well formed; what is wrong is that it belongs to a
     * database that no longer exists. */
    if (unlink(pathcat("add.rec")) != 0 && errno != ENOENT)
        FATAL("unlink stale add.rec: %s", strerror(errno));

    files_reserve(argc);
    Nfiles = argc;
    memset(Files, 0, sizeof(*Files) * (size_t)argc);
    for (i = 0; i < argc; i++) {
        if (realpath(argv[i], Files[i].path) == NULL)
            FATAL("realpath %s: %s", argv[i], strerror(errno));
        stat_file(&Files[i]);
        bytes += Files[i].size;
    }

    fprintf(stderr, "building %s from %d file%s, %d threads\n",
            Dbdir, Nfiles, Nfiles == 1 ? "" : "s", Nthreads);
    say_types();
    fprintf(stderr, "file order is priority: on a duplicate the lowest "
                    "index wins\n");
    project_build(0);

    part_open();
    for (i = 0; i < Nfiles; i++) {
        Files[i].lines = scatter_file(&Files[i], i);
        Files[i].consumed = consumed_to(&Files[i]);
        file_fingerprint(&Files[i], Files[i].consumed);
        lines += Files[i].lines;
    }
    part_close();
    thash = now() - t0;
    hashed_report(lines, bytes, thash, "hashed");

    emit_index(NULL, -1);
    part_remove();
    manifest_write();
    fprintf(stderr, "done in %.1fs\n", now() - t0);
}

static void cmd_update(int argc, char **argv)
{
    unsigned long long added = 0, bytes = 0;
    double t0 = now(), thash;
    int i, changed = 0;

    manifest_read(0);

    /* New files join at the END of the manifest, so they are the LOWEST
     * priority: a word they share with an existing file keeps the older
     * file's record.  Promoting a file above one already indexed, or
     * reordering the sources at all, means 'build'. */
    if (argc > 0) {
        int a;
        files_reserve(Nfiles + argc);
        for (a = 0; a < argc; a++) {
            char rp[4096];
            int  j;
            if (realpath(argv[a], rp) == NULL)
                FATAL("realpath %s: %s", argv[a], strerror(errno));
            for (j = 0; j < Nfiles; j++)
                if (strcmp(Files[j].path, rp) == 0)
                    FATAL("%s is already source %d; update re-reads it from "
                          "its watermark automatically.", rp, j);
            if (Nfiles >= MAXFILES) FATAL("at most %d source files", MAXFILES);
            memset(&Files[Nfiles], 0, sizeof(Files[0]));
            snprintf(Files[Nfiles].path, sizeof(Files[0].path), "%s", rp);
            stat_file(&Files[Nfiles]);
            Files[Nfiles].consumed = 0;
            fprintf(stderr, "adding %s as source %d (lowest priority)\n",
                    rp, Nfiles);
            Nfiles++;
            changed++;
        }
    }

    if (files_check(0))
        FATAL("a source no longer matches the index, so its stored offsets "
              "are stale and the words it masked in lower-priority files "
              "cannot be recovered without a rescan. Run 'build'.");

    for (i = 0; i < Nfiles; i++) {
        unsigned long long was = Files[i].consumed;
        stat_file(&Files[i]);
        if (Files[i].size > was) { changed++; bytes += Files[i].size - was; }
    }

    if (changed == 0) {
        fprintf(stderr, "no source file has grown and none was added; "
                        "index is current\n");
        return;
    }

    /* index.rec is NOT rewritten here.  New records go to the overlay, so
     * an update costs the lines it reads and not the index it adds them
     * to; 'compact' is the command that rewrites index.rec. */
    index_map();

    fprintf(stderr, "updating %s: %d change%s, %s records held",
            Dbdir, changed, changed == 1 ? "" : "s", commify(Nrec));
    if (Nadd) fprintf(stderr, ", %s in the overlay", commify(Nadd));
    fprintf(stderr, "\n");
    say_types();

    part_open();
    for (i = 0; i < Nfiles; i++) {
        unsigned long long n = scatter_file(&Files[i], i);
        Files[i].lines   += n;
        Files[i].consumed = consumed_to(&Files[i]);
        file_fingerprint(&Files[i], Files[i].consumed);
        added += n;
    }
    part_close();
    thash = now() - t0;
    hashed_report(added, bytes, thash, "hashed");

    overlay_absorb();
    part_remove();
    manifest_write();
    fprintf(stderr, "done in %.1fs\n", now() - t0);
}

/* Fold the overlay into index.rec.  This is the whole-index rewrite that
 * update used to do every time, now run only when asked -- and run through
 * the two-way merge, so the old index is streamed past rather than sorted
 * again. */
static void cmd_compact(void)
{
    uint64_t      *olddir;
    unsigned char *raw;
    unsigned long long dsz, k;
    int dirfd, oldfd;
    double t0 = now();

    manifest_read(0);
    files_check(1);
    index_map();

    if (Nadd == 0) {
        fprintf(stderr, "no overlay: %s is already one array of %s records\n",
                Dbdir, commify(Nrec));
        return;
    }

    fprintf(stderr, "compacting %s: folding %s overlay records into %s\n",
            Dbdir, commify(Nadd), commify(Nrec));
    say_types();

    /* Scatter the overlay into the scratch partitions emit_index reads.
     * The partition IS the first key byte and the overlay is sorted, so
     * each partition's records are one contiguous run and this is 256
     * writes, not one per record. */
    part_open();
    {
        unsigned long long i = 0;
        while (i < Nadd) {
            unsigned long long j = i;
            int part = Add[i * SRECSZ];
            while (j < Nadd && Add[j * SRECSZ] == part) j++;
            if (write(Partfd[part], Add + i * SRECSZ,
                      (size_t)((j - i) * SRECSZ)) < 0)
                FATAL("write partition %d: %s", part, strerror(errno));
            i = j;
        }
    }
    part_close();

    dsz = fsize(pathcat("index.dir"));
    if (dsz != 8ULL * (NBUCK + 1))
        FATAL("index.dir is %llu bytes, expected %llu -- rebuild",
              dsz, 8ULL * (NBUCK + 1));
    dirfd = open(pathcat("index.dir"), O_RDONLY | O_BINARY);
    if (dirfd < 0) FATAL("open index.dir: %s", strerror(errno));
    raw = xmalloc((size_t)dsz);
    readall(dirfd, raw, (size_t)dsz, "index.dir");
    close(dirfd);
    olddir = xmalloc(sizeof(uint64_t) * (NBUCK + 1));
    for (k = 0; k <= NBUCK; k++) olddir[k] = be_get(raw + k * 8, 8);
    free(raw);

    oldfd = open(pathcat("index.rec"), O_RDONLY | O_BINARY);
    if (oldfd < 0) FATAL("open index.rec: %s", strerror(errno));

    /* emit_index renames index.rec.new over index.rec, and the unlink
     * below removes add.rec.  Both are still mapped from index_open, and
     * Windows refuses either while a mapping is held. */
    index_unmap();
    emit_index(olddir, oldfd);      /* consumes oldfd -- see emit_index */
    part_remove();

    /* After the rename above, the overlay records are in index.rec AND
     * still in add.rec.  A lookup in that window finds each twice at the
     * same locator, which the candidate collapse removes, so a crash here
     * costs nothing but the next compact. */
    if (unlink(pathcat("add.rec")) != 0 && errno != ENOENT)
        FATAL("unlink add.rec: %s", strerror(errno));
    manifest_write();
    free(olddir);
    fprintf(stderr, "done in %.1fs\n", now() - t0);
}

static void cmd_info(void)
{
    unsigned long long n, i, lines = 0;
    int t;

    manifest_read(0);
    n = fsize(pathcat("index.rec")) / RECSZ;
    printf("database   %s\n", Dbdir);
    printf("records    %s  (%s bytes, %d per bucket average)\n",
           commify(n), commify(n * RECSZ), (int)(n / NBUCK));
    {
        unsigned long long a = access(pathcat("add.rec"), R_OK) == 0
                             ? fsize(pathcat("add.rec")) / SRECSZ : 0;
        if (a)
            printf("overlay    %s records (%s bytes) awaiting compact\n",
                   commify(a), commify(a * SRECSZ));
        else
            printf("overlay    none; the index is one array\n");
        n += a;
    }
    printf("directory  %s buckets, %s bytes\n",
           commify(NBUCK), commify(8ULL * (NBUCK + 1)));
    printf("key        %d bits stored, %d bits implied by bucket\n",
           KEYBITS, BUCKBITS);
    printf("types     ");
    for (t = 0; t < Nhtype; t++) printf(" %s", Htype[t].name);
    printf("\n");
    /* A user-defined type is the one kind whose name does not say where
     * its definition came from.  The expression it was built with is in
     * the manifest and is what answers queries, so printing it here is
     * what distinguishes "this index holds a type I defined" from "this
     * index holds a catalog type I do not recognise". */
    for (t = 0; t < Nhtype; t++)
        if (Htype[t].uid != NULL)
            printf("user       %s  id %s  from %s\n             %s\n",
                   Htype[t].name, Htype[t].uid,
                   Htype[t].ufile && Htype[t].ufile[0] ? Htype[t].ufile
                                                       : "(unrecorded)",
                   Htype[t].expr ? Htype[t].expr : "");
    printf("\n idx %16s %16s  %s\n", "lines", "bytes", "path");
    for (i = 0; i < (unsigned long long)Nfiles; i++) {
        printf(" %3llu %16s %16s  %s\n", i, commify(Files[i].lines),
               commify(Files[i].consumed), Files[i].path);
        lines += Files[i].lines;
    }
    printf("\n%s lines indexed, %s records (%.2f records per line)\n",
           commify(lines), commify(n), lines ? (double)n / (double)lines : 0.0);
    fflush(stdout);
    files_check(0);
}

/* ------------------------------------------------------------------ */
/* check -- full sort-order and dedup verification                     */
/*                                                                      */
/* Every record in a bucket shares the three key bytes the bucket       */
/* NUMBER implies, so what emit_index wrote inside one is ordered by    */
/* memcmp over the residue alone -- and dedup dropped every repeat of a */
/* whole key, so adjacent residues are STRICTLY increasing.  Both       */
/* halves are checked here: a descending pair is a sort failure, an     */
/* equal pair is a dedup escape.  The second is not hypothetical --     */
/* the adjacent-record dedup in emit_index is correct only over data    */
/* that is fully sorted, so a sort that drops a work item produces      */
/* both faults at once.                                                 */
/*                                                                      */
/* This lived in a standalone scanner with the record size compiled     */
/* into it.  When the format went to v3 that scanner still read 11-byte */
/* records and called all 16,777,216 buckets unsorted on a perfectly    */
/* good index -- a checker cannot be trusted further than its agreement */
/* with the writer, and the only way to guarantee that agreement is to  */
/* build it from the same constants.  Hence: in here, not beside.       */
/* ------------------------------------------------------------------ */

/* Are the n records at rec strictly increasing on the key?  Returns 0 if
 * so, else the index of the first record that is not, and sets *dup to 1
 * when the fault is an equal key rather than a descending one.
 *
 * RECSZ, not RESID, is the comparison width, and the reason changed with
 * the dedup rule.  Dedup now keys on the whole record, so two records
 * sharing a residue and differing in locator are two words whose digests
 * collide -- legitimate, and ascending, since records sort key-major and
 * locator-minor.  What must never repeat is a whole record.  Comparing
 * the residue alone would now report every collision as a fault; comparing
 * narrower than the whole record would let a repeat through. */
static unsigned long long run_ordered(const unsigned char *rec,
                                      unsigned long long n, int *dup)
{
    unsigned long long i;

    *dup = 0;
    for (i = 1; i < n; i++) {
        int c = memcmp(rec + i * RECSZ, rec + (i - 1) * RECSZ, RECSZ);
        if (c > 0) continue;
        *dup = (c == 0);
        return i;
    }
    return 0;
}

/* Walk every bucket.  Returns the number of faulty buckets; at most one
 * fault is reported per bucket, and only the first SHOWMAX are printed,
 * so a wholesale format mismatch names a few buckets instead of 16
 * million lines. */
#define SHOWMAX 20

static unsigned long long index_scan(const unsigned char *rec,
                                     unsigned long long *nordp,
                                     unsigned long long *ndupp)
{
    unsigned long long nord = 0, ndup = 0, shown = 0;
    uint64_t b;
    double t0 = now();

    for (b = 0; b < NBUCK; b++) {
        unsigned long long lo = dirget((uint32_t)b);
        unsigned long long hi = dirget((uint32_t)b + 1);
        unsigned long long at;
        int dup = 0;

        if (Verbose && (b & 0xFFFFF) == 0xFFFFF)
            fprintf(stderr, "\r  %s of %s buckets  %.0fs   ",
                    commify(b + 1), commify(NBUCK), now() - t0);

        if (hi < lo) {
            nord++;
            if (shown++ < SHOWMAX)
                printf("  bucket %06llx  directory runs backwards, %s to %s\n",
                       (unsigned long long)b, commify(lo), commify(hi));
            continue;
        }
        if (hi - lo < 2) continue;

        at = run_ordered(rec + lo * RECSZ, hi - lo, &dup);
        if (at == 0) continue;
        if (dup) ndup++; else nord++;
        if (shown++ < SHOWMAX)
            printf("  bucket %06llx  record %s of %s is %s\n",
                   (unsigned long long)b, commify(at), commify(hi - lo),
                   dup ? "a duplicate record" : "out of order");
    }
    if (Verbose) fputc('\n', stderr);

    if (shown > SHOWMAX)
        printf("  ... %s further faulty buckets not listed\n",
               commify(shown - SHOWMAX));
    *nordp = nord;
    *ndupp = ndup;
    return nord + ndup;
}

/* check [index|overlay|all].  The split exists because update no longer
 * writes index.rec: on a night that only absorbed new words there is
 * nothing in the main array that could have changed, and re-reading 226 GB
 * to prove it is the kind of check that gets switched off for being slow.
 * The overlay IS rewritten every update, so that part is checked nightly
 * and costs milliseconds. */
static void cmd_check(int argc, char **argv)
{
    unsigned long long bad = 0, nord = 0, ndup = 0;
    int domain = 1, doadd = 1;
    double t0 = now();

    if (argc > 0) {
        if      (strcmp(argv[0], "index")   == 0) doadd  = 0;
        else if (strcmp(argv[0], "overlay") == 0) domain = 0;
        else if (strcmp(argv[0], "all")     != 0)
            FATAL("check takes 'index', 'overlay' or 'all', not '%s'", argv[0]);
    }

    index_open();
    if (domain) {
#ifdef MADV_SEQUENTIAL
        /* ponytail: one pass, front to back, over a file far larger than
         * RAM.  Without this the page cache keeps what it will never be
         * asked for again and evicts the caller's working set to do it. */
        (void)madvise((void *)(uintptr_t)Rec, (size_t)(Nrec * RECSZ),
                      MADV_SEQUENTIAL);
#endif
        printf("checking %s records in %s buckets\n",
               commify(Nrec), commify(NBUCK));
        fflush(stdout);
        bad = index_scan(Rec, &nord, &ndup);
        printf("%s: %s buckets out of order, %s with a duplicate key, %.0fs\n",
               Dbdir, commify(nord), commify(ndup), now() - t0);
    }

    /* The overlay is searched by binary search, so it must be sorted on
     * the whole key for the same reason index.rec must, and for the same
     * reason it is strictly increasing: one record per key.  Checking the
     * index and not the overlay would verify half the database and report
     * on all of it. */
    if (doadd && Nadd) {
        unsigned long long i, aord = 0, adup = 0;
        for (i = 1; i < Nadd; i++) {
            int c = memcmp(Add + i * SRECSZ, Add + (i - 1) * SRECSZ, KEYSZ);
            if (c > 0) continue;
            if (c == 0) adup++; else aord++;
            if (aord + adup <= SHOWMAX)
                printf("  add.rec record %s is %s\n", commify(i),
                       c ? "out of order" : "a duplicate key");
        }
        printf("%s/add.rec: %s records, %s out of order, %s duplicate keys\n",
               Dbdir, commify(Nadd), commify(aord), commify(adup));
        bad += aord + adup;
    }
    exit(bad ? 2 : 0);
}

/* ------------------------------------------------------------------ */
/* selftest                                                            */
/*                                                                      */
/* The digest vectors are PUBLISHED ones, or ones an independent        */
/* implementation produced -- RFC 1321 for MD5, FIPS 180-4 for          */
/* SHA-256, the standard NTLM "password" vector, and for MD5x02 and the */
/* three NTLM readings of a non-ASCII word, what mdxfind itself prints. */
/* A self-test fed by the code under test proves only that the code     */
/* agrees with itself, which is how a type stays broken while reporting */
/* Pass.                                                                */
/* ------------------------------------------------------------------ */

static int  Fails;
static char Stdir[4096];

static void ck(int ok, const char *what)
{
    printf("  %-62s %s\n", what, ok ? "Pass" : "FAIL");
    if (!ok) Fails++;
}

static void ck_type(const char *key, const char *in, const char *want,
                    const char *what)
{
    struct hout v[MAXVAR];
    char hex[MAXDIG * 2 + 1];
    int  t, n;

    for (t = 0; t < Nhtype; t++) if (strcmp(Htype[t].key, key) == 0) break;
    if (t == Nhtype) { ck(0, what); return; }
    n = Htype[t].fn((const unsigned char *)in, (int)strlen(in), v);
    if (n < 1) { ck(0, what); return; }
    bin2hex(v[0].dig, Htype[t].dlen, hex);
    ck(strcmp(hex, want) == 0, what);
}

/* Run the real lookup path with stdout captured, so emit_hit, the wrapper
 * logic and the batch machinery are all exercised rather than bypassed. */
/* Silence stderr around a command whose chatter would bury the checks,
 * and put back whatever it was.
 *
 * This replaces freopen("/dev/null") / freopen("/dev/tty"), which was
 * wrong twice. Neither device exists on Windows, so the selftest lost
 * stderr at the first use and the run ended mid-section with no message.
 * And /dev/tty is not a restore even on Unix: it reopens the TERMINAL, so
 * `mdindex selftest > log 2>&1` sent everything after the first silenced
 * block to the tty instead of the log. Saving the descriptor puts back a
 * pipe, a file or a tty alike. */
static int st_saved;

static int st_hush(void)
{
    int saved = dup(2), fd;

    fflush(stderr);
    fd = open(DEVNULL, O_WRONLY | O_BINARY);
    if (fd >= 0) { dup2(fd, 2); close(fd); }
    return saved;
}

static void st_speak(int saved)
{
    fflush(stderr);
    if (saved >= 0) { dup2(saved, 2); close(saved); }
}

static char *st_run(const char *hex)
{
    static char buf[65536];
    char  path[8192];
    struct query q;
    int   saved, fd;
    FILE *f;
    size_t n = 0;

    snprintf(path, sizeof(path), "%s/out.txt", Stdir);
    fflush(stdout);
    saved = dup(1);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
    if (fd < 0) FATAL("open %s: %s", path, strerror(errno));
    dup2(fd, 1);
    close(fd);
    if (parse_query(hex, &q)) run_batch(&q, 1);
    fflush(stdout);
    dup2(saved, 1);
    close(saved);

    buf[0] = 0;
    f = fopen(path, "r");
    if (f) { n = fread(buf, 1, sizeof(buf) - 1, f); fclose(f); }
    buf[n] = 0;
    return buf;
}

static int st_lines(const char *s)
{
    int n = 0;
    while (*s) if (*s++ == '\n') n++;
    return n;
}

/* How many output lines are repeats of an earlier one?  A line is read once
 * and every type regenerated from it, so no answer can legitimately appear
 * twice -- any repeat means a candidate was counted more than once. */
static int st_repeats(const char *s)
{
    char  seen[64][512];
    int   n = 0, rep = 0, i;

    while (*s && n < 64) {
        const char *e = strchr(s, '\n');
        size_t len = e ? (size_t)(e - s) : strlen(s);
        if (len == 0) break;
        if (len > sizeof(seen[0]) - 1) len = sizeof(seen[0]) - 1;
        for (i = 0; i < n; i++)
            if (strncmp(seen[i], s, len) == 0 && seen[i][len] == 0) { rep++; break; }
        if (i == n) { memcpy(seen[n], s, len); seen[n][len] = 0; n++; }
        if (!e) break;
        s = e + 1;
    }
    return rep;
}

/* Which source file does the one candidate for this digest live in? */
static int st_fidx(const char *hex)
{
    struct query q;
    if (!parse_query(hex, &q)) return -1;
    Ncand = 0;
    probe_query(&q, 0);
    if (Ncand == 0) return -1;
    return (int)(Cand[0].loc >> OFFBITS);
}

static void st_write(const char *name, const char *data)
{
    char  path[8192];
    FILE *f;
    snprintf(path, sizeof(path), "%s/%s", Stdir, name);
    f = fopen(path, "w");
    if (f == NULL) FATAL("open %s: %s", path, strerror(errno));
    fputs(data, f);
    if (fclose(f) != 0) FATAL("write %s: %s", path, strerror(errno));
}

static void st_append(const char *name, const char *data)
{
    char  path[8192];
    FILE *f;
    snprintf(path, sizeof(path), "%s/%s", Stdir, name);
    f = fopen(path, "a");
    if (f == NULL) FATAL("open %s: %s", path, strerror(errno));
    fputs(data, f);
    if (fclose(f) != 0) FATAL("write %s: %s", path, strerror(errno));
}

static void cmd_selftest(void)
{
    char *a[3], apath[8192], bpath[8192];
    unsigned char dec[256];
    unsigned char *tv = NULL;
    const unsigned char *mp;
    int ml;

    snprintf(Stdir, sizeof(Stdir), "/tmp/mdindex-selftest.XXXXXX");
    if (mkdtemp(Stdir) == NULL) FATAL("mkdtemp: %s", strerror(errno));
    snprintf(Dbdir, sizeof(Dbdir), "%s/db", Stdir);
    if (mkdir(Dbdir, 0755) != 0) FATAL("mkdir %s: %s", Dbdir, strerror(errno));

    printf("digests, against published vectors and mdxfind:\n");
    ck_type("md5", "", "d41d8cd98f00b204e9800998ecf8427e",
            "MD5 of the empty string (RFC 1321)");
    ck_type("md5", "abc", "900150983cd24fb0d6963f7d28e17f72",
            "MD5 of abc (RFC 1321)");
    ck_type("sha256", "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA-256 of abc (FIPS 180-4)");
    ck_type("sha256", "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA-256 of the empty string (FIPS 180-4)");
    ck_type("ntlm", "password", "8846f7eaee8fb117ad06bdd830b7586c",
            "NTLM of password (standard vector)");
    ck_type("md5x02", "password", "696d29e0940a4957748fe3fc9efd22a3",
            "MD5x02 of password = md5 of the HEX (mdxfind -i 2)");
    ck_type("sql5", "password", "2470c0c06dee42fd1618bb99005adca2ec9d1e19",
            "SQL5 of password (the MySQL 4.1 hash, less its '*')");
    ck_type("sql5", "hashcat", "fcf7c1b8749cf99d88e5f34271d636178fb5d130",
            "SQL5 of hashcat (hashcat -m 300 example hash)");
    ck_type("sha1", "password", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
            "SHA1 of password (standard vector)");
    ck_type("sha1", "hashcat", "b89eaac7e61417341b710b727768294d0e6a277b",
            "SHA1 of hashcat (hashcat -m 100 example hash)");
    {
        /* The scatter copies KEYSZ bytes out of every digest.  A type
         * shorter than the key would read past the digest into whatever
         * h_* left in the struct, so its keys would not be reproducible
         * between runs -- the index would simply stop finding that type
         * after a rebuild, with nothing anywhere saying why. */
        int t, shortest = MAXDIG;
        for (t = 0; t < Nhtype; t++)
            if (Htype[t].dlen < shortest) shortest = Htype[t].dlen;
        ck(shortest >= KEYSZ,
           "every type's digest is at least as long as the index key");
    }

    printf("\nNTLM reads a non-ASCII word three ways, as mdxfind does:\n");
    {
        struct hout v[MAXVAR];
        static const unsigned char cafe[] = { 0x63,0x61,0x66,0xc3,0xa9 };
        char h0[33], h1[33], h2[33];
        int t, n;
        for (t = 0; t < Nhtype; t++) if (strcmp(Htype[t].key, "ntlm") == 0) break;
        n = Htype[t].fn(cafe, 5, v);
        ck(n == 3, "three readings for 636166c3a9 (UTF-8, CP1251, CP1252)");
        if (n == 3) {
            bin2hex(v[0].dig, 16, h0);
            bin2hex(v[1].dig, 16, h1);
            bin2hex(v[2].dig, 16, h2);
            ck(strcmp(h0, "b1db12409c00d1fc586fc48ecadc36a1") == 0,
               "  UTF-8   reading matches mdxfind");
            ck(strcmp(h1, "3cea4c283475f27ec56c2cf0d51ba10a") == 0,
               "  CP1251  reading matches mdxfind");
            ck(strcmp(h2, "79ce465afc649cffc4dea9962775bbbc") == 0,
               "  CP1252  reading matches mdxfind");
            ck(v[0].verbatim == 1 && v[1].verbatim == 0,
               "  only the UTF-8 reading reports the word's own bytes");
            ck(v[1].plain != v[2].plain,
               "  each reading keeps its own reported plaintext");
        } else {
            Fails += 5;
        }
        /* Ill-formed UTF-8 loses the UTF-8 reading and KEEPS the two
         * code-page ones -- the bytes are still a legal CP1251 or CP1252
         * password.  mdxfind prints exactly these two for 618062. */
        n = Htype[t].fn((const unsigned char *)"a\x80" "b", 3, v);
        ck(n == 2, "ill-formed UTF-8 keeps the two code-page readings");
        if (n == 2) {
            bin2hex(v[0].dig, 16, h0);
            bin2hex(v[1].dig, 16, h1);
            ck(strcmp(h0, "50d5cd3e70d1d04198568c699b09171a") == 0 &&
               strcmp(h1, "5a796c292c5e7c018136ce8de8a7dc19") == 0,
               "  both match mdxfind, and the UTF-8 reading is absent");
            ck(v[0].verbatim == 0 && v[1].verbatim == 0,
               "  neither reports the word's own bytes");
        } else {
            Fails += 2;
        }
    }

    printf("\nhex-run extraction:\n");
    {
        int   n;
        char *h;
        char c1[] = "2055d9ef479bf00a61ae9a3ab2246213:b780915efdb2c702f8d29026eefb5a74";
        char c2[] = "alice:d0763edaa9d9bd2a9516280e9044d885";
        char c3[] = "$dynamic_0$d0763edaa9d9bd2a9516280e9044d885";
        char c4[] = "word\td0763EDAA9D9BD2A9516280E9044D885  trailing";
        char c5[] = "ETL:";
        char c6[] = "deadbeef";
        char c7[] = "$P$BOWLBZV02p4JeBXQXkqRc75yklWPQU1:cf768fd736bf7233deb44db1eea06019";

        n = 0; h = first_hex_run(c1, 16, &n);
        ck(h == c1 && n == 32,
           "hash:salt yields the hash, the run stopping at the colon");
        n = 0; h = first_hex_run(c2, 16, &n);
        ck(h == c2 + 6 && n == 32,
           "a login is stepped over, its own hex runs being too short");
        n = 0; h = first_hex_run(c3, 16, &n);
        ck(h == c3 + 11 && n == 32,
           "a $dynamic_N$ lead-in is stepped over");
        n = 0; h = first_hex_run(c4, 16, &n);
        ck(h == c4 + 5 && n == 32,
           "a digest in a later column is found, upper case included");
        n = 0;
        ck(first_hex_run(c5, 16, &n) == NULL,
           "a line with no run that long is refused");
        n = 0;
        ck(first_hex_run(c6, 16, &n) == NULL,
           "a run shorter than the minimum is refused, not padded");
        /* Stated as a check because it is the one case where the first long
         * run is NOT the hash: field 1 is a phpass MCF, which this index
         * cannot hold anyway, so field 2 is what gets looked up.  4 lines in
         * a 63,042-line sample. */
        n = 0; h = first_hex_run(c7, 16, &n);
        ck(h == c7 + 35 && n == 32,
           "a non-hex MCF in field 1 yields field 2 -- known consequence");
    }

    printf("\nquery lead-in:\n");
    {
        char b1[] = "$dynamic_0$d0763edaa9d9bd2a9516280e9044d885";
        char b2[] = "alice:$dynamic_0$d0763edaa9d9bd2a9516280e9044d885";
        char b3[] = "d0763edaa9d9bd2a9516280e9044d885";
        char b4[] = "$dynamic_1$5f4dcc3b5aa765d61d8327deb882cf99$SALT";

        ck(strcmp(skip_leadin(b1), "d0763edaa9d9bd2a9516280e9044d885") == 0,
           "a $dynamic_N$ lead-in is skipped");
        ck(strcmp(skip_leadin(b2), "d0763edaa9d9bd2a9516280e9044d885") == 0,
           "a login in front of the lead-in is skipped with it");
        ck(skip_leadin(b3) == b3,
           "a bare digest is returned untouched");
        /* skip_leadin now serves the ARGUMENT path only; the stdin path
         * scans for a hex run instead.  It still leaves a trailing field
         * attached, which is what this checks -- but note the consequence
         * has changed for stdin: a salted $dynamic_1$ line used to be
         * counted as ignored, and now its digest is found and looked up as
         * if unsalted, so it reads as an ordinary miss.  That is the price
         * of reading a noisy list at all, and it is the same trade every
         * `hash:salt` line in such a list already makes. */
        ck(!all_hex(skip_leadin(b4), strlen(skip_leadin(b4))),
           "a trailing $salt is left on by skip_leadin (argument path)");
    }

    printf("\nwrapper decoding:\n");
    ck(md_unwrap((const unsigned char *)"$HEX[616263]", 12, dec, sizeof(dec),
                 &tv, &mp, &ml, "t", 0) == 1 && ml == 3 &&
       memcmp(mp, "abc", 3) == 0,
       "$HEX[616263] denotes abc");
    ck(md_unwrap((const unsigned char *)"$HEX[zz]", 8, dec, sizeof(dec),
                 &tv, &mp, &ml, "t", 0) == 0,
       "malformed $HEX[] is hashed literally, not rejected");
    ck(tv == NULL, "no $TESTVEC[] seen yet, so no vector buffer allocated");
    ck(md_unwrap((const unsigned char *)"$TESTVEC[00 x 16]", 17, dec,
                 sizeof(dec), &tv, &mp, &ml, "t", 0) == 1 && ml == 16,
       "$TESTVEC[00 x 16] expands to 16 bytes");
    ck(tv != NULL, "the vector buffer is allocated on first sight of one");
    /* The decode buffer here is a few hundred bytes, far smaller than the
     * vector: proof that outmax no longer bounds an expansion, which is
     * what made mdindex refuse vectors hashpipe accepts. */
    ck(md_unwrap((const unsigned char *)"$TESTVEC[41 x 500000]", 21, dec,
                 sizeof(dec), &tv, &mp, &ml, "t", 0) == 1 && ml == 500000 &&
       mp[0] == 'A' && mp[499999] == 'A',
       "a 500,000 byte vector expands though the decode buffer is tiny");

    printf("\nend to end, a.txt at priority 0:\n");
    st_write("a.txt", "password\nabc\n");
    st_write("b.txt", "abc\n$HEX[636166c3a9]\nhunter2\n");
    snprintf(apath, sizeof(apath), "%s/a.txt", Stdir);
    snprintf(bpath, sizeof(bpath), "%s/b.txt", Stdir);
    a[0] = apath; a[1] = bpath; a[2] = NULL;
    {
        int sv = Verbose;
        Verbose = 0;
        st_saved = st_hush();
        cmd_build(2, a);
        st_speak(st_saved);
        Verbose = sv;
    }
    index_open();

    ck(strstr(st_run("5f4dcc3b5aa765d61d8327deb882cf99"),
              "MD5x01 5f4dcc3b5aa765d61d8327deb882cf99:password\n") != NULL,
       "full MD5 of password returns MD5x01 hash:password");
    ck(strstr(st_run("696d29e0940a4957748fe3fc9efd22a3"),
              "MD5x02 696d29e0940a4957748fe3fc9efd22a3:password\n") != NULL,
       "full MD5x02 digest finds the same word");
    ck(strstr(st_run("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef7"
                     "21d1542d8"),
              "SHA256x01 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11"
              "ef721d1542d8:password\n") != NULL,
       "full SHA-256 digest finds the same word");
    ck(strstr(st_run("8846f7eaee8fb117ad06bdd830b7586c"),
              "NTLMx01 8846f7eaee8fb117ad06bdd830b7586c:password\n") != NULL,
       "full NTLM digest finds the same word");
    ck(strstr(st_run("2470c0c06dee42fd1618bb99005adca2ec9d1e19"),
              "SQL5x01 2470c0c06dee42fd1618bb99005adca2ec9d1e19:password\n")
       != NULL, "full SQL5 digest finds the same word");

    ck(strstr(st_run("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"),
              "SHA1x01 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8:password\n")
       != NULL, "full SHA1 digest finds the same word");

    ck(strstr(st_run("b1db12409c00d1fc586fc48ecadc36a1"),
              "NTLMx01 b1db12409c00d1fc586fc48ecadc36a1:$HEX[636166c3a9]\n")
       != NULL, "NTLM UTF-8 reading reports the stored $HEX[] line");
    ck(strstr(st_run("3cea4c283475f27ec56c2cf0d51ba10a"),
              "NTLMx01 3cea4c283475f27ec56c2cf0d51ba10a:$HEX[636166d093c2a9]\n")
       != NULL, "NTLM CP1251 reading reports its own re-encoded plaintext");

    ck(strstr(st_run("5f4dcc3b5aa765d6"),
              "MD5x01 5f4dcc3b5aa765d61d8327deb882cf99:password\n") != NULL,
       "16-character partial query finds it and prints the FULL digest");
    ck(st_lines(st_run("5f4d")) >= 1,
       "4-character partial query still reaches the same record");
    ck(st_repeats(st_run("5")) == 0 && st_repeats(st_run("a")) == 0,
       "a 1-character query prints each answer once, not once per record");
    {
        /* The window a PIPED line has to fall in.  The floor is the index
         * key, so a half-MD5 is accepted; the ceiling is the longest
         * digest held.  Argv and a terminal are not filtered at all,
         * which the two partial queries just above exercise. */
        int lo = 0, hi = 0;
        hexlen_range(&lo, &hi);
        ck(lo == MINQHEX && lo == 16,
           "a piped query is taken from half-MD5 width up");
        ck(hi == 64, "  and up to the longest digest the database holds");
    }
    ck(st_run("00000000000000000000000000000000")[0] == 0,
       "a digest that is not present prints nothing");

    ck(st_fidx("900150983cd24fb0d6963f7d28e17f72") == 0,
       "abc is in both files and resolves to file 0, the first that had it");

    printf("\noverlay:\n");
    {
        /* An appended word must be findable WITHOUT index.rec changing,
         * and an already-indexed one must not enter the overlay at all --
         * that second property is what keeps the overlay proportional to
         * new words rather than to lines read. */
        unsigned long long recbefore = fsize(pathcat("index.rec"));
        int sv = Verbose;

        /* TWO new words and one repeat.  The second new word is what
         * guards the per-line probe grouping: group too coarsely and one
         * line's probe decides another line's fate, which silently drops
         * every record of a word that was never in the index. */
        /* The REPEAT comes first on purpose.  It is the line with the
         * lowest locator, so it is the one a too-coarse grouping would
         * probe -- and its key IS in the index, so that grouping would
         * filter the two new words out behind it and lose them silently.
         * Ordered the other way round this test passes on broken code. */
        st_append("a.txt", "abc\noverlaid\nsecondnew\n");
        Verbose = 0;
        st_saved = st_hush();
        cmd_update(0, (char **)0);
        st_speak(st_saved);
        Verbose = sv;
        index_map();            /* the mappings this process holds are stale */

        ck(fsize(pathcat("index.rec")) == recbefore,
           "update leaves index.rec untouched");
        {
            /* One record per TYPE for the new word, and none at all for
             * the repeat: without the main-index test in overlay_absorb
             * this would be twice as many, which is the whole difference
             * between an overlay that tracks new words and one that
             * tracks lines read. */
            unsigned ntypes = 0;
            int t;
            ntypes = Nhtype;
            ck(Nadd == 2 * ntypes,
               "both new words enter the overlay once per type, the repeat not");
        }
        ck(strstr(st_run("04ab503a7de44d3eaede8300614b5233"),
                  "MD5x01 04ab503a7de44d3eaede8300614b5233:overlaid\n")
           != NULL, "a word added since the last build is found");
        ck(strstr(st_run("d870ac483814c636668edfcaa420febc"),
                  "MD5x01 d870ac483814c636668edfcaa420febc:secondnew\n")
           != NULL, "  a second new word is not filtered by the first's probe");
        ck(strstr(st_run("5f4dcc3b5aa765d61d8327deb882cf99"),
                  "MD5x01 5f4dcc3b5aa765d61d8327deb882cf99:password\n")
           != NULL, "  and the index.rec records still answer alongside it");
        ck(st_repeats(st_run("900150983cd24fb0d6963f7d28e17f72")) == 0,
           "  a word in both index.rec and the sources prints once");
    }
    {
        /* compact must fold the overlay in and change no answer. */
        int sv = Verbose;
        char before[65536], after[65536];

        snprintf(before, sizeof(before), "%s", st_run("04ab503a7de44d3eaede8300614b5233"));
        Verbose = 0;
        st_saved = st_hush();
        cmd_compact();
        st_speak(st_saved);
        Verbose = sv;
        index_map();

        snprintf(after, sizeof(after), "%s", st_run("04ab503a7de44d3eaede8300614b5233"));
        ck(Nadd == 0 && access(pathcat("add.rec"), F_OK) != 0,
           "compact removes the overlay");
        ck(strcmp(before, after) == 0,
           "  and the word it folded in answers exactly as before");
    }

    printf("\nsort order:\n");
    {
        /* A clean whole-index pass first -- this walks the directory and
         * ties it to index.rec end to end.  It is NOT coverage of the
         * comparison: a test index this small puts every record in a
         * bucket of its own, so the inner loop never runs.  That is the
         * shape of a vacuous test, and the hand-built runs below are
         * where the comparison is actually pinned down. */
        unsigned long long nord = 1, ndup = 1;
        ck(index_scan(Rec, &nord, &ndup) == 0 && nord == 0 && ndup == 0,
           "the index this test just built scans clean");
    }
    {
        /* Two records whose keys differ only in the LAST residue byte,
         * and two whose keys are equal and differ only in the locator.
         * Together these pin the comparison width at exactly RESID: a
         * narrower one reads the first pair as a repeat, a wider one
         * reads the second as a legitimate ascending pair and lets a
         * dedup escape through. */
        unsigned char r[3 * RECSZ];
        unsigned long long at;
        int dup = 7;

        memset(r, 0, sizeof(r));
        memcpy(r + 0 * RECSZ, "\x11\x22\x33\x44\x55\x66\x77\x88\x01", RESID);
        memcpy(r + 1 * RECSZ, "\x11\x22\x33\x44\x55\x66\x77\x88\x02", RESID);
        memcpy(r + 2 * RECSZ, "\x11\x22\x33\x44\x55\x66\x77\x89\x00", RESID);
        ck(run_ordered(r, 3, &dup) == 0,
           "a run that rises only in the last key byte is in order");

        memcpy(r + 1 * RECSZ, "\x11\x22\x33\x44\x55\x66\x77\x88\x00", RESID);
        at = run_ordered(r, 3, &dup);
        ck(at == 1 && !dup, "a descending pair is reported, as out of order");

        /* Same key, different locator.  Legitimate since dedup keys on
         * the whole record: two words whose digests collide, which the
         * old key-only rule threw one of away.  Ascending, because
         * records sort key-major and locator-minor. */
        memcpy(r + 1 * RECSZ, r + 0 * RECSZ, RESID);
        r[1 * RECSZ + RESID] = 0x01;
        at = run_ordered(r, 3, &dup);
        ck(at == 0, "an equal key with a higher locator is in order");

        /* A repeated WHOLE record is the dedup escape now. */
        memcpy(r + 1 * RECSZ, r + 0 * RECSZ, RECSZ);
        at = run_ordered(r, 3, &dup);
        ck(at == 1 && dup, "an identical record is reported, as a duplicate");

        /* And the locator must still be compared: equal key with a LOWER
         * locator is descending, which is a sort fault. */
        memcpy(r + 1 * RECSZ, r + 0 * RECSZ, RECSZ);
        r[0 * RECSZ + RESID] = 0x01;
        at = run_ordered(r, 3, &dup);
        ck(at == 1 && !dup, "an equal key with a lower locator is out of order");
        r[0 * RECSZ + RESID] = 0x00;

        ck(run_ordered(r, 1, &dup) == 0 && run_ordered(r, 0, &dup) == 0,
           "a bucket of one record, and of none, are both in order");
    }

    printf("\nstaleness:\n");
    st_write("a.txt", "XXXXXXXX\nabc\n");
    {
        st_saved = st_hush();
        ck(files_check(0) == 1, "a rewritten source is reported, not ignored");
        st_speak(st_saved);
    }

    printf("\n%s\n", Fails ? "SELFTEST FAILED" : "selftest passed");
    {
        char cmd[8192];
#ifdef _WIN32
        snprintf(cmd, sizeof(cmd), "rmdir /s /q \"%s\"", Stdir);
#else
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", Stdir);
#endif
        if (system(cmd) != 0) fprintf(stderr, "note: %s left behind\n", Stdir);
    }
    exit(Fails ? 1 : 0);
}

/* ------------------------------------------------------------------ */

static void usage(void)
{
    int i;

    fprintf(stderr,
"mdindex - partial-hash index from digest to (file, offset) over very large\n"
"          wordlists, for several unsalted hash types at once\n"
"\n"
"usage: mdindex [-d dir] [-t threads] [-C file] [-H types] [-i depth] [-vy]\n"
"               build file [file ...]\n"
"       mdindex [-d dir] [-t threads] [-v] update [newfile ...]\n"
"       mdindex [-d dir] [-v] [lookup] [hash ...]\n"
"       mdindex [-d dir] info\n"
"       mdindex [-d dir] [-t threads] [-v] compact\n"
"       mdindex [-d dir] [-v] check [index|overlay|all]\n"
"       mdindex selftest\n"
"\n"
"  -d dir      database directory (default %s)\n"
"  -t threads  worker threads (default: one per core)\n"
"  -C file     stanza file of user-defined types, in the format mdxfind\n"
"              reads as userdef.txt: [name], id =, hx =.  Named outright;\n"
"              there is no search path and MDXFIND_CACHE is not consulted.\n"
"              A built index records each expression in its manifest, so\n"
"              this file is needed to build and never to read.\n"
"  -H types    comma-separated hash types to index (build only).  A type is\n"
"              named by canonical name (SHA1MD5PASS), by mdxfind eN (e259),\n"
"              by hashcat mode (300), or by its -C id (u47); a trailing :N\n"
"              selects mdxfind iteration N.  'all' takes every indexable\n"
"              catalog type.\n"
"              Default:",
    DBDIR_DEFAULT);
    for (i = 0; i < NDEFSIX; i++) fprintf(stderr, " %s", Defsix[i].key);
    fprintf(stderr,
"\n"
"  -i depth    index iterations 1..depth of every selected type\n"
"  -v          progress and a per-phase timing breakdown\n"
"  -V          print the version and exit\n"
"  -y          proceed past the projected-space refusal\n"
"\n"
"lookup is the default command: with no arguments mdindex reads hashes from\n"
"stdin, so `md5 <<<word | mdindex` works.  Output is the mdxfind shape,\n"
"TYPE hash:plain, so it pipes straight into hashpipe.  A piped line that is\n"
"not hex, or is shorter than the shortest digest in the database, is skipped\n"
"without comment and counted in the summary -- a mixed file can be fed in as\n"
"it stands.  A hash given as an argument, or typed at a terminal, is always\n"
"taken as asked, however short.\n"
"\n"
"PARTIAL HASHES ARE FINE.  The index stores %d bits of each digest, so a\n"
"query of 16 hex characters is exactly as selective as the index itself and\n"
"a longer one is filtered the rest of the way after the line is read.  A\n"
"shorter query is answered too -- it simply matches more records, and every\n"
"one of them is printed.  Supply as many digits as you have.\n"
"\n"
"Every hit is regenerated from the line and compared against all the digits\n"
"you supplied before it is printed, so a key collision costs a read and\n"
"prints nothing rather than producing a wrong answer.\n"
"\n"
"build takes the source files in PRIORITY order: when the same word appears\n"
"in more than one file, the record from the earliest file on the command\n"
"line is the one kept.  update re-reads each file from where build left off,\n"
"so an appended file costs only its new lines, and a file named on the\n"
"update line is ADDED at the lowest priority.  Sources may only GROW:\n"
"rewriting or reordering one invalidates every offset into it, is reported\n"
"against the size, mtime and end fingerprints in the manifest, and means\n"
"build.\n"
"\n"
"update does NOT rewrite index.rec.  New records go to an overlay beside it,\n"
"add.rec, which lookup searches as well, so absorbing a day of new words costs\n"
"those words and not the index they join: the measured case was 164 records\n"
"against a 452 GB rewrite.  compact folds the overlay in and is the only\n"
"command that rewrites index.rec; run it when update says the overlay is\n"
"getting large, or whenever it suits.  Nothing needs compacting to be correct.\n"
"\n"
"check reads every record and verifies that each bucket is strictly\n"
"increasing on the stored key -- a descending pair is a sort failure, an\n"
"equal pair a dedup escape.  'check index' is a full pass over index.rec and\n"
"costs an index-sized read; 'check overlay' reads only add.rec and is\n"
"instant, which is the one worth running after an update, since an update\n"
"writes only the overlay.  The default is both.  -v reports progress, and\n"
"exit 2 means a fault was found.\n"
"\n"
"Both $HEX[] and $TESTVEC[] are understood on input: the digest indexed for\n"
"a wrapped line is the digest of the bytes it DENOTES, not of its literal\n"
"text.\n",
    KEYBITS);
    exit(1);
}

int main(int argc, char **argv)
{
    char *Hlist[64];
    int   Nhlist = 0;
    int   c;

    mdindex_bridges_register();
    snprintf(Dbdir, sizeof(Dbdir), "%s", DBDIR_DEFAULT);
    Nthreads = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (Nthreads < 1) Nthreads = 1;

    /* -C must be read before any -H that names a u<id> from it, and getopt
     * hands options over in command-line order.  Every other mdindex option
     * is position-free, and making this one the exception would turn
     * "-H u47 -C types.txt" into an error about an unknown id, which names
     * the wrong thing entirely.
     *
     * So -H is COLLECTED here and resolved after the loop, once -C is
     * known.  An earlier version made two getopt passes instead, which
     * needs optreset to rewind -- a BSD extension that glibc spells as
     * optind = 0 and that mingw's getopt does not declare at all.  One
     * pass has no state to rewind and is portable by construction. */
    while ((c = getopt(argc, argv, "d:t:H:i:C:vhVy")) != -1) {
        switch (c) {
        case 'y': Yes = 1; break;
        case 'd': snprintf(Dbdir, sizeof(Dbdir), "%s", optarg); break;
        case 't': Nthreads = atoi(optarg);
                  if (Nthreads < 1) FATAL("-t needs a positive thread count");
                  break;
        case 'C': snprintf(Cfgfile, sizeof(Cfgfile), "%s", optarg); break;
        case 'V': printf("%s: %s\n", Prog, Version); exit(0);
        case 'H': if (Nhlist >= (int)(sizeof(Hlist)/sizeof(Hlist[0])))
                      FATAL("at most %d -H options",
                            (int)(sizeof(Hlist)/sizeof(Hlist[0])));
                  Hlist[Nhlist++] = optarg;
                  break;
        case 'i': Maxiter = atoi(optarg);
                  if (Maxiter < 1 || Maxiter > 16)
                      FATAL("-i needs an iteration depth of 1..16");
                  break;
        case 'v': Verbose = 1; break;
        default:  usage();
        }
    }
    argc -= optind;
    argv += optind;

    /* Now that -C is known, resolve the -H list that was collected above. */
    cfg_load();
    { int h; for (h = 0; h < Nhlist; h++) sel_from_list(Hlist[h]); }

    /* Only build chooses its own types; every other command reads them back
     * from the manifest, because an index holds what it holds and a -H on a
     * lookup would silently ask the wrong questions of it.  selftest wants
     * the six native arms, which is also what a build with no -H takes. */
    if (Nhtype == 0 && argc >= 1 &&
        (strcmp(argv[0], "build") == 0 || strcmp(argv[0], "selftest") == 0))
        sel_default();
    sel_expand_iters();
    maxvar_set();

    if (argc < 1) { cmd_lookup(0, (char **)0); return Nstale ? 2 : 0; }

    if (strcmp(argv[0], "selftest") == 0) cmd_selftest();

    if (Nhtype && strcmp(argv[0], "build") != 0)
        FATAL("-H selects the types a build indexes; every other command "
              "reads them back from the manifest");

    if (strcmp(argv[0], "build") == 0) {
        if (mkdir(Dbdir, 0755) != 0 && errno != EEXIST)
            FATAL("mkdir %s: %s", Dbdir, strerror(errno));
        cmd_build(argc - 1, argv + 1);
    } else if (strcmp(argv[0], "update") == 0) {
        cmd_update(argc - 1, argv + 1);
    } else if (strcmp(argv[0], "lookup") == 0) {
        cmd_lookup(argc - 1, argv + 1);
    } else if (strcmp(argv[0], "info") == 0) {
        cmd_info();
    } else if (strcmp(argv[0], "check") == 0) {
        cmd_check(argc - 1, argv + 1);
    } else if (strcmp(argv[0], "compact") == 0) {
        cmd_compact();
    } else {
        cmd_lookup(argc, argv);        /* bare hashes, no command word */
    }
    return Nstale ? 2 : 0;
}
