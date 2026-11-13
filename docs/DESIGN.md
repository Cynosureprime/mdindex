# Design

Why the index is shaped the way it is, and what can be relied on.

## The record

```
 0                 9        11           17
 +-----------------+--------+------------+
 | digest residue  |  type  |  locator   |
 |     9 bytes     | 2 bytes|  6 bytes   |
 +-----------------+--------+------------+

key     = 96 bits:  24 implied by the bucket, 72 stored as the residue
type    = 16 bits:  the type's position in the manifest's type list
locator = 48 bits:  11-bit file index, 37-bit byte offset
```

17 bytes per record. The first 24 bits of the key are the bucket number, so
they are not stored — every record in a bucket shares them. 2^24 buckets,
16,777,216 of them, and `index.dir` holds one 64-bit offset per bucket plus a
terminator.

The locator gives **2,048 source files and 137 GB per file**.

### Why 96 bits, and why not fewer

The key is not sized for lookup. 64 bits already selects about one record in a
15-billion-record index; the probability a random 64-bit query meets a record
is about 8 in ten billion.

It is sized for **deduplication**. Deduplication deletes a record when its key
and type equal its neighbour's, and a truncated key cannot tell a duplicate
from a collision — it resolves the difference by deleting data. At 64 bits,
two distinct words colliding in those bits under one type means one of them is
silently removed from the index and can never be found. At 96 bits the
expected number of such pairs across 15 billion records is about one in a
billion.

The general rule: **size a dedup key for dedup, not for lookup.** The birthday
bound is n²/2^(bits+1), and the cost of being wrong is invisible data loss
rather than a slow query.

## One implementation of every hash

mdindex computes no digest of its own. Every type is an
[hx](https://github.com/Cynosureprime/hashpipe) expression, compiled once to
bytecode at build time and run by the same engine mdxfind and hashpipe use,
over the same hash libraries.

This is a correctness property before it is a convenience one. A tool that
carried its own md5-of-md5 would be a second implementation that had to agree
with the first, and a self-test cannot tell you which of two disagreeing
implementations is right. With one implementation there is nothing to
diverge.

It costs less than it sounds. The engine is an interpreter, but its dispatch
is a few instructions around the same library call a hand-written arm would
make: measured at about 1.8 million hash operations per second per thread,
against a build whose hashing phase is bound by writing scratch to disk at
115 MB/s. The interpreter fits inside I/O the build is already waiting on.

### Eligibility is a predicate, not a list

A type is indexable if its digest is a function of the word alone. mdxfind's
type table already declares what each type needs handed to it, so mdindex
reads that rather than keeping its own list: a type needing only the password
qualifies, and one needing a salt, a userid, a pepper or a structured stored
form does not.

Because it is a predicate over a generated table, a type whose declaration is
corrected becomes eligible on the next build with nothing to edit, and no
list goes stale.

### Several digests from one word

A type can yield more than one digest per word. NTLM is the familiar case —
three code-page readings — and an enumerated-salt type is the extreme one, at
768 digests from a single word. The number is a property of the type and is
declared in the table with it, not a compile-time constant, and the buffer
that holds a line's digests is sized from the largest type actually selected.

That bound is **asserted, not assumed**. A type producing more variants than
it declared aborts rather than filling the buffer and stopping, because a
truncated variant set builds an index that passes every structural check,
answers most queries, and is silently missing the rest.

## Lossy by design, exact in answer

A record does not store the whole digest. It stores 96 bits of it, and the
type it was made under. The answer is recovered rather than stored: a hit
reads the line, regenerates every configured digest of it, and compares
against the whole hash the caller supplied.

Two consequences, and they are the heart of the design:

- **A key collision cannot produce a wrong answer.** It costs one wasted read
  and prints nothing.
- **Adding a hash type is a table entry and a rebuild, not a format change.**
  The stored type is a position in the manifest's list, not a code, so the
  record, the sort, the merge and the wrapper decoding know nothing about any
  particular function.

The index is a filter. The verification is exact.

## Why the record carries its type

Deduplication must tell the same word met twice from two different words that
reach one digest. Without the type, the only way to tell was to read both
source lines and compare the text: two random reads for every word the sources
share, which on a full build is billions of reads. A build that did this was
stopped after four and a half hours with a fraction of a percent of the index
written.

Two different words reach one digest only through two different types:
`MD5x02` of `password` is `MD5x01` of its own hex. A random collision of two
words in 96 bits under one type is about one in a billion over the whole
index. So the rule needs no read: **an equal key under an equal type is the
same word**, and the copy from the highest-priority file is kept; an equal key
under a different type is kept as well, and that digest answers with both
words. A word stored both raw and as `$HEX[]` is one word, and is kept once.

## The sort, and the invariant `check` tests

Records are sorted by key, then type, and written as a packed array, with the
directory giving each bucket's extent. Within a bucket all records share the
first 24 bits, so ordering is a memcmp over the stored residue and type.

Deduplication removes every repeat of a key under one type, so within a
bucket the (residue, type) pairs are **strictly increasing**. That is a stronger statement than "sorted", and it
is the invariant worth testing:

- a **descending** pair is a sort failure;
- an **equal** pair is a deduplication escape.

Both have one cause, because deduplication compares adjacent records only: if
the sort misplaced a record, its duplicate was never adjacent to it and
survived. One pass tests both.

`check` is a subcommand rather than a separate tool, deliberately. A verifier
that restates a layout constant will eventually disagree with the writer, and
the disagreement arrives looking like total corruption — a standalone scanner
carrying its own record width once reported all 16,777,216 buckets unsorted on
an index that was perfectly clean. Built from the same constants as the
writer, it cannot drift.

## Two pieces

```
index.rec   packed sorted array, 17-byte records, directory in index.dir
add.rec     overlay: sorted 20-byte records, whole key + type + locator, no directory
index.flt   blocked Bloom filter over every key in index.rec
```

`index.rec` is a packed sorted array, which means absorbing one new word costs
a read and a write of all of it. A measured night of 1,197 new lines holding
164 records not already indexed cost 452 GB of I/O and 36 minutes under the
old single-file design.

So `update` writes only `add.rec`: the whole 96-bit key (no bucket to imply it
from), the type, and the same locator, sorted, binary-searched, no directory. Lookup
searches both. `compact` folds the overlay in and is the only command that
rewrites the main index.

**The overlay holds new words, not lines read.** Before a record is written,
the main index is probed for its key and type; one already held is dropped. That is not
only a size optimisation — without it a word appended to a higher-priority
file would sit in both files at two different locators and print its answer
twice.

One probe is made per **line**, not per record: a line's records are all the
same word, and a build indexes every configured type of every line, so if any
one of a line's keys is present then all are.

## The merge

`compact` and `build` share one routine. Both the existing index and the new
records are already sorted on the whole scratch record — key, then type, then
file, then offset — so the two streams are **merged** rather than concatenated and
re-sorted. Taking the smaller head reproduces exactly what sorting the union
would have produced, including which record of an equal-key pair survives
deduplication.

That matters for priority: the locator carries the file index in its high
bits and the manifest is in priority order, so ordering on the whole record
keeps the highest-priority copy without any special case.

## The filter

A miss is the common answer, and without help each one costs a random read of
`index.rec`. `index.flt` answers most misses from a much smaller file.

```
 header   4 KB: magic, version, page bits, k, page size,
                record count and mtime of the index.rec it covers
 pages    2^p pages of 4 KB, p chosen for at least 9 bits per key
```

The key is already a digest, so it is its own hash. Its leading *p* bits
choose the page, and bytes 4 to 11 give the six bit positions within it by
double hashing. All six bits of a key are in one page, so a test is one 4 KB
read. Because pages follow key order, the filter is written in one sequential
pass over `index.rec`, and a sorted batch of queries reads its pages in order.

At 15.1 billion records the filter is 2^22 pages, 16 GB, 9.1 bits per key,
with about 1.3% false positives. A false positive costs the probe it would
have cost anyway; a filter cannot produce a false negative for a key it
covers, so it cannot hide a hit.

**It covers `index.rec` only.** The overlay changes every night and is small
enough to search for every query, so `update` does not touch the filter, and
`build` and `compact`, which rewrite `index.rec`, rewrite the filter after it.

**A filter over different keys is not used.** One that does not cover a key
reports it absent, which reads exactly like a miss. So the header records the
record count and mtime of the `index.rec` it was built from, and a lookup
that finds a mismatch says so on standard error and probes every query as
before. `check index` tests every key against the filter and counts each
rejection as a fault.

Only a query for a whole key, 24 hex characters or more, uses the filter. A
shorter query names a range of keys, which a filter cannot speak for. The
full-scan path does not use it either: it reads all of `index.rec` once
however many queries there are.

## Priority

A digest is stored once per type. When a word appears in several sources, the record
kept is from the file earliest on the `build` command line; within a file, the
first occurrence wins.

One behavioural note. A word re-appearing in a *higher*-priority file during an
`update` keeps the record it already has rather than being re-attributed. Both
records name a line that yields the same plaintext, and the output is
`TYPE hash:plain`, so it is not observable in the answer.

## Verification on the way out

Every candidate is re-hashed from the line that was fetched and compared
against the digits the caller supplied, before anything is printed. This is
what makes a lossy index safe, and it also catches a source that was rewritten
between update and lookup: the offset still points somewhere, but the bytes
there no longer hash to the key, so the hit is dropped rather than printed as
a confident wrong answer.

The manifest's head and tail fingerprints catch the same fault earlier and more
cheaply. The per-hit check catches what a fingerprint cannot — an edit in the
middle of a file that left its size and mtime alone.

## What is deliberately absent

**Salted types.** The index maps a digest to a position, which works only
because the digest is a function of the word alone. See the README.

**The answer.** A record names the type that made its key, but not the word:
that is read from the source and re-hashed, so a source rewritten under the
index is caught rather than believed.

**A free list, or in-place update.** `index.rec` is a packed array with no
slack. Insertion points are uniformly distributed, so per-partition slack
would need to be everywhere to help anywhere; the overlay solves the same
problem in a simpler format with a compaction story.
