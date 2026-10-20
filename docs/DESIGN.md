# Design

Why the index is shaped the way it is, and what can be relied on.

## The record

```
 0                 9            15
 +-----------------+------------+
 | digest residue  |  locator   |
 |     9 bytes     |  6 bytes   |
 +-----------------+------------+

key     = 96 bits:  24 implied by the bucket, 72 stored as the residue
locator = 48 bits:  11-bit file index, 37-bit byte offset
```

15 bytes per record. The first 24 bits of the key are the bucket number, so
they are not stored — every record in a bucket shares them. 2^24 buckets,
16,777,216 of them, and `index.dir` holds one 64-bit offset per bucket plus a
terminator.

The locator gives **2,048 source files and 137 GB per file**.

### Why 96 bits, and why not fewer

The key is not sized for lookup. 64 bits already selects about one record in a
15-billion-record index; the probability a random 64-bit query meets a record
is about 8 in ten billion.

It is sized for **deduplication**. Deduplication deletes a record when its key
equals its neighbour's, and a truncated key cannot tell a duplicate from a
collision — it resolves the difference by deleting data. At 64 bits, two
distinct words colliding in those bits means one of them is silently removed
from the index and can never be found. At 96 bits the expected number of such
pairs across 15 billion records is negligible.

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

A record does not store the whole digest, and does not record which hash
function produced it. Both are recovered rather than stored: a hit reads the
line, regenerates every configured digest of it, and compares against the
whole hash the caller supplied.

Two consequences, and they are the heart of the design:

- **A key collision cannot produce a wrong answer.** It costs one wasted read
  and prints nothing.
- **Adding a hash type is a table entry and a rebuild, not a format change.**
  Nothing in the record, the sort, the merge or the wrapper decoding knows
  which function made a key.

The index is a filter. The verification is exact.

## The sort, and the invariant `check` tests

Records are sorted by key and written as a packed array, with the directory
giving each bucket's extent. Within a bucket all records share the first 24
bits, so ordering is a memcmp over the stored residue.

Deduplication removes every repeat of a whole key, so within a bucket residues
are **strictly increasing**. That is a stronger statement than "sorted", and it
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
index.rec   packed sorted array, 15-byte records, directory in index.dir
add.rec     overlay: sorted 18-byte records, whole key + locator, no directory
```

`index.rec` is a packed sorted array, which means absorbing one new word costs
a read and a write of all of it. A measured night of 1,197 new lines holding
164 records not already indexed cost 452 GB of I/O and 36 minutes under the
old single-file design.

So `update` writes only `add.rec`: the whole 96-bit key (no bucket to imply it
from) plus the same locator, sorted, binary-searched, no directory. Lookup
searches both. `compact` folds the overlay in and is the only command that
rewrites the main index.

**The overlay holds new words, not lines read.** Before a record is written,
the main index is probed for its key; one already held is dropped. That is not
only a size optimisation — without it a word appended to a higher-priority
file would sit in both files at two different locators and print its answer
twice.

One probe is made per **line**, not per record: a line's records are all the
same word, and a build indexes every configured type of every line, so if any
one of a line's keys is present then all are.

## The merge

`compact` and `build` share one routine. Both the existing index and the new
records are already sorted on the whole scratch record — key, then file, then
offset — so the two streams are **merged** rather than concatenated and
re-sorted. Taking the smaller head reproduces exactly what sorting the union
would have produced, including which record of an equal-key pair survives
deduplication.

That matters for priority: the locator carries the file index in its high
bits and the manifest is in priority order, so ordering on the whole record
keeps the highest-priority copy without any special case.

## Priority

A digest is stored once. When a word appears in several sources, the record
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

**Any record of which function made a key.** Storing it would cost bytes on
every record to save a recomputation that costs microseconds, and would make
adding a type a format change.

**A free list, or in-place update.** `index.rec` is a packed array with no
slack. Insertion points are uniformly distributed, so per-partition slack
would need to be everywhere to help anywhere; the overlay solves the same
problem in a simpler format with a compaction story.
