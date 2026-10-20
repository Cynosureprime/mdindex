# Sizing: disk, time, and when not to use the index

Every figure here was measured on one reference build: three wordlists
totalling 53.5 GB and 4,147,323,844 lines, indexed for **six** hash types, on
a 16-core machine with the database on spinning storage. The type count is
the figure to vary: everything below scales with it.

## The index is larger than the wordlists

This surprises people, so take it first.

```
sources                        53.5 GB
index.rec                     226.4 GB      4.2x
```

A record is **15 bytes whatever the word costs**. One source line leaves about
3.6 records once duplicate keys are dropped — six hash types, and up to three
NTLM readings of a non-ASCII word — so a line averaging 13 bytes of text
occupies some 55 bytes of index.

The ratio is a property of **the wordlist and the types you chose**, not of
the index. It falls as the average line gets longer, and it scales with the
number of types. A list of long passphrases indexed for two types is a
fraction of its own size; a list of six-character passwords indexed for fifty
types is many times it.

```
bytes of index per source line  ~=  types x records-per-type x 15 x kept
```

Six types give about 3.6 surviving records per line. Fifty give about thirty,
and a 226 GB index becomes closer to 1.9 TB.

Two things drive `kept` and they are easy to confuse. On this corpus most of
the loss is **duplicate words** between the three source files, which is why
six types yield 3.6 and not 6. On a deduplicated wordlist that loss is gone
and only **digest collisions between types** remain: measured over 538 single-digest
types on a 10,000-word list, 518 records survive per word, or 0.96 per
type. So a list you have already deduplicated costs close to one record
per word per type, and the 3.6-from-6 ratio here is a property of these
sources, not of the index.

A third factor appears once the type set is wide enough to include them:
a type that **enumerates its own domain** yields many digests per word
rather than one. The five HEXSALT types walk 256 salts over three shapes,
768 records per word each, so adding them to a 538-type selection takes it
from 518 records per word to 4,358 — and to 4,884 once `-i 2` doubles
everything else. See
[IDENTIFYING.md](IDENTIFYING.md) for the measured figures.

## Before the build: the projection

You are not required to work any of this out. `build` does it first and tells
you, because the alternative is discovering at hour six that the filesystem is
full with scratch spread across 256 partition files.

**It counts the input before reading a line of it.** The counter is the SIMD
newline scan from mdxfind — AVX2 behind a runtime check, NEON on ARM, scalar
tail — and it reads only the part of each source not already indexed. On a
fresh build that is everything, which costs one sequential pass: 268 s for
53.5 GB at the reference machine's ~200 MB/s.

**Usually it costs nothing at all.** mdxfind caches line counts in a SQLite
table keyed on `(path, size, mtime)`, and mdindex reads and writes the same
cache when `MDXFIND_CACHE` is set. These are the same wordlists both tools
work on, so the count is typically already there. On the reference machine
4.116 of 4.147 billion lines were already cached; only the small nightly file
needed counting, about two seconds. The key includes size and mtime, so a file
that has grown misses rather than returning a stale count.

**Then it observes the expansion** rather than assuming it. Records per line
is not a constant — it depends on the types chosen and on how many lines are
non-ASCII, since NTLM alone emits up to three readings of one. Hashing a
sample of the real input and counting what comes out gives the multiplier.

The sample is budgeted in **digests, not lines**, with a floor of 64 lines so
the non-ASCII share is still visible. A line costs one digest per type, so a
line-count budget would be 4,914 times dearer against the 1,081-type
identification set than against the default six; a digest budget costs 1.2 s
against either.

Measured accuracy, projection against the build it predicts:

| selection | projected | actual, pre-dedup |
|---|---|---|
| default six | 60,006 | 60,006 |
| `-i 2 -H all` | 49,145,851 | 49,144,934 |

From those two numbers come projected records, index bytes, scratch bytes and
wall clock, printed before anything is written.

**The alert is a share of free space, not a fixed size.** If the projected
peak exceeds a tenth of what is available on the database filesystem, `build`
prints the projection, writes nothing and exits 1; `-y` proceeds. A tenth rather
than a half because a build runs for hours while other things write to the
same filesystem, and on a shared or snapshotting volume the reading is a
moment in time and not a reservation.

This is the one place mdindex refuses rather than reports. Everywhere else —
an unusual type, a pathological line, a vast selection — it tells you loudly
and computes anyway.

## Space to have free before a build

```
scratch         lines x records-per-line x 18 bytes
new index.rec   surviving records x 15 bytes
old index.rec   survives until the rename
```

Scratch is one 18-byte record per line **per type**, written before
deduplication, so it is the largest of the three and it is transient. For the
reference build:

```
scratch                       449.7 GB
new index.rec                 226.4 GB
old index.rec                 226.4 GB
peak observed                ~785    GB
```

Plan for roughly **1.5x the finished index, plus the finished index itself,
plus whatever the old one occupies**. Scratch lives in `part/` inside the
database directory, so one filesystem carries all of it.

## Time

```
build, total                 7,918.8 s     2 h 12 m
  of which hashing           3,895.3 s     1.06 M lines/s, 16 threads
  remainder                                sort, dedup, emit
```

The hashing phase is **I/O-bound, not CPU-bound**: it writes 449.7 GB of
scratch at about 115 MB/s while reading 53.5 GB. Adding types costs less time
than the line count suggests, right up until scratch outgrows the disk.

An `update` is in a different league, because it reads only what was appended
and writes only the overlay:

```
update, 17,277 appended lines   110.7 s
  hashing                         0.6 s
  main-index probes             110.1 s     one per new line
```

**The probe is the whole cost of an update.** Before a record can enter the
overlay, the main index is checked for its key — a word already indexed must
not be stored twice at two different locators, or it prints its answer twice.
That is one random read per new *line* (not per record: a line's records share
a word, so one probe decides the group), and random reads run at whatever the
device gives. On the reference machine that is about 150 a second.

## Lookup

```
2,000 hashes, cold               18.472 s    108 lookups/s
  sort                            0.000 s
  index probe                    18.108 s    110 probes/s
  fetch + verify                  0.363 s
  digests regenerated            12,000
```

A lookup is one random read to find the record and one more to read the line.
The rate is the device's random-read rate, not the CPU's. A warm directory
helps; nothing else does much.

Past a batch size of roughly `records x 15 x IOPS / sequential-bytes-per-sec`
queries — about 257,000 against the reference index — mdindex stops probing
and makes one sequential pass over `index.rec` instead. It switches
automatically.

## When a linear mdxfind run is cheaper

Because the index is 4.2x its sources, there is a crossover. mdindex's cost is
roughly zero fixed plus one seek per hash; a linear pass is a large fixed cost
and then nothing.

With a lookup rate of ~100/s and sources read at ~200 MB/s:

```
linear pass over 53.5 GB          ~268 s
crossover                      ~27,000 hashes
```

Under ten thousand hashes, use the index without thinking. Over a hundred
thousand, a linear pass moves fewer bytes. **At the crossover it does not
matter** — both take about four and a half minutes — which is the one place
the answer is uncertain and also the one place the choice is free.

Two things the arithmetic does not capture, both favouring the index: it
returns the first answer in milliseconds and can be stopped when you have seen
enough, and it answers partial hashes and hashes whose type you do not know.

Recompute these for your own hardware. The three inputs are your sequential
read rate, your random-read rate at queue depth 1, and the total size of your
sources.
