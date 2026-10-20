# Identifying an unknown hash list

My default index is wide in words and narrow in types: billions of lines,
six hashes. It answers *have I seen this password*. Build one the other way
round — a small wordlist against every type that can be indexed — and the
same code answers *what kind of hash is this*.

Many indexes can coexist with no interaction, using the -d option of mdindex, and
this creates an ability to generate this new kind of tool. The identification index
can hold essentially all of the unsalted hash types that mdxfind knows about, so it
is a perfect way to analyze a new, unknown-type hash list.

## Building one

```
$ mdindex -d ~/.mdindex/ident -i 2 -H all build 10kpass.txt
projection  10,001 lines x 4914.09 records/line = 49,145,851 records
            scratch 862.9 MB, new index 719.1 MB, peak 2.2 GB; 12.9 TB free
  10kpass.txt                     10,001 lines    10.4s
hashed 10,001 lines (73,018 bytes) in 11.0s -- 905.92 lines/sec, 6.61KB/sec
49,960,212 records, 304,834 duplicates dropped, 2.8s
done in 13.9s
```

`-H all` takes every type that is a function of the password alone and that
this build can compile and prove — **551** of them — and `-i 2` indexes each
one at iterations 1 and 2, for **1,088** types in all. Iterating is worth the
doubling: of the 243 types that named something in the run below, 44 were
reachable only at `x02`. See [Choosing hash types](../README.md#choosing-hash-types) for what that
excludes and why. The wordlist should be small and *common* — a list of the
passwords people actually choose, not a dictionary. Ten thousand is enough
to start with.

Keep it in its own directory. It is not the default index, 
and is not something `update` should ever touch.  You can, if you find new
patterns of common passwords, add and rebuild over time.

## Using it

```
mdindex -d ~/.mdindex/ident < unknown.hashes | awk '{print $1}' \
    | sort | uniq -c | sort -rn | head
```

Run against 53.2 million unidentified 32-hex digests:

```
   7236 SHA1x01          1872 MD5HEXSALTx01    1036 LMx01
   7236 AICHx01          1315 SHA1x02            566 NTLMx01
   6954 SHA256x01        1315 AICHx02            566 MD4UTF16UCx01
   3973 SHA1MD5x01       1266 SHA1RAWx01         553 SHA1revpx01
```

**`LMx01` at 1,036 is the ninth most common type in the corpus.**

The list is largely **SHA-1 stored truncated to 32 hex**, which is why
query shorter than a digest works, and mdindex prints the whole digest it matched.

**`MD5HEXSALTx01` is the case that justifies the expense.** That family
enumerates its own 256 salts, costing 768 records per word, and **1,875 of
the 27,099 identified digests carry no other name** — 7% of the answer, for
one family. The seven HUM types are the same argument at 1/48th the cost:
eight line-ending separators over two placements, 16 records per word,
and **32 digests that nothing else names** — every one of their hits. A salted type is normally
unindexable because the salt arrives with the hash; this one is indexable
precisely because it supplies its own. Its output carries the salt it
matched, since nothing could re-verify the line without it:

```
SHA1HEXSALTx01 476649c6a099a8173dee369a46d88c9ddba127dd:0a:098765
```

The two equal counts of 7,236 are **one digest reported under two names**:

```
$ echo f6a7651443d5867f394fe61ab082aac01c3c25fd | mdindex -d ~/.mdindex/ident
SHA1x01 f6a7651443d5867f394fe61ab082aac01c3c25fd:098765
AICHx01 f6a7651443d5867f394fe61ab082aac01c3c25fd:098765
```

AICH is built on SHA-1 and reduces to it for any message short enough to be
a password. mdxfind reports it too, so mdindex does: the index stores
presence, not type, and every type that genuinely reproduces the digest is
a true answer.  You can select the appropriate type, depending on what your
hash list contains.

What you will **not** see is false positives. Three kinds are excluded:

- **A type that differs only in output form.** `SHA1UC` is SHA-1 in
  uppercase hex, the same digest once stored as bytes, so it is indexed
  once under `SHA1`. It becomes a distinct type only from x02, where the
  uppercase hex is what gets rehashed — which is what `-i` is for.
- **A type whose transform does nothing to this word.** `SHA1UTF7` is
  SHA-1 of the UTF-7 encoding, and UTF-7 of pure ASCII is the input
  unchanged. mdxfind skips such a word outright, and so does mdindex, at
  build and at lookup alike.
- **A type needing a salt someone else holds.** Refused: the digest stops
  being a function of the password, and no amount of indexing recovers it.

The tail is not noise to be discarded either — a genuinely mixed list looks
like this too, and the only way to tell a mixed list from a clean one with a
few collisions is the ratio of how many hashes of each type there are.

There is no histogram subcommand and will not be one. mdindex emits lines;
`sort | uniq -c`, or [rling](https://github.com/Cynosureprime/rling) `-q`,
counts them, and the pipe lets you slice the
output any way you need.

## What it costs

Measured, not projected. One machine, 16 cores — a workstation in
interactive use, not a dedicated benchmark host, so treat every wall-clock
figure here as indicative. Record counts and byte sizes are exact and
reproducible; times are not.

| | words | types | records | `index.rec` | on disk | build |
|---|---|---|---|---|---|---|
| default index | 4,147,323,844 | 6 | 15,093,499,954 | 226.4 GB | 226.5 GB | hours |
| ident, `-i 2 -H all` | 10,001 | 1,088 | 49,960,212 | 749.4 MB | 883.6 MB | **13.9 s** |
| the same, no HEXSALT | 10,001 | 1,072 | 10,416,259 | 156.2 MB | 290.5 MB | **3.1 s** |

That is **4,996 records per word**, and the cost is linear in words: a
wordlist of *n* words takes very close to `n x 4,996 x 15` bytes and
proportional time. The relation holds to one part in ten thousand at a
hundred thousand words: ten times the input, ten times the records.

**Five types account for 79% of that.** The HEXSALT family enumerates its
own salt — all 256 two-hex values, over three shapes — so one word yields
768 digests per type where an ordinary type yields one. (They are the five
names the second row drops, and they appear at x01 only: an enumerated
family is not iterated.) That is the price of being able to identify the
family at all; drop them with an explicit `-H`
list and the same wordlist costs 1,041 records per word and 156 MB instead
of 733 MB.

`index.dir` is one 8-byte offset per bucket plus a terminator —
`8 x (2^24 + 1)` = 134,217,736 bytes — **whatever the record count**. It
dominated when the index was small; at these sizes it is 15% of the full
index and 46% of the one without HEXSALT.

### Lookup

The index was queried with **53,201,030** hashes — a 1.76 GB file of 32-hex
digests — in **154 seconds**:

```
36,773 hits for 27,099 of 53,201,030 hashes, lookup time 153.793s
```

That is the whole-file case, where mdindex abandons per-query probes and
reads the index sequentially, so the time tracks the index size rather than
the query count; a few thousand queries against the same index answer in
milliseconds. 243 distinct types appeared, and 187 of them matched a type
the corpus was already known to contain — out of 576 such types in all.
380K hashes per second, helping you to resolve a completely unknown list
in a couple of minutes.

**On the timings.** This machine is a workstation in interactive use, not a
benchmark host, so read every wall-clock figure here as the right order of
magnitude rather than as a benchmark. Competing work moves them by 20% —
more than the page cache does, which is worth 1.3%: the same query takes
137.8 s warm and 139.6 s cold after `purge`, against a 733 MB index and a
1.76 GB input. A number that matters is measured somewhere nothing else is
running.

Resolution is per **distinct matched word**, not per hit, because the
re-hash is what names the type and a word only needs it once.

### Depth

`-i N` indexes iterations 1 to N of every selected type, the way mdxfind's
`-i` does, and multiplies the record count by roughly N. It is worth the
cost when a list resists identification at depth 1: an iterated type is a
different digest, not a different label, so a hash of `md5(md5(pass))` is
invisible to an index built only at depth 1.

## The four things it cannot tell you

**Salted, user-keyed and peppered types are absent by construction.** They
cannot be indexed at all, because the salt is not known at build time. An
unknown *salted* list is not identifiable this way. It returns zero hits.

**Zero hits is ambiguous.** Either no word of your list is in the corpus, or
the list's type is not in the index. The output cannot distinguish them, and
a type the index never held looks exactly like one it lost. The manifest is
what resolves it:

```
mdindex -d ~/.mdindex/ident info
```

That prints the types the index holds, so the second possibility is
answerable by inspection rather than by guessing. Check it *before* widening
the wordlist.

**Wordlist coverage is the binding constraint, not type coverage.** But
identification needs a handful of resolved hits, not a good hit rate: one
hundredth of one percent of a million-hash list is still a hundred hits, and
a hundred hits is plenty to take a mode over. A list of hashes of long
random strings will return nothing however many types you index, and that
itself is informative.

**One digest may resolve to several type names.** The catalog carries
duplicate registrations — distinct entries with identical expressions — and
both verify against the same digest. That is information, not an error. Every
matching name is reported, and the histogram shows the tie.

## What it is not

It is not a replacement for running mdxfind over the list. mdxfind tries
every type against every hash and is the right tool when you want the
answer for *each* hash. This answers a cheaper question — what is this list,
as a whole — using hashes that are already on disk, and it answers it in the
time of a few thousand seeks rather than a full pass.

It is also not chained to the default index. You can have as many indexes, each with their own
set of types, as you have disk space for.
