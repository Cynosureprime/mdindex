 # mdindex

mdindex is an extension of an idea started more than a decade ago, of a program
to look up common words by hash - the first checkin was 2013.01.09.20.35.13.

### The problem

Often, when resolving a new hash list, many "intermediate hashes", or hashes-of-hashes appear, because
many wordlists contain common hashes.  Sometimes, this can be your only way to finding out what kinds of
hashes are present.  The classic example:

```
MD5x01 cfcc929fc79d0882d37cfd8811ad413b:5f4dcc3b5aa765d61d8327deb882cf99KaK
```

might appear as a solution to a new hash list.  In fact, that's a md5(md5(pass).salt) (Hashcat 2611, or mdxfind e31)
hash.  But what does that 5f4dcc3b5aa765d61d8327deb882cf99 represent?  mdindex is the fast way to look up small
numbers of hashes.

```
echo 5f4dcc3b5aa765d61d8327deb882cf99 | mdindex
MD5x01 5f4dcc3b5aa765d61d8327deb882cf99:password
1 hit for 1 of 1 hashes, lookup time 0.000s, 0.000126s per hash (7.94K lookups/sec)

echo cfcc929fc79d0882d37cfd8811ad413b:KaK:password | hashpipe
MD5SALT cfcc929fc79d0882d37cfd8811ad413b:KaK:password
```

mdindex can quickly resolve this. But mdindex does not solve for just one hash type.  
You can index almost any kind of unsalted hash - and you can index as many hash algorithms as you like.
Virtually all Hashcat, mdxfind and John hash types are supported,
and you can also use hx to generate custom types.  In the following example, I have md5(pass), md5(md5(pass)),
sha1(pass),sha256(pass),ntlm(pass), and sql5(pass) indexed.

```
echo '5f4dcc3b5aa765d61d8327deb882cf99
696d29e0940a4957748fe3fc9efd22a3
5baa61e4c9b93f3f0682250b6cf8331b
5e884898da28047151d0e56f8dc62927
2470c0c06dee42fd1618bb99005adca2
8846f7eaee8fb117ad06bdd830b7586c' | mdindex

MD5x01 5f4dcc3b5aa765d61d8327deb882cf99:password
MD5x02 696d29e0940a4957748fe3fc9efd22a3:password
SHA256x01 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8:password
NTLMx01 8846f7eaee8fb117ad06bdd830b7586c:password
SQL5x01 2470c0c06dee42fd1618bb99005adca2ec9d1e19:password
SHA1x01 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8:password
6 hits for 6 of 6 hashes, lookup time 0.000s, 0.000031s per hash (31.91K lookups/sec)
```

Output is the [mdxfind](https://github.com/Cynosureprime/mdxfind) shape,
`TYPE hash:plain`, so a line pipes straight into
[hashpipe](https://github.com/Cynosureprime/hashpipe):

```
$ printf password | md5 | mdindex
MD5x01 5f4dcc3b5aa765d61d8327deb882cf99:password
```

### When to use it

- **A handful of hashes, right now.** A lookup is a seek, not a scan. Tens of
  thousands of hashes resolve in the time a linear pass would take to start.
- **Many small jobs.** mdxfind is built to drive one enormous wordlist past
  one enormous hash list. The opposite shape — a great many small hash lists,
  each wanting an answer now — is what this is for.
- **You do not know the type.** A record does not record which function
  produced it. Every configured digest is regenerated from the line and
  compared, so the answer arrives labelled.
- **You only have part of the hash.** The stored key is 24 hex characters,
  and 16 still resolves about one candidate. Shorter works too; it just
  matches more.

### When not to

- **Salted types.** Out of scope, permanently — see [Why no salts](#why-no-salts).
- **One huge hash list against one huge wordlist.** That is mdxfind's shape,
  and past a few tens of thousands of hashes a linear pass over the sources
  moves fewer bytes than the index does. See [docs/SIZING.md](docs/SIZING.md).
- **Rules, masks, or keyspace enumeration.** The index holds words that exist
  in a file. It cannot invent one.

## Build

```
make mdindex
```

Needs OpenSSL (`libcrypto`) and pthreads, the hx expression engine, and the
hash libraries it draws on — libsph, libmhash, librhash and gosthash — which
are the same set [mdxfind](https://github.com/Cynosureprime/mdxfind) links.
`qsort_mt.c` and `ruleproc32.c` build alongside it.

mdindex does not implement any hash itself. Every digest is computed by the
same code the rest of the suite uses, so a type cannot mean one thing here
and another in mdxfind or hashpipe.

```
mdindex selftest
```

checks every digest against a published vector or against what mdxfind
prints, checks both encoding wrappers, then builds a small index in a
temporary directory and checks priority, partial lookup, the NTLM readings,
the overlay, compaction, sort order and staleness detection end to end. It
touches nothing else.

## Usage

```
mdindex [-d dir] [-t threads] [-C file] [-H types] [-i depth] [-vy]
        build file [file ...]
mdindex [-d dir] [-t threads] [-v] update [newfile ...]
mdindex [-d dir] [-v] [lookup] [hash ...]
mdindex [-d dir] info
mdindex [-d dir] [-t threads] [-v] compact
mdindex [-d dir] [-v] check [index|overlay|all]
mdindex selftest
```

`lookup` is the default. With no arguments, hashes are read from standard
input, so `md5 <<<word | mdindex` works. Counts and timings go to standard
error, so standard output carries solutions or nothing and is safe to pipe.

### Commands

**`build file ...`** — Build from scratch, discarding any existing index.
**Arguments are in priority order:** when the same word appears in more than
one file, the record kept is the one from the file named earliest. That order
is recorded and every later `update` honours it.

Before it writes anything, `build` projects what the build will cost and
**refuses if the projected peak exceeds a tenth of the free space** on the
database filesystem — the one place mdindex refuses rather than reports.
`-y` proceeds.

```
projection  10,001 lines x 4892.09 records/line = 48,925,829 records
            scratch 839.9 MB, new index 699.9 MB, peak 1.5 GB; 1012.0 MB free
```

Lines are counted with mdxfind's SIMD newline scan over the unindexed tail
only, and shared with mdxfind through its line cache when `MDXFIND_CACHE` is
set. Records per line is *observed* from a sample of the real input, not
assumed. See [docs/SIZING.md](docs/SIZING.md).

**`update [newfile ...]`** — Re-read each indexed file from the byte offset
where the last build or update stopped, and hash only what was appended. A
file named on the `update` line is *added*, at the end of the manifest and so
at the lowest priority.

`update` does not rewrite the main index. New records go to an overlay beside
it, which lookup searches as well, so absorbing a day of new words costs those
words and not the index they join.

**`lookup [hash ...]`** — Print `TYPE hash:plain` for every match. Nothing is
printed for a hash that is absent; an absent hash is an answer, not an error.

**`compact`** — Fold the overlay into the main index. The only command that
rewrites it, and it reads and writes all of it, so it costs twice the index in
I/O however small the overlay is. **Nothing needs compacting to be correct** —
a lookup searches both files and gives the same answer either way.

**`check [index|overlay|all]`** — Verify that each bucket is strictly
increasing on the stored key. A descending pair is a sort failure; an equal
pair is a duplicate that deduplication should have dropped. `check overlay` is
instant and is the one worth running after an update, which cannot have
changed the main index. Exit 2 means a fault was found.

**`info`** — Record and bucket counts, key width, hash types, and the
manifest. Also runs the source checks and reports any ALERT.

### Options

**`-d dir`** — Database directory. Default `/usr/local/share/mdfind`, and the way to keep more than one index. See
[Several indexes](#several-indexes).

**`-t threads`** — Workers for build and update. Default: one per core.

**`-H types`** — Comma-separated hash types to index. Build only. See
[Choosing hash types](#choosing-hash-types).

**`-i depth`** — Index iterations 1 to *depth* of every selected type, as
mdxfind's `-i` does. Build only, default 1. mdxfind iterates a type by
applying its **outermost** function again to the previous round's output,
re-rendered as hex in that type's own case convention — so iteration 2 of
`md5(sha1(pass))` is `md5(md5(sha1(pass)))`, not `md5(sha1(md5(sha1(pass))))`.
Depth is counted in the `xNN` of the type name rather than from the type's
own first round, so a chain whose first real iteration is `x02` yields
`x02` and `x03` at `-i 3`. Each extra depth multiplies the record count.
An iterated type is a different digest, not a different label: a hash of
`md5(md5(pass))` is invisible to an index built only at depth 1.

**`-C file`** — Stanza file of user-defined hash types, in the format mdxfind
reads as `userdef.txt`. Build only. The file is named outright — there is no
search path, no default location, and `MDXFIND_CACHE` is not consulted. See
[User-defined types](#user-defined-types).

**`-V`** — Print the version and exit.

**`-y`** — Proceed past the projection's refusal. `build` prints what it will
cost and exits without writing if the projected peak exceeds a tenth of the
free space on the database filesystem; this says you know. The projection is
still printed.

**`-v`** — Progress during build and update, and a per-phase timing breakdown
during lookup: sort, index probe or scan, fetch and verify, and the number of
digests regenerated.

Progress is a percentage in the three phases that can run long — the per-source
scatter, the 256-partition emit, and an `update`'s probe of the index, which is
one random seek per new word and the slow half of a nightly run.

There is **no progress indicator during `lookup`**, by design rather than by
omission. Its standard output carries solutions and is meant to be piped; its
standard error carries the counts that go with them. A progress line in the
middle of that is noise to a pipeline that has no use for it.

The type set is recorded in the manifest, and **`update` reads it back from
there**, so a new type only ever enters through a full `build`. Neither
`update` nor `lookup` reads `-C`.

## The index is deliberately lossy

A record stores **96 bits** of the digest, not all of it, and does not record
which hash function produced it. Both are recovered rather than stored: a hit
is answered by reading the line, regenerating every configured digest of it,
and comparing against the whole hash you supplied.

So the index is only a filter, and the verification is exact. **A key collision
costs one wasted read and prints nothing — it cannot produce a wrong answer.**
This is also why adding a hash type costs a table entry and a rebuild rather
than a format change.

### Partial hashes

Because the supplied hash is checked in full after the line is read, a partial
hash is a perfectly good query. A query of *q* bits selects a contiguous run of
buckets and, inside them, a contiguous run of records:

```
24 hex characters  exactly the stored key, about one candidate
16 hex characters  about one candidate
12 hex characters  about one candidate
 6 hex characters  one bucket, about 900
 4 hex characters  256 buckets, about 230,000
 2 hex characters  a 256th of the index, about 59 million
 1 hex character   a 16th of the index, about 943 million
```

(counts against a 15.1-billion-record index)

The last two lines are why a very short query is accepted only as an argument
or from a terminal: each candidate costs a seek into a source file, so one
stray one-character line in a piped list asks for more reads than the rest of
the list together, and the run looks like a hang. From a pipe, a line that is
not hex, or is shorter than the shortest digest in the database, is skipped
without comment and counted — a mixed file carrying salts, plaintexts or blank
lines can be fed in as it stands.

Every match is printed, with the full digest rather than the fragment you
asked with. A short query against a multi-type index therefore returns hits of
several different types, which is correct: those digits really are the start
of each of those digests.

## Choosing hash types

The type set is yours to choose. It is recorded in the manifest at build time,
and every later `update` honours it.

### What can be indexed

An index maps a digest to a position, so it can hold a type **whose digest is
a function of the word alone**. mdxfind's own type table already declares
which those are — each type records what must be handed to it — and mdindex
takes that declaration as the eligibility rule:

| flag | needs | indexable |
|---|---|---|
| `f` | nothing but the password | **yes** |
| `F` | a structured stored form (bcrypt and family) | no |
| `s` | a salt | no |
| `u` | a userid | no |
| `j` | a pepper | no |

A type marked `f` and nothing else qualifies. That is **620 of the 1,061**
types in the catalog, of which **551** also carry an hx expression this
build can compile, prove, and distinguish from a type it already holds —
those are what `-H all` selects. Twelve of them enumerate their own
domain: the five HEXSALT types cost 768 records per word, and the seven
HUM types 16. With `-i 2` the
selection becomes **1,088** types: 550 at `x01`, 538 at `x02` — every one at
both iterations bar the twelve enumerated families, which are not iterated —
plus `MD5RAWUCx02`, whose first round is `x02` and which has no `x01`.

**A digest narrower than the key is refused**, explicitly or through `all`.
The scatter copies 12 bytes out of every digest, so a shorter one is read
past into whatever followed it in memory: the keys would not reproduce
between builds, and the type would simply stop being found after a rebuild
with nothing saying why. Three catalog types are eight bytes and fall under
this — `MYSQL3`, `MURMUR64A` and `MURMUR64AZERO`. That width is also why they
would match things they are not: 64 bits of digest against an index keyed on
96. A type that *nests* one of them is unaffected and is indexed, because
`md5(mysql3(pass))` is an ordinary 16-byte MD5. Everything else is
refused at build time, by predicate rather than by a maintained
list, so a type whose declaration is corrected becomes eligible on the next
build with nothing to edit.

Note what this does *not* exclude. A type that enumerates its own salt
domain — `MD5HEXSALT` and family try all 256 two-character salts themselves,
over three shapes each — needs nothing supplied and is perfectly indexable.
It costs **768 records per word** rather than one, which is your choice to
make and not the tool's. The salt that matched is reported in the output
line, because nothing could re-verify it otherwise:

```
SHA1HEXSALTx01 476649c6a099a8173dee369a46d88c9ddba127dd:0a:098765
```

### Naming a type

Six namespaces, disjoint by grammar, so nothing has to be tried in turn:

```
e<digits>      mdxfind catalog type        e259
u<digits>      a type defined in -C        u47
dynamic_<N>    john(1) built-in format     dynamic_2
<digits>       hashcat mode                300
all            every indexable catalog type
anything else  canonical name              SQL5x01
```

A trailing `:N` selects mdxfind's iteration *N*; the default is 1. A John
label already names one — `dynamic_2` is `MD5x02` — so the two may not be
combined.

```
mdindex -H md5,sha1,ntlm build words.txt
mdindex -H e1,e8,300,md5:2,dynamic_2 build words.txt
```

Of the **132** portable John labels, **96** are indexable and 36 are refused
for the ordinary reason — a salt or a userid they cannot supply. Only the
portable table is consulted: John's config-defined dynamics are numbered per
machine, so selecting through them would mean one `-H` line naming different
types on two hosts.

### User-defined types

`-C` names a stanza file of your own hash types, in the format mdxfind reads
as `userdef.txt`. Both tools share the loader, so one file and one `id`
select the same type in either.

```ini
[Cust1]
id = 47
hx = sha1(md5(pass)."register")
```

```
mdindex -C mytypes.txt -H u47 build words.txt
mdxfind  -m u47 -f hashes.txt words.txt        # MDXFIND_CACHE/userdef.txt
```

An hx expression does not go on the command line — commas, parentheses,
quotes and `$` make a shell a poor place for one — so it goes here. You are
not limited to the catalog: anything expressible in
[hx](https://github.com/Cynosureprime/hx) that depends only on the password
can be indexed, under a name you choose. The hx manual is the reference for
what an expression may contain.

**The file is named outright.** No search path, no default location,
`MDXFIND_CACHE` not consulted. That is deliberate, because this file decides
what an index *means*: a type built from it goes into the index under its own
name, and a different file answering to that name later would reinterpret
records already on disk.

**So the expression is copied into the manifest, and `-C` is needed to build
and never to read.** Lookup, update, info and compact all take their types
from the manifest. A `-C` file that has since changed, or been deleted,
cannot alter what the database holds:

```
$ mdindex -d db -C mytypes.txt -H u47 build words.txt
$ sed -i 's/"register"/"TAMPERED"/' mytypes.txt     # change it underneath
$ rm mytypes.txt                                    # or delete it outright
$ echo 0432c806f0f6f00b83a4e91c327cdbf9ed459804 | mdindex -d db
USER_Cust1x01 0432c806f0f6f00b83a4e91c327cdbf9ed459804:monkey
```

`info` names the file and `id` a type came from, so a database stays
self-describing after the file is gone:

```
user       USER_Cust1x01  id 47  from /u/dlr/mytypes.txt
             sha1(md5(pass)."register")
```

Two things differ from a catalog type.

**A salt is refused permanently, not provisionally.** An expression naming
`salt`, `salt2`, `userid` or `pepper` cannot be indexed, same as a catalog
type — but the reasons differ and the messages say so. The catalog's HEXSALT
family supplies its own salt from an mdxfind arm that enumerates it, so that
refusal is waiting on the enumeration. A user type has no arm, so its salt
can only come from outside, and no amount of work here recovers it.

**Iteration runs the other way.** A catalog type repeats its **outermost**
call over the previous round's digest. A user type has no mdxfind arm, so
mdxfind's generic loop re-runs the **whole** expression with `pass` bound to
the previous digest, and mdindex builds that form:

```
u47 at x01   sha1(md5(pass)."register")
u47 at x02   sha1(md5(sha1(md5(pass)."register"))."register")
```

not `sha1(sha1(md5(pass)."register"))`, which is what the catalog rule would
give. A user expression that never names `pass`, or that carries a prelude of
its own, is left at depth 1 rather than guessed at.

### The default six

With no `-H` and no `-C`:

| type | computation | hashcat |
|---|---|---|
| `MD5x01` | `md5(pass)` | 0 |
| `MD5x02` | `md5(md5(pass))`, inner consumed as 32 hex characters | 2600 |
| `SHA1x01` | `sha1(pass)` | 100 |
| `SHA256x01` | `sha256(pass)` | 1400 |
| `NTLMx01` | `md4(utf16le(pass))` | 1000 |
| `SQL5x01` | `sha1(sha1_bin(pass))`, inner consumed as 20 **raw bytes** | 300 |

Note the contrast between `MD5x02` and `SQL5x01`: one consumes hex, the other
raw bytes. Getting either backwards builds an index that passes its own
self-test and never matches anything the suite emits.

### Every type costs records

A type is not free: it multiplies the record count, and therefore the index,
the scratch space and the build time. Six types give about 3.6 records per
source line after deduplication. Fifty give about thirty.

`build` measures this before it commits — it counts the input, observes the
real expansion over the first few thousand lines, and prints the projected
records, index size, scratch and wall clock. If the projected peak exceeds a
tenth of the free space it stops and says so; `-y` proceeds. See
[docs/SIZING.md](docs/SIZING.md).

MySQL displays a SQL5 hash with a leading `*`, which is not part of the digest.
Neither mdxfind nor mdindex loads that form — strip it first.

**NTLM is read up to three ways**, as mdxfind reads it. Windows mapped the
user's code page into UTF-16LE through its own tables rather than
zero-extending, so a word is indexed as UTF-8, as CP1251 and as CP1252. An
all-ASCII word collapses to one reading; a word that is not well-formed UTF-8
loses the UTF-8 reading and keeps the other two. For the code-page readings the
reported plaintext is the UTF-8 spelling of the codepoints that were actually
hashed, which is *not* the bytes in the wordlist — the same thing mdxfind
reports, and the only form that re-verifies.

## Several indexes

`-d` selects the database directory, and everything an index needs lives
inside it — manifest, directory, records, overlay. So you can keep more than
one, with different wordlists and different type sets, and nothing is shared
between them.

That is worth more than it sounds, because a second index can answer a
different question. The default index is wide in words and narrow in types:
billions of lines, six hashes. Invert it — a *small* wordlist against *every*
type you can index — and the same code tells you **what kind of hash you are
looking at**.

```
mdindex -d ~/.mdindex/ident -i 2 -H all build 10kpass.txt
mdindex -d ~/.mdindex/ident < unknown.hashes | awk '{print $1}' \
    | sort | uniq -c | sort -rn | head
```

The modal type names the list. There is no identification mode and none is
needed: every line mdindex emits carries the type that produced it, so with
1,088 types in the manifest a hit *is* an identification.

It is cheap because the type dimension is nearly free and the word dimension
is what costs. Ten thousand words against 1,088 types is 884 MB and 13.9
seconds to build, against 226 GB for the default index, and it scales
linearly in words. Querying it with 53.2 million hashes identified **27,067**
of them under **238** distinct type names. The catch is that
salted types cannot be indexed at all, so a salted list is not identifiable
this way, and it will return zero hits that look exactly like a wordlist miss.
See [docs/IDENTIFYING.md](docs/IDENTIFYING.md).

## Reading hashes in

A query line may carry a non-hex lead-in. A [john(1)](https://github.com/openwall/john)
hash names its format in front of the digest, and sometimes a login in front
of that — both are read:

```
$ D=000c285457fc971f862a79b786476c78812c8897063c6fa9c045f579a3b2d63f
$ printf '$dynamic_60$%s\nalice:$dynamic_60$%s\n' $D $D | mdindex
SHA256x01 000c285457fc971f862a79b786476c78812c8897063c6fa9c045f579a3b2d63f:monkey
SHA256x01 000c285457fc971f862a79b786476c78812c8897063c6fa9c045f579a3b2d63f:monkey
```

**The tag is skipped, not believed.** mdindex reads past it to the digest
and never asks what it claimed: the type comes from re-hashing the word it
found, so a line labelled `$dynamic_60$` carrying an MD5 is answered
`MD5x01`, and a mislabelled list costs nothing. That is also why a digest
with several true names returns all of them here, exactly as it does for a
bare hash.

The digest begins after the second `$` in every such form, whatever precedes
the first, so that is where mdindex resumes — and only when the lead-in was
the reason the line did not parse, so a line that already read as a digest is
never re-read as something else.

A **trailing** field is left attached on purpose. In a John line it is the
salt, and a salted digest is not something this index holds; leaving it makes
the line fail the hex test and be **counted among the ignored**, rather than
looked up as though it were unsalted and reported as an ordinary miss:

```
$ printf '$dynamic_1$5f4dcc3b5aa765d61d8327deb882cf99$SALT\n' | mdindex
0 hits for 0 of 0 hashes
1 input line ignored: not 16 to 128 hex characters
```

## Encoding wrappers

`$HEX[...]` and `$TESTVEC[HH x N]` are ways of *writing* a word, not decoration
on one, so the digest indexed for a wrapped line is the digest of the bytes the
line **denotes**, never of its literal text. A malformed wrapper is not an
error: it is hashed literally, exactly as mdxfind and hashpipe treat it. On
output a line stored wrapped is reported wrapped, because that is the spelling
the file holds and it already round-trips.

```
$ mdindex 7f11a7875a8f7bd91f27b68878dd39dc | hashpipe
MD5x01 7f11a7875a8f7bd91f27b68878dd39dc:$TESTVEC[41 x 200000]
```

## Priority and duplicates

A digest is stored once. When the same word appears in more than one source
file, the record kept is the one from the file that came **earliest on the
build command line**. Within a file, the first occurrence wins. A word
re-appearing in an updated file adds nothing.

This is why the source order is part of the database and not a detail of how it
was made: put your most trustworthy or best-spelled list first.

## Sources may only grow

Before reading, each source is checked against the size, mtime and the MD5s of
the first and last megabyte of the indexed region recorded in the manifest.
Appending changes neither fingerprint. Truncating, rewriting, sorting or
deduplicating in place changes at least one, is reported as an ALERT naming the
file and what moved, and forces a full `build` — because every stored offset
into that file is now meaningless.

A lookup runs the same check, and re-hashes every line it fetches before
printing it. A source rewritten between update and lookup is caught rather than
answered from whatever bytes now sit at the offset.

## Limits

```
source files                    2,048
bytes per source file           137 GB      (37-bit offset)
longest line                    262,144     longer is dropped and counted
$HEX[] decoded                  131,136
$TESTVEC[] expanded             2,097,152
```

A line past the cap is **dropped, not fatal** — one malformed record in a four
billion line source should not end a multi-hour build. Dropped lines are
counted and the total is printed per source file, because a word that was
skipped cannot be told at lookup time from one the index never held.

Everything on disk is big-endian, so a database is portable between hosts.

## Why no salts

The index maps a digest to a position, and that works only because the digest
is a function of the word alone. A salt arrives with the hashes you are trying
to crack, at lookup time, long after the index was built — so there is nothing
to index.

Committing to a salt set in advance does not rescue it: one type with a
thousand salts over four billion lines is four trillion records, and it still
cannot answer for salt number 1,001. mdxfind iterates candidates against salts
at crack time with constant memory, and a new salt costs nothing. That is not
mdindex being worse at salts; it is the two tools having different jobs.

Two exceptions that are not exceptions:

- A **site-wide constant** key is a salt of cardinality one, which is simply
  part of the word. Write it into the expression — `md5('sitekey' . pass)` —
  and it indexes like any unsalted type.
- A type that **enumerates its own salt domain** supplies nothing from
  outside. `MD5HEXSALT` and its family try all 256 two-character salts
  themselves, over three shapes each, so every digest they can produce is
  still a function of the word. Indexable, at 768 records per word — and
  worth it: on a 53-million-hash corpus that family alone identified 1,872
  hashes no other indexed type could name.

The line is not "does the word salt appear" but "must something be handed in
at crack time". The type table answers that, and the build enforces it — see
[Choosing hash types](#choosing-hash-types).

## Files

| file | contents |
|---|---|
| `manifest` | Tab-separated text, the only human-readable file: version, hash-type list, then one row per source giving index, bytes consumed, size, mtime, line count and the head and tail fingerprints. |
| `index.dir` | Bucket directory, 16,777,217 big-endian 64-bit offsets into `index.rec`, one per bucket plus a terminator. |
| `index.rec` | The records, 15 bytes each, sorted by key: 9 bytes of digest residue then a 48-bit locator packing an 11-bit file index and a 37-bit offset. The other 24 bits of the 96-bit key are implied by the bucket. |
| `add.rec` | The overlay: records added since the last build or compact, 18 bytes each — the whole 96-bit key, then the same locator — sorted, binary-searched, no directory of its own. |
| `part/` | Scratch partitions, present only while a build or update runs. Left behind means the run died; safe to delete. |

**Anything that reads `index.rec` must take the record width from the same
source the writer does.** A reader carrying its own copy of the constant
reports every bucket unsorted the first time the format widens, which looks
exactly like total corruption and is not.

**Expect `index.rec` to be larger than the wordlists it indexes** — see
[docs/SIZING.md](docs/SIZING.md). A record is 15 bytes whatever the word costs,
and a line leaves about 3.6 of them after deduplication, so a 13-byte line
occupies some 55 bytes of index.

The database is worth excluding from backups; it is large and entirely derived.
On macOS:

```
sudo tmutil addexclusion -p /usr/local/share/mdfind
touch /usr/local/share/mdfind/.metadata_never_index
```

## Exit status

| code | meaning |
|---|---|
| 0 | Success, including a lookup that found nothing. |
| 1 | Fatal: a source is missing or rewritten, the database is unreadable or of the wrong version, a configured type will not compile, the projected peak exceeds a tenth of the free space without `-y`, or an argument is wrong. |
| 2 | A candidate failed its re-hash check, or `check` found a bucket out of order or a duplicate key. The index no longer matches a source, or no longer matches itself. |

## Further reading

- **[docs/SIZING.md](docs/SIZING.md)** — how much disk and how much time, with
  measured figures; why the index is four times its sources; where the
  crossover against a linear mdxfind run falls.
- **[docs/OPERATIONS.md](docs/OPERATIONS.md)** — running it: the nightly update
  pattern, when to compact, what to check and when, and what a scheduled job
  needs that an interactive shell gives you for free.
- **[docs/IDENTIFYING.md](docs/IDENTIFYING.md)** — using a second, small
  index over every indexable type to identify an unknown hash list; what it
  costs, and the four things it cannot tell you.
- **[docs/DESIGN.md](docs/DESIGN.md)** — the record layout, the two-piece
  index, the two-way merge, and the invariants `check` exists to test.
- **[mdindex(1)](man/man1/mdindex.1)** — the manual page.

## See also

[mdxfind](https://github.com/Cynosureprime/mdxfind) ·
[hashpipe](https://github.com/Cynosureprime/hashpipe) ·
[hx](https://github.com/Cynosureprime/hx)

## Author

Waffle.

## License

MIT — see [LICENSE](LICENSE).
