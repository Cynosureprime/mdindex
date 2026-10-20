# Operations

Running an index that is rebuilt rarely, updated nightly, and queried
constantly.

## The shape of it

```
build     rare       hours        rewrites everything
update    nightly    seconds      writes only the overlay
compact   seldom     ~2x index    folds the overlay in
check     after      varies       verifies the invariant
lookup    constant   milliseconds reads both pieces
```

The index is in two pieces: `index.rec`, a packed sorted array, and `add.rec`,
a small sorted overlay beside it. `update` writes only the overlay, so a
night's new words cost those words rather than the index they join. A lookup
searches both and gives the same answer either way, so **nothing needs
compacting to be correct**.

## Nightly update

```sh
#!/bin/sh
# Lock, because two updates at once would both read the same watermark.
lock=$HOME/.mdindex-update.lock
mkdir "$lock" 2>/dev/null || { echo "already running"; exit 0; }
trap 'rmdir "$lock"' EXIT

exec >> "$HOME/mdindex-update-$(date +%F).log" 2>&1
echo "start $(date)"

mdindex -v update
echo "update exit=$?"

# Only the overlay can have changed, so only the overlay needs checking.
mdindex check overlay
echo "check exit=$?"

# One known digest per indexed type.  If the database is broken, this is
# what notices, and it costs six seeks.
printf '%s\n' \
  5f4dcc3b5aa765d61d8327deb882cf99 \
  696d29e0940a4957748fe3fc9efd22a3 \
  5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 \
  8846f7eaee8fb117ad06bdd830b7586c \
  2470c0c06dee42fd1618bb99005adca2ec9d1e19 \
  5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 \
  | mdindex
```

All six are the digest of `password`. If one stops answering, something has
moved that should not have.

### Use a real scheduler, not a self-requeuing chain

`at` is one-shot. A job that re-queues itself at the end of each run dies
silently the first time a run fails, and the first evidence is a stale index
nobody noticed for a week. Use cron, systemd timers or launchd — something
that fires on a calendar regardless of whether the last run succeeded.

### A scheduled job does not get your shell's limits

This bites hard. `build` and `update` open one scratch file per partition —
256 of them, plus the usual few. An interactive shell on macOS typically
allows over a million descriptors; **launchd hands a job 256**, which is one
short of enough and fails partway through a build with the index half
written.

mdindex asks for `NPART + 32` up front and names the shortfall on stderr
before any work starts, rather than discovering it a partition at a time. But
raise the limit anyway:

- launchd: `SoftResourceLimits` / `NumberOfFiles` in the plist.
- systemd: `LimitNOFILE=`.
- cron: `ulimit -S -n` in the job script.

Test it with `ulimit -S -n` from inside the scheduled environment, not from
your terminal. Note the `-S`: bare `ulimit -n` lowers the *hard* limit too,
which no process can raise back, so that form tests a different and
unfixable case.

## When to compact

When you feel like it, or when `update` says the overlay is getting large —
it prints a note past 256 MB. Every lookup binary-searches the overlay, so it
is not free, but it is a sorted array of 18-byte records and it stays cheap
for a long time. At a few hundred new records a night, years.

`compact` reads and writes the entire main index however small the overlay is.
Run it when the machine is otherwise idle.

## When to check

| after | run | cost |
|---|---|---|
| `update` | `check overlay` | milliseconds |
| `compact` or `build` | `check index` | an index-sized sequential read |
| suspicion | `check` | both |

`check overlay` nightly, `check index` after anything that rewrites the main
index. A full pass on an index an update cannot have touched is a check that
gets switched off for being slow, which is worse than not having it.

Exit 2 means a bucket is out of order or holds a duplicate key. Both have one
cause, since deduplication only ever compares adjacent records.

## The type configuration is not live state

`-C file` is read **once**, by `build`. Its contents are copied into the
manifest, and from then on the manifest is authoritative: `update` and
`lookup` never open the file, and deleting it changes nothing about a
database already built.

That is deliberate. This file decides what the database *means* — which
digests it holds — so a database whose behaviour could change because
somebody edited a file beside it would be a database you could not reason
about. There is also no search path: mdindex reads the file you name and no
other.

The manifest records a fingerprint of each type's compiled form, not just its
name. An expression that changes behind a name it kept is therefore caught
when the database is opened, reported, and refused — rather than quietly
answering with digests no current build would produce.

### A type that will not compile is a hard error

If a configured type cannot be compiled — an hx upgrade dropped a function,
an expression was edited into nonsense — mdindex does not carry on without
it.

| command | behaviour |
|---|---|
| `update` | refuses, with a definitive error |
| `lookup` | refuses |
| `info` | reports it as an ALERT and names the type |
| `check` | runs; it is structural and needs no hashing |
| `compact` | runs; it moves records and computes nothing |

`update` refusing matters most: a degraded update would write an overlay
missing one type's records and leave nothing behind to say so, and every
later lookup for that type would report absence — indistinguishable from the
word not being there.

`info` and `check` stay usable on purpose. A tool that refuses everything
when something is wrong cannot be used to find out what is wrong.

## When a rebuild is unavoidable

`update` handles appended bytes. It cannot handle:

- **A source rewritten, sorted, deduplicated or truncated in place.** Every
  stored offset into that file is now meaningless. Caught by the manifest's
  size, mtime and end fingerprints and reported as an ALERT.
- **Any change to the type set.** `update` reads the list back from the
  manifest; `-H` and `-C` are build-time inputs. Adding, removing or
  redefining a type means a rebuild, because the existing records were
  produced by the old set and nothing marks which type made which record.
- **Reordering the sources.** The order is the duplicate-resolution priority.

Adding a *new file* does not need a rebuild — `mdindex update /path/to/new`
appends it at the lowest priority. Only promoting a file above one already
indexed requires `build`.

## Keeping the rebuild script in step

If you keep a rebuild script, **both** the source list and the type selection
in it must match the manifest, the sources in the same order. A file added by `update` but missing from the script is
silently dropped by the next rebuild, and the words it contributed vanish with
no error — which reads exactly like data loss. `mdindex info` prints the
manifest; diff it against the script after any change.

## Reading the output

A lookup that finds nothing exits 0. Absence is an answer.

That cuts both ways: a hash of a type the database does not index also
produces silence, and the index cannot tell you which it was, because a record
does not record which function made it. `mdindex info` lists the types. Run it
first when a result surprises you.
