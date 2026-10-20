/*
 * mdindex_win32.h - the POSIX calls mdindex uses that Windows does not have.
 *
 * Included only under _WIN32.  Every definition here is a thin shim over the
 * Win32 call that does the same job; nothing changes behaviour on a platform
 * that already has the real thing, because nothing here is compiled there.
 *
 * $Revision: $
 * $Log: $
 */

#ifndef MDINDEX_WIN32_H
#define MDINDEX_WIN32_H
#ifdef _WIN32

#include <windows.h>
#include <io.h>
#include <direct.h>
#include <stdint.h>
#include <errno.h>

/* stat() overflows on a file past 2 GB, and mdindex's whole reason for
 * existing is files far past it -- mdfind's 32-bit offset leaves 87% of a
 * 31.8 GB wordlist unreachable.  Same fix mdxfind carries. */
#define stat  _stat64
#define fstat _fstat64

#define mkdir(p, m)  _mkdir(p)
#define realpath(p, r)  _fullpath((r), (p), PATH_MAX)

/*
 * pread: READ AT AN OFFSET WITHOUT MOVING THE FILE POINTER.
 *
 * The obvious shim is _lseeki64() then _read(), and it is WRONG here. A
 * build runs sixteen scatter threads against ONE descriptor per source
 * file, and a lookup fetches lines through a shared Srcfd[]. Seek-then-read
 * is two operations against one shared pointer: thread A seeks, thread B
 * seeks, thread A reads from B's offset. The result is not a crash -- it is
 * a correct-looking index built from the wrong bytes, which is the failure
 * this whole program is written to avoid.
 *
 * OVERLAPPED carries the offset INTO the read, so the file pointer is never
 * consulted and never moved, and concurrent calls on one handle cannot
 * interfere. That is what POSIX pread guarantees and it is the only reason
 * the callers are allowed to share a descriptor.
 */
static ssize_t mdx_pread(int fd, void *buf, size_t count, long long off)
{
    HANDLE     h = (HANDLE)_get_osfhandle(fd);
    OVERLAPPED ov;
    DWORD      got = 0;

    if (h == INVALID_HANDLE_VALUE) { errno = EBADF; return -1; }
    if (count > 0x7fffffff) count = 0x7fffffff;

    memset(&ov, 0, sizeof(ov));
    ov.Offset     = (DWORD)(off & 0xffffffffULL);
    ov.OffsetHigh = (DWORD)((unsigned long long)off >> 32);

    if (!ReadFile(h, buf, (DWORD)count, &got, &ov)) {
        /* Reading at or past end of file is not an error; it is 0 bytes,
         * which is what every caller here already tests for. */
        if (GetLastError() == ERROR_HANDLE_EOF) return 0;
        errno = EIO;
        return -1;
    }
    return (ssize_t)got;
}
#define pread(fd, buf, n, off)  mdx_pread((fd), (buf), (n), (long long)(off))

/*
 * mmap, read-only and shared, which is the only form mdindex uses: the
 * bucket directory, the record array and the overlay are all mapped
 * PROT_READ/MAP_SHARED and never written through.
 *
 * The mapping handle is closed immediately after the view is created. A
 * view keeps the section alive on its own, so there is nothing to track
 * per mapping and munmap needs only the address -- which is what lets this
 * keep the POSIX signature rather than making callers carry a handle.
 */
#define PROT_READ    1
#define MAP_SHARED   1
#define MAP_FAILED   ((void *)-1)

static void *mmap(void *addr, size_t len, int prot, int flags,
                  int fd, long long off)
{
    HANDLE h, m;
    void  *p;

    (void)addr; (void)prot; (void)flags;
    h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE) { errno = EBADF; return MAP_FAILED; }

    m = CreateFileMapping(h, NULL, PAGE_READONLY, 0, 0, NULL);
    if (m == NULL) { errno = ENOMEM; return MAP_FAILED; }

    p = MapViewOfFile(m, FILE_MAP_READ,
                      (DWORD)((unsigned long long)off >> 32),
                      (DWORD)(off & 0xffffffffULL), len);
    CloseHandle(m);
    if (p == NULL) { errno = ENOMEM; return MAP_FAILED; }
    return p;
}

static int munmap(void *addr, size_t len)
{
    (void)len;
    return UnmapViewOfFile(addr) ? 0 : -1;
}

/*
 * statvfs, for the one field the build-cost projection reads: how many
 * bytes are free on the database filesystem. GetDiskFreeSpaceEx reports
 * the caller's quota-adjusted free space, which is the figure a build
 * actually gets to use.
 */
struct statvfs {
    unsigned long long f_bavail;   /* blocks available, see f_frsize */
    unsigned long long f_frsize;   /* 1, so f_bavail is already bytes */
};

static int statvfs(const char *path, struct statvfs *out)
{
    ULARGE_INTEGER avail, total, free_total;

    if (!GetDiskFreeSpaceExA(path, &avail, &total, &free_total)) {
        errno = ENOENT;
        return -1;
    }
    out->f_bavail = (unsigned long long)avail.QuadPart;
    out->f_frsize = 1;
    return 0;
}

/* One per online core, the same number sysconf reports. */
#define _SC_NPROCESSORS_ONLN 1
static long sysconf(int name)
{
    SYSTEM_INFO si;
    (void)name;
    GetSystemInfo(&si);
    return (long)si.dwNumberOfProcessors;
}

/* Only ever called to pace the progress poller, so millisecond rounding
 * is immaterial; the shortest interval mdindex asks for is 250 ms. */
struct timespec_win { long tv_sec; long tv_nsec; };
static int nanosleep_win(const struct timespec *ts, void *rem)
{
    (void)rem;
    Sleep((DWORD)(ts->tv_sec * 1000 + ts->tv_nsec / 1000000));
    return 0;
}
#define nanosleep(ts, rem)  nanosleep_win((ts), (rem))

/*
 * open: with POSIX sharing semantics.
 *
 * The CRT's _open shares reads and writes but NOT deletes, so a file that
 * is merely open cannot be renamed over or unlinked. On POSIX an open
 * descriptor never blocks either, and mdindex relies on that: compact
 * reads the old index.rec through an open fd while renaming the newly
 * built index.rec.new over it, which is the whole shape of "write to .new
 * and rename last".
 *
 * FILE_SHARE_DELETE restores the POSIX behaviour. Without it compact dies
 * with "rename index.rec: Permission denied" after doing all the work.
 */
static int mdx_open(const char *path, int flags, ...)
{
    DWORD  access, disp;
    HANDLE h;
    int    fd;

    access = (flags & (_O_WRONLY | _O_RDWR)) ? (GENERIC_READ | GENERIC_WRITE)
                                             : GENERIC_READ;
    if (flags & _O_CREAT)
        disp = (flags & _O_TRUNC) ? CREATE_ALWAYS : OPEN_ALWAYS;
    else
        disp = (flags & _O_TRUNC) ? TRUNCATE_EXISTING : OPEN_EXISTING;

    h = CreateFileA(path, access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, disp, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        errno = (GetLastError() == ERROR_FILE_NOT_FOUND) ? ENOENT : EACCES;
        return -1;
    }
    /* Carry the mode flags onto the descriptor. _O_BINARY above all:
     * _open_osfhandle defaults to TEXT mode, which translates CRLF and
     * stops at 0x1A, and every file here is binary -- including the
     * index itself, where a translated byte is a corrupted record. */
    fd = _open_osfhandle((intptr_t)h,
                         (flags & (_O_BINARY | _O_TEXT | _O_APPEND)) |
                         ((flags & (_O_WRONLY | _O_RDWR)) ? 0 : _O_RDONLY));
    if (fd < 0) { CloseHandle(h); errno = EMFILE; return -1; }
    return fd;
}
#define open(p, ...)  mdx_open((p), __VA_ARGS__)

/*
 * rename: POSIX rename() atomically REPLACES an existing destination.
 * Windows rename() fails with EEXIST instead, which breaks the one
 * guarantee mdindex depends on everywhere it writes: build, update and
 * compact all write to a .new file and rename last, precisely so that a
 * torn file cannot be mistaken for a good one.
 *
 * The naive shim -- remove(dst) then rename(src, dst) -- would compile and
 * appear to work while DESTROYING that guarantee: between the two calls
 * there is no manifest, no index.rec, no add.rec at all, and a crash in
 * that window leaves a database with a missing file rather than an old
 * one. MoveFileEx with MOVEFILE_REPLACE_EXISTING is the atomic form on a
 * single volume, which is where these renames always happen -- the .new
 * file is created in the database directory beside its target.
 */
static int mdx_rename(const char *from, const char *to)
{
    if (MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING)) return 0;
    errno = EACCES;
    return -1;
}
#define rename(f, t)  mdx_rename((f), (t))

/*
 * mkdtemp: used by the selftest, which builds a throwaway database. The
 * CRT has _mktemp_s, which only rewrites the template -- it does not
 * create the directory and does not guarantee the name is still free when
 * you get there. Loop until _mkdir actually succeeds, so the directory
 * this returns is one we created rather than one we hope is ours.
 */
static char *mkdtemp(char *tmpl)
{
    static const char set[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    size_t len = strlen(tmpl);
    int    tries;

    if (len < 6 || strcmp(tmpl + len - 6, "XXXXXX") != 0) {
        errno = EINVAL;
        return NULL;
    }
    for (tries = 0; tries < 256; tries++) {
        int i;
        for (i = 0; i < 6; i++)
            tmpl[len - 6 + i] = set[(rand() ^ (GetTickCount() >> i)) % 36];
        if (_mkdir(tmpl) == 0) return tmpl;
        if (errno != EEXIST) return NULL;
    }
    errno = EEXIST;
    return NULL;
}

#ifndef strtok_r
#define strtok_r strtok_s
#endif
#ifndef strcasecmp
#define strcasecmp  _stricmp
#endif
#ifndef strncasecmp
#define strncasecmp _strnicmp
#endif

#endif /* _WIN32 */
#endif /* MDINDEX_WIN32_H */
