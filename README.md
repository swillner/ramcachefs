# ramcachefs

Userspace in-memory filesystem with on-demand persistance using [FUSE
(Filesystem in Userspace)](https://github.com/libfuse/).

`ramcachefs` caches a directory in memory and persists changes to the
directory and its files back to disk on demand only. Useful for
caching directories with lots of read/write operations, e.g. for
inefficient I/O processes or to protect SSDs from frequent writes to
browser caches.

## Features

- No root needed as long as FUSE is enabled on the system (unlike
  `tmpfs`)
- Caches the directory and all its files and subdirectories in place
  (i.e. no path changes for processes accessing the directory)
- Write-back of changes (file changes, type changes, creations,
  deletions, permissions, and changes to owner) on demand (calling
  `ramcachefs -p <mountpoint>`) and optionally automatically after
  unmount.

## Installation

### Prerequisites

To build `ramcachefs` you need the FUSE 3 libraries. On Debian/Ubuntu,
just install these using

```
sudo apt-get install libfuse3-dev
```

### Building

Just build the `ramcachefs` binary using

```
make
```

## Usage

Just call the `ramcachefs` binary and specify the directory to cache
as `<mountpoint>`. By default it forks to the background as a daemon,
which can be disabled using the `-f` option. Stop the caching by
unmounting the `<mountpoint>` (`umount <mountpoint`) or by terminating
the `ramcachefs` process.

Persist changes done so far back to the underlying directory on disk
(or any other filesystem to start with) calling `ramcachefs -p
<mountpoint>`. By default changes are persistet after unmount, which
can be disabled using the `-o noautopersist` option.

### Options

```
usage: ramcachefs [options] <mountpoint>

    -p   --trigger-persist trigger persist
    -h   --help            print help
    -V   --version         print version
    -d   -o debug          enable debug output (implies -f)
    -f                     foreground operation
    -s                     disable multi-threaded operation
    -o clone_fd            use separate fuse device fd for each thread
                           (may improve performance)
    -o max_idle_threads    the maximum number of idle worker threads
                           allowed (default: 10)
    -o allow_other         allow access by all users
    -o allow_root          allow access by root
    -o auto_unmount        auto unmount on process termination
    -o direct_io           always use direct_io (breaks mmap!)
    -o maxinodes=NUMBER    maximum number of inodes (default: '1000000')
    -o noautopersist       do not persist on unmount
    -o prepopulate         read full files at start (prepopulate mmaps)
    -o size=SIZE           size (default: '1G')
```

## Disclaimer

Bugs in filesystems can easily lead to data losses! Use `ramcachefs`
at your own risk. I am using it on a day-to-day basis without any
issues so far. Nevertheless, please be careful when using it for
crucial data.
