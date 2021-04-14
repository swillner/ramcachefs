/*
  MIT License

  Copyright (c) 2021 Sven Willner <sven.willner@yfx.de>

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/

#define _GNU_SOURCE
#define FUSE_USE_VERSION 34

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fuse_lowlevel.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <unistd.h>
#ifndef DONT_USE_MMAP
#include <sys/mman.h>
#endif

typedef char __assert_ino_t_large_enough[sizeof(fuse_ino_t) >= sizeof(uintptr_t) ? 1 : -1]; /* fuse_ino_t needs to hold a pointer */

#ifdef DEBUG
#define debug(...) fuse_log(FUSE_LOG_DEBUG, __VA_ARGS__)
#else
#define debug(...)
#endif

static const double RAMCACHEFS_TIMEOUT = 86400.0;

enum {
    RAMCACHEFS_TRIGGER_PERSIST = _IO('E', 0),
};

struct ramcachefs_inode {
    /* the following are all protected by data->node_mutex: */

    uint64_t nlookup;

    struct ramcachefs_inode* parent;
    struct ramcachefs_inode* prev;
    struct ramcachefs_inode* next;
    struct ramcachefs_inode* first_child;
    struct ramcachefs_inode* last_child;
    struct ramcachefs_inode* origin;        /* which original file is represented by this content+info */
    struct ramcachefs_inode* orig_moved_to; /* where the original content+info of orig_name has been moved to */
    /* ALWAYS inode->origin->orig_moved_to == inode && inode->orig_moved_to->origin == inode */

    char* orig_name; /* NULL if only in memory yet */
    char* name;      /* NULL if orig_name was deleted or moved to orig_moved_to */

    /* the following do not need to be protected: */

    fuse_ino_t ino; /* does not change */

    off_t dir_offset; /* offset in parent dir */
    size_t size;      /* size of content (or strlen(content) for links) */
    void* content;    /* file content or (null-terminated) link target */

    struct timespec times[2]; /* as for utimensat: 0: atime, 1: mtime */

    uid_t uid;
    gid_t gid;
    mode_t mode;
    dev_t dev;

    unsigned int changed_content : 1;
    unsigned int changed_mode : 1;
    unsigned int changed_name : 1;
    unsigned int changed_owner : 1;
    unsigned int changed_time : 1;
#ifndef DONT_USE_MMAP
    unsigned int file_backed : 1; /* mmap is still backed by file */
#endif
};

struct ramcachefs_data {
    struct ramcachefs_inode* root;

    int prepopulate;

    int orig_root_fd;
    int opendir_result;

    unsigned long block_size;
    fsblkcnt_t max_blocks;
    fsfilcnt_t max_inodes;
    fsblkcnt_t free_blocks; /* protected by node_mutex */
    fsfilcnt_t free_inodes; /* protected by node_mutex */

    int writers;                   /* number of current writing threads, protected by writers_mutex */
    pthread_mutex_t writers_mutex; /* protects writers (number of current writing threads */
    pthread_mutex_t persist_mutex; /* looks writing operations while persisting is in progress */
    pthread_mutex_t node_mutex;    /* protects members in ramcachefs_inode that are accessible "from the outside", e.g. from their parent directory */

#ifdef DEBUG
    int debug;
#endif
};

struct ramcachefs_file_info {
    size_t max_written;
    int orig_flags;
};

struct ramcachefs_opts {
    char* size;
    int noautopersist;
    int prepopulate;
    int trigger_persist;
    unsigned long max_inodes;
};

static const struct fuse_opt ramcachefs_opts[] = {
    {"--trigger-persist", offsetof(struct ramcachefs_opts, trigger_persist), 1},
    {"-p", offsetof(struct ramcachefs_opts, trigger_persist), 1},
    {"maxinodes=%u", offsetof(struct ramcachefs_opts, max_inodes), 1},
    {"noautopersist", offsetof(struct ramcachefs_opts, noautopersist), 1},
    {"prepopulate", offsetof(struct ramcachefs_opts, prepopulate), 1},
    {"size=%s", offsetof(struct ramcachefs_opts, size), 1},
    FUSE_OPT_END  //
};

#ifdef DEBUG
static void print_inode_simple(const char* prefix, struct ramcachefs_inode* inode) {
    if (prefix) {
        fuse_log(FUSE_LOG_DEBUG, "%s", prefix);
    }
    if (inode) {
        fuse_log(FUSE_LOG_DEBUG, "%lu %s", inode->ino, inode->name);
        if (inode->orig_name) {
            fuse_log(FUSE_LOG_DEBUG, " [orig_name: %s]", inode->orig_name);
        }
    } else {
        fuse_log(FUSE_LOG_DEBUG, "(null)");
    }
    fuse_log(FUSE_LOG_DEBUG, "\n");
}

static void print_inode(struct ramcachefs_inode* inode) {
    fuse_log(FUSE_LOG_DEBUG, "   ino:           %lu\n", inode->ino);

    fuse_log(FUSE_LOG_DEBUG, "   name:          %s\n", inode->name);
    fuse_log(FUSE_LOG_DEBUG, "   orig_name:     %s\n", inode->orig_name);

    fuse_log(FUSE_LOG_DEBUG, "   ch_content:    %d\n", inode->changed_content);
    fuse_log(FUSE_LOG_DEBUG, "   changed_mode:  %d\n", inode->changed_mode);
    fuse_log(FUSE_LOG_DEBUG, "   changed_name:  %d\n", inode->changed_name);
    fuse_log(FUSE_LOG_DEBUG, "   changed_owner: %d\n", inode->changed_owner);
    fuse_log(FUSE_LOG_DEBUG, "   changed_time:  %d\n", inode->changed_time);

    fuse_log(FUSE_LOG_DEBUG, "   nlookup:       %lu\n", inode->nlookup);

    print_inode_simple("   parent:        ", inode->parent);
    print_inode_simple("   prev:          ", inode->prev);
    print_inode_simple("   next:          ", inode->next);
    print_inode_simple("   first_child:   ", inode->first_child);
    print_inode_simple("   last_child:    ", inode->last_child);
    print_inode_simple("   origin:        ", inode->origin);
    print_inode_simple("   orig_moved_to: ", inode->orig_moved_to);

    fuse_log(FUSE_LOG_DEBUG, "   dir_offset:    %lu\n", inode->dir_offset);
    fuse_log(FUSE_LOG_DEBUG, "   size:          %lu\n", inode->size);

    fuse_log(FUSE_LOG_DEBUG, "   atime:         %lu\n", inode->times[0]);
    fuse_log(FUSE_LOG_DEBUG, "   mtime:         %lu\n", inode->times[1]);
    fuse_log(FUSE_LOG_DEBUG, "   uid:           %d\n", inode->uid);
    fuse_log(FUSE_LOG_DEBUG, "   gid:           %d\n", inode->gid);
    fuse_log(FUSE_LOG_DEBUG, "   mode:          %d\n", inode->mode);
}

static void print_parent_path(struct ramcachefs_inode* inode) {
    if (inode->parent) {
        print_parent_path(inode->parent);
        fuse_log(FUSE_LOG_DEBUG, "%s/", inode->parent->name);
    }
}

static void print_path(struct ramcachefs_inode* inode, struct ramcachefs_inode* fallbackparent, const char* fallbackname) {
    if (inode) {
        print_parent_path(inode);
        fuse_log(FUSE_LOG_DEBUG, "%s(%ld)", inode->name, inode->ino);
    } else if (fallbackparent) {
        print_parent_path(fallbackparent);
        fuse_log(FUSE_LOG_DEBUG, "%s/%s(not found)", fallbackparent->name, fallbackname);
    } else {
        fuse_log(FUSE_LOG_DEBUG, "?/%s(not found)", fallbackname);
    }
}

static void print_tree(struct ramcachefs_inode* inode, int depth) {
    static const int indentwidth = 4;
    const int indent = depth * indentwidth;
    fuse_log(FUSE_LOG_DEBUG, "%*s", indent, "");
    print_inode_simple("", inode);
    if (inode->orig_moved_to) {
        fuse_log(FUSE_LOG_DEBUG, "%*s  orig_moved_to=", indent, "");
        print_inode_simple("", inode->orig_moved_to);
        if (inode != inode->orig_moved_to->origin) {
            fuse_log(FUSE_LOG_DEBUG, "%*s  ERROR orig_moved_to->origin=", indent, "");
            print_inode_simple("", inode->orig_moved_to->origin);
        }
    }
    if (inode->origin) {
        fuse_log(FUSE_LOG_DEBUG, "%*s  origin=", indent, "");
        print_inode_simple("", inode->origin);
        if (inode != inode->origin->orig_moved_to) {
            fuse_log(FUSE_LOG_DEBUG, "%*s  ERROR origin->orig_moved_to=", indent, "");
            print_inode_simple("", inode->origin->orig_moved_to);
        }
    }
    struct ramcachefs_inode* child = inode->first_child;
    struct ramcachefs_inode* prev = NULL;
    while (child) {
        print_tree(child, depth + 1);
        if (prev != child->prev) {
            fuse_log(FUSE_LOG_DEBUG, "%*sERROR prev=", indent + indentwidth, "");
            print_inode_simple("", child->prev);
        }
        prev = child;
        child = child->next;
    }
    if (prev && prev->next) {
        fuse_log(FUSE_LOG_DEBUG, "%*sERROR next=", indent + indentwidth, "");
        print_inode_simple("", prev->next);
    }
    if (prev != inode->last_child) {
        fuse_log(FUSE_LOG_DEBUG, "%*sERROR last_child=", indent, "");
        print_inode_simple("", inode->last_child);
    }
}
#endif

static struct ramcachefs_data* get_data(fuse_req_t req) { return (struct ramcachefs_data*)fuse_req_userdata(req); }

static struct ramcachefs_inode* get_inode(fuse_req_t req, fuse_ino_t ino) {
    if (ino == FUSE_ROOT_ID) {
        return get_data(req)->root;
    }
    return (struct ramcachefs_inode*)(uintptr_t)ino;
}

static void start_writing(struct ramcachefs_data* data) {
    pthread_mutex_lock(&data->writers_mutex);
    ++data->writers;
    if (data->writers == 1) {
        pthread_mutex_lock(&data->persist_mutex);
    }
    pthread_mutex_unlock(&data->writers_mutex);
}

static void stop_writing(struct ramcachefs_data* data) {
    pthread_mutex_lock(&data->writers_mutex);
    --data->writers;
    if (data->writers == 0) {
        pthread_mutex_unlock(&data->persist_mutex);
    }
    pthread_mutex_unlock(&data->writers_mutex);
}

static struct ramcachefs_inode* alloc_inode(const char* name, struct stat* stbuf) {
    struct ramcachefs_inode* inode = malloc(sizeof(struct ramcachefs_inode));
    if (inode) {
        memset(inode, 0, sizeof(struct ramcachefs_inode));
        inode->ino = (fuse_ino_t)inode;
        inode->nlookup = 1;
        if (name) {
            inode->name = strdup(name);
            if (!inode->name) {
                free(inode);
                return NULL;
            }
        }
        if (stbuf) {
            inode->mode = stbuf->st_mode;
            inode->uid = stbuf->st_uid;
            inode->gid = stbuf->st_gid;
            inode->size = stbuf->st_size;
            inode->times[0] = stbuf->st_atim;
            inode->times[1] = stbuf->st_mtim;
            inode->dev = stbuf->st_rdev;
        }
    }
    return inode;
}

static void set_parent_unsafe(struct ramcachefs_inode* inode, struct ramcachefs_inode* parent) { /* data->node_mutex must be locked */
    inode->parent = parent;
    if (parent->first_child) {
        parent->last_child->next = inode;
        inode->prev = parent->last_child;
        inode->dir_offset = parent->last_child->dir_offset + 1;
        parent->last_child = inode;
    } else {
        inode->dir_offset = 1;
        parent->first_child = inode;
        parent->last_child = inode;
    }
}

static void remove_inode_from_parent_unsafe(struct ramcachefs_inode* child) { /* data->node_mutex must be locked */
    if (child == child->parent->first_child) {
        child->parent->first_child = child->next;
    }
    if (child == child->parent->last_child) {
        child->parent->last_child = child->prev;
    }
    if (child->next) {
        child->next->prev = child->prev;
    }
    if (child->prev) {
        child->prev->next = child->next;
    }
    child->parent = NULL;
    child->prev = NULL;
    child->next = NULL;
}

static void free_inode(struct ramcachefs_inode* inode) {
    struct ramcachefs_inode* child = inode->first_child;
    struct ramcachefs_inode* next_child;
    while (child) {
        next_child = child->next;
        free_inode(child);
        child = next_child;
    }
    free(inode->orig_name);
    free(inode->name);
#ifdef DONT_USE_MMAP
    free(inode->content);
#else
    if (S_ISREG(inode->mode)) {
        if (inode->content && munmap(inode->content, inode->size)) {
            fuse_log(FUSE_LOG_ERR, "munmap failed: %m\n");
        }
    } else {
        free(inode->content);
    }
#endif
    free(inode);
}

static int is_dot_or_dotdot(const char* name) { return name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0')); }

static int cache_dir_unsafe(struct ramcachefs_data* data, struct ramcachefs_inode* dirnode, DIR* dir) { /* not thread safe */
    struct ramcachefs_inode* inode;
    struct stat stbuf;
    DIR* subdir;
    int fd;
    errno = 0;
    struct dirent* entry;
    for (entry = readdir(dir); entry; entry = readdir(dir)) {
        if (is_dot_or_dotdot(entry->d_name)) {
            continue;
        }
        if (fstatat(dirfd(dir), entry->d_name, &stbuf, AT_SYMLINK_NOFOLLOW)) {
            fuse_log(FUSE_LOG_ERR, "can't fstatat `%s': %m\n", entry->d_name);
            return 1;
        }
        if (data->free_inodes == 0) {
            fuse_log(FUSE_LOG_ERR, "no space left\n");
            return 1;
        }
        inode = alloc_inode(entry->d_name, &stbuf);
        if (!inode) {
            fuse_log(FUSE_LOG_ERR, "can't allocate memory: %m\n");
            return 1;
        }
        --data->free_inodes;
        inode->orig_name = strdup(entry->d_name);
        if (!inode->orig_name) {
            fuse_log(FUSE_LOG_ERR, "can't allocate memory: %m\n");
            goto err_out;
        }
        switch (stbuf.st_mode & S_IFMT) {
            case S_IFDIR: /* directory */
                fd = openat(dirfd(dir), entry->d_name, O_DIRECTORY | O_NOATIME | O_RDONLY);
                if (fd < 0) {
                    fuse_log(FUSE_LOG_ERR, "can't open `%s': %m\n", entry->d_name);
                    goto err_out;
                }
                subdir = fdopendir(fd);
                if (!subdir) {
                    fuse_log(FUSE_LOG_ERR, "can't open `%s' using fdopendir: %m\n", entry->d_name);
                    goto err_out;
                }
                if (cache_dir_unsafe(data, inode, subdir)) {
                    closedir(subdir);
                    goto err_out;
                }
                closedir(subdir);
                break;
            case S_IFLNK: /* symbolic link */
                if (inode->size > 0) {
                    inode->content = calloc(inode->size + 1, sizeof(char));
                    if (!inode->content) {
                        fuse_log(FUSE_LOG_ERR, "can't allocate memory: %m\n");
                        goto err_out;
                    }
                    ssize_t res = readlinkat(dirfd(dir), entry->d_name, inode->content, inode->size);
                    if (res < 0) {
                        fuse_log(FUSE_LOG_ERR, "can't read link `%s': %m\n", entry->d_name);
                        free(inode->content);
                        inode->content = NULL;
                        goto err_out;
                    }
                }
                break;
            case S_IFREG: /* regular file */
                if (inode->size > 0) {
                    size_t needed_size = (inode->size + data->block_size - 1) / data->block_size;
                    if (needed_size > data->free_blocks) {
                        fuse_log(FUSE_LOG_ERR, "no space left\n");
                        goto err_out;
                    }
                    fd = openat(dirfd(dir), entry->d_name, O_NOATIME | O_RDONLY);
                    if (fd < 0) {
                        fuse_log(FUSE_LOG_ERR, "can't open `%s': %m\n", entry->d_name);
                        goto err_out;
                    }
#ifdef DONT_USE_MMAP
                    inode->content = malloc(inode->size);
                    if (!inode->content) {
                        fuse_log(FUSE_LOG_ERR, "can't allocate memory: %m\n");
                        close(fd);
                        goto err_out;
                    }
                    ssize_t res;
                    ssize_t size = inode->size;
                    char* buf = inode->content;
                    while (1) {
                        res = read(fd, buf, size);
                        if (res < 0) {
                            fuse_log(FUSE_LOG_ERR, "can't read from `%s': %m\n", entry->d_name);
                            goto err_out;
                        }
                        if (res == size) {
                            break;
                        }
                        size -= res;
                        buf += res;
                    }
#else
                    inode->content = mmap(NULL, inode->size, PROT_READ | PROT_WRITE, MAP_PRIVATE | (data->prepopulate ? MAP_POPULATE : 0), fd, 0);
                    if (inode->content == MAP_FAILED) {
                        fuse_log(FUSE_LOG_ERR, "mmap failed: %m\n");
                        close(fd);
                        goto err_out;
                    }
                    inode->file_backed = 1;
#endif
                    close(fd);
                    data->free_blocks -= needed_size;
                }
                break;
            case S_IFBLK:  /* block device */
            case S_IFCHR:  /* character device */
            case S_IFIFO:  /* FIFO */
            case S_IFSOCK: /* socket */
                /* these are handled by stat already */
                break;
            default:
                fuse_log(FUSE_LOG_ERR, "unsupported file type for `%s'\n", entry->d_name);
                goto err_out;
        }
        set_parent_unsafe(inode, dirnode);
    }
    if (errno) {
        fuse_log(FUSE_LOG_ERR, "readdir failed: %m\n");
        return 1;
    }
    return 0;
err_out:
    ++data->free_inodes;
    free_inode(inode);
    return 1;
}

static int resize_file_unsafe(struct ramcachefs_data* data,
                              struct ramcachefs_inode* inode,
                              size_t newsize) { /* must be protected by start/stop_writing(data) */
    if (newsize == inode->size) {
        return 0;
    }
    if (newsize == 0) {
#ifdef DONT_USE_MMAP
        free(inode->content);
#else
        if (munmap(inode->content, inode->size)) {
            fuse_log(FUSE_LOG_ERR, "munmap failed: %m\n");
        }
#endif
        data->free_blocks += (inode->size + data->block_size - 1) / data->block_size;
        inode->content = NULL;
        inode->size = 0;
        return 0;
    }

    if (newsize > inode->size
        && data->free_blocks < (newsize + data->block_size - 1) / data->block_size - (inode->size + data->block_size - 1) / data->block_size) {
        return ENOSPC;
    }

    void* newbuf;
#ifdef DONT_USE_MMAP
    newbuf = realloc(inode->content, newsize);
    if (!newbuf) {
        return ENOMEM;
    }
    if (newsize > inode->size) {
        memset(newbuf + inode->size, 0, newsize - inode->size);
    }
#else
    if (inode->file_backed || !inode->content) {
        newbuf = mmap(NULL, newsize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    } else {
        newbuf = mremap(inode->content, inode->size, newsize, MREMAP_MAYMOVE);
    }
    if (newbuf == MAP_FAILED) {
        fuse_log(FUSE_LOG_ERR, "mmap or mremap failed: %m\n");
        return errno;
    }
    if (inode->file_backed) {
        memcpy(newbuf, inode->content, inode->size < newsize ? inode->size : newsize);
        if (munmap(inode->content, inode->size)) {
            fuse_log(FUSE_LOG_ERR, "munmap failed: %m\n");
        }
        inode->file_backed = 0;
    }
#endif
    data->free_blocks += (inode->size + data->block_size - 1) / data->block_size;
    data->free_blocks -= (newsize + data->block_size - 1) / data->block_size;
    inode->content = newbuf;
    inode->size = newsize;
    return 0;
}

static void fill_stat(struct stat* stbuf, struct ramcachefs_inode* inode) {
    stbuf->st_dev = 0; /* ignored by libfuse */
    stbuf->st_ino = inode->ino;
    stbuf->st_mode = inode->mode;
    stbuf->st_nlink = S_ISDIR(inode->mode) ? 2 : 1;
    stbuf->st_uid = inode->uid;
    stbuf->st_gid = inode->gid;
    stbuf->st_rdev = inode->dev;
    stbuf->st_size = inode->size;
    stbuf->st_blksize = 0; /* ignored by libfuse */
    stbuf->st_blocks = (inode->size + 511) / 512;
    stbuf->st_atim = inode->times[0];
    stbuf->st_mtim = inode->times[1];
}

static struct ramcachefs_inode* find_child(struct ramcachefs_data* data, struct ramcachefs_inode* inode, const char* name) {
    pthread_mutex_lock(&data->node_mutex);
    struct ramcachefs_inode* child = inode->first_child;
    while (child) {
        if (child->name && strcmp(name, child->name) == 0) {
            goto out;
        }
        child = child->next;
    }
out:
    pthread_mutex_unlock(&data->node_mutex);
    return child;
}

static int get_original_path_internal_unsafe(struct ramcachefs_inode* inode, char** out, int is_last, int came_from_origin) {
    if (!inode->parent) {
        return 0;
    }
    if (inode->origin && !came_from_origin) { /* make sure to not jump twice using origin (for swapped inodes) */
        return get_original_path_internal_unsafe(inode->origin, out, is_last, 1);
    }
    int offset = get_original_path_internal_unsafe(inode->parent, out, 0, 0);
    int len = strlen(inode->orig_name);
    *out = realloc(*out, offset + len + (is_last ? 1 : 2));
    memcpy(*out + offset, inode->orig_name, len + 1);
    if (!is_last) {
        (*out)[offset + len] = '/';
        (*out)[offset + len + 1] = '\0';
        return offset + len + 1;
    }
    return offset + len;
}

static char* get_original_path_unsafe(struct ramcachefs_inode* inode) {
    char* out = NULL;
    get_original_path_internal_unsafe(inode, &out, 1, 0);
    return out;
}

static int persist_internal_unsafe(struct ramcachefs_data* data, int parentfd, struct ramcachefs_inode* inode, int depth) {
#ifdef DEBUG
    const int indent = depth * 4;
    fuse_log(FUSE_LOG_DEBUG, "%*s", indent, "");
    print_inode_simple("", inode);
#endif

#ifdef DEBUG_DETAILS
    if (inode->orig_moved_to) {
        fuse_log(FUSE_LOG_DEBUG, "%*s  orig_moved_to=", indent, "");
        print_inode_simple("", inode->orig_moved_to);
        if (inode != inode->orig_moved_to->origin) {
            fuse_log(FUSE_LOG_DEBUG, "%*s  ERROR orig_moved_to->origin=", indent, "");
            print_inode_simple("", inode->orig_moved_to->origin);
        }
    }
    if (inode->origin) {
        fuse_log(FUSE_LOG_DEBUG, "%*s  origin=", indent, "");
        print_inode_simple("", inode->origin);
        if (inode != inode->origin->orig_moved_to) {
            fuse_log(FUSE_LOG_DEBUG, "%*s  ERROR origin->orig_moved_to=", indent, "");
            print_inode_simple("", inode->origin->orig_moved_to);
        }
    }
#endif

    if (inode->orig_moved_to && inode->orig_moved_to->orig_moved_to != inode) {
        return 1;
    }

    if (inode->origin) {
        char* original_path = get_original_path_unsafe(inode);
        debug("%*s  move %s -> %s\n", indent, "", original_path, inode->name);
        int exchange = inode->origin->origin == inode;
        if (renameat2(data->orig_root_fd, original_path, parentfd, inode->name, exchange ? RENAME_EXCHANGE : 0)) {
            fuse_log(FUSE_LOG_ERR, "can't move `%s' to `%s': %m\n", original_path, inode->origin->orig_name);
            return -1;
        }
        if (exchange) {
            char* tmpchar = inode->orig_name;
            inode->orig_name = inode->origin->orig_name;
            inode->origin->orig_name = tmpchar;
        } else {
            free(inode->origin->orig_name);
            inode->origin->orig_name = NULL;
            free(inode->orig_name);
            inode->orig_name = strdup(inode->name);
        }
        inode->changed_name = 0;
        free(original_path);
        if (!inode->origin->orig_moved_to->name) {
            free(inode->origin->orig_moved_to->orig_name);
            inode->origin->orig_moved_to->orig_name = NULL;
        }
        inode->origin->orig_moved_to = NULL;
        inode->origin = NULL;
    } else if (inode->name) {
        if (inode->changed_name) {
            debug("%*s  rename %s -> %s\n", indent, "", inode->orig_name, inode->name);
            if (renameat2(parentfd, inode->orig_name, parentfd, inode->name, RENAME_NOREPLACE)) {
                fuse_log(FUSE_LOG_ERR, "can't rename `%s' to `%s': %m\n", inode->orig_name, inode->name);
                return -1;
            }
            free(inode->orig_name);
            inode->orig_name = strdup(inode->name);
            inode->changed_name = 0;
        }

        if (!inode->orig_name) {
            debug("%*s  create\n", indent, "");
            switch (inode->mode & S_IFMT) {
                case S_IFDIR: /* directory */
                    if (mkdirat(parentfd, inode->name, inode->mode)) {
                        fuse_log(FUSE_LOG_ERR, "can't mkdir `%s': %m\n", inode->name);
                        return -1;
                    }
                    break;
                case S_IFLNK: /* symbolic link */
                    if (symlinkat(inode->content, parentfd, inode->name)) {
                        fuse_log(FUSE_LOG_ERR, "can't symlink `%s': %m\n", inode->name);
                        return -1;
                    }
                    break;
                case S_IFREG: /* regular file */
                    inode->changed_content = 1;
                    break;
                case S_IFBLK:  /* block device */
                case S_IFCHR:  /* character device */
                case S_IFSOCK: /* socket */
                    if (mknodat(parentfd, inode->name, inode->mode, inode->dev)) {
                        fuse_log(FUSE_LOG_ERR, "can't mknod `%s': %m\n", inode->name);
                        return -1;
                    }
                    break;
                case S_IFIFO: /* FIFO */
                    if (mkfifoat(parentfd, inode->name, inode->mode)) {
                        fuse_log(FUSE_LOG_ERR, "can't mkfifo `%s': %m\n", inode->name);
                        return -1;
                    }
                    break;
                    fuse_log(FUSE_LOG_ERR, "can't persist socket file `%s'\n", inode->name);
                    break;
                default:
                    fuse_log(FUSE_LOG_ERR, "unsupported file type for `%s'\n", inode->name);
                    return -1;
            }
            inode->changed_name = 0;
            inode->changed_mode = 0; /* either already handled my mkdirat/symlinkat/mknodat/mkfifoat or later by openat */
            inode->changed_owner = 1;
            inode->changed_time = 1;
            inode->orig_name = strdup(inode->name);
        }

#ifdef DEBUG_DETAILS
        if (strcmp(inode->name, inode->orig_name)) {
            print_inode(inode);
            return -1;
        }
#endif

        if (inode->changed_content) {
            if (S_ISREG(inode->mode)) {
                debug("%*s  write\n", indent, "");
#ifdef DONT_USE_MMAP
                int fd = openat(parentfd, inode->name, O_CREAT | O_TRUNC | O_WRONLY, inode->mode);
                if (fd >= 0) {
                    ssize_t written;
                    ssize_t size = inode->size;
                    void* buf = inode->content;
                    while (1) {
                        errno = 0;
                        written = write(fd, buf, size);
                        if (written < 0) {
                            if (errno == EINTR) {
                                continue;
                            }
                            fuse_log(FUSE_LOG_ERR, "can't write to `%s': %m\n", inode->name);
                            close(fd);
                            return -1;
                        }
                        if (written == size) {
                            break;
                        }
                        size -= written;
                        buf += written;
                    }
#else
                int fd = openat(parentfd, inode->name, O_CREAT | O_RDWR, inode->mode);
                if (fd >= 0) {
                    if (ftruncate(fd, inode->size)) {
                        fuse_log(FUSE_LOG_ERR, "ftruncate `%s' failed: %m\n", inode->name);
                        close(fd);
                        return -1;
                    }
                    if (inode->size > 0) {
                        void* buf = mmap(NULL, inode->size, PROT_WRITE, MAP_SHARED, fd, 0);
                        if (buf == MAP_FAILED) {
                            fuse_log(FUSE_LOG_ERR, "mmap `%s' failed: %m\n", inode->name);
                            close(fd);
                            return -1;
                        }
                        memcpy(buf, inode->content, inode->size);
                        if (munmap(buf, inode->size)) {
                            fuse_log(FUSE_LOG_ERR, "munmap `%s' failed: %m\n", inode->name);
                            close(fd);
                            return -1;
                        }
                        if (munmap(inode->content, inode->size)) {
                            fuse_log(FUSE_LOG_ERR, "munmap `%s' failed: %m\n", inode->name);
                            close(fd);
                            return -1;
                        }
                        inode->content = mmap(NULL, inode->size, PROT_READ | PROT_WRITE, MAP_PRIVATE | (data->prepopulate ? MAP_POPULATE : 0), fd, 0);
                        if (inode->content == MAP_FAILED) {
                            fuse_log(FUSE_LOG_ERR, "mmap `%s' failed: %m\n", inode->name);
                            close(fd);
                            return -1;
                        }
                    }
#endif
                    close(fd);
                } else {
                    fuse_log(FUSE_LOG_ERR, "can't open `%s': %m\n", inode->name);
                    return -1;
                }
            }
            inode->changed_content = 0;
        }

        if (inode->changed_mode) {
            debug("%*s  chmod\n", indent, "");
            if (fchmodat(parentfd, inode->name, inode->mode, AT_SYMLINK_NOFOLLOW)) {
                if (errno != ENOTSUP || fchmodat(parentfd, inode->name, inode->mode, 0)) {
                    fuse_log(FUSE_LOG_ERR, "can't chmod `%s': %m\n", inode->name);
                    return -1;
                }
            }
            inode->changed_mode = 0;
        }

        if (inode->changed_owner) {
            debug("%*s  chown\n", indent, "");
            if (fchownat(parentfd, inode->name, inode->uid, inode->gid, AT_SYMLINK_NOFOLLOW)) {
                if (errno != ENOTSUP || fchownat(parentfd, inode->name, inode->uid, inode->gid, 0)) {
                    fuse_log(FUSE_LOG_ERR, "can't chown `%s': %m\n", inode->name);
                    return -1;
                }
            }
            inode->changed_owner = 0;
        }

        if (inode->changed_time) {
            debug("%*s  change time\n", indent, "");
            if (utimensat(parentfd, inode->name, inode->times, AT_SYMLINK_NOFOLLOW)) {
                fuse_log(FUSE_LOG_ERR, "can't utimensat `%s': %m\n", inode->name);
                return -1;
            }
            inode->changed_time = 0;
        }
    }

    if (inode->orig_name) {
        if (S_ISDIR(inode->mode)) {
            int res = 0;
            int fd = openat(parentfd, inode->orig_name, O_DIRECTORY);
            if (fd < 0) {
                fuse_log(FUSE_LOG_ERR, "can't open `%s': %m\n", inode->orig_name);
                return -1;
            }
            struct ramcachefs_inode* next;
            struct ramcachefs_inode* child = inode->first_child;
            while (child) {
                res |= persist_internal_unsafe(data, fd, child, depth + 1);
                if (res < 0) {
                    close(fd);
                    return res;
                }
                next = child->next;
                if (!child->name && !child->orig_name && !child->orig_moved_to && !child->origin) {
                    debug("%*s  removing inode\n", indent, "");
                    remove_inode_from_parent_unsafe(child);
                    ++data->free_inodes;
                    free_inode(child);
                }
                child = next;
            }
            close(fd);
        }

        if (!inode->name) {
            debug("%*s  delete\n", indent, "");
            if (unlinkat(parentfd, inode->orig_name, S_ISDIR(inode->mode) ? AT_REMOVEDIR : 0)) {
                fuse_log(FUSE_LOG_ERR, "can't rename `%s' to `%s': %m\n", inode->orig_name, inode->name);
                return -1;
            }
            free(inode->orig_name);
            inode->orig_name = NULL;
        }
    }

    return 0;
}

static int persist(struct ramcachefs_data* data) {
    debug("persisting...\n");
    pthread_mutex_lock(&data->persist_mutex);
    pthread_mutex_lock(&data->node_mutex);

#ifdef DEBUG_DETAILS
    fuse_log(FUSE_LOG_DEBUG, "\nbefore persisting:\n");
    print_tree(data->root, 0);
#endif

    int res = 1;

    int dir = openat(data->orig_root_fd, ".", O_DIRECTORY);
    if (dir < 0) {
        fuse_log(FUSE_LOG_ERR, "can't open `%s': %m\n", data->root->orig_name);
        res = -1;
        goto out1;
    }

    struct ramcachefs_inode* next;
    struct ramcachefs_inode* child;
    while (res) {
#ifdef DEBUG_DETAILS
        fuse_log(FUSE_LOG_DEBUG, "\npersisting round:\n");
#endif
        res = 0;
        child = data->root->first_child;
        while (child) {
            res |= persist_internal_unsafe(data, dir, child, 1);
            if (res < 0) {
                goto out2;
            }
            next = child->next;
            if (!child->name && !child->orig_name && !child->orig_moved_to && !child->origin) {
                debug("      removing inode\n");
                remove_inode_from_parent_unsafe(child);
                ++data->free_inodes;
                free_inode(child);
            }
            child = next;
        }
    }

    if (data->root->changed_mode) {
        debug("  chmod\n");
        if (fchmod(dir, data->root->mode)) {
            fuse_log(FUSE_LOG_ERR, "can't chmod `%s': %m\n", data->root->orig_name);
            res = -1;
            goto out2;
        }
        data->root->changed_mode = 0;
    }

    if (data->root->changed_owner) {
        debug("  chown\n");
        if (fchown(dir, data->root->uid, data->root->gid)) {
            fuse_log(FUSE_LOG_ERR, "can't chown `%s': %m\n", data->root->orig_name);
            res = -1;
            goto out2;
        }
        data->root->changed_owner = 0;
    }

    if (data->root->changed_time) {
        debug("  change time\n");
        if (futimens(dir, data->root->times)) {
            fuse_log(FUSE_LOG_ERR, "can't utimensat `%s': %m\n", data->root->orig_name);
            res = -1;
            goto out2;
        }
        data->root->changed_time = 0;
    }

out2:
    close(dir);
out1:
#ifdef DEBUG_DETAILS
    fuse_log(FUSE_LOG_DEBUG, "\nafter persisting:\n");
    print_tree(data->root, 0);
    fuse_log(FUSE_LOG_DEBUG, "\n");
#endif
    pthread_mutex_unlock(&data->node_mutex);
    pthread_mutex_unlock(&data->persist_mutex);
    return res < 0 ? 1 : 0;
}

static void forget_inode_unsafe(struct ramcachefs_data* data, struct ramcachefs_inode* inode, uint64_t nlookup) { /* data->node_mutex must be locked */
    if (nlookup < inode->nlookup) {
        inode->nlookup -= nlookup;
    } else {
        if (inode->origin) {
            /* this inode represents an original file, mark this as deleted as well */
            inode->origin->orig_moved_to = NULL;
            inode->origin = NULL;
        }

        if (inode->nlookup) {
            inode->nlookup = 0;

            free(inode->name);
            inode->name = NULL;

            if (S_ISREG(inode->mode)) {
                data->free_blocks += (inode->size + data->block_size - 1) / data->block_size;
            }

#ifdef DONT_USE_MMAP
            free(inode->content);
#else
            if (S_ISREG(inode->mode)) {
                if (inode->content && munmap(inode->content, inode->size)) {
                    fuse_log(FUSE_LOG_ERR, "munmap failed: %m\n");
                }
            } else {
                free(inode->content);
            }
#endif
            inode->content = NULL;
            inode->size = 0;
        }
        if (!inode->orig_name) {
            if (inode->prev || inode->next || inode->first_child) {
                fuse_log(FUSE_LOG_ERR, "error: trying to forget inode %lu which is still linked\n", inode->ino);
            } else {
                ++data->free_inodes;
                free_inode(inode);
            }
        }
    }
}

static void interchange_inodes_unsafe(struct ramcachefs_inode* i, struct ramcachefs_inode* j) { /* data->node_mutex must be locked */
    /* interchange node positions keeping their dir_offset, orig_moved_to, name, and orig_name in place */
    struct ramcachefs_inode* tmpnode;
    char* tmpname;
    off_t tmpoff;

    tmpnode = i->orig_moved_to;
    i->orig_moved_to = j->orig_moved_to;
    j->orig_moved_to = tmpnode;

    tmpname = i->name;
    i->name = j->name;
    j->name = tmpname;

    tmpname = i->orig_name;
    i->orig_name = j->orig_name;
    j->orig_name = tmpname;

    tmpoff = i->dir_offset;
    i->dir_offset = j->dir_offset;
    j->dir_offset = tmpoff;

    if (i->parent != j->parent) {
        tmpnode = i->parent;
        i->parent = j->parent;
        j->parent = tmpnode;

        if (i->parent) {
            if (i->parent->first_child == j) {
                i->parent->first_child = i;
            }
            if (i->parent->last_child == j) {
                i->parent->last_child = i;
            }
        }

        if (j->parent) {
            if (j->parent->first_child == i) {
                j->parent->first_child = j;
            }
            if (j->parent->last_child == i) {
                j->parent->last_child = j;
            }
        }
    } else {
        if (i->parent) {
            if (i->parent->first_child == j) {
                i->parent->first_child = i;
            } else if (j->parent->first_child == i) {
                j->parent->first_child = j;
            }
            if (i->parent->last_child == j) {
                i->parent->last_child = i;
            } else if (j->parent->last_child == i) {
                j->parent->last_child = j;
            }
        }
    }

    if (i->prev == j) { /* then also j->next == i */
        tmpnode = j->prev;
        j->prev = i;
        i->prev = tmpnode;

        tmpnode = i->next;
        i->next = j;
        j->next = tmpnode;

        if (i->prev) {
            i->prev->next = i;
        }
        if (j->next) {
            j->next->prev = j;
        }
    } else if (j->prev == i) { /* then also i->next == j */
        tmpnode = i->prev;
        i->prev = j;
        j->prev = tmpnode;

        tmpnode = j->next;
        j->next = i;
        i->next = tmpnode;

        if (i->next) {
            i->next->prev = i;
        }
        if (j->prev) {
            j->prev->next = j;
        }
    } else {
        tmpnode = i->prev;
        i->prev = j->prev;
        j->prev = tmpnode;

        tmpnode = i->next;
        i->next = j->next;
        j->next = tmpnode;

        if (i->prev) {
            i->prev->next = i;
        }
        if (i->next) {
            i->next->prev = i;
        }
        if (j->prev) {
            j->prev->next = j;
        }
        if (j->next) {
            j->next->prev = j;
        }
    }

    if (i->orig_moved_to) {
        i->orig_moved_to->origin = i;
    } else if (i->orig_name && !j->origin) { /* if i->orig_name && j->origin then i->orig_name has already been overwritten */
        i->orig_moved_to = j;
        j->origin = i;
    }

    if (j->orig_moved_to) {
        j->orig_moved_to->origin = j;
    } else if (j->orig_name && !i->origin) { /* if j->orig_name && i->origin then j->orig_name has already been overwritten */
        j->orig_moved_to = i;
        i->origin = j;
    }
}

static struct ramcachefs_file_info* new_file_info(struct fuse_file_info* fi) {
    struct ramcachefs_file_info* rfi = malloc(sizeof(struct ramcachefs_file_info));
    if (rfi) {
        rfi->max_written = 0;
        rfi->orig_flags = fi->flags;
        fi->fh = (uint64_t)rfi;
    }
    return rfi;
}

static void mark_inode_removed_unsafe(struct ramcachefs_data* data, struct ramcachefs_inode* inode) { /* data->node_mutex must be locked */
    free(inode->name);
    inode->name = NULL;
    if (inode->origin) {
        /* this inode represents an original file, mark that as deleted as well */
        inode->origin->orig_moved_to = NULL;
        inode->origin = NULL;
    }
    if (!inode->orig_name) {
        remove_inode_from_parent_unsafe(inode);
    }
    forget_inode_unsafe(data, inode, 1);
}

static void remove_file_or_dir(fuse_req_t req, fuse_ino_t parent, const char* name, int rmdir) {
    struct ramcachefs_data* data = get_data(req);
    struct ramcachefs_inode* parentnode = get_inode(req, parent);
    struct ramcachefs_inode* child = find_child(data, parentnode, name);
#ifdef DEBUG
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   remove_file_or_dir ");
        print_path(child, parentnode, name);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif
    if (!child) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    start_writing(data);
    pthread_mutex_lock(&data->node_mutex);

    int res = 0;
    if (rmdir && child->first_child) {
        res = ENOTEMPTY;
    } else {
        mark_inode_removed_unsafe(data, child);
    }

    pthread_mutex_unlock(&data->node_mutex);
    stop_writing(data);

    fuse_reply_err(req, res);
}

static void ramcachefs_copy_file_range(fuse_req_t req,
                                       fuse_ino_t ino_in,
                                       off_t off_in,
                                       struct fuse_file_info* UNUSED_fi_in,
                                       fuse_ino_t ino_out,
                                       off_t off_out,
                                       struct fuse_file_info* fi_out,
                                       size_t len,
                                       int UNUSED_flags) {
    (void)UNUSED_fi_in;
    (void)UNUSED_flags;

    struct ramcachefs_data* data = get_data(req);
    struct ramcachefs_inode* inode_in = get_inode(req, ino_in);
    struct ramcachefs_inode* inode_out = get_inode(req, ino_out);

#ifdef DEBUG
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   remove_file_or_dir ");
        print_path(inode_in, NULL, NULL);
        fuse_log(FUSE_LOG_DEBUG, " to ");
        print_path(inode_out, NULL, NULL);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif

    if (off_in + len > inode_in->size) {
        fuse_reply_err(req, EINVAL);
        return;
    }

    start_writing(data);

    if (off_out + len > inode_out->size) {
        pthread_mutex_lock(&data->node_mutex);
        int res = resize_file_unsafe(data, inode_out, off_out + len);
        pthread_mutex_unlock(&data->node_mutex);
        if (res) {
            stop_writing(data);
            fuse_reply_err(req, res);
            return;
        }
    }

    inode_out->changed_content = 1;
    if (inode_out->mode & (S_ISUID | S_ISGID)) {
        inode_out->changed_mode = 1;
        inode_out->mode &= ~(S_ISUID | S_ISGID);
    }
    memcpy(inode_out->content + off_out, inode_in->content + off_in, len);

    stop_writing(data);

    struct ramcachefs_file_info* rfi = (struct ramcachefs_file_info*)fi_out->fh;
    if (off_out + len > rfi->max_written) {
        rfi->max_written = off_out + len;
    }
    fuse_reply_write(req, len);
}

static int mkinode(fuse_req_t req, struct ramcachefs_inode* parentnode, struct ramcachefs_inode* inode, struct fuse_file_info* fi) {
    struct ramcachefs_data* data = get_data(req);

    const struct fuse_ctx* ctx = fuse_req_ctx(req);
    if (ctx) {
        inode->uid = ctx->uid;
        inode->gid = ctx->gid;
    }
    clock_gettime(CLOCK_REALTIME, &inode->times[0]);
    clock_gettime(CLOCK_REALTIME, &inode->times[1]);

    struct fuse_entry_param entry = {
        .ino = inode->ino,
        .attr_timeout = RAMCACHEFS_TIMEOUT,
        .entry_timeout = RAMCACHEFS_TIMEOUT,
        .generation = 0,
    };
    fill_stat(&entry.attr, inode);

    pthread_mutex_lock(&data->node_mutex);

    if (data->free_inodes == 0) {
        fuse_reply_err(req, ENOSPC);
        free_inode(inode);
        pthread_mutex_unlock(&data->node_mutex);
        return 1;
    }

    int res;
    if (fi) {
        res = fuse_reply_create(req, &entry, fi);
    } else {
        res = fuse_reply_entry(req, &entry);
    }

    if (res) {
        free_inode(inode);
        pthread_mutex_unlock(&data->node_mutex);
        return 1;
    }

    --data->free_inodes;
    ++inode->nlookup;
    set_parent_unsafe(inode, parentnode);

    pthread_mutex_unlock(&data->node_mutex);

    return 0;
}

static void ramcachefs_create(fuse_req_t req, fuse_ino_t parent, const char* name, mode_t mode, struct fuse_file_info* fi) {
    struct ramcachefs_inode* parentnode = get_inode(req, parent);

#ifdef DEBUG
    struct ramcachefs_data* data = get_data(req);
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   create ");
        print_path(NULL, parentnode, name);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif

    struct ramcachefs_file_info* rfi = new_file_info(fi);
    if (!rfi) {
        fuse_reply_err(req, ENOMEM);
        return;
    }

    struct ramcachefs_inode* inode = alloc_inode(name, NULL);
    if (!inode) {
        fuse_reply_err(req, ENOMEM);
        free(rfi);
        fi->fh = 0;
        return;
    }

    inode->mode = mode;

    if (mkinode(req, parentnode, inode, fi)) {
        free(rfi);
        fi->fh = 0;
    }
}

static void ramcachefs_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {
    struct ramcachefs_data* data = get_data(req);
    struct ramcachefs_inode* inode = get_inode(req, ino);
#ifdef DEBUG
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   forget ");
        print_path(inode, NULL, NULL);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif
    pthread_mutex_lock(&data->node_mutex);
    forget_inode_unsafe(data, inode, nlookup);
    pthread_mutex_unlock(&data->node_mutex);
    fuse_reply_none(req);
}

static void ramcachefs_forget_multi(fuse_req_t req, size_t count, struct fuse_forget_data* forgets) {
    struct ramcachefs_data* data = get_data(req);
    struct ramcachefs_inode* inode;
    pthread_mutex_lock(&data->node_mutex);
    size_t i;
    for (i = 0; i < count; ++i) {
        inode = get_inode(req, forgets[i].ino);
#ifdef DEBUG
        if (data->debug) {
            fuse_log(FUSE_LOG_DEBUG, "   forget_multi ");
            print_path(inode, NULL, NULL);
            fuse_log(FUSE_LOG_DEBUG, "\n");
        }
#endif
        forget_inode_unsafe(data, inode, forgets[i].nlookup);
    }
    pthread_mutex_unlock(&data->node_mutex);
    fuse_reply_none(req);
}

static void ramcachefs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* UNUSED_fi) {
    (void)UNUSED_fi;

    struct stat stbuf;
    struct ramcachefs_inode* inode = get_inode(req, ino);

#ifdef DEBUG
    struct ramcachefs_data* data = get_data(req);
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   getattr ");
        print_path(inode, NULL, NULL);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif

    fill_stat(&stbuf, inode);
    fuse_reply_attr(req, &stbuf, RAMCACHEFS_TIMEOUT);
}

static void ramcachefs_init(void* userdata, struct fuse_conn_info* conn) {
    struct ramcachefs_data* data = userdata;

    /* FUSE docs on FUSE_CAP_ASYNC_DIO:
     *
     * Indicates that the filesystem supports asynchronous direct I/O submission.
     *
     * If this capability is not requested/available, the kernel will ensure that
     * there is at most one pending read and one pending write request per direct
     * I/O file-handle at any time.
     */
    conn->want &= ~FUSE_CAP_ASYNC_DIO;

    /* FUSE docs on FUSE_CAP_NO_OPENDIR_SUPPORT:
     *
     * Indicates support for zero-message opendirs. If this flag is set in
     * the `capable` field of the `fuse_conn_info` structure, then the filesystem
     * may return `ENOSYS` from the opendir() handler to indicate success. Further
     * opendir and releasedir messages will be handled in the kernel. (If this
     * flag is not set, returning ENOSYS will be treated as an error and signalled
     * to the caller.)
     */
    if (conn->capable & FUSE_CAP_NO_OPENDIR_SUPPORT) {
        data->opendir_result = ENOSYS;
    }
}

static void ramcachefs_ioctl(fuse_req_t req,
                             fuse_ino_t ino,
                             int cmd,
                             void* UNUSED_arg,
                             struct fuse_file_info* UNUSED_fi,
                             unsigned flags,
                             const void* UNUSED_in_buf,
                             size_t UNUSED_in_bufsz,
                             size_t UNUSED_out_bufsz) {
    (void)UNUSED_arg;
    (void)UNUSED_fi;
    (void)UNUSED_in_buf;
    (void)UNUSED_in_bufsz;
    (void)UNUSED_out_bufsz;

    if (flags & FUSE_IOCTL_COMPAT) {
        fuse_reply_err(req, ENOSYS);
        return;
    }

#ifdef DEBUG
    struct ramcachefs_data* data = get_data(req);
    if (data->debug) {
        struct ramcachefs_inode* inode = get_inode(req, ino);
        fuse_log(FUSE_LOG_DEBUG, "   ioctl ");
        print_path(inode, NULL, NULL);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif

    switch (cmd) {
        case RAMCACHEFS_TRIGGER_PERSIST:
            fuse_reply_ioctl(req, ino == FUSE_ROOT_ID ? persist(get_data(req)) : -1, NULL, 0);
            return;
    }

    fuse_reply_err(req, EINVAL);
}

static void ramcachefs_lookup(fuse_req_t req, fuse_ino_t parent, const char* name) {
    struct ramcachefs_data* data = get_data(req);
    struct ramcachefs_inode* parentnode = get_inode(req, parent);
    struct ramcachefs_inode* child = find_child(data, parentnode, name);
#ifdef DEBUG
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   lookup ");
        print_path(child, parentnode, name);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif
    if (!child) {
        fuse_reply_err(req, ENOENT);
        return;
    }
    struct fuse_entry_param entry = {
        .ino = child->ino,
        .attr_timeout = RAMCACHEFS_TIMEOUT,
        .entry_timeout = RAMCACHEFS_TIMEOUT,
        .generation = 0,
    };
    fill_stat(&entry.attr, child);

    pthread_mutex_lock(&data->node_mutex);
    if (!fuse_reply_entry(req, &entry)) {
        ++child->nlookup;
    }
    pthread_mutex_unlock(&data->node_mutex);
}

static void ramcachefs_mkdir(fuse_req_t req, fuse_ino_t parent, const char* name, mode_t mode) {
    struct ramcachefs_inode* parentnode = get_inode(req, parent);

#ifdef DEBUG
    struct ramcachefs_data* data = get_data(req);
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   mkdir ");
        print_path(NULL, parentnode, name);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif

    struct ramcachefs_inode* inode = alloc_inode(name, NULL);
    if (!inode) {
        fuse_reply_err(req, ENOMEM);
        return;
    }

    inode->mode = mode | S_IFDIR;

    mkinode(req, parentnode, inode, NULL);
}

static void ramcachefs_mknod(fuse_req_t req, fuse_ino_t parent, const char* name, mode_t mode, dev_t rdev) {
    struct ramcachefs_inode* parentnode = get_inode(req, parent);

#ifdef DEBUG
    struct ramcachefs_data* data = get_data(req);
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   mknod ");
        print_path(NULL, parentnode, name);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif

    struct ramcachefs_inode* inode = alloc_inode(name, NULL);
    if (!inode) {
        fuse_reply_err(req, ENOMEM);
        return;
    }

    inode->mode = mode;
    inode->dev = rdev;

    mkinode(req, parentnode, inode, NULL);
}

static void ramcachefs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
#ifdef DEBUG
    struct ramcachefs_data* data = get_data(req);
    struct ramcachefs_inode* inode = get_inode(req, ino);
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   open ");
        print_path(inode, NULL, NULL);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#else
    (void)ino;
#endif

    struct ramcachefs_file_info* rfi = new_file_info(fi);
    if (!rfi) {
        fuse_reply_err(req, ENOMEM);
        return;
    }
    fi->direct_io = 1;
    fuse_reply_open(req, fi);
}

static void ramcachefs_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
    struct ramcachefs_data* data = get_data(req);

#ifdef DEBUG
    struct ramcachefs_inode* inode = get_inode(req, ino);
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   opendir ");
        print_path(inode, NULL, NULL);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#else
    (void)ino;
#endif

    if (data->opendir_result) {
        fuse_reply_err(req, data->opendir_result);
        return;
    }
    fuse_reply_open(req, fi);
}

static void ramcachefs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info* UNUSED_fi) {
    (void)UNUSED_fi;

    struct ramcachefs_inode* inode = get_inode(req, ino);

#ifdef DEBUG
    struct ramcachefs_data* data = get_data(req);
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   read ");
        print_path(inode, NULL, NULL);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif

    if ((size_t)off > inode->size) {
        fuse_reply_buf(req, NULL, 0);
        return;
    }
    size_t remaining = inode->size - off;
    fuse_reply_buf(req, inode->content + off, size < remaining ? size : remaining);
}

static void ramcachefs_readdir_maybe_plus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, unsigned int plus) {
    struct ramcachefs_inode* inode = get_inode(req, ino);
    struct ramcachefs_inode* child = inode->first_child;
    if (!child) {
        fuse_reply_buf(req, 0, 0);
        return;
    }

    char* buf = malloc(size);
    if (!buf) {
        fuse_reply_err(req, ENOMEM);
        return;
    }

    char* p = buf;
    size_t remaining = size;
    struct fuse_entry_param entry = {
        .attr_timeout = RAMCACHEFS_TIMEOUT,
        .entry_timeout = RAMCACHEFS_TIMEOUT,
        .generation = 0,
    };
    size_t entsize;

    while (child && child->dir_offset <= off) {
        child = child->next;
    }

    while (child) {
        if (child->name) {
            if (plus) {
                entry.ino = child->ino;
                fill_stat(&entry.attr, child);
                entsize = fuse_add_direntry_plus(req, p, remaining, child->name, &entry, child->dir_offset);
                if (entsize <= remaining) {
                    ++child->nlookup;
                }
            } else {
                entry.attr.st_ino = child->ino;
                entry.attr.st_mode = child->mode;
                entsize = fuse_add_direntry(req, p, remaining, child->name, &entry.attr, child->dir_offset);
            }
            if (entsize > remaining) {
                break;
            }
            p += entsize;
            remaining -= entsize;
        }
        child = child->next;
    }

    fuse_reply_buf(req, buf, size - remaining);
    free(buf);
}

static void ramcachefs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info* UNUSED_fi) {
    (void)UNUSED_fi;

#ifdef DEBUG
    struct ramcachefs_data* data = get_data(req);
    struct ramcachefs_inode* inode = get_inode(req, ino);
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   readdir ");
        print_path(inode, NULL, NULL);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif

    ramcachefs_readdir_maybe_plus(req, ino, size, off, 0);
}

static void ramcachefs_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info* UNUSED_fi) {
    (void)UNUSED_fi;

#ifdef DEBUG
    struct ramcachefs_data* data = get_data(req);
    struct ramcachefs_inode* inode = get_inode(req, ino);
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   readdirplus ");
        print_path(inode, NULL, NULL);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif

    ramcachefs_readdir_maybe_plus(req, ino, size, off, 1);
}

static void ramcachefs_readlink(fuse_req_t req, fuse_ino_t ino) {
    struct ramcachefs_inode* inode = get_inode(req, ino);

#ifdef DEBUG
    struct ramcachefs_data* data = get_data(req);
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   readlink ");
        print_path(inode, NULL, NULL);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif

    if (!S_ISLNK(inode->mode)) {
        fuse_reply_err(req, EINVAL);
        return;
    }
    fuse_reply_readlink(req, inode->content);
}

static void ramcachefs_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
    struct ramcachefs_data* data = get_data(req);
    struct ramcachefs_inode* inode = get_inode(req, ino);

#ifdef DEBUG
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   release ");
        print_path(inode, NULL, NULL);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif

    struct ramcachefs_file_info* rfi = (struct ramcachefs_file_info*)fi->fh;
    int res = 0;
    if (rfi->orig_flags & O_TRUNC) {
        if (rfi->max_written < inode->size) {
            start_writing(data);
            pthread_mutex_lock(&data->node_mutex);
            res = resize_file_unsafe(data, inode, rfi->max_written);
            pthread_mutex_unlock(&data->node_mutex);
            stop_writing(data);
        }
    }
    free(rfi);
    fi->fh = 0;
    fuse_reply_err(req, res);
}

static void ramcachefs_rename(fuse_req_t req, fuse_ino_t parent, const char* name, fuse_ino_t newparent, const char* newname, unsigned int flags) {
    struct ramcachefs_data* data = get_data(req);

    struct ramcachefs_inode* parentnode = get_inode(req, parent);
    struct ramcachefs_inode* inode = find_child(data, parentnode, name);

    struct ramcachefs_inode* newparentnode = get_inode(req, newparent);
    struct ramcachefs_inode* newnode = find_child(data, newparentnode, newname);

#ifdef DEBUG
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   rename ");
        print_path(inode, parentnode, name);
        fuse_log(FUSE_LOG_DEBUG, " to ");
        print_path(newnode, newparentnode, newname);
        if (flags == RENAME_EXCHANGE) {
            fuse_log(FUSE_LOG_DEBUG, " RENAME_EXCHANGE");
        } else if (flags == RENAME_NOREPLACE) {
            fuse_log(FUSE_LOG_DEBUG, " RENAME_NOREPLACE");
        }
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif

    if (!inode) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    int res = 0;
    start_writing(data);

    if (!newnode) {
        if (parentnode == newparentnode || !inode->orig_name) {
            /* just a rename in the same directory or node can be moved */
            char* newname_copy = strdup(newname);
            if (!newname_copy) {
                res = ENOMEM;
                goto out;
            }
            pthread_mutex_lock(&data->node_mutex);
            free(inode->name);
            inode->name = newname_copy;
            /* move the inode to the end of the parent */
            remove_inode_from_parent_unsafe(inode);
            set_parent_unsafe(inode, newparentnode);
            if (inode->orig_name && !inode->orig_moved_to) {
                inode->changed_name = 1;
            }
            pthread_mutex_unlock(&data->node_mutex);
            goto out;
        }
        /* create a new node which will be used as a placeholder */
        newnode = alloc_inode(newname, NULL);
        if (!newnode) {
            res = ENOMEM;
            goto out;
        }
    } else if (flags == RENAME_NOREPLACE) {
        res = EEXIST;
        goto out;
    }

    pthread_mutex_lock(&data->node_mutex);

    if (!newnode->parent) {
        /* newnode has been newly allocated above as a placeholder */
        /* insert into tree here because data->node_mutex is locked here */
        if (data->free_inodes == 0) {
            res = ENOSPC;
            pthread_mutex_unlock(&data->node_mutex);
            goto out;
        }
        --data->free_inodes;
        set_parent_unsafe(newnode, newparentnode);
    }

    /* interchange node positions keeping their dir_offset, orig_moved_to, name, and orig_name in place */
    interchange_inodes_unsafe(inode, newnode);
    /* now inode is at the new position, newnode at the old one */

    if (flags != RENAME_EXCHANGE) {
        /* newnode has been overwritten. if it's a placeholder (i.e. orig_name!=NULL it won't be cleaned up, though. */
        mark_inode_removed_unsafe(data, newnode);
    }

    pthread_mutex_unlock(&data->node_mutex);

out:
    stop_writing(data);
    fuse_reply_err(req, res);
}

static void ramcachefs_rmdir(fuse_req_t req, fuse_ino_t parent, const char* name) { remove_file_or_dir(req, parent, name, 1); }

static void ramcachefs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat* attr, int to_set, struct fuse_file_info* fi) {
    struct ramcachefs_data* data = get_data(req);
    struct ramcachefs_inode* inode = get_inode(req, ino);

#ifdef DEBUG
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   setattr ");
        print_path(inode, NULL, NULL);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif

    start_writing(data);

    if (to_set & FUSE_SET_ATTR_MODE) {
        inode->changed_mode = 1;
        inode->mode = attr->st_mode;
    }
    if (to_set & FUSE_SET_ATTR_UID) {
        inode->changed_mode = 1;
        inode->changed_owner = 1;
        inode->mode &= ~(S_ISUID | S_ISGID);
        inode->uid = attr->st_uid;
    }
    if (to_set & FUSE_SET_ATTR_GID) {
        inode->changed_mode = 1;
        inode->changed_owner = 1;
        inode->mode &= ~(S_ISUID | S_ISGID);
        inode->gid = attr->st_gid;
    }
    if (to_set & FUSE_SET_ATTR_SIZE) {
        if (inode->mode & (S_ISUID | S_ISGID)) {
            inode->changed_mode = 1;
            inode->mode &= ~(S_ISUID | S_ISGID);
        }
        if (S_ISREG(inode->mode) && inode->size != (size_t)attr->st_size) {
            inode->changed_content = 1;
            pthread_mutex_lock(&data->node_mutex);
            int res = resize_file_unsafe(data, inode, attr->st_size);
            pthread_mutex_unlock(&data->node_mutex);
            if (res) {
                stop_writing(data);
                fuse_reply_err(req, res);
                return;
            }
        }
    }
    if (to_set & FUSE_SET_ATTR_ATIME) {
        inode->changed_time = 1;
        if (to_set & FUSE_SET_ATTR_ATIME_NOW) {
            clock_gettime(CLOCK_REALTIME, &inode->times[0]);
        } else {
            inode->times[0] = attr->st_atim;
        }
    }
    if (to_set & FUSE_SET_ATTR_MTIME) {
        inode->changed_time = 1;
        if (to_set & FUSE_SET_ATTR_MTIME_NOW) {
            clock_gettime(CLOCK_REALTIME, &inode->times[1]);
        } else {
            inode->times[1] = attr->st_mtim;
        }
    }

    stop_writing(data);
    ramcachefs_getattr(req, ino, fi);
}

static void ramcachefs_statfs(fuse_req_t req, fuse_ino_t UNUSED_ino) {
    (void)UNUSED_ino;
    struct ramcachefs_data* data = get_data(req);
    pthread_mutex_lock(&data->node_mutex);
    struct statvfs stat = {
        .f_bsize = data->block_size,   /* Filesystem block size */
        .f_frsize = data->block_size,  /* Fragment size */
        .f_blocks = data->max_blocks,  /* Size of fs in f_frsize units */
        .f_bfree = data->free_blocks,  /* Number of free blocks */
        .f_bavail = data->free_blocks, /* Number of free blocks for unprivileged users */
        .f_files = data->max_inodes,   /* Number of inodes */
        .f_ffree = data->free_inodes,  /* Number of free inodes */
        .f_namemax = 255               /* Maximum filename length */
    };
    pthread_mutex_unlock(&data->node_mutex);
    fuse_reply_statfs(req, &stat);
}

static void ramcachefs_symlink(fuse_req_t req, const char* link, fuse_ino_t parent, const char* name) {
    struct ramcachefs_inode* parentnode = get_inode(req, parent);

#ifdef DEBUG
    struct ramcachefs_data* data = get_data(req);
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   symlink ");
        print_path(NULL, parentnode, name);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif

    struct ramcachefs_inode* inode = alloc_inode(name, NULL);
    if (!inode) {
        fuse_reply_err(req, ENOMEM);
        return;
    }

    inode->mode = S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO;
    inode->content = strdup(link);
    if (!inode->content) {
        fuse_reply_err(req, ENOMEM);
        free_inode(inode);
        return;
    }
    inode->size = strlen(link);

    mkinode(req, parentnode, inode, NULL);
}

static void ramcachefs_unlink(fuse_req_t req, fuse_ino_t parent, const char* name) { remove_file_or_dir(req, parent, name, 0); }

static void ramcachefs_write_buf(fuse_req_t req, fuse_ino_t ino, struct fuse_bufvec* bufv, off_t off, struct fuse_file_info* fi) {
    struct ramcachefs_data* data = get_data(req);
    struct ramcachefs_inode* inode = get_inode(req, ino);

#ifdef DEBUG
    if (data->debug) {
        fuse_log(FUSE_LOG_DEBUG, "   write ");
        print_path(inode, NULL, NULL);
        fuse_log(FUSE_LOG_DEBUG, "\n");
    }
#endif

    start_writing(data);

    if (off + bufv->buf[0].size > inode->size) {
        pthread_mutex_lock(&data->node_mutex);
        int res = resize_file_unsafe(data, inode, off + bufv->buf[0].size);
        pthread_mutex_unlock(&data->node_mutex);
        if (res) {
            stop_writing(data);
            fuse_reply_err(req, res);
            return;
        }
    }

    ssize_t res;
    struct fuse_bufvec outbufv = {
        .count = 1,
        .idx = 0,
        .off = 0,
        .buf[0] =
            {
                .size = inode->size - off,
                .flags = 0,
                .mem = inode->content + off,
            },
    };

    inode->changed_content = 1;
    if (inode->mode & (S_ISUID | S_ISGID)) {
        inode->changed_mode = 1;
        inode->mode &= ~(S_ISUID | S_ISGID);
    }

    res = fuse_buf_copy(&outbufv, bufv, 0);

    stop_writing(data);

    if (res < 0) {
        fuse_reply_err(req, -res);
    } else {
        struct ramcachefs_file_info* rfi = (struct ramcachefs_file_info*)fi->fh;
        if (off + bufv->buf[0].size > rfi->max_written) {
            rfi->max_written = off + bufv->buf[0].size;
        }
        fuse_reply_write(req, (size_t)res);
    }
}

static const struct fuse_lowlevel_ops ramcachefs_ops = {
    .copy_file_range = ramcachefs_copy_file_range,
    .create = ramcachefs_create,
    .forget = ramcachefs_forget,
    .forget_multi = ramcachefs_forget_multi,
    .getattr = ramcachefs_getattr,
    .init = ramcachefs_init,
    .ioctl = ramcachefs_ioctl,
    .lookup = ramcachefs_lookup,
    .mkdir = ramcachefs_mkdir,
    .mknod = ramcachefs_mknod,
    .open = ramcachefs_open,
    .opendir = ramcachefs_opendir,
    .read = ramcachefs_read,
    .readdir = ramcachefs_readdir,
    .readdirplus = ramcachefs_readdirplus,
    .readlink = ramcachefs_readlink,
    .release = ramcachefs_release,
    .rename = ramcachefs_rename,
    .rmdir = ramcachefs_rmdir,
    .setattr = ramcachefs_setattr,
    .statfs = ramcachefs_statfs,
    .symlink = ramcachefs_symlink,
    .unlink = ramcachefs_unlink,
    .write_buf = ramcachefs_write_buf,
};

int main(int argc, char* argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_cmdline_opts fuse_opts;
    int res = 1;

    umask(0);

    if (fuse_parse_cmdline(&args, &fuse_opts)) {
        return 1;
    }

    if (fuse_opt_add_arg(&args, "-o") || fuse_opt_add_arg(&args, "default_permissions,fsname=ramcachefs")) {
        fuse_log(FUSE_LOG_ERR, "can't allocate memory: %m\n");
        goto out1;
    }

    if (fuse_opts.show_version) {
        printf("FUSE library version %s\n", fuse_pkgversion());
        fuse_lowlevel_version();
        res = 0;
        goto out1;
    }

    if (fuse_opts.show_help) {
        printf("usage: %s [options] <mountpoint>\n\n", argv[0]);
        printf("    -p   --trigger-persist trigger persist\n");
        fuse_cmdline_help();
        fuse_lowlevel_help();
        printf("    -o maxinodes=NUMBER    maximum number of inodes (default: '1000000')\n");
        printf("    -o noautopersist       do not persist on unmount\n");
#ifndef DONT_USE_MMAP
        printf("    -o prepopulate         read full files at start (prepopulate mmaps)\n");
#endif
        printf("    -o size=SIZE           size (default: '1G')\n");
        res = 0;
        goto out1;
    }

    if (!fuse_opts.show_help && !fuse_opts.mountpoint) {
        fuse_log(FUSE_LOG_ERR, "no mountpoint specified\n");
        goto out1;
    }

    struct ramcachefs_opts opts;
    memset(&opts, 0, sizeof(struct ramcachefs_opts));
    opts.max_inodes = 1000000; /* default value */

    if (fuse_opt_parse(&args, &opts, ramcachefs_opts, NULL) < 0) {
        goto out1;
    }

    if (opts.trigger_persist) {
        int fd = open(fuse_opts.mountpoint, O_RDONLY);
        if (fd < 0) {
            fuse_log(FUSE_LOG_ERR, "can't open `%s': %m\n", fuse_opts.mountpoint);
        } else {
            if (ioctl(fd, RAMCACHEFS_TRIGGER_PERSIST)) {
                if (errno) {
                    fuse_log(FUSE_LOG_ERR, "can't ioctl on `%s': %m\n", fuse_opts.mountpoint);
                } else {
                    fuse_log(FUSE_LOG_ERR, "an error occured persisting `%s'\n", fuse_opts.mountpoint);
                }
            } else {
                res = 0;
            }
            close(fd);
        }
        goto out1;
    }

    char* absmountpoint = realpath(fuse_opts.mountpoint, NULL);
    if (!absmountpoint) {
        fuse_log(FUSE_LOG_ERR, "can't get realpath to `%s': %m\n", fuse_opts.mountpoint);
        goto out1;
    }

    struct ramcachefs_data data;
    memset(&data, 0, sizeof(struct ramcachefs_data));
    pthread_mutex_init(&data.writers_mutex, NULL);
    pthread_mutex_init(&data.persist_mutex, NULL);
    pthread_mutex_init(&data.node_mutex, NULL);

    size_t size = 1024 * 1024 * 1024; /* default: 1G */
    if (opts.size) {
        char* end = opts.size;
        errno = 0;
        size = strtoul(opts.size, &end, 10);
        if (errno || end == opts.size || (end[0] != '\0' && end[1] != '\0')) {
            fuse_log(FUSE_LOG_ERR, "invalid size value: %s\n", opts.size);
            goto out1;
        }
        switch (*end) {
            case 'k':
                size *= 1024;
                break;
            case 'M':
                size *= 1024 * 1024;
                break;
            case 'G':
                size *= 1024 * 1024 * 1024;
                break;
            case 0:
                break;
            default:
                fuse_log(FUSE_LOG_ERR, "invalid size value: %s\n", opts.size);
                goto out1;
        }
        free(opts.size);
    }
    data.block_size = sysconf(_SC_PAGESIZE);
    data.prepopulate = opts.prepopulate;
    data.max_inodes = opts.max_inodes;
    data.max_blocks = (size + data.block_size - 1) / data.block_size;
    data.free_blocks = data.max_blocks;
    data.free_inodes = data.max_inodes - 1; /* count root inode */

    data.orig_root_fd = open(fuse_opts.mountpoint, O_PATH | O_RDWR);
    if (data.orig_root_fd < 0) {
        fuse_log(FUSE_LOG_ERR, "can't open `%s': %m\n", fuse_opts.mountpoint);
        goto out1;
    }

    struct fuse_session* session = fuse_session_new(&args, &ramcachefs_ops, sizeof(ramcachefs_ops), &data);
    if (!session) {
        goto out1;
    }

    if (fuse_set_signal_handlers(session)) {
        goto out2;
    }

    if (fuse_session_mount(session, fuse_opts.mountpoint)) {
        goto out3;
    }

    int fd = openat(data.orig_root_fd, ".", O_DIRECTORY | O_NOFOLLOW | O_RDONLY);
    if (fd < 0) {
        fuse_log(FUSE_LOG_ERR, "can't open `%s': %m\n", fuse_opts.mountpoint);
        goto out4;
    }

    DIR* dir = fdopendir(fd);
    if (!dir) {
        fuse_log(FUSE_LOG_ERR, "can't open `%s' using fdopendir: %m\n", fuse_opts.mountpoint);
        goto out4;
    }

    struct stat stbuf;
    if (fstat(dirfd(dir), &stbuf)) {
        fuse_log(FUSE_LOG_ERR, "can't stat `%s': %m\n", fuse_opts.mountpoint);
        goto out4;
    }

    data.root = alloc_inode("(root)", &stbuf);
    data.root->ino = FUSE_ROOT_ID;
    data.root->orig_name = absmountpoint;

    if (cache_dir_unsafe(&data, data.root, dir)) {
        closedir(dir);
        goto out4;
    }
    closedir(dir);

    if (fuse_daemonize(fuse_opts.foreground)) {
        goto out4;
    }

#ifdef DEBUG
    if (fuse_opts.debug) {
        fuse_log(FUSE_LOG_DEBUG, "size of ramcachefs_inode: %ld bytes\n", sizeof(struct ramcachefs_inode));
        data.debug = 1;
        fuse_opts.singlethread = 1; /* force single threaded operations when debugging */
    }
#endif

    if (fuse_opts.singlethread) {
        res = fuse_session_loop(session);
    } else {
        struct fuse_loop_config config = {
            .clone_fd = fuse_opts.clone_fd,
            .max_idle_threads = fuse_opts.max_idle_threads  //
        };
        res = fuse_session_loop_mt(session, &config);
    }

out4:
    fuse_session_unmount(session);

    if (!res && !opts.noautopersist) {
        if (persist(&data)) {
            fuse_log(FUSE_LOG_ERR, "persist failed\n");
            res = 1;
        }
    }

    if (data.root) {
        free_inode(data.root);
    }
out3:
    fuse_remove_signal_handlers(session);
out2:
    fuse_session_destroy(session);
out1:
    free(fuse_opts.mountpoint);
    fuse_opt_free_args(&args);

    if (data.orig_root_fd >= 0) {
        close(data.orig_root_fd);
    }

    return res;
}
