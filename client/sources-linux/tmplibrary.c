#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <link.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

#include "list.h"
#include "tmplibrary.h"
#include "debug.h"

#ifdef Linux
#include "memfd.h"
#endif

#include "decompress.h"

extern char **environ;

/*

  So.. We don't want to bother with reflective bla-bla-bla. Just
  upload buffer to temporary file, load it as a library using standard
  glibc calls, then delete

*/

// gettemptpl gets the first effective 
// template for drop_library
static inline
const char *gettemptpl() {
    static const char *templates[] = {
#ifdef Linux
        "/dev/shm/XXXXXX",
        "/run/shm/XXXXXX",
        "/run/",
#endif
        "/tmp/XXXXXX",
        "/var/tmp/XXXXXX",
        NULL
    };

    static const char *tmpdir = NULL;
    // weird check... but okay
    if (! tmpdir) {
        int i;
	// for each template
        for (i=0; templates[i]; i++) {
	    // allocate some memory for the 
	    // current template
            char *buf = alloca(strlen(templates[i]+1));

	    // copy the template over
            strcpy(buf, templates[i]);

	    // get a filedesc for a tempfile
            int fd = mkstemp(buf);

            int found = 0;
            if (fd != -1) {
		// get the page size for mem on system
                int page_size = sysconf(_SC_PAGESIZE);

		// truncate the tempfile to the memory 
		// page size for memory mapping
                if (ftruncate(fd, page_size) != -1) {
		    // assuming this doesn't 
		    // fail we map some memory
		    // to test the file location
                    void *map = mmap(
                        NULL,
                        page_size,
                        PROT_READ|PROT_EXEC,
#ifdef Linux
                        MAP_PRIVATE|MAP_DENYWRITE,
#else
                        MAP_PRIVATE,
#endif
                        fd,
                        0
                    );
		    // if map failed
		    // then fail the 
		    // template check
                    if (map != MAP_FAILED) {
                        munmap(map, page_size);
                        found = 1;
                    } else {
                        dprint("Couldn't use %s -> %m\n", buf);
                    }
                }

		// destroy our 
		// test file
                unlink(buf);
                close(fd);

                if (found) {
                    tmpdir = templates[i];
                    break;
                }
            }
            dprint("TRY: %s -> %d (%m)\n", buf, fd);

        }
        if (!tmpdir) {
	    // if we can't find a viable 
	    // temp dir, freak out and 
	    // panic
            abort();
        }
    }
    // we return the successful template
    return tmpdir;
}

typedef struct library {
    const char *name;
    void *base;
} library_t;
// helper function for something 100loc down
// this finds the library in the list
//
// this is also a callback function called each
// element in the list
//
// wait a minute, this smells like a closure
// you know, without first class functions... kinda
// c is weird
bool search_library(void *pState, void *pData) {
    library_t *search = (library_t *) pState;
    library_t *current = (library_t *) pData;

    // if the current element name is the search element name
    // set the search base to the current base (reloc addr)
    if (!strcmp(search->name, current->name)) {
        search->base = current->base;
        dprint("FOUND! %s = %p\n", search->name, search->base);

        return true;
    }

    return false;
}

int drop_library(char *path, size_t path_size, const char *buffer, size_t size) {

/* this section just gets somewhere to write */
#if defined(Linux)
    int fd = pupy_memfd_create(path, path_size);
    bool memfd = true;
#elif defined(SunOS)
    char tmp[PATH_MAX] = {};
    snprintf(tmp, sizeof(tmp), "/tmp/%s", path);
    int fd = open(tmp, O_CREAT | O_RDWR, 0600);
    strncpy(path, tmp, path_size);
    bool memfd = false;
#else
    int fd = -1;
    bool memfd = false;
#endif

/* got fd (if memfd worked */

    // if no memfd go with an 
    // tempfile drop
    if (fd < 0) {
        dprint("pupy_memfd_create() failed: %m\n");
        memfd = false;

        const char *template = gettemptpl();

        if (path_size < strlen(template))
            return -1;

        strcpy(path, template);

        fd = mkstemp(path);
        if (fd < 0) {
            return fd;
        }
    }

    // if the buffer we got is compressed
    // decompress it and write to out
    // the fd we got
    if (size > 2 && buffer[0] == '\x1f' && buffer[1] == '\x8b') {
        dprint("Decompressing library %s\n", path);
        int r = decompress(fd, buffer, size);
        if (!r == 0) {
            dprint("Decompress error: %d\n", r);
            close(fd);
            return -1;
        }
    // if we got uncompressed data
    // write it straight up
    } else {
        while (size > 0) {
            size_t n = write(fd, buffer, size);
            if (n == -1) {
                dprint("Write failed: %d left, error = %m, buffer = %p, tmpfile = %s\n", size, buffer, path);
                close(fd);
                unlink(path);
                fd = -1;
                break;
            }
	    // write till done
            buffer += n;
            size -= n;
        }
    }

#ifdef Linux
    if (memfd) {
	// if we are on linux and can memfd, then seal file writing (prevent)
        fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
    }
#endif

    return fd;
}

// helper function to set cloexec flag
// (which closes the exe fd on execution)
static inline int
set_cloexec_flag (int desc) {
    int oldflags = fcntl (desc, F_GETFD, 0);
    if (oldflags < 0)
        return oldflags;
    oldflags |= FD_CLOEXEC;
    return fcntl (desc, F_SETFD, oldflags);
}

// this executes a plain elf exe in memory (or tempfd)
pid_t memexec(const char *buffer, size_t size, const char* const* argv, int stdior[3], bool redirected_stdio, bool detach) {
    dprint("memexec(%p, %ull, %d)\n", buffer, size, redirected_stdio);

    char buf[PATH_MAX]={};
    // get a fd for loading use
    int fd = drop_library(buf, sizeof(buf), buffer, size);
    if (fd < 0) {
        dprint("Couldn't drop executable: %m\n");
        return -1;
    }

    // define some pipes for use
    // later
    int p_wait[2];
    int p_stdin[2];
    int p_stdout[2];
    int p_stderr[2];

    // get a pipe for communication
    // between the cradle fork proc 
    // and the parent proc
    if (pipe(p_wait) < 0) {
        dprint("Couldn't create wait pipe: %m\n");
        goto _lbClose;
    }

    // if we are redirecting 
    // then create the pipes
    // for them as well
    if (redirected_stdio) {
        if (pipe(p_stdin) < 0)
            goto _lbClose0;

        if (pipe(p_stdout) < 0)
            goto _lbClose1;

        if (pipe(p_stderr) < 0)
            goto _lbClose2;
    }

    pid_t pid = 0;
    // if we are detaching the
    // process we then
    // go ahead with a fork now
    // as to make it so our
    // child process will handle
    // it's connection to the 
    // child child process that
    // will then fork&exec 
    if (detach) {
        pid = fork();
        if (pid == -1) {
            dprint("Couldn't fork: %m\n");
            goto _lbClose3;
        }
    }

    // if we are the child (pid 0)
    if (!pid) {
	// call fork again :|
        pid = fork();
        if (pid == -1) {
            exit(1);
        }
	// if we are the parent then
	// write the pid to the child
	// with the wait-pipe
        if (pid) {
            if (detach) {
                write(p_wait[1], &pid, sizeof(pid));
                exit(0);
            }
	// otherwise we are the child
	// and we set up the execution
	// enviroment
        } else {
            if (redirected_stdio) {
		// set the read side of the pipe
		// to stdin and close the write end
                dup2(p_stdin[0], 0);  close(p_stdin[1]);
		// for the stdout,err side we set the 
		// write end as our end of the pipe 
		// and close the read side of the pipe
                dup2(p_stdout[1], 1); close(p_stdout[0]);
                dup2(p_stderr[1], 2); close(p_stderr[0]);
		// then we close the wait pipes read side 
		// as we will be writing the exec'd procs
		// errors to it
                close(p_wait[0]);
            } else {
		// otherwise we do some
		// tomfoolery that results
		// in stdin being the fd
		// for std in?
		// I don't know - this is a guess
                int i;

                if (setsid ( ) == -1)
                    return -1;

		// oh yeah, and we close everything that
		// is not the p-wait pipe
                for (i = 0; i < sysconf(_SC_OPEN_MAX); i++)
                    if (i != p_wait[1])
                        close(i);

                open ("/dev/null", O_RDWR);
                dup (0);
                dup (0);
            }
		
	    // we set the cloexec flag
	    // on the write side of the
	    // wait pipe
            set_cloexec_flag(p_wait[1]);

	    // actually execute the binary
	    // causing this child's image
	    // to be the exe'd process,
	    // execpt the dup'd file desciptors 
            execv(buf, (char *const *) argv);

            int status = errno;
	    // now we write any errors back to the
	    // parent
            write(p_wait[1], &status, sizeof(status));
	    // then we exit the cradle process
            exit(1);
        }
    }

    // back to this proc (parent)
    // we close the write side of wait
    close(p_wait[1]);
    p_wait[1] = -1;

    int status = 0;
    int error = 0;
    pid_t child_pid = 0;

    // if we are detaching
    if (detach) {
	// read the pid 
	// from the child cradle proc
        if (read(p_wait[0], &child_pid, sizeof(child_pid)) < 0) {
            dprint("Reading child pid failed: %m\n");
            goto _lbClose3;
        }

	// wait for the process to exit
        if (waitpid(pid, &status, 0) < 0 || WEXITSTATUS(status) != 0) {
            dprint("Invalid child state\n");
            goto _lbClose3;
        }

        dprint("Detached pid catched and closed: %d status=%d\n",
               pid, WEXITSTATUS(status));
    } else {
        child_pid = pid;
    }

    dprint("Wait exec status...\n");

    // now read the error value of the
    // executed process
    if (read(p_wait[0], &error, sizeof(error)) < 0) {
        dprint("Reading error failed: %m\n");
        goto _lbClose3;
    }

    dprint("Child error status: %d (%d)\n", error, errno);
    if (error)
        goto _lbClose3;

    // clean up the 
    // redirected fds
    dprint("Child at %d\n", child_pid);
    if (redirected_stdio) {
        close(p_stdin[0]);  stdior[0] = p_stdin[1];
        close(p_stdout[1]); stdior[1] = p_stdout[0];
        close(p_stderr[1]); stdior[2] = p_stderr[0];
    }

    close(p_wait[0]);
    close(fd);

#ifdef Linux
    if (!is_memfd_path(buf))
#endif
    unlink(buf);
    return child_pid;

 _lbClose3:
    if (redirected_stdio) {
        close(p_stderr[0]); close(p_stderr[1]);
    }
 _lbClose2:
    if (redirected_stdio) {
        close(p_stdout[0]); close(p_stdout[1]);
    }
 _lbClose1:
    if (redirected_stdio) {
        close(p_stdin[0]); close(p_stdin[1]);
    }
 _lbClose0:
    if (p_wait[0] > 0)
        close(p_wait[0]);
    if (p_wait[1] > 0)
        close(p_wait[1]);

 _lbClose:
    close(fd);
    unlink(buf);

    dprint("Exited with error\n");
    return -1;
}

#if defined(SunOS)
// For some unknown reason malloc doesn't work on newly created LM in Solaris 10
// Fallback to old shitty way of loading libs
// TODO: write own ELF loader
static void *_dlopen(int fd, const char *path, int flags, const char *soname) {
    void *handle = dlopen(path, flags | RTLD_PARENT | RTLD_GLOBAL);
    if (fd != -1) {
        unlink(path);
        close(fd);
    }
    return handle;
}
#elif defined(LM_ID_NEWLM) && defined(Linux)

// Part of private link_map structure

struct libname_list;

struct libname_list {
    char *name;
    struct libname_list *next;
    int dont_free;
};

struct link_map_private;

/* Dangerous! Hacked link_map structure */
struct link_map_private {
    void *l_addr;
    char *l_name;
    void *l_ld;
    struct link_map_private *l_next, *l_prev;

    /* ------------- private part starts here ----------------- */

    struct link_map_private *l_real; // dlmopen
    Lmid_t l_ns;                     // dlmopen
    struct libname_list *l_libname;  // ancient

    /* ------------- .... and there much more ----------------- */


};

// internal memory exec enabled version of dlopen
static void *_dlopen(int fd, const char *path, int flags, const char *soname) {
    void *handle = NULL;
// if we are using a linkmap to 
// supplement our call define it
// and get the handle 
#if defined(WIP_LMID)
    static Lmid_t lmid = LM_ID_NEWLM;

    flags &= ~RTLD_GLOBAL;

    if ((flags & RTLD_NOLOAD) && (lmid == LM_ID_NEWLM))
	    return NULL;

    handle = dlmopen(lmid, path, flags);
    if (lmid == LM_ID_NEWLM && handle) {
        dlinfo(handle, RTLD_DI_LMID, &lmid);
        dprint("memdlopen - dlmopen - new lmid created: %08x\n", lmid);
    }
// otherwise we use a normal dlopen
#else
    static Lmid_t lmid = LM_ID_BASE;
    handle = dlopen(path, flags);
#endif

    dprint("memdlopen - dlmopen - _dlopen(lmid=%08x, %s, %s)\n", lmid, path, soname);

    // if we are useing noload and a handle
    // exits return the handle
    if (flags & RTLD_NOLOAD || !handle) {
        return handle;
    }

    // check and see if we can memfd
    bool is_memfd = is_memfd_path(path);
    bool linkmap_hacked = false;

    if (soname) {
        struct link_map_private *linkmap = NULL;
        dlinfo(handle, RTLD_DI_LINKMAP, &linkmap);
        /* If memfd, then try to verify as best as possible that all that
           addresses are valid. If not - there is no reason to touch this
        */

        if (is_memfd) {
	    // if we can memfd set up the linkmap (TODO: more detail)
            if (linkmap && linkmap->l_ns == lmid &&
                linkmap->l_libname && linkmap->l_libname->name &&
                !strncmp(linkmap->l_name, linkmap->l_libname->name, strlen(linkmap->l_name))) {

                dprint("memdlopen - change l_name %s/%p (%s/%p) -> %s (linkmap: %p)\n",
                       linkmap->l_name, linkmap->l_name,
                       linkmap->l_libname->name,
                       linkmap->l_libname->name,
                       soname, linkmap);

                /* Do not care about leaks. It's not the worst thing to happen */
                linkmap->l_name = strdup(soname);
                linkmap->l_libname->name = strdup(soname);

                linkmap_hacked = true;
            } else {
                dprint("memdlopen - bad signature (lmid=%08x name1=%s name2=%s)\n",
                       linkmap->l_ns, linkmap->l_name, linkmap->l_libname->name);
            }
        }

        if (!is_memfd || linkmap_hacked) {
            /* If linkmap altered or it's not memfd, then delete/close path/fd */
            if (!is_memfd)
                unlink(path);

            close(fd);
        }
    }

    return handle;
}
#else

/* Linux x86 or any other thing */

static void *_dlopen(int fd, const char *path, int flags, const char *soname) {

    /* Try to fallback to symlink hack */

    bool is_memfd = is_memfd_path(path);
    char fake_path[PATH_MAX] = {};

    const char *effective_path = path;

    static const char DROP_PATH[] = "/dev/shm/memfd:";

    // if we can use mem file descriptors
    if (is_memfd) {
        int i;

	// append sopath to the 
	// /dev/shm/memfd: string
        snprintf(fake_path, sizeof(fake_path), "%s%s", DROP_PATH, soname);
        for (i=sizeof(DROP_PATH)-1; fake_path[i]; i++)
	    // replace / with !
            if (fake_path[i] == '/')
                fake_path[i] = '!';

	// if we cannot symlink then
	// we decare this non memfd able
        if (!symlink(path, fake_path)) {
            effective_path = fake_path;
            is_memfd = false;
        } else {
            dprint("symlink error %s -> %s: %m\n", path, fake_path);
        }
    }

    // now we use real dlopen to open our
    // found temp or memfd path
    void *handle = dlopen(effective_path, flags);
    if (fd != -1) {
        unlink(effective_path);

        /*
          If all workarounds failed we have nothing to do but leave this as
          is */
        if (!is_memfd)
            close(fd);
    }
    return handle;
}
#endif


// this one is pretty critical
// This implements the list search of 
// currently loaded modules and
// loads new modules (used by
// import_module) later
void *memdlopen(const char *soname, const char *buffer, size_t size) {
    dprint("memdlopen(\"%s\", %p, %ull)\n", soname, buffer, size);

    // internally implmenented list
    // data structure
    static PLIST libraries = NULL;
    if (!libraries) {
        libraries = list_create();
    }

    // create our search entry
    library_t search = {
        .name = soname,
        .base = NULL,
    };

    // if the library id found the search_library callback 
    // sets search.base to the handle (base addr of) the
    // already loaded module
    if (list_enumerate(libraries, search_library, &search)) {
        dprint("SO %s FOUND: %p\n", search.name, search.base);
        return search.base;
    }

    // call our internal dlopen (arch dependent)
    void *base = _dlopen(-1, soname, RTLD_NOLOAD, NULL);
    if (base) {
        dprint("Library \"%s\" loaded from OS\n", soname);
        return base;
    }

    char buf[PATH_MAX]={};

#if defined(DEBUG) || defined(SunOS)
    if (soname)
        strncpy(buf, soname, sizeof(buf)-1);
#endif

    // if that all didn't work, then we have to 
    // resort to a tempfile 
    int fd = drop_library(buf, sizeof(buf)-1, buffer, size);

    if (fd < 0) {
        dprint("Couldn't drop library %s: %m\n", soname);
        return NULL;
    }

    int flags = RTLD_NOW | RTLD_LOCAL;

    // call out dlopen on the tempfile
    dprint("dlopen(%s, %08x)\n", buf, flags);
    base = _dlopen(fd, buf, flags, soname);
    dprint("dlopen(%s, %08x) = %p\n", buf, flags, base);

    if (!base) {
        dprint("Couldn't load library %s (%s): %s\n", soname, buf, dlerror());
        return NULL;
    }

    dprint("Library %s loaded to %p\n", soname, base);

    // add new entry to loaded files and return handle
    library_t *record = (library_t *) malloc(sizeof(library_t));
    record->name = strdup(soname);
    record->base = base;
    list_add(libraries, record);
    return base;
}
