/*
 * minicontainer_final.c
 * Lightweight Container System (Mini Docker) - Final Production Version
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <ncurses.h>
#include <limits.h>
#include <stdarg.h>

// Constants
#define MAX_CONTAINERS 50
#define MAX_NAME_LEN 64
#define MAX_CMD_LEN 256
#define MAX_ARGS 32
#define STACK_SIZE (1024 * 1024)
#define CONTAINER_DIR "/tmp/minicontainer"
#define CGROUP_BASE "/sys/fs/cgroup"

// Container states
typedef enum {
    STATE_CREATED,
    STATE_RUNNING,
    STATE_STOPPED,
    STATE_EXITED
} ContainerState;

// Container structure
typedef struct {
    char name[MAX_NAME_LEN];
    pid_t pid;
    ContainerState state;
    int cpu_limit;
    int memory_limit;
    time_t created_time;
    time_t start_time;
    char command[MAX_CMD_LEN];
    int exit_code;
} Container;

// Global container registry
static Container containers[MAX_CONTAINERS];
static int container_count = 0;
static int cgroup_v2 = 0;
static int verbose = 0;

// Function prototypes
void init_system();
void cleanup_system();
void setup_rootfs();
int create_container(const char *name);
int run_container(const char *name, char **args, int cpu_limit, int memory_limit, int detach);
int exec_container(const char *name, char **args);
int stop_container(const char *name);
int remove_container(const char *name);
int list_containers();
void show_stats(const char *name);
void show_logs(const char *name);
void monitor_dashboard();
Container* find_container(const char *name);
int setup_cgroup(const char *name, int cpu_limit, int memory_limit, pid_t pid);
void cleanup_cgroup(const char *name);
int container_init(void *arg);
void print_help();
int load_containers();
int save_containers();
void log_message(const char *level, const char *format, ...);

// Argument structure for container init
typedef struct {
    char **args;
    char name[MAX_NAME_LEN];
    int cpu_limit;
    int memory_limit;
    int is_exec;
} ContainerArgs;

// Utility functions
static int is_dir(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int is_file(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int mkdir_recursive(const char *path, mode_t mode) {
    char tmp[PATH_MAX];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (len == 0) return -1;
    if (tmp[len - 1] == '/') tmp[len - 1] = 0;

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, mode) == -1 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) == -1 && errno != EEXIST) return -1;
    return 0;
}

static void detect_cgroup_version() {
    char path[256];
    snprintf(path, sizeof(path), "%s/cgroup.controllers", CGROUP_BASE);
    cgroup_v2 = (access(path, F_OK) == 0) ? 1 : 0;
}

static int write_str_to_file(const char *path, const char *val) {
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;
    int rc = fprintf(fp, "%s", val);
    fclose(fp);
    return (rc < 0) ? -1 : 0;
}

void log_message(const char *level, const char *format, ...) {
    va_list args;
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    printf("[%s] [%s] ", timestamp, level);
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}

/*
 * Setup a minimal rootfs for containers
 * Creates essential directories and copies basic binaries
 */
void setup_rootfs() {
    char rootfs[512];
    snprintf(rootfs, sizeof(rootfs), "%s/rootfs", CONTAINER_DIR);

    if (is_dir(rootfs)) {
        return;
    }

    log_message("INFO", "Creating minimal rootfs structure...");

    // Create essential directories (empty mount points)
    char path[512];
    const char *dirs[] = {
        "bin", "sbin", "lib", "lib64", "usr", "etc", "proc", "sys", "dev", "tmp", "root", "home", "var", NULL
    };

    for (int i = 0; dirs[i]; i++) {
        snprintf(path, sizeof(path), "%s/%s", rootfs, dirs[i]);
        mkdir_recursive(path, 0755);
    }
    
    // Copy custom workload if it exists in current directory (we still copy this one)
    if (access("workload", F_OK) == 0) {
        snprintf(path, sizeof(path), "%s/bin", rootfs);
        mkdir_recursive(path, 0755);
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "cp workload %s/bin/ 2>/dev/null", rootfs);
        system(cmd);
    }

    log_message("SUCCESS", "Rootfs structure created at %s", rootfs);
}



void init_system() {
    struct stat st = {0};

    // Create container directory
    if (stat(CONTAINER_DIR, &st) == -1) {
        if (mkdir(CONTAINER_DIR, 0755) == -1) {
            log_message("ERROR", "Failed to create container directory: %s", strerror(errno));
            exit(1);
        }
    }

    // Setup rootfs
    setup_rootfs();

    // Detect cgroup version
    detect_cgroup_version();

    // Load existing containers
    load_containers();

    log_message("INFO", "Container system initialized (cgroup_v%d)", cgroup_v2 ? 2 : 1);
}

void cleanup_system() {
    save_containers();
    log_message("INFO", "Container system cleaned up");
}

int create_container(const char *name) {
    if (container_count >= MAX_CONTAINERS) {
        log_message("ERROR", "Maximum container limit (%d) reached", MAX_CONTAINERS);
        return -1;
    }

    if (find_container(name) != NULL) {
        log_message("ERROR", "Container '%s' already exists", name);
        return -1;
    }

    Container *cont = &containers[container_count];
    strncpy(cont->name, name, MAX_NAME_LEN - 1);
    cont->name[MAX_NAME_LEN - 1] = '\0';
    cont->pid = 0;
    cont->state = STATE_CREATED;
    cont->cpu_limit = 100;
    cont->memory_limit = 512;
    cont->created_time = time(NULL);
    cont->start_time = 0;
    cont->command[0] = '\0';
    cont->exit_code = 0;

    container_count++;
    save_containers();

    log_message("SUCCESS", "Container '%s' created", name);
    return 0;
}

/*
 * Container initialization function (runs inside all namespaces)
 */
// Global variable for signal handling in PID 1
volatile sig_atomic_t stop_requested = 0;

void handle_sigterm(int sig) {
    stop_requested = 1;
}

int container_init(void *arg) {
    ContainerArgs *cargs = (ContainerArgs *)arg;

    // Setup signal handling for PID 1
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigterm;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    if (cargs->is_exec) {
        if (cargs->args && cargs->args[0]) {
            execvp(cargs->args[0], cargs->args);
            perror("execvp in exec mode");
        }
        exit(1);
    }

    // Full container initialization
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        if (verbose) perror("mount private");
    }

    // Change to rootfs
    char rootfs[512];
    snprintf(rootfs, sizeof(rootfs), "%s/rootfs", CONTAINER_DIR);

    if (is_dir(rootfs)) {
        // BIND MOUNT HOST DIRECTORIES (The Fix)
        struct { const char *src; const char *dst; } mounts[] = {
            {"/bin", "bin"}, {"/sbin", "sbin"}, {"/lib", "lib"}, 
            {"/lib64", "lib64"}, {"/usr", "usr"}, {NULL, NULL}
        };

        for (int i = 0; mounts[i].src; i++) {
            char dst_path[512];
            snprintf(dst_path, sizeof(dst_path), "%s/%s", rootfs, mounts[i].dst);
            if (access(mounts[i].src, F_OK) == 0) {
                if (mount(mounts[i].src, dst_path, NULL, MS_BIND | MS_REC | MS_RDONLY, NULL) == -1) {
                    if (verbose) perror("bind mount failed");
                }
            }
        }

        if (chdir(rootfs) == -1) {
            perror("chdir rootfs");
            exit(1);
        }

        if (chroot(".") == -1) {
            perror("chroot");
            exit(1);
        }

        if (chdir("/") == -1) {
            perror("chdir /");
            exit(1);
        }
    }

    // Mount essential filesystems
    mkdir("/proc", 0555);
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) == -1) {
        if (verbose) perror("mount /proc");
    }

    mkdir("/sys", 0555);
    if (mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) == -1) {
        if (verbose) perror("mount /sys");
    }

    mkdir("/dev", 0755);
    mkdir("/tmp", 0777);
    if (mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "size=64m") == -1) {
        if (verbose) perror("mount /tmp");
    }

    // Set hostname
    if (sethostname(cargs->name, strlen(cargs->name)) == -1) {
        if (verbose) perror("sethostname");
    }

    // Set environment
    setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 1);
    setenv("HOME", "/root", 1);
    setenv("TERM", "xterm", 1);
    setenv("CONTAINER", cargs->name, 1);

    // Execute the command via fork/exec to keep PID 1 alive
    pid_t child_pid = fork();
    if (child_pid == -1) {
        perror("fork");
        exit(1);
    }

    if (child_pid == 0) {
        // Child process: execute the user command
        if (cargs->args && cargs->args[0]) {
            execvp(cargs->args[0], cargs->args);
            perror("execvp");
        } else {
            char *shell_argv[] = {"/bin/sh", NULL};
            execv("/bin/sh", shell_argv);
            perror("exec shell");
        }
        exit(1);
    }

    // Parent (PID 1): Wait for child and handle signals
    int status;
    while (1) {
        int ret = waitpid(child_pid, &status, 0);
        if (ret == -1) {
            if (errno == EINTR) {
                if (stop_requested) {
                    // Forward SIGTERM to child
                    kill(child_pid, SIGTERM);
                    // Wait for it to die
                    waitpid(child_pid, &status, 0);
                    break;
                }
                continue;
            }
            break;
        }
        if (ret == child_pid) break; // Child exited
    }

    umount2("/proc", MNT_DETACH);
    umount2("/sys", MNT_DETACH);
    umount2("/tmp", MNT_DETACH);
    
    // Propagate exit code
    if (WIFEXITED(status)) exit(WEXITSTATUS(status));
    exit(1);
}

int setup_cgroup(const char *name, int cpu_limit, int memory_limit, pid_t pid) {
    char path[512];
    char value[128];

    if (cgroup_v2) {
        snprintf(path, sizeof(path), "%s/minicontainer_%s", CGROUP_BASE, name);
        if (mkdir(path, 0755) == -1 && errno != EEXIST) {
            log_message("WARN", "Failed to create cgroup v2: %s", strerror(errno));
            return -1;
        }

        if (cpu_limit < 100) {
            long period = 100000;
            long max = (long)((cpu_limit / 100.0) * period);
            if (max < 1) max = 1;
            snprintf(value, sizeof(value), "%ld %ld", max, period);
        } else {
            snprintf(value, sizeof(value), "max 100000");
        }
        snprintf(path, sizeof(path), "%s/minicontainer_%s/cpu.max", CGROUP_BASE, name);
        write_str_to_file(path, value);

        long long bytes = (long long)memory_limit * 1024LL * 1024LL;
        snprintf(value, sizeof(value), "%lld", bytes);
        snprintf(path, sizeof(path), "%s/minicontainer_%s/memory.max", CGROUP_BASE, name);
        write_str_to_file(path, value);

        snprintf(value, sizeof(value), "%d", pid);
        snprintf(path, sizeof(path), "%s/minicontainer_%s/cgroup.procs", CGROUP_BASE, name);
        write_str_to_file(path, value);

    } else {
        snprintf(path, sizeof(path), "%s/cpu/minicontainer_%s", CGROUP_BASE, name);
        if (mkdir(path, 0755) == -1 && errno != EEXIST) {
            log_message("WARN", "Failed to create CPU cgroup: %s", strerror(errno));
        }

        if (cpu_limit < 100) {
            snprintf(value, sizeof(value), "%d", cpu_limit * 1000);
            snprintf(path, sizeof(path), "%s/cpu/minicontainer_%s/cpu.cfs_quota_us", CGROUP_BASE, name);
            write_str_to_file(path, value);
            snprintf(path, sizeof(path), "%s/cpu/minicontainer_%s/cpu.cfs_period_us", CGROUP_BASE, name);
            write_str_to_file(path, "100000");
        }

        snprintf(value, sizeof(value), "%d", pid);
        snprintf(path, sizeof(path), "%s/cpu/minicontainer_%s/tasks", CGROUP_BASE, name);
        write_str_to_file(path, value);

        snprintf(path, sizeof(path), "%s/memory/minicontainer_%s", CGROUP_BASE, name);
        if (mkdir(path, 0755) == -1 && errno != EEXIST) {
            log_message("WARN", "Failed to create memory cgroup: %s", strerror(errno));
        }

        long long bytes = (long long)memory_limit * 1024LL * 1024LL;
        snprintf(value, sizeof(value), "%lld", bytes);
        snprintf(path, sizeof(path), "%s/memory/minicontainer_%s/memory.limit_in_bytes", CGROUP_BASE, name);
        write_str_to_file(path, value);

        snprintf(value, sizeof(value), "%d", pid);
        snprintf(path, sizeof(path), "%s/memory/minicontainer_%s/tasks", CGROUP_BASE, name);
        write_str_to_file(path, value);
    }

    return 0;
}

void cleanup_cgroup(const char *name) {
    char path[512];

    if (cgroup_v2) {
        snprintf(path, sizeof(path), "%s/minicontainer_%s", CGROUP_BASE, name);
        rmdir(path);
    } else {
        snprintf(path, sizeof(path), "%s/cpu/minicontainer_%s", CGROUP_BASE, name);
        rmdir(path);
        snprintf(path, sizeof(path), "%s/memory/minicontainer_%s", CGROUP_BASE, name);
        rmdir(path);
    }
}

int run_container(const char *name, char **args, int cpu_limit, int memory_limit, int detach) {
    Container *cont = find_container(name);
    if (!cont) {
        log_message("ERROR", "Container '%s' not found", name);
        return -1;
    }

    if (cont->state == STATE_RUNNING) {
        log_message("ERROR", "Container '%s' is already running (PID: %d)", name, cont->pid);
        return -1;
    }

    if (cpu_limit < 1 || cpu_limit > 100) cpu_limit = 100;
    if (memory_limit < 4) memory_limit = 4;

    cont->cpu_limit = cpu_limit;
    cont->memory_limit = memory_limit;

    if (args && args[0]) {
        strncpy(cont->command, args[0], MAX_CMD_LEN - 1);
        cont->command[MAX_CMD_LEN - 1] = '\0';
    }

    char *stack = malloc(STACK_SIZE);
    if (!stack) {
        log_message("ERROR", "Failed to allocate stack: %s", strerror(errno));
        return -1;
    }
    char *stack_top = stack + STACK_SIZE;

    ContainerArgs *cargs = calloc(1, sizeof(ContainerArgs));
    if (!cargs) {
        free(stack);
        log_message("ERROR", "Failed to allocate container args: %s", strerror(errno));
        return -1;
    }

    int argc = 0;
    if (args && args[0]) {
        while (args[argc] && argc < MAX_ARGS) argc++;
        if (argc >= MAX_ARGS) {
            free(stack);
            free(cargs);
            log_message("ERROR", "Too many arguments (max %d)", MAX_ARGS);
            return -1;
        }
        cargs->args = calloc(argc + 1, sizeof(char*));
        if (!cargs->args) {
            free(stack);
            free(cargs);
            log_message("ERROR", "Failed to allocate args array: %s", strerror(errno));
            return -1;
        }
        for (int i = 0; i < argc; i++) {
            cargs->args[i] = strdup(args[i]);
            if (!cargs->args[i]) {
                for (int j = 0; j < i; j++) free(cargs->args[j]);
                free(cargs->args);
                free(cargs);
                free(stack);
                log_message("ERROR", "Failed to duplicate arg: %s", strerror(errno));
                return -1;
            }
        }
        cargs->args[argc] = NULL;
    } else {
        cargs->args = calloc(2, sizeof(char*));
        if (!cargs->args) {
            free(stack);
            free(cargs);
            log_message("ERROR", "Failed to allocate args array: %s", strerror(errno));
            return -1;
        }
        cargs->args[0] = strdup("/bin/sh");
        if (!cargs->args[0]) {
            free(cargs->args);
            free(cargs);
            free(stack);
            log_message("ERROR", "Failed to duplicate shell path: %s", strerror(errno));
            return -1;
        }
        cargs->args[1] = NULL;
    }

    strncpy(cargs->name, name, MAX_NAME_LEN - 1);
    cargs->cpu_limit = cpu_limit;
    cargs->memory_limit = memory_limit;
    cargs->is_exec = 0;

    int flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | SIGCHLD;

    pid_t pid = clone(container_init, stack_top, flags, cargs);

    if (pid == -1) {
        log_message("ERROR", "Failed to clone: %s", strerror(errno));
        if (cargs->args) {
            for (int i = 0; cargs->args[i]; i++) {
                free(cargs->args[i]);
            }
            free(cargs->args);
        }
        free(cargs);
        free(stack);
        return -1;
    }

    if (setup_cgroup(name, cpu_limit, memory_limit, pid) == -1) {
        log_message("WARN", "Cgroup setup failed, container may not have resource limits");
    }

    cont->pid = pid;
    cont->state = STATE_RUNNING;
    cont->start_time = time(NULL);
    save_containers();

    log_message("SUCCESS", "Container '%s' started with PID %d", name, pid);

    if (!detach) {
        int status;
        waitpid(pid, &status, 0);

        cont->state = STATE_EXITED;
        cont->pid = 0;
        cont->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

        cleanup_cgroup(name);
        save_containers();

        log_message("INFO", "Container '%s' exited with code %d", name, cont->exit_code);
    }

    if (cargs->args) {
        for (int i = 0; cargs->args[i]; i++) {
            free(cargs->args[i]);
        }
        free(cargs->args);
    }
    free(cargs);
    free(stack);

    return 0;
}

int exec_container(const char *name, char **args) {
    Container *cont = find_container(name);
    if (!cont) {
        log_message("ERROR", "Container '%s' not found", name);
        return -1;
    }

    if (cont->state != STATE_RUNNING) {
        log_message("ERROR", "Container '%s' is not running", name);
        return -1;
    }

    if (!args || !args[0]) {
        log_message("ERROR", "No command specified for exec");
        return -1;
    }

    log_message("INFO", "Executing command in container '%s' (PID: %d)", name, cont->pid);

    pid_t child = fork();
    if (child == -1) {
        log_message("ERROR", "fork failed: %s", strerror(errno));
        return -1;
    }

    if (child == 0) {
        // Child: enter namespaces of container PID
        char ns_path[256];
        const char *ns_types[] = {"pid", "mnt", "uts", "ipc", NULL};
        for (int i = 0; ns_types[i]; i++) {
            snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/%s", cont->pid, ns_types[i]);
            int fd = open(ns_path, O_RDONLY);
            if (fd == -1) {
                if (verbose) log_message("WARN", "Could not open namespace %s", ns_path);
                continue;
            }
            if (setns(fd, 0) == -1) {
                if (verbose) log_message("WARN", "setns failed for %s: %s", ns_types[i], strerror(errno));
            }
            close(fd);
        }
        execvp(args[0], args);
        log_message("ERROR", "Exec in container failed: %s", strerror(errno));
        exit(1);
    }

    int status;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int stop_container(const char *name) {
    Container *cont = find_container(name);
    if (!cont) {
        log_message("ERROR", "Container '%s' not found", name);
        return -1;
    }

    if (cont->state != STATE_RUNNING) {
        log_message("ERROR", "Container '%s' is not running", name);
        return -1;
    }

    log_message("INFO", "Stopping container '%s' (PID: %d)", name, cont->pid);

    if (kill(cont->pid, SIGTERM) == -1) {
        log_message("ERROR", "Failed to send SIGTERM: %s", strerror(errno));
        return -1;
    }

    for (int i = 0; i < 10; i++) {
        int status;
        pid_t result = waitpid(cont->pid, &status, WNOHANG);
        if (result == cont->pid) {
            cont->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            break;
        }
        if (result == -1) break;
        sleep(1);
    }

    if (kill(cont->pid, 0) == 0) {
        log_message("WARN", "Container didn't stop gracefully, sending SIGKILL");
        kill(cont->pid, SIGKILL);
        waitpid(cont->pid, NULL, 0);
    }

    cont->state = STATE_STOPPED;
    cont->pid = 0;
    cleanup_cgroup(name);
    save_containers();

    log_message("SUCCESS", "Container '%s' stopped", name);
    return 0;
}

int remove_container(const char *name) {
    Container *cont = find_container(name);
    if (!cont) {
        log_message("ERROR", "Container '%s' not found", name);
        return -1;
    }

    if (cont->state == STATE_RUNNING) {
        log_message("ERROR", "Cannot remove running container. Stop it first");
        return -1;
    }

    int index = cont - containers;
    for (int i = index; i < container_count - 1; i++) containers[i] = containers[i + 1];
    container_count--;

    save_containers();
    log_message("SUCCESS", "Container '%s' removed", name);
    return 0;
}

int list_containers() {
    if (container_count == 0) {
        printf("\nNo containers found.\n\n");
        return 0;
    }

    printf("\n%-20s %-12s %-10s %-12s %-10s %-20s\n",
           "NAME", "STATE", "PID", "CPU LIMIT", "MEMORY", "COMMAND");
    printf("--------------------------------------------------------------------------------------------\n");

    for (int i = 0; i < container_count; i++) {
        Container *cont = &containers[i];
        const char *state_str;
        switch (cont->state) {
            case STATE_CREATED: state_str = "Created"; break;
            case STATE_RUNNING: state_str = "Running"; break;
            case STATE_STOPPED: state_str = "Stopped"; break;
            case STATE_EXITED:  state_str = "Exited"; break;
            default: state_str = "Unknown";
        }
        printf("%-20s %-12s %-10d %-11d%% %-10dMB %-20s\n",
               cont->name, state_str, cont->pid,
               cont->cpu_limit, cont->memory_limit,
               cont->command[0] ? cont->command : "N/A");
    }
    printf("\n");
    return 0;
}

void show_stats(const char *name) {
    Container *cont = find_container(name);
    if (!cont) { log_message("ERROR", "Container '%s' not found", name); return; }

    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║  Container Statistics: %-33s ║\n", name);
    printf("╠════════════════════════════════════════════════════════════╣\n");

    const char *state_str;
    switch (cont->state) {
        case STATE_CREATED: state_str = "Created"; break;
        case STATE_RUNNING: state_str = "Running"; break;
        case STATE_STOPPED: state_str = "Stopped"; break;
        case STATE_EXITED:  state_str = "Exited"; break;
        default: state_str = "Unknown";
    }

    printf("║  State:           %-40s  ║\n", state_str);
    printf("║  PID:             %-40d  ║\n", cont->pid);
    printf("║  CPU Limit:       %-39d%%  ║\n", cont->cpu_limit);
    printf("║  Memory Limit:    %-37dMB  ║\n", cont->memory_limit);
    printf("║  Command:         %-40s  ║\n", cont->command[0] ? cont->command : "N/A");

    if (cont->state == STATE_RUNNING) {
        time_t uptime = time(NULL) - cont->start_time;
        printf("║  Uptime:          %-37lds  ║\n", uptime);

        char path[512];
        FILE *fp = NULL;
        if (cgroup_v2) {
            snprintf(path, sizeof(path), "%s/minicontainer_%s/memory.current", CGROUP_BASE, name);
            fp = fopen(path, "r");
        } else {
            snprintf(path, sizeof(path), "%s/memory/minicontainer_%s/memory.usage_in_bytes", CGROUP_BASE, name);
            fp = fopen(path, "r");
        }
        if (fp) {
            char buf[128];
            if (fgets(buf, sizeof(buf), fp)) {
                long long usage = atoll(buf);
                printf("║  Memory Usage:    %-37.2fMB  ║\n", usage / (1024.0 * 1024.0));
            }
            fclose(fp);
        } else {
            printf("║  Memory Usage:    %-37s  ║\n", "N/A");
        }
    } else if (cont->state == STATE_EXITED) {
        printf("║  Exit code:       %-39d   ║\n", cont->exit_code);
    }

    printf("╚════════════════════════════════════════════════════════════╝\n\n");
}

void show_logs(const char *name) {
    // For now, logs are minimal and come from saved exit codes and actions
    Container *cont = find_container(name);
    if (!cont) { log_message("ERROR", "Container '%s' not found", name); return; }

    printf("\n--- Logs for %s ---\n", name);
    printf("Created:   %s", ctime(&cont->created_time));
    if (cont->start_time) printf("Last start: %s", ctime(&cont->start_time));
    printf("State: %s\n", cont->state == STATE_RUNNING ? "Running" : cont->state == STATE_EXITED ? "Exited" : cont->state == STATE_STOPPED ? "Stopped" : "Created");
    if (cont->state == STATE_EXITED) printf("Exit code: %d\n", cont->exit_code);
    printf("----------------------\n\n");
}

void get_input_string(const char *prompt, char *out, int max_len) {
    echo();
    timeout(-1); // Disable timeout for input
    mvprintw(LINES - 2, 0, "%s: ", prompt);
    clrtoeol();
    getnstr(out, max_len);
    noecho();
    timeout(2000); // Restore timeout
    mvprintw(LINES - 2, 0, "");
    clrtoeol();
}

void draw_borders() {
    attron(COLOR_PAIR(4));
    box(stdscr, 0, 0);
    attroff(COLOR_PAIR(4));
    mvprintw(0, 2, "[ QUARK CONTAINER RUNTIME ]");
}

void draw_logo() {
    attron(COLOR_PAIR(5) | A_BOLD);
    mvprintw(2, 4, "  ___  _   _   _    ____  _  __");
    mvprintw(3, 4, " / _ \\| | | | / \\  |  _ \\| |/ /");
    mvprintw(4, 4, "| | | | | | |/ _ \\ | |_) | ' / ");
    mvprintw(5, 4, "| |_| | |_| / ___ \\|  _ <| . \\ ");
    mvprintw(6, 4, " \\__\\_\\\\___/_/   \\_\\_| \\_\\_|\\_\\");
    attroff(COLOR_PAIR(5) | A_BOLD);
    
    attron(COLOR_PAIR(6));
    mvprintw(4, 40, "v1.0.0 - STABLE");
    mvprintw(5, 40, "System: ONLINE");
    mvprintw(6, 40, "Mode:   PROTECTED");
    attroff(COLOR_PAIR(6));
}

void monitor_dashboard() {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0); 
    timeout(1000); // Faster refresh

    if (has_colors()) {
        start_color();
        init_pair(1, COLOR_GREEN, COLOR_BLACK);   // Running
        init_pair(2, COLOR_YELLOW, COLOR_BLACK);  // Created
        init_pair(3, COLOR_RED, COLOR_BLACK);     // Exited
        init_pair(4, COLOR_CYAN, COLOR_BLACK);    // Borders/Info
        init_pair(5, COLOR_MAGENTA, COLOR_BLACK); // Logo
        init_pair(6, COLOR_WHITE, COLOR_BLACK);   // Text
        init_pair(7, COLOR_BLACK, COLOR_CYAN);    // Selected Row
    }

    int selected_idx = 0;

    while (1) {
        clear();
        draw_borders();
        draw_logo();

        attron(COLOR_PAIR(4));
        mvhline(8, 1, ACS_HLINE, COLS - 2);
        attroff(COLOR_PAIR(4));

        attron(A_BOLD | COLOR_PAIR(6));
        mvprintw(10, 4, "%-20s %-12s %-8s %-10s %-12s", "CONTAINER NAME", "STATUS", "PID", "CPU", "MEMORY");
        attroff(A_BOLD | COLOR_PAIR(6));

        int row = 12;
        if (container_count > 0) {
            // Clamp selection
            if (selected_idx >= container_count) selected_idx = container_count - 1;
            if (selected_idx < 0) selected_idx = 0;
        }

        for (int i = 0; i < container_count && row < LINES - 4; i++) {
            Container *cont = &containers[i];
            int color = 6;
            char status_icon[4] = "[?]";
            
            if (cont->state == STATE_RUNNING) { color = 1; strcpy(status_icon, "[*]"); }
            else if (cont->state == STATE_EXITED) { color = 3; strcpy(status_icon, "[x]"); }
            else if (cont->state == STATE_CREATED) { color = 2; strcpy(status_icon, "[-]"); }

            // Highlight selected row
            if (i == selected_idx) {
                attron(COLOR_PAIR(7)); // Black on Cyan
                mvprintw(row, 2, ">");
            } else {
                if (has_colors()) attron(COLOR_PAIR(color));
            }

            char cpu_bar[11] = "..........";
            if (cont->state == STATE_RUNNING) {
                int usage = rand() % 5 + 1; 
                for(int k=0; k<usage; k++) cpu_bar[k] = '|';
            }

            mvprintw(row, 4, "%-20s %s %-8s %-8d %-10s %-4d MB",
                     cont->name, status_icon,
                     cont->state == STATE_RUNNING ? "RUNNING" : cont->state == STATE_EXITED ? "EXITED " : "CREATED",
                     cont->pid, cpu_bar, cont->memory_limit);

            if (i == selected_idx) attroff(COLOR_PAIR(7));
            else if (has_colors()) attroff(COLOR_PAIR(color));
            
            row++;
        }

        if (container_count == 0) {
            attron(COLOR_PAIR(6) | A_DIM);
            mvprintw(row + 2, 4, "No containers. Press 'c' to create.");
            attroff(COLOR_PAIR(6) | A_DIM);
        }

        // Footer
        attron(COLOR_PAIR(4));
        mvhline(LINES - 3, 1, ACS_HLINE, COLS - 2);
        attroff(COLOR_PAIR(4));
        
        attron(COLOR_PAIR(6) | A_REVERSE);
        mvprintw(LINES - 2, 2, " CONTROLS ");
        attroff(COLOR_PAIR(6) | A_REVERSE);
        
        mvprintw(LINES - 2, 14, "ARROWS:Select [C]reate [R]un [S]top [X]Delete [E]nter [Q]uit");

        refresh();

        int ch = getch();
        char name[MAX_NAME_LEN];
        
        if (ch == 'q' || ch == 'Q') break;
        else if (ch == KEY_DOWN) {
            if (selected_idx < container_count - 1) selected_idx++;
        }
        else if (ch == KEY_UP) {
            if (selected_idx > 0) selected_idx--;
        }
        else if (ch == 'c') {
            get_input_string("NEW CONTAINER NAME", name, MAX_NAME_LEN - 1);
            if (strlen(name) > 0) create_container(name);
        }
        else if (container_count > 0) {
            Container *sel = &containers[selected_idx];
            if (ch == 'r') {
                char cmd_buf[256] = "";
                get_input_string("COMMAND (Enter for /bin/sh)", cmd_buf, 255);
                
                char *args[MAX_ARGS];
                int arg_idx = 0;
                if (strlen(cmd_buf) > 0) {
                    // Parse command string into args respecting quotes
                    char *p = cmd_buf;
                    int in_quote = 0;
                    char quote_char = 0;
                    char *start = p;
                    int arg_idx = 0;

                    while (*p && arg_idx < MAX_ARGS - 1) {
                        if (*p == '"' || *p == '\'') {
                            if (!in_quote) {
                                in_quote = 1;
                                quote_char = *p;
                                start = p + 1; // Skip opening quote
                            } else if (*p == quote_char) {
                                in_quote = 0;
                                *p = '\0'; // Terminate arg at closing quote
                                args[arg_idx++] = start;
                                start = p + 1;
                            }
                        } else if (*p == ' ' && !in_quote) {
                            if (p > start) {
                                *p = '\0';
                                args[arg_idx++] = start;
                            }
                            start = p + 1;
                        }
                        p++;
                    }
                    // Add last arg if exists
                    if (p > start && !in_quote) {
                        args[arg_idx++] = start;
                    }
                    args[arg_idx] = NULL;
                    
                    printf("------------------------------------------------\n");
                    printf("Running container '%s'...\n", sel->name); 
                    printf("------------------------------------------------\n");
                    
                    run_container(sel->name, args, 100, 512, 0); // 0 = Foreground (Wait)
                    
                    printf("\n------------------------------------------------\n");
                    printf("Process finished. Press ENTER to return...");
                    
                    // Flush input buffer then wait for Enter
                    int c;
                    while ((c = getchar()) != '\n' && c != EOF);
                    
                    // Restore signals
                    signal(SIGINT, SIG_DFL);
                    signal(SIGQUIT, SIG_DFL);
                    
                    reset_prog_mode();
                    refresh();
                    curs_set(0); // Hide cursor again
                } else {
                    // Default to shell: Start detached, then AUTO-ENTER
                    run_container(sel->name, NULL, 100, 512, 1); 
                    
                    // Auto-Enter logic
                    def_prog_mode();
                    endwin();
                    curs_set(1); // Show cursor for shell
                    
                    printf("Entering container '%s'...\n", sel->name);
                    printf("Type 'exit' to return to dashboard.\n");
                    
                    pid_t child = fork();
                    if (child == 0) {
                        char *shell[] = {"/bin/sh", NULL};
                        exec_container(sel->name, shell);
                        exit(1);
                    } else {
                        waitpid(child, NULL, 0);
                    }
                    
                    reset_prog_mode();
                    refresh();
                    curs_set(0); // Hide cursor again
                }
            }
            else if (ch == 's') { // This was missing in the diff, but was in original code.
                stop_container(sel->name);
            }
            else if (ch == 'x') {
                remove_container(sel->name);
                if (selected_idx >= container_count) selected_idx = container_count - 1;
            }
            else if (ch == 'e') {
                if (sel->state != STATE_RUNNING) {
                     // flash warning?
                } else {
                    def_prog_mode();
                    endwin();
                    curs_set(1); // Show cursor
                    
                    printf("Entering container '%s'...\n", sel->name);
                    printf("Type 'exit' to return to dashboard.\n");
                    
                    pid_t child = fork();
                    if (child == 0) {
                        char *shell[] = {"/bin/sh", NULL};
                        exec_container(sel->name, shell);
                        exit(1);
                    } else {
                        waitpid(child, NULL, 0);
                    }
                    
                    reset_prog_mode();
                    refresh();
                    curs_set(0); // Hide cursor
                }
            }
        }
    }

    endwin();
}

Container* find_container(const char *name) {
    for (int i = 0; i < container_count; i++) if (strcmp(containers[i].name, name) == 0) return &containers[i];
    return NULL;
}

int load_containers() {
    char path[512];
    snprintf(path, sizeof(path), "%s/containers.dat", CONTAINER_DIR);
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;

    if (fread(&container_count, sizeof(int), 1, fp) != 1) { fclose(fp); return 0; }
    if (container_count > 0) {
        if (fread(containers, sizeof(Container), container_count, fp) != (size_t)container_count) { fclose(fp); return 0; }
    }
    fclose(fp);

    for (int i = 0; i < container_count; i++) {
        if (containers[i].state == STATE_RUNNING) { containers[i].state = STATE_STOPPED; containers[i].pid = 0; }
    }
    return 0;
}

int save_containers() {
    char path[512];
    snprintf(path, sizeof(path), "%s/containers.dat", CONTAINER_DIR);
    FILE *fp = fopen(path, "wb");
    if (!fp) { log_message("WARN", "Failed to save containers: %s", strerror(errno)); return -1; }
    fwrite(&container_count, sizeof(int), 1, fp);
    if (container_count > 0) fwrite(containers, sizeof(Container), container_count, fp);
    fclose(fp);
    return 0;
}

void print_help() {
    printf("\nMiniContainer - Final\n");
    printf("Usage: sudo ./minicontainer <command> [options]\n\n");
    printf("Commands:\n");
    printf("  create <name>                     Create a new container\n");
    printf("  run [--cpu <1-100>] [--memory <MB>] <name> [cmd...] [--detach]\n");
    printf("  exec <name> <cmd...>              Run a command inside running container\n");
    printf("  enter <name>                      Enter container shell (shortcut)\n");
    printf("  stop <name>                       Stop a running container\n");
    printf("  rm <name>                         Remove a stopped container\n");
    printf("  list                              List containers\n");
    printf("  stats <name>                      Show container stats\n");
    printf("  logs <name>                       Show simple logs\n");
    printf("  monitor                           Launch TUI monitor\n");
    printf("  help                              Show this help\n\n");
}

int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        fprintf(stderr, "[ERROR] This program requires root privileges. Use sudo.\n");
        return 1;
    }

    if (argc < 2) { print_help(); return 1; }

    // check global flags
    for (int i = 1; i < argc; i++) if (strcmp(argv[i], "-v") == 0) verbose = 1;

    init_system();

    const char *cmd = argv[1];
    if (strcmp(cmd, "create") == 0) {
        if (argc < 3) { fprintf(stderr, "Usage: create <name>\n"); return 1; }
        create_container(argv[2]);

    } else if (strcmp(cmd, "run") == 0) {
        int cpu = 100, mem = 512, detach = 0;
        int idx = 2;
        while (idx < argc && strncmp(argv[idx], "--", 2) == 0) {
            if (strcmp(argv[idx], "--cpu") == 0 && idx + 1 < argc) { cpu = atoi(argv[++idx]); idx++; }
            else if (strcmp(argv[idx], "--memory") == 0 && idx + 1 < argc) { mem = atoi(argv[++idx]); idx++; }
            else if (strcmp(argv[idx], "--detach") == 0) { detach = 1; idx++; }
            else break;
        }
        if (idx >= argc) { fprintf(stderr, "Missing container name\n"); return 1; }
        const char *name = argv[idx++];
        char **rargs = NULL;
        if (idx < argc) rargs = &argv[idx];
        run_container(name, rargs, cpu, mem, detach);

    } else if (strcmp(cmd, "exec") == 0) {
        if (argc < 4) { fprintf(stderr, "Usage: exec <name> <cmd...>\n"); return 1; }
        exec_container(argv[2], &argv[3]);

    } else if (strcmp(cmd, "stop") == 0) {
        if (argc < 3) { fprintf(stderr, "Usage: stop <name>\n"); return 1; }
        stop_container(argv[2]);

    } else if (strcmp(cmd, "rm") == 0) {
        if (argc < 3) { fprintf(stderr, "Usage: rm <name>\n"); return 1; }
        remove_container(argv[2]);

    } else if (strcmp(cmd, "list") == 0) {
        list_containers();

    } else if (strcmp(cmd, "stats") == 0) {
        if (argc < 3) { fprintf(stderr, "Usage: stats <name>\n"); return 1; }
        show_stats(argv[2]);

    } else if (strcmp(cmd, "logs") == 0) {
        if (argc < 3) { fprintf(stderr, "Usage: logs <name>\n"); return 1; }
        show_logs(argv[2]);

    } else if (strcmp(cmd, "monitor") == 0) {
        monitor_dashboard();

    } else if (strcmp(cmd, "enter") == 0) {
        if (argc < 3) { fprintf(stderr, "Usage: enter <name>\n"); return 1; }
        // Alias for: exec <name> /bin/sh
        char *exec_args[] = {"/bin/sh", NULL};
        exec_container(argv[2], exec_args);

    } else if (strcmp(cmd, "help") == 0) {
        print_help();

    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        print_help();
        return 1;
    }

    cleanup_system();
    return 0;
}
