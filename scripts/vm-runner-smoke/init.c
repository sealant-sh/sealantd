// A stand-in for `sealantd --vm` as PID 1, for scripts/vm-runner-smoke.sh: it plays the guest
// side of the vsock:1026 protocol and nothing else, printing what it sees to the serial console.
//
//   1. says whether the kernel passed `--vm` in its arguments (from `-- --vm` on the cmdline);
//   2. dials 2:1026 and reads the runner's VmBootConfig line;
//   3. dials 2:1026 again, which the runner must refuse (it serves one connection only), and
//      2:1027, the session channel, which only a normal boot accepts;
//   4. with /etc/smoke-wait-power on the base disk, waits for the runner's shutdown line on the
//      boot connection (or, failing that, the power button, KEY_POWER on /dev/input/event*);
//   5. syncs, sends {"version":1,"type":"exit","exitCode":76,"synced":true,...}, waits for the
//      runner's exitAck and powers off.
#include <dirent.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/vm_sockets.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <unistd.h>

static char buf[1 << 16];
static size_t buffered;

// Reads one line from fd into line (without the newline); keeps what follows it for the next
// call. Returns 0 on success, -1 on EOF or error.
static int read_line(int fd, char *line, size_t cap) {
    for (;;) {
        char *nl = memchr(buf, '\n', buffered);
        if (nl) {
            size_t n = (size_t)(nl - buf);
            size_t copy = n < cap - 1 ? n : cap - 1;
            memcpy(line, buf, copy);
            line[copy] = 0;
            buffered -= n + 1;
            memmove(buf, nl + 1, buffered);
            return 0;
        }
        if (buffered == sizeof buf) return -1;
        ssize_t r = read(fd, buf + buffered, sizeof buf - buffered);
        if (r <= 0) return -1;
        buffered += (size_t)r;
    }
}

static int dial(unsigned port) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    struct sockaddr_vm addr = {
        .svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_HOST, .svm_port = port};
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// Waits for the shutdown line on boot (checked first) or the power button.
static void wait_for_shutdown(int boot) {
    struct pollfd fds[17];
    int n = 0;
    fds[n++] = (struct pollfd){.fd = boot, .events = POLLIN};
    DIR *dir = opendir("/dev/input");
    struct dirent *e;
    while (dir && (e = readdir(dir)) && n < 17) {
        if (strncmp(e->d_name, "event", 5) != 0) continue;
        char path[64];
        snprintf(path, sizeof path, "/dev/input/%s", e->d_name);
        int fd = open(path, O_RDONLY);
        if (fd >= 0) fds[n++] = (struct pollfd){.fd = fd, .events = POLLIN};
    }
    printf("smoke-init: waiting for shutdown (boot channel + %d input devices)\n", n - 1);
    fflush(stdout);
    for (;;) {
        if (buffered == 0 && poll(fds, n, -1) <= 0) continue;
        if (buffered > 0 || (fds[0].revents & POLLIN)) {
            char line[256];
            if (read_line(boot, line, sizeof line) < 0) {
                printf("smoke-init: boot channel closed while waiting\n");
                return;
            }
            if (strstr(line, "\"type\":\"shutdown\"")) {
                printf("smoke-init: shutdown frame received: %s\n", line);
                fflush(stdout);
                return;
            }
            continue;
        }
        for (int i = 1; i < n; i++) {
            struct input_event ev;
            if ((fds[i].revents & POLLIN) && read(fds[i].fd, &ev, sizeof ev) == sizeof ev &&
                ev.type == EV_KEY && ev.code == KEY_POWER && ev.value == 1) {
                printf("smoke-init: power button pressed\n");
                fflush(stdout);
                return;
            }
        }
    }
}

int main(int argc, char **argv) {
    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
    mount("proc", "/proc", "proc", 0, NULL);
    int vm = 0;
    for (int i = 1; i < argc; i++) vm |= strcmp(argv[i], "--vm") == 0;
    printf("smoke-init: argv has --vm: %s\n", vm ? "yes" : "no");

    int boot = dial(1026);
    if (boot < 0) {
        perror("smoke-init: vsock connect 1026");
        reboot(RB_POWER_OFF);
    }
    static char config[1 << 16];
    if (read_line(boot, config, sizeof config) < 0) {
        printf("smoke-init: no boot config\n");
        reboot(RB_POWER_OFF);
    }
    printf("smoke-init: boot config: %s\n", config);

    int second = dial(1026);
    printf("smoke-init: second 1026 dial: %s\n", second < 0 ? "refused" : "accepted");
    if (second >= 0) close(second);
    int session = dial(1027);
    printf("smoke-init: session channel 1027: %s\n", session < 0 ? "refused" : "accepted");
    if (session >= 0) close(session);
    fflush(stdout);

    if (access("/etc/smoke-wait-power", F_OK) == 0) wait_for_shutdown(boot);
    sync();
    const char *frame =
        "{\"version\":1,\"type\":\"exit\",\"exitCode\":76,\"synced\":true,\"reason\":\"smoke\"}\n";
    if (write(boot, frame, strlen(frame)) < 0) perror("smoke-init: write exit status");
    char ack[256];
    for (;;) {
        if (read_line(boot, ack, sizeof ack) < 0) {
            printf("smoke-init: no exit ack\n");
            break;
        }
        if (strstr(ack, "\"type\":\"exitAck\"") && strstr(ack, "\"accepted\":true")) {
            printf("smoke-init: exit acknowledged: %s\n", ack);
            break;
        }
    }
    printf("smoke-init: powering off\n");
    fflush(stdout);
    reboot(RB_POWER_OFF);
    return 0;
}
