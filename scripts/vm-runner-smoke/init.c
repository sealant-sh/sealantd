// A stand-in for `sealantd --vm` as PID 1, for scripts/vm-runner-smoke.sh: it plays the guest
// side of the vsock:1026 handshake and nothing else.
//
// It reads the runner's VmBootConfig line, prints it to the serial console, says whether the host
// accepts a connection on vsock:1027 (the session channel, absent in recovery), and then:
//   - with /etc/smoke-wait-power on the base disk, waits for the power button (KEY_POWER on any
//     /dev/input/event*), the runner's graceful stop;
//   - otherwise carries straight on.
// Either way it syncs, sends GuestExitStatus {version 1, exit_code 76, synced true} and powers off.
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

static void wait_for_power_button(void) {
    struct pollfd fds[16];
    int n = 0;
    DIR *dir = opendir("/dev/input");
    struct dirent *e;
    while (dir && (e = readdir(dir)) && n < 16) {
        if (strncmp(e->d_name, "event", 5) != 0) continue;
        char path[64];
        snprintf(path, sizeof path, "/dev/input/%s", e->d_name);
        int fd = open(path, O_RDONLY);
        if (fd >= 0) fds[n++] = (struct pollfd){.fd = fd, .events = POLLIN};
    }
    printf("smoke-init: waiting for the power button on %d input devices\n", n);
    fflush(stdout);
    for (;;) {
        if (poll(fds, n, -1) <= 0) continue;
        for (int i = 0; i < n; i++) {
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

int main(void) {
    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
    mount("proc", "/proc", "proc", 0, NULL);
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    struct sockaddr_vm addr = {
        .svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_HOST, .svm_port = 1026};
    if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("smoke-init: vsock connect 1026");
        reboot(RB_POWER_OFF);
    }
    static char buf[1 << 16];
    size_t len = 0;
    ssize_t r;
    while (len < sizeof buf - 1 && (r = read(fd, buf + len, sizeof buf - 1 - len)) > 0) {
        len += (size_t)r;
        if (memchr(buf, '\n', len)) break;
    }
    buf[len] = 0;
    printf("smoke-init: boot config: %s", buf);
    int session = socket(AF_VSOCK, SOCK_STREAM, 0);
    struct sockaddr_vm session_addr = {
        .svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_HOST, .svm_port = 1027};
    int accepted = connect(session, (struct sockaddr *)&session_addr, sizeof session_addr) == 0;
    printf("smoke-init: session channel 1027: %s\n", accepted ? "accepted" : "refused");
    close(session);
    fflush(stdout);
    if (access("/etc/smoke-wait-power", F_OK) == 0) wait_for_power_button();
    sync();
    const char *frame = "{\"version\":1,\"exit_code\":76,\"synced\":true,\"reason\":\"smoke\"}\n";
    if (write(fd, frame, strlen(frame)) < 0) perror("smoke-init: write exit status");
    shutdown(fd, SHUT_WR);
    while (read(fd, buf, sizeof buf) > 0) {
    }
    close(fd);
    printf("smoke-init: exit status sent, powering off\n");
    fflush(stdout);
    reboot(RB_POWER_OFF);
    return 0;
}
