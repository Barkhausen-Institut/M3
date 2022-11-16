#!/bin/awk -f

BEGIN {
    running = 0
}

/client: replay=/ {
    running += 1
}

/client: sending/ {
    if (running == 1) {
        res = match($0, /client: sending ([0-9]+) bytes/, m)
        if (res != 0) {
            printf("request: %d\n", m[1])
        }
    }
}

/client: total=/ {
    if (running == 1) {
        if (match($0, /client: total=([0-9]+) cycles, op=([0-9]+) cycles, xfer=([0-9]+) cycles, size=([0-9]+)/, m) != 0) {
            printf("compute: %d\n", m[2])
            printf("response-rdma: %d\n", m[4])
            printf("response: %d\n", 32)
        }
    }
}

/write\(5,/ {
    if (running == 1) {
        if (match($0, /write\(5, .*\) -> ([0-9]+)/, m) != 0) {
            printf("file-rdma: %d\n", m[1])
        }
    }
}
