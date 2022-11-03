#!/bin/awk -f

BEGIN {
    running = 0
}

/Starting Benchmark:/ {
    running = 1
}

/client: sending/ {
    res = match($0, /client: sending ([0-9]+) bytes/, m)
    if (res != 0) {
        printf("request: %d\n", m[1])
    }
}

/client: total=/ {
    if (match($0, /client: total=([0-9]+) cycles, op=([0-9]+) cycles, xfer=([0-9]+) cycles, size=([0-9]+)/, m) != 0) {
        printf("compute: %d\n", m[2])
        printf("response-rdma: %d\n", m[4])
        printf("response: %d\n", 32)
    }
}

/write\(5,/ {
    if (match($0, /write\(5, .*\) -> ([0-9]+)/, m) != 0) {
        if (running) {
            printf("file-rdma: %d\n", m[1])
        }
    }
}
