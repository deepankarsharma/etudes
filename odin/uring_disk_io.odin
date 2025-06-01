package uring_disk_io

import "core:os"
import "core:fmt"
import "core:time"
import "core:math/rand"
import "core:sync"
import "core:mem"
import "core:c"
import "core:sys/linux"

foreign import libc "system:c"

O_DIRECT :: 0x4000

POSIX_FADV_DONTNEED :: 4

IORING_SETUP_IOPOLL :: 0x01
IORING_SETUP_SQPOLL :: 0x02
IORING_SETUP_SQ_AFF :: 0x04

IORING_OP_READV :: 1
IORING_OP_WRITEV :: 2
IORING_OP_READ :: 22
IORING_OP_WRITE :: 23

IORING_OFF_SQ_RING :: 0
IORING_OFF_CQ_RING :: 0x8000000
IORING_OFF_SQES :: 0x10000000

IORING_SQ_NEED_WAKEUP :: 1 << 0
IORING_SQ_CQ_OVERFLOW :: 1 << 1

io_uring_sqe :: struct #packed {
    opcode:      u8,
    flags:       u8,
    ioprio:      u16,
    fd:          i32,
    off:         u64,
    addr:        u64,
    len:         u32,
    misc_flags:  u32,
    user_data:   u64,
    buf_index:   u16,
    personality: u16,
    splice_fd:   i32,
    _pad2:       [2]u64,
}

io_uring_cqe :: struct #packed {
    user_data: u64,
    res:       i32,
    flags:     u32,
}

io_sqring_offsets :: struct {
    head:         u32,
    tail:         u32,
    ring_mask:    u32,
    ring_entries: u32,
    flags:        u32,
    dropped:      u32,
    array:        u32,
    resv1:        u32,
    resv2:        u64,
}

io_cqring_offsets :: struct {
    head:         u32,
    tail:         u32,
    ring_mask:    u32,
    ring_entries: u32,
    overflow:     u32,
    cqes:         u32,
    flags:        u32,
    resv1:        u32,
    resv2:        u64,
}

io_uring_params :: struct {
    sq_entries:     u32,
    cq_entries:     u32,
    flags:          u32,
    sq_thread_cpu:  u32,
    sq_thread_idle: u32,
    features:       u32,
    wq_fd:          u32,
    resv:           [3]u32,
    sq_off:         io_sqring_offsets,
    cq_off:         io_cqring_offsets,
}

io_uring :: struct {
    sq_ring_ptr: rawptr,
    cq_ring_ptr: rawptr,
    sqes:        [^]io_uring_sqe,
    
    sq_head:     ^u32,
    sq_tail:     ^u32,
    sq_mask:     u32,
    sq_entries:  u32,
    sq_flags:    ^u32,
    sq_dropped:  ^u32,
    sq_array:    [^]u32,
    
    cq_head:     ^u32,
    cq_tail:     ^u32,
    cq_mask:     u32,
    cq_entries:  u32,
    cq_overflow: ^u32,
    cqes:        [^]io_uring_cqe,
    
    ring_fd:     i32,
    features:    u32,
}

foreign libc {
    @(link_name="syscall")
    _syscall :: proc(number: c.long, #c_vararg args: ..any) -> c.long ---
    
    mmap :: proc(addr: rawptr, length: c.size_t, prot: c.int, flags: c.int, fd: c.int, offset: c.long) -> rawptr ---
    munmap :: proc(addr: rawptr, length: c.size_t) -> c.int ---
    ftruncate :: proc(fd: c.int, length: c.long) -> c.int ---
    fsync :: proc(fd: c.int) -> c.int ---
    posix_fadvise :: proc(fd: c.int, offset: c.long, len: c.long, advice: c.int) -> c.int ---
}

SYS_io_uring_setup :: 425
SYS_io_uring_enter :: 426
SYS_io_uring_register :: 427

PROT_READ  :: 0x1
PROT_WRITE :: 0x2
MAP_SHARED :: 0x01
MAP_POPULATE :: 0x08000

io_uring_setup :: proc(entries: u32, p: ^io_uring_params) -> i32 {
    return cast(i32)_syscall(SYS_io_uring_setup, entries, p)
}

io_uring_enter :: proc(fd: i32, to_submit: u32, min_complete: u32, flags: u32, sig: rawptr) -> i32 {
    return cast(i32)_syscall(SYS_io_uring_enter, fd, to_submit, min_complete, flags, sig)
}

setup_io_uring :: proc(ring: ^io_uring, entries: u32) -> (ok: bool) {
    params := io_uring_params{}
    
    ring.ring_fd = io_uring_setup(entries, &params)
    if ring.ring_fd < 0 {
        fmt.eprintln("io_uring_setup failed:", ring.ring_fd)
        return false
    }
    
    sq_ring_size := params.sq_off.array + params.sq_entries * size_of(u32)
    cq_ring_size := params.cq_off.cqes + params.cq_entries * size_of(io_uring_cqe)
    
    ring.sq_ring_ptr = mmap(nil, cast(c.size_t)sq_ring_size, PROT_READ | PROT_WRITE, 
                            MAP_SHARED | MAP_POPULATE, cast(c.int)ring.ring_fd, cast(c.long)IORING_OFF_SQ_RING)
    if cast(uintptr)ring.sq_ring_ptr == ~uintptr(0) {
        fmt.eprintln("mmap sq_ring failed")
        os.close(os.Handle(ring.ring_fd))
        return false
    }
    
    ring.cq_ring_ptr = mmap(nil, cast(c.size_t)cq_ring_size, PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_POPULATE, cast(c.int)ring.ring_fd, cast(c.long)IORING_OFF_CQ_RING)
    if cast(uintptr)ring.cq_ring_ptr == ~uintptr(0) {
        fmt.eprintln("mmap cq_ring failed")
        munmap(ring.sq_ring_ptr, cast(c.size_t)sq_ring_size)
        os.close(os.Handle(ring.ring_fd))
        return false
    }
    
    sqes_size := params.sq_entries * size_of(io_uring_sqe)
    ring.sqes = cast([^]io_uring_sqe)mmap(nil, cast(c.size_t)sqes_size, PROT_READ | PROT_WRITE,
                                          MAP_SHARED | MAP_POPULATE, cast(c.int)ring.ring_fd, cast(c.long)IORING_OFF_SQES)
    if cast(uintptr)ring.sqes == ~uintptr(0) {
        fmt.eprintln("mmap sqes failed")
        munmap(ring.sq_ring_ptr, cast(c.size_t)sq_ring_size)
        munmap(ring.cq_ring_ptr, cast(c.size_t)cq_ring_size)
        os.close(os.Handle(ring.ring_fd))
        return false
    }
    
    ring.sq_head = cast(^u32)(uintptr(ring.sq_ring_ptr) + uintptr(params.sq_off.head))
    ring.sq_tail = cast(^u32)(uintptr(ring.sq_ring_ptr) + uintptr(params.sq_off.tail))
    ring.sq_mask = (cast(^u32)(uintptr(ring.sq_ring_ptr) + uintptr(params.sq_off.ring_mask)))^
    ring.sq_entries = (cast(^u32)(uintptr(ring.sq_ring_ptr) + uintptr(params.sq_off.ring_entries)))^
    ring.sq_flags = cast(^u32)(uintptr(ring.sq_ring_ptr) + uintptr(params.sq_off.flags))
    ring.sq_dropped = cast(^u32)(uintptr(ring.sq_ring_ptr) + uintptr(params.sq_off.dropped))
    ring.sq_array = cast([^]u32)(uintptr(ring.sq_ring_ptr) + uintptr(params.sq_off.array))
    
    ring.cq_head = cast(^u32)(uintptr(ring.cq_ring_ptr) + uintptr(params.cq_off.head))
    ring.cq_tail = cast(^u32)(uintptr(ring.cq_ring_ptr) + uintptr(params.cq_off.tail))
    ring.cq_mask = (cast(^u32)(uintptr(ring.cq_ring_ptr) + uintptr(params.cq_off.ring_mask)))^
    ring.cq_entries = (cast(^u32)(uintptr(ring.cq_ring_ptr) + uintptr(params.cq_off.ring_entries)))^
    ring.cq_overflow = cast(^u32)(uintptr(ring.cq_ring_ptr) + uintptr(params.cq_off.overflow))
    ring.cqes = cast([^]io_uring_cqe)(uintptr(ring.cq_ring_ptr) + uintptr(params.cq_off.cqes))
    
    ring.features = params.features
    
    return true
}

get_sqe :: proc(ring: ^io_uring) -> ^io_uring_sqe {
    head := sync.atomic_load(ring.sq_head)
    next := sync.atomic_load(ring.sq_tail) + 1
    
    if next - head > ring.sq_entries {
        return nil
    }
    
    idx := sync.atomic_load(ring.sq_tail) & ring.sq_mask
    return &ring.sqes[idx]
}

submit_sqes :: proc(ring: ^io_uring, count: u32) -> i32 {
    tail := sync.atomic_load(ring.sq_tail)
    
    for i: u32 = 0; i < count; i += 1 {
        idx := (tail + i) & ring.sq_mask
        ring.sq_array[idx] = idx
    }
    
    sync.atomic_add(ring.sq_tail, count)
    sync.atomic_thread_fence(.Release)
    
    return io_uring_enter(ring.ring_fd, count, 0, 0, nil)
}

wait_cqe :: proc(ring: ^io_uring) -> ^io_uring_cqe {
    head := sync.atomic_load(ring.cq_head)
    tail := sync.atomic_load(ring.cq_tail)
    
    if head == tail {
        io_uring_enter(ring.ring_fd, 0, 1, 0, nil)
        tail = sync.atomic_load(ring.cq_tail)
    }
    
    if head == tail {
        return nil
    }
    
    idx := head & ring.cq_mask
    return &ring.cqes[idx]
}

advance_cq :: proc(ring: ^io_uring) {
    sync.atomic_add(ring.cq_head, 1)
    sync.atomic_thread_fence(.Release)
}

BenchmarkConfig :: struct {
    block_size:    int,
    is_sequential: bool,
    is_write:      bool,
    num_requests:  int,
}

BenchmarkResult :: struct {
    config:         BenchmarkConfig,
    elapsed_time:   time.Duration,
    iops:           f64,
    throughput_mbs: f64,
}

run_benchmark :: proc(ring: ^io_uring, fd: os.Handle, buffers: [][]u8, config: BenchmarkConfig, file_size: u64) -> BenchmarkResult {
    QUEUE_DEPTH :: 128
    
    start_time := time.now()
    completed := 0
    submitted := 0
    sequential_offset: u64 = 0
    
    for completed < config.num_requests {
        pending_in_batch := 0
        
        for i := 0; submitted < config.num_requests && i < QUEUE_DEPTH && pending_in_batch < QUEUE_DEPTH; i += 1 {
            sqe := get_sqe(ring)
            if sqe == nil {
                break
            }
            
            buffer_idx := submitted % len(buffers)
            
            // Ensure buffer is large enough for this I/O size
            if len(buffers[buffer_idx]) < config.block_size {
                continue
            }
            
            offset: u64
            if config.is_sequential {
                offset = sequential_offset
                sequential_offset += u64(config.block_size)
                if sequential_offset + u64(config.block_size) > file_size {
                    sequential_offset = 0
                }
            } else {
                // Random offset aligned to block size
                max_blocks := file_size / u64(config.block_size)
                random_block := rand.uint64() % max_blocks
                offset = random_block * u64(config.block_size)
            }
            
            if config.is_write {
                // Fill buffer with random data for writes
                for j := 0; j < config.block_size; j += 1 {
                    buffers[buffer_idx][j] = u8(rand.uint32() & 0xFF)
                }
                sqe.opcode = IORING_OP_WRITE
            } else {
                sqe.opcode = IORING_OP_READ
            }
            
            sqe.flags = 0
            sqe.ioprio = 0
            sqe.fd = i32(fd)
            sqe.off = offset
            sqe.addr = cast(u64)cast(uintptr)raw_data(buffers[buffer_idx])
            sqe.len = u32(config.block_size)
            sqe.user_data = u64(submitted)
            
            submitted += 1
            pending_in_batch += 1
        }
        
        if pending_in_batch > 0 {
            submit_sqes(ring, u32(pending_in_batch))
        }
        
        for completed < submitted {
            cqe := wait_cqe(ring)
            if cqe == nil {
                break
            }
            
            if cqe.res < 0 {
                fmt.eprintln("I/O error:", cqe.res)
            }
            
            completed += 1
            advance_cq(ring)
        }
    }
    
    elapsed := time.since(start_time)
    elapsed_seconds := time.duration_seconds(elapsed)
    
    result := BenchmarkResult{
        config         = config,
        elapsed_time   = elapsed,
        iops           = f64(config.num_requests) / elapsed_seconds,
        throughput_mbs = f64(config.num_requests * config.block_size) / (elapsed_seconds * 1024 * 1024),
    }
    
    return result
}

drop_caches :: proc() -> bool {
    cache_file, err := os.open("/proc/sys/vm/drop_caches", os.O_WRONLY)
    if err == 0 {
        os.write_string(cache_file, "3")
        os.close(cache_file)
        return true
    }
    return false
}

main :: proc() {
    QUEUE_DEPTH :: 128
    SMALL_BLOCK_SIZE :: 4 * 1024        // 4KB
    LARGE_BLOCK_SIZE :: 1024 * 1024     // 1MB
    NUM_REQUESTS_SMALL :: 10000
    NUM_REQUESTS_LARGE :: 1000
    FILE_SIZE :: u64(2) << 30           // 2GB
    
    filename := "test_file.dat"
    
    fd, err := os.open(filename, os.O_RDWR | os.O_CREATE | O_DIRECT)
    if err != 0 {
        fmt.eprintln("Failed to open file:", err)
        return
    }
    defer os.close(fd)
    
    if ftruncate(cast(c.int)fd, cast(c.long)FILE_SIZE) != 0 {
        fmt.eprintln("Failed to truncate file")
        return
    }
    
    ring := io_uring{}
    if !setup_io_uring(&ring, QUEUE_DEPTH) {
        fmt.eprintln("Failed to setup io_uring")
        return
    }
    defer os.close(os.Handle(ring.ring_fd))
    
    // Allocate buffers for both small and large I/O
    buffers := make([][]u8, QUEUE_DEPTH)
    for i := 0; i < QUEUE_DEPTH; i += 1 {
        buffer, alloc_err := mem.alloc_bytes(LARGE_BLOCK_SIZE, 4096)
        if alloc_err != .None {
            fmt.eprintln("Failed to allocate aligned buffer")
            return
        }
        buffers[i] = buffer
    }
    defer {
        for buffer in buffers {
            delete(buffer)
        }
        delete(buffers)
    }
    
    // Define all benchmark configurations
    configs := []BenchmarkConfig{
        // Small I/O (4KB)
        {block_size = SMALL_BLOCK_SIZE, is_sequential = false, is_write = true,  num_requests = NUM_REQUESTS_SMALL}, // small random write
        {block_size = SMALL_BLOCK_SIZE, is_sequential = false, is_write = false, num_requests = NUM_REQUESTS_SMALL}, // small random read
        {block_size = SMALL_BLOCK_SIZE, is_sequential = true,  is_write = true,  num_requests = NUM_REQUESTS_SMALL}, // small sequential write
        {block_size = SMALL_BLOCK_SIZE, is_sequential = true,  is_write = false, num_requests = NUM_REQUESTS_SMALL}, // small sequential read
        
        // Large I/O (1MB)
        {block_size = LARGE_BLOCK_SIZE, is_sequential = false, is_write = true,  num_requests = NUM_REQUESTS_LARGE}, // large random write
        {block_size = LARGE_BLOCK_SIZE, is_sequential = false, is_write = false, num_requests = NUM_REQUESTS_LARGE}, // large random read
        {block_size = LARGE_BLOCK_SIZE, is_sequential = true,  is_write = true,  num_requests = NUM_REQUESTS_LARGE}, // large sequential write
        {block_size = LARGE_BLOCK_SIZE, is_sequential = true,  is_write = false, num_requests = NUM_REQUESTS_LARGE}, // large sequential read
    }
    
    results := make([]BenchmarkResult, len(configs))
    defer delete(results)
    
    fmt.println("=== io_uring Disk I/O Benchmark ===")
    fmt.printf("File size: %d MB\n", FILE_SIZE / (1024 * 1024))
    fmt.printf("Queue depth: %d\n\n", QUEUE_DEPTH)
    
    cache_dropped := false
    
    for config, i in configs {
        // Describe the benchmark
        size_str := config.block_size == SMALL_BLOCK_SIZE ? "4KB" : "1MB"
        pattern_str := config.is_sequential ? "sequential" : "random"
        op_str := config.is_write ? "write" : "read"
        
        fmt.printf("Running %s %s %s benchmark...\n", size_str, pattern_str, op_str)
        
        // For read benchmarks, try to drop caches first
        if !config.is_write && i > 0 {
            fsync(cast(c.int)fd)
            posix_fadvise(cast(c.int)fd, 0, cast(c.long)FILE_SIZE, POSIX_FADV_DONTNEED)
            if !cache_dropped {
                cache_dropped = drop_caches()
                if !cache_dropped && i == 1 {  // First read benchmark
                    fmt.println("Note: Cannot drop caches. Read results may show cache effects.")
                    fmt.println("      Run with 'sudo ./uring_disk_io' for accurate results.")
                }
            }
        }
        
        results[i] = run_benchmark(&ring, fd, buffers, config, FILE_SIZE)
        
        fmt.printf("  Completed in %.3f seconds\n", time.duration_seconds(results[i].elapsed_time))
        fmt.printf("  IOPS: %.0f, Throughput: %.2f MB/s\n\n", results[i].iops, results[i].throughput_mbs)
    }
    
    // Print summary table
    fmt.println("=== Summary Results ===")
    fmt.println("┌─────────┬────────────┬───────────┬────────────┬─────────────────┐")
    fmt.println("│ Size    │ Pattern    │ Operation │ IOPS       │ Throughput MB/s │")
    fmt.println("├─────────┼────────────┼───────────┼────────────┼─────────────────┤")
    
    for result in results {
        size_str := result.config.block_size == SMALL_BLOCK_SIZE ? "4KB " : "1MB "
        pattern_str := result.config.is_sequential ? "Sequential" : "Random    "
        op_str := result.config.is_write ? "Write" : "Read "
        
        fmt.printf("│ %s    │ %s │ %s     │ %10.0f │ %15.2f │\n", 
                   size_str, pattern_str, op_str, result.iops, result.throughput_mbs)
    }
    
    fmt.println("└─────────┴────────────┴───────────┴────────────┴─────────────────┘")
    
    if !cache_dropped {
        fmt.println("\n* Read results may include cache effects. Run with sudo for accurate results.")
    }
}