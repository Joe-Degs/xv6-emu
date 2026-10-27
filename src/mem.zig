const std = @import("std");

pub const Error = error{ LoadAccessFault, StoreAccessFault };

pub const Dram = struct {
    pub const base: u64 = 0x8000_0000;

    const Self = @This();

    allocator: std.mem.Allocator,

    /// physical memory backing [base, base + memory.len)
    memory: []u8,

    pub fn init(allocator: std.mem.Allocator, size: usize) (std.mem.Allocator.Error || error{BadMemSize})!Self {
        if (size == 0 or size % 4096 != 0) return error.BadMemSize;
        const memory = try allocator.alloc(u8, size);
        @memset(memory, 0);
        return .{ .allocator = allocator, .memory = memory };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.memory);
    }

    /// the `len` bytes backing physical `addr`, or null if any of them fall outside dram
    fn region(self: Self, addr: u64, len: usize) ?[]u8 {
        if (addr < base) return null;
        const off = addr - base;
        if (off > self.memory.len or self.memory.len - off < len) return null;
        return self.memory[@intCast(off)..][0..len];
    }

    /// read `buf.len` bytes starting at `addr` into `buf`
    pub fn read_into(self: Self, addr: u64, buf: []u8) Error!void {
        const bytes = self.region(addr, buf.len) orelse return Error.LoadAccessFault;
        @memcpy(buf, bytes);
    }

    /// write `buf.len` bytes from `buf` starting at `addr`
    pub fn write_from(self: *Self, addr: u64, buf: []const u8) Error!void {
        const bytes = self.region(addr, buf.len) orelse return Error.StoreAccessFault;
        @memcpy(bytes, buf);
    }

    /// read a little-endian integer `T` at `addr`
    pub fn read_into_val(self: Self, comptime T: type, addr: u64) Error!T {
        const bytes = self.region(addr, @sizeOf(T)) orelse return Error.LoadAccessFault;
        return std.mem.readInt(T, bytes[0..@sizeOf(T)], .little);
    }

    /// write integer `val` as little-endian at `addr`
    pub fn write_from_val(self: *Self, comptime T: type, addr: u64, val: T) Error!void {
        const bytes = self.region(addr, @sizeOf(T)) orelse return Error.StoreAccessFault;
        std.mem.writeInt(T, bytes[0..@sizeOf(T)], val, .little);
    }
};

pub const Bus = struct {
    dram: Dram,

    pub fn init(allocator: std.mem.Allocator, size: u64) anyerror!Bus {
        return .{ .dram = try Dram.init(allocator, size) };
    }

    pub fn deinit(self: *Bus) void {
        self.dram.deinit();
    }

    pub fn load(self: Bus, comptime T: type, addr: u64) Error!T {
        if (addr >= Dram.base) {
            return try self.dram.read_into_val(T, addr);
        }
        return error.LoadAccessFault;
    }

    pub fn store(self: *Bus, comptime T: type, addr: u64, val: T) Error!void {
        if (addr >= Dram.base) {
            return try self.dram.write_from_val(T, addr, val);
        }
        return error.StoreAccessFault;
    }

    pub fn write(self: *Bus, addr: u64, buf: []const u8) !void {
        if (addr >= Dram.base) {
            return try self.dram.write_from(addr, buf);
        }
        return error.StoreAccessFault;
    }
};

const testing = std.testing;

test "round trip every width" {
    var dram = try Dram.init(testing.allocator, 4096);
    var bus = try Bus.init(testing.allocator, 4096);
    defer dram.deinit();
    defer bus.deinit();
    inline for (.{ u8, u16, u32, u64 }) |T| {
        const v: T = @truncate(0x1122334455667788);
        try dram.write_from_val(T, Dram.base + 8, v);
        try bus.store(T, Dram.base + 8, v);
        try testing.expectEqual(v, try dram.read_into_val(T, Dram.base + 8));
        try testing.expectEqual(v, try bus.load(T, Dram.base + 8));
    }
}

test "bus routes the first byte of dram" {
    var bus = try Bus.init(testing.allocator, 4096);
    defer bus.deinit();
    try bus.store(u8, Dram.base, 0xaa);
    try testing.expectEqual(0xaa, try bus.load(u8, Dram.base));
}

test "little endian byte order" {
    var dram = try Dram.init(testing.allocator, 4096);
    defer dram.deinit();
    try dram.write_from_val(u32, Dram.base, 0xdeadbeef);
    var buf: [4]u8 = undefined;
    try dram.read_into(Dram.base, &buf);
    try testing.expectEqualSlices(u8, &.{ 0xef, 0xbe, 0xad, 0xde }, &buf);
}

test "starts zeroed" {
    var dram = try Dram.init(testing.allocator, 4096);
    defer dram.deinit();
    for (dram.memory) |b| try testing.expectEqual(0, b);
}

test "misaligned access" {
    var dram = try Dram.init(testing.allocator, 4096);
    defer dram.deinit();
    try dram.write_from_val(u64, Dram.base + 3, 0x0102030405060708);
    try testing.expectEqual(0x0102030405060708, try dram.read_into_val(u64, Dram.base + 3));
}

test "edges of the range" {
    var dram = try Dram.init(testing.allocator, 4096);
    defer dram.deinit();
    const end = Dram.base + 4096;

    try dram.write_from_val(u8, end - 1, 0xff);
    try testing.expectEqual(0xff, try dram.read_into_val(u8, end - 1));
    try dram.write_from_val(u64, end - 8, 1);

    try testing.expectError(Error.LoadAccessFault, dram.read_into_val(u8, Dram.base - 1));
    try testing.expectError(Error.LoadAccessFault, dram.read_into_val(u8, 0));
    try testing.expectError(Error.LoadAccessFault, dram.read_into_val(u8, end));
    try testing.expectError(Error.LoadAccessFault, dram.read_into_val(u32, end - 3));
    try testing.expectError(Error.LoadAccessFault, dram.read_into_val(u64, std.math.maxInt(u64) - 2));
    try testing.expectError(Error.StoreAccessFault, dram.write_from_val(u32, end - 3, 0));
    try testing.expectError(Error.StoreAccessFault, dram.write_from_val(u8, Dram.base - 1, 0));
}

test "bad sizes rejected" {
    try testing.expectError(error.BadMemSize, Dram.init(testing.allocator, 0));
    try testing.expectError(error.BadMemSize, Dram.init(testing.allocator, 100));
}
