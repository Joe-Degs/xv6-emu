const std = @import("std");
const mem = @import("mem.zig");

const Class = enum(u8) { elf32 = 1, elf64 = 2, _ };

const Data = enum(u8) { little = 1, big = 2, _ };

const Type = enum(u16) { none = 0, rel = 1, exec = 2, dyn = 3, core = 4, _ };

const Machine = enum(u16) { x86_64 = 0x3e, aarch64 = 0xb7, riscv = 0xf3, _ };

const SegmentType = enum(u32) {
    null = 0,
    load = 1,
    dynamic = 2,
    interp = 3,
    note = 4,
    phdr = 6,
    tls = 7,
    gnu_stack = 0x6474e551,
    _,
};

const Header = extern struct {
    magic: [4]u8,
    class: Class, // arch
    data: Data, // endian
    version: u8, // of elf format
    os_abi: u8,
    // abi_version:  u8, // this is now part of the padding
    pad: [8]u8,
    type: u16,
    machine: Machine, // isa (risc-v)
    _version: u32,
    entry: u64,
    phoff: u64, // program header table
    shoff: u64, // section header table
    flags: u32,
    ehsize: u16, // size of this header
    phentsize: u16, // size of prog header table entry 0x38 for 64 bit
    phnum: u16, // num entries in prog header table
    shentsize: u16, // size of section header table entry 0x40 for 64 bit
    shnum: u16, // num entries in section header table
    shstrndx: u16, // entry of section header table that contains section names
};

const Flags = packed struct(u32) { x: bool, w: bool, r: bool, _: u29 };

const ProgramHeader = extern struct {
    type: SegmentType,
    flags: Flags,
    offset: u64, // offset in file
    vaddr: u64, // virtual address
    paddr: u64, // physical address
    filesz: u64, // segment size in file
    memsz: u64, // segment size in memory
    @"align": u64, //
};

pub const Error = error{
    Truncated,
    NotElf,
    Not64Bit,
    NotLittleEndian,
    NotRiscv,
};

const Self = @This();

file: []const u8,
header: Header,
prog_headers: []align(1) const ProgramHeader,

pub fn parse(file: []const u8) !Self {
    if (file.len < @sizeOf(Header)) return error.Truncated;

    if (!std.mem.eql(u8, file[0..4], "\x7fELF"))
        return error.NotElf;

    const hdr = std.mem.bytesToValue(Header, file[0..64]);
    if (hdr.class != .elf64) return error.Not64Bit;
    if (hdr.data != .little) return error.NotLittleEndian;
    if (hdr.machine != .riscv) return error.NotRiscv;

    if (hdr.phoff + hdr.phnum * @sizeOf(ProgramHeader) > file.len) return error.Truncated;

    const table = file[hdr.phoff..][0 .. hdr.phnum * @sizeOf(ProgramHeader)];

    return .{
        .header = hdr,
        .file = file,
        .prog_headers = std.mem.bytesAsSlice(ProgramHeader, table),
    };
}

// load elf file into memory and return program entry point
pub fn load(self: Self, bus: *mem.Bus) mem.Error!u64 {
    for (self.prog_headers) |ph| {
        if (ph.type != .load) continue;
        try bus.write(ph.paddr, self.file[ph.offset..][0..ph.filesz]);
    }
    return self.header.entry;
}

pub fn link(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
    const result = try std.process.run(allocator, std.testing.io, .{ .argv = &.{
        "sh", "-c",
        \\dir=$(mktemp -d) &&
        \\printf '%s\n' "$1" | llvm-mc -triple=riscv64 -filetype=obj -o "$dir/t.o" &&
        \\printf "SECTIONS { . = 0x80000000; .text : { *(.text) } }" > "$dir/t.ld" &&
        \\ld.lld -T "$dir/t.ld" -e 0x80000000 "$dir/t.o" -o "$dir/t.elf" &&
        \\cat "$dir/t.elf"
        \\status=$?
        \\rm -rf "$dir"
        \\exit $status
        ,
        "sh", src,
    } });
    defer allocator.free(result.stderr);
    errdefer allocator.free(result.stdout);
    if (result.term != .exited or result.term.exited != 0 or result.stderr.len != 0) {
        std.debug.print("{s}", .{result.stderr});
        return error.LinkFailed;
    }
    return result.stdout;
}

test "parse a linked elf" {
    const file = try link(std.testing.allocator, "nop");
    defer std.testing.allocator.free(file);
    const elf = try parse(file);
    try std.testing.expectEqual(0x8000_0000, elf.header.entry);
}

test "parse rejects a broken field" {
    const allocator = std.testing.allocator;
    const file = try link(allocator, "nop");
    defer allocator.free(file);
    for ([_]struct { offset: usize, byte: u8, err: Error }{
        // magic
        .{ .offset = 0, .byte = 0x00, .err = error.NotElf },
        // class: 32-bit
        .{ .offset = 4, .byte = 1, .err = error.Not64Bit },
        // data: big endian
        .{ .offset = 5, .byte = 2, .err = error.NotLittleEndian },
        // machine: x86-64
        .{ .offset = 18, .byte = 0x3e, .err = error.NotRiscv },
    }) |case| {
        const broken = try allocator.dupe(u8, file);
        defer allocator.free(broken);
        broken[case.offset] = case.byte;
        try std.testing.expectError(case.err, parse(broken));
    }
}

test "parse program headers" {
    const allocator = std.testing.allocator;
    const file = try link(allocator, "nop");
    defer allocator.free(file);
    const elf = try parse(file);

    try std.testing.expectEqual(2, elf.prog_headers.len);
    const text = elf.prog_headers[0];
    try std.testing.expectEqual(.load, text.type);
    try std.testing.expectEqual(0x1000, text.offset);
    try std.testing.expectEqual(0x8000_0000, text.paddr);
    // one nop
    try std.testing.expectEqual(4, text.filesz);
    try std.testing.expect(text.flags.r and text.flags.x and !text.flags.w);
}

test "load copies segments to their paddr" {
    const allocator = std.testing.allocator;

    // link and load 8 bytes to start of mem and check that they land
    const file = try link(allocator, ".dword 0x1122334455667788");
    defer allocator.free(file);
    const elf = try parse(file);

    var bus = try mem.Bus.init(allocator, 4096);
    defer bus.deinit();
    const entry = try elf.load(&bus);

    try std.testing.expectEqual(mem.Dram.base, entry);
    try std.testing.expectEqual(0x1122334455667788, try bus.load(u64, mem.Dram.base));
}
