const std = @import("std");
const mem = @import("./mem.zig");
const arch = @import("./cpu.zig");
const Elf = @import("./elf.zig");

const Cpu = arch.Cpu;

pub const Debug = struct {
    exec: bool = false,
    cpu: bool = false,
    elf: bool = false,

    pub fn parse(text: []const u8) !Debug {
        var result: Debug = .{};
        var opts = std.mem.splitScalar(u8, text, ',');

        while (opts.next()) |opt| {
            inline for (@typeInfo(Debug).@"struct".fields) |field| {
                if (std.mem.eql(u8, opt, field.name)) {
                    @field(result, field.name) = true;
                    break;
                }
            } else return error.UnknowDebugFlag;
        }
        return result;
    }
};

const MAX_CPU = 8;

const Self = @This();

bus: mem.Bus,
cpus: [MAX_CPU]Cpu,
num_cpus: usize,

pub fn init(self: *Self, allocator: std.mem.Allocator, memsz: usize, num_cpus: usize) !void {
    // TODO: support more cpus
    if (num_cpus != 1) return error.SingleCpuOnly;
    self.bus = try mem.Bus.init(allocator, memsz);
    errdefer self.bus.deinit();
    self.num_cpus = num_cpus;
    for (self.cpus[0..num_cpus]) |*cpu| cpu.* = try Cpu.init(&self.bus);
}

pub fn deinit(self: *Self) void {
    self.bus.deinit();
}

// load program and set program entry point
pub fn load(self: *Self, kernel: []const u8) !void {
    const elf = try Elf.parse(kernel);
    const entry = try elf.load(&self.bus);
    for (self.cpus[0..self.num_cpus]) |*cpu| cpu.pc = entry;
}

pub fn run(self: *Self, debug: Debug, log: *std.Io.Writer) !void {
    while (true) {
        for (self.cpus[0..self.num_cpus], 0..) |*cpu, id| {
            if (debug.exec) try traceInst(log, id, cpu.*);
            try cpu.step();
            if (debug.cpu) try log.print("{f}\n", .{cpu.*});
        }
    }
}

pub fn traceInst(log: *std.Io.Writer, id: usize, cpu: Cpu) !void {
    const word = cpu.bus.load(u32, cpu.pc) catch 0;
    try log.print("[{d}] pc: 0x{x:0>16} inst: 0x{x:0>8} {any}\n", .{
        id, cpu.pc, word, arch.decode(word) catch null,
    });
}

test "run a kernel until it hits an illegal instruction" {
    const allocator = std.testing.allocator;
    const kernel = try Elf.link(allocator,
        \\    addi a0, zero, 42
        \\    .word 0
    );
    defer allocator.free(kernel);

    var machine: Self = undefined;
    try machine.init(allocator, 4096, 1);
    defer machine.deinit();
    try machine.load(kernel);

    try std.testing.expectError(error.IllegalInstruction, machine.run());
    const hart = machine.cpus[0];
    try std.testing.expectEqual(42, hart.get(.a0));
    // stopped on the .word 0, one instruction past the start
    try std.testing.expectEqual(mem.Dram.base + 4, hart.pc);
}
