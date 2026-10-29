const std = @import("std");
const Machine = @import("machine.zig");
const cpu = @import("cpu.zig");

pub fn parse(comptime T: type, args: []const []const u8) !T {
    const fields = @typeInfo(T).@"struct".fields;
    var result: T = undefined;
    var seen = [_]bool{false} ** fields.len;

    var i: usize = 0;
    while (i < args.len) : (i += 2) {
        if (i + 1 == args.len) return error.MissingValue;
        inline for (fields, 0..) |field, f| {
            if (std.mem.eql(u8, args[i], "-" ++ field.name)) {
                @field(result, field.name) = try parseValue(field.type, args[i + 1]);
                seen[f] = true;
                break;
            }
        } else return error.UnknownFlag;
    }

    inline for (fields, 0..) |field, f| {
        if (!seen[f])
            @field(result, field.name) = field.defaultValue() orelse return error.MissingFlag;
    }

    return result;
}

fn parseValue(comptime T: type, text: []const u8) !T {
    if (T == []const u8) return text;
    return switch (@typeInfo(T)) {
        .int => std.fmt.parseInt(T, text, 10),
        .@"struct" => T.parse(text),
        else => @compileError("no parser for " ++ @typeName(T)),
    };
}

const Size = struct {
    bytes: usize,

    fn mib(n: usize) Size {
        return .{ .bytes = n << 20 };
    }

    // qemu style: 64M, 1G, 512K; a bare number is MiB
    fn parse(text: []const u8) !Size {
        if (text.len == 0) return error.InvalidCharacter;
        const shift: u6 = switch (text[text.len - 1]) {
            'K' => 10,
            'M' => 20,
            'G' => 30,
            else => return mib(try std.fmt.parseInt(usize, text, 10)),
        };
        return .{ .bytes = try std.fmt.parseInt(usize, text[0 .. text.len - 1], 10) << shift };
    }
};

const Opts = struct {
    kernel: []const u8,
    m: Size = .mib(128),
    smp: usize = 1,
    d: Machine.Debug = .{},
};

const usage =
    \\usage: {s} -kernel <path> [-m <size>] [-smp <n>]
    \\  -kernel <path>    ELF to load
    \\  -m <size>         dram size, like qemu: 128M (default), 1G
    \\  -smp <n>          number of harts (default 1)
;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();

    const args = try init.minimal.args.toSlice(arena);
    const opts = parse(Opts, args[1..]) catch |err|
        std.process.fatal("{t}\n" ++ usage, .{ err, args[0] });

    const kernel = try std.Io.Dir.cwd().readFileAlloc(init.io, opts.kernel, arena, .limited(opts.m.bytes));

    var machine: Machine = undefined;
    try machine.init(init.gpa, opts.m.bytes, opts.smp);
    defer machine.deinit();
    try machine.load(kernel);

    var buf: [4096]u8 = undefined;
    var stderr = std.Io.File.stderr().writer(init.io, &buf);
    const log = &stderr.interface;
    defer log.flush() catch {};

    machine.run(opts.d, log) catch {
        for (machine.cpus[0..machine.num_cpus], 0..) |hart, id| {
            const trap = hart.trap orelse continue;
            // const word = machine.bus.load(u32, trap.epc) catch 0;
            // std.debug.print(
            //     \\error: {t}
            //     \\  hart {d}  pc 0x{x:0>16}  inst 0x{x:0>8}  tval 0x{x}
            //     \\  decoded {any}
            //     \\
            //     \\{f}
            // , .{ trap.cause, id, trap.epc, word, trap.tval, cpu.decode(word) catch null, hart });
            try log.print("error: {t}  tval 0x{x}\n", .{ trap.cause, trap.tval });
            try Machine.traceInst(log, id, hart);
            try log.print("\n{f}", .{hart});
        }
        try log.flush();
        std.process.exit(1);
    };
}

test {
    _ = @import("cpu.zig");
    _ = @import("elf.zig");
    _ = @import("machine.zig");
    _ = @import("mem.zig");
}
