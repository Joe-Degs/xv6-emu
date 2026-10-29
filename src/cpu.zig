// https://github.com/dvoytik/riscv-cheats
//
const std = @import("std");
const mem = @import("./mem.zig");

pub const Error = error{IllegalInstruction};
pub const StepError = Error || mem.Error;

pub const Trap = struct {
    cause: StepError,
    epc: u64,
    tval: u64,
};

const registers = enum(u5) {
    zero, // read as zero, write is ignored
    ra, // ret addr - used to hold subroutine return address (link register) in standard SW convention
    sp, // used to hold stack pointer in standard SW convention
    gp, // global pointer
    tp, // thread pointer
    t0, // temp reg 0, alternate link register
    t1, // temp reg 1
    t2, // temp reg 2
    s0, // saved register 0 or frame pointer (fp)
    s1, // saved register 1
    a0, // return value or function argument 0
    a1, // return value or function argument 1
    a2, // function argument 2
    a3, // function argument 3
    a4, // function argument 4
    a5, // function argument 5
    a6, // function argument 6
    a7, // function argument 7
    s2, // saved register 2
    s3, // saved register 3
    s4, // saved register 4
    s5, // saved register 5
    s6, // saved register 6
    s7, // saved register 7
    s8, // saved register 8
    s9, // saved register 9
    s10, // saved register 10
    s11, // saved register 11
    t3, // temp reg 2
    t4, // temp reg 2
    t5, // temp reg 2
    t6, // temp reg 6
};

pub const Instruction = union(enum) {
    op: Rtype,
    op_32: Rtype,
    amo: Rtype,
    op_imm: Itype,
    op_imm_32: Itype,
    load: Itype,
    jalr: Itype,
    misc_mem: Itype,
    system: Itype,
    store: Stype,
    branch: Btype,
    lui: Utype,
    auipc: Utype,
    jal: Jtype,
};

const Rtype = packed struct(u32) {
    opcode: u7,
    rd: registers,
    funct3: u3,
    rs1: registers,
    rs2: registers,
    funct7: u7,
};

const Itype = packed struct(u32) {
    opcode: u7,
    rd: registers,
    funct3: u3,
    rs1: registers,
    imm11_0: u12,

    fn imm(self: Itype) i64 {
        const signed: i12 = @bitCast(@as(u12, self.imm11_0));
        return signed;
    }
};

const Stype = packed struct(u32) {
    opcode: u7,
    imm4_0: u5,
    funct3: u3,
    rs1: registers,
    rs2: registers,
    imm11_5: u7,

    fn imm(self: Stype) i64 {
        const raw: u12 = @as(u12, self.imm11_5) << 5 |
            @as(u12, self.imm4_0);
        const signed: i12 = @bitCast(raw);
        return signed;
    }
};

const Btype = packed struct(u32) {
    opcode: u7,
    imm11: u1,
    imm4_1: u4,
    funct3: u3,
    rs1: registers,
    rs2: registers,
    imm10_5: u6,
    imm12: u1,

    fn imm(self: Btype) i64 {
        const raw: u13 = @as(u13, self.imm12) << 12 |
            @as(u13, self.imm11) << 11 |
            @as(u13, self.imm10_5) << 5 |
            @as(u13, self.imm4_1) << 1;
        const signed: i13 = @bitCast(raw);
        return signed;
    }
};

const Utype = packed struct(u32) {
    opcode: u7,
    rd: registers,
    imm31_12: u20,

    fn imm(self: Utype) i64 {
        const signed: i32 = @bitCast(@as(u32, self.imm31_12) << 12);
        return signed;
    }
};

const Jtype = packed struct(u32) {
    opcode: u7,
    rd: registers,
    imm19_12: u8,
    imm11: u1,
    imm10_1: u10,
    imm20: u1,

    fn imm(self: Jtype) i64 {
        const raw: u21 = @as(u21, self.imm20) << 20 |
            @as(u21, self.imm19_12) << 12 |
            @as(u21, self.imm11) << 11 |
            @as(u21, self.imm10_1) << 1;
        const signed: i21 = @bitCast(raw);
        return signed;
    }
};

// decode risc-v inst
pub fn decode(inst: u32) Error!Instruction {
    const opcode: u7 = @truncate(inst);
    return switch (opcode) {
        // R: add sub sll slt sltu xor srl sra or and, mul div rem
        0b0110011 => .{ .op = @bitCast(inst) },
        // R: addw subw sllw srlw sraw, mulw divw remw
        0b0111011 => .{ .op_32 = @bitCast(inst) },
        // R: lr sc amoswap amoadd amoand amoor ...
        0b0101111 => .{ .amo = @bitCast(inst) },
        // I: addi slti sltiu xori ori andi slli srli srai
        0b0010011 => .{ .op_imm = @bitCast(inst) },
        // I: addiw slliw srliw sraiw
        0b0011011 => .{ .op_imm_32 = @bitCast(inst) },
        // I: lb lh lw ld lbu lhu lwu
        0b0000011 => .{ .load = @bitCast(inst) },
        // I: jalr
        0b1100111 => .{ .jalr = @bitCast(inst) },
        // I: fence fence.i
        0b0001111 => .{ .misc_mem = @bitCast(inst) },
        // I: ecall ebreak mret sret wfi, csrrw csrrs csrrc ...
        0b1110011 => .{ .system = @bitCast(inst) },
        // S: sb sh sw sd
        0b0100011 => .{ .store = @bitCast(inst) },
        // B: beq bne blt bge bltu bgeu
        0b1100011 => .{ .branch = @bitCast(inst) },
        // U: lui
        0b0110111 => .{ .lui = @bitCast(inst) },
        // U: auipc
        0b0010111 => .{ .auipc = @bitCast(inst) },
        // J: jal
        0b1101111 => .{ .jal = @bitCast(inst) },
        else => error.IllegalInstruction,
    };
}

// sign-extend for 32 bit ops to 64. needed for opp_imm_32 and op_32 type isntructions
fn sext32(x: u32) u64 {
    return @bitCast(@as(i64, @as(i32, @bitCast(x))));
}

pub const Cpu = struct {
    regs: [32]u64 = [_]u64{0} ** 32,
    pc: u64 = mem.Dram.base,
    bus: *mem.Bus,
    trap: ?Trap = null,

    pub fn init(bus: *mem.Bus) !Cpu {
        return .{ .bus = bus };
    }

    // set register value
    pub fn set(self: *Cpu, r: registers, val: u64) void {
        if (r == .zero) return;
        self.regs[@intFromEnum(r)] = val;
    }

    // get register value
    pub fn get(self: Cpu, r: registers) u64 {
        return self.regs[@intFromEnum(r)];
    }

    // execute next instruction and set pc on the cpu
    pub fn step(self: *Cpu) StepError!void {
        const word = self.bus.load(u32, self.pc) catch |err| return self.raise(err, self.pc);
        const inst = decode(word) catch |err| return self.raise(err, word);
        self.pc = self.execute(inst) catch |err| switch (err) {
            error.IllegalInstruction => return self.raise(err, word),
            else => return err,
        };
    }

    fn raise(self: *Cpu, cause: StepError, tval: u64) StepError {
        self.trap = .{ .cause = cause, .epc = self.pc, .tval = tval };
        return cause;
    }

    fn read(self: *Cpu, comptime T: type, addr: u64) StepError!T {
        return self.bus.load(T, addr) catch |err| self.raise(err, addr);
    }

    fn write(self: *Cpu, comptime T: type, addr: u64, val: T) StepError!void {
        return self.bus.store(T, addr, val) catch |err| self.raise(err, addr);
    }

    pub fn format(self: Cpu, w: *std.Io.Writer) std.Io.Writer.Error!void {
        for (std.enums.values(registers), 0..) |r, i| {
            try w.print("{s:<4} {x:0>16}", .{ @tagName(r), self.get(r) });
            try w.writeAll(if (i % 4 == 3) "\n" else "  ");
        }
        try w.print("pc   {x:0>16}\n", .{self.pc});
    }

    // run instruction at pc and return the next pc
    fn execute(self: *Cpu, inst: Instruction) StepError!u64 {
        switch (inst) {
            .op => |r| try self.op(r),
            .op_imm => |i| try self.opImm(i),
            .op_imm_32 => |i| try self.opImm32(i),
            .op_32 => |r| try self.op32(r),
            .lui => |u| self.lui(u),
            .auipc => |u| self.auipc(u),
            .jal => |j| return self.jal(j),
            .jalr => |i| return self.jalr(i),
            .branch => |b| return self.branch(b),
            .load => |i| try self.load(i),
            .store => |s| try self.store(s),
            .misc_mem => |i| try self.miscMem(i),
            else => return error.IllegalInstruction,
        }
        return self.pc + 4;
    }

    // I: lb lh lw ld lbu lhu lwu
    fn load(self: *Cpu, i: Itype) (Error || mem.Error)!void {
        const addr = self.get(i.rs1) +% @as(u64, @bitCast(i.imm()));
        self.set(i.rd, switch (i.funct3) {
            // lb
            0b000 => @bitCast(@as(i64, try self.read(i8, addr))),
            // lh
            0b001 => @bitCast(@as(i64, try self.read(i16, addr))),
            // lw
            0b010 => @bitCast(@as(i64, try self.read(i32, addr))),
            // ld
            0b011 => try self.read(u64, addr),
            // lbu
            0b100 => try self.read(u8, addr),
            // lhu
            0b101 => try self.read(u16, addr),
            // lwu
            0b110 => try self.read(u32, addr),
            else => return error.IllegalInstruction,
        });
    }

    // S: sb sh sw sd
    fn store(self: *Cpu, s: Stype) (Error || mem.Error)!void {
        const addr = self.get(s.rs1) +% @as(u64, @bitCast(s.imm()));
        const val = self.get(s.rs2);
        switch (s.funct3) {
            // sb
            0b000 => try self.write(u8, addr, @truncate(val)),
            // sh
            0b001 => try self.write(u16, addr, @truncate(val)),
            // sw
            0b010 => try self.write(u32, addr, @truncate(val)),
            // sd
            0b011 => try self.write(u64, addr, val),
            else => return error.IllegalInstruction,
        }
    }

    // I: addi slti sltiu xori ori andi slli srli srai
    fn opImm(self: *Cpu, i: Itype) Error!void {
        const rs1 = self.get(i.rs1);
        const imm: u64 = @bitCast(i.imm());
        const shamt: u6 = @truncate(i.imm11_0);
        const arith = i.imm11_0 >> 10 & 1 == 1;
        self.set(i.rd, switch (i.funct3) {
            // addi
            0b000 => rs1 +% imm,
            // slti
            0b010 => @intFromBool(@as(i64, @bitCast(rs1)) < i.imm()),
            // sltiu
            0b011 => @intFromBool(rs1 < imm),
            // xori
            0b100 => rs1 ^ imm,
            // ori
            0b110 => rs1 | imm,
            // andi
            0b111 => rs1 & imm,
            // slli
            0b001 => rs1 << shamt,
            // srai / srli
            0b101 => if (arith) @as(u64, @bitCast(@as(i64, @bitCast(rs1)) >> shamt)) else rs1 >> shamt,
        });
    }

    // I: fence fence.i
    fn miscMem(self: *Cpu, i: Itype) Error!void {
        _ = self;
        switch (i.funct3) {
            // fence
            0b000 => {},
            // fence.i
            0b001 => {},
            else => return error.IllegalInstruction,
        }
    }

    // I: addiw slliw srliw sraiw
    fn opImm32(self: *Cpu, i: Itype) Error!void {
        const rs1: u32 = @truncate(self.get(i.rs1));
        const imm: u32 = @bitCast(@as(i32, @truncate(i.imm())));
        const shamt: u5 = @truncate(i.imm11_0);
        const funct7: u7 = @truncate(i.imm11_0 >> 5);
        self.set(i.rd, sext32(switch (i.funct3) {
            // addiw
            0b000 => rs1 +% imm,
            // slliw
            0b001 => if (funct7 == 0b0000000) rs1 << shamt else return error.IllegalInstruction,
            0b101 => switch (funct7) {
                // srliw
                0b0000000 => rs1 >> shamt,
                // sraiw
                0b0100000 => @bitCast(@as(i32, @bitCast(rs1)) >> shamt),
                else => return error.IllegalInstruction,
            },
            else => return error.IllegalInstruction,
        }));
    }

    fn branch(self: *Cpu, b: Btype) Error!u64 {
        const rs1 = self.get(b.rs1);
        const rs2 = self.get(b.rs2);
        const taken = self.pc +% @as(u64, @bitCast(b.imm()));
        const next = self.pc + 4;
        return switch (b.funct3) {
            // beq
            0b000 => if (rs1 == rs2) taken else next,
            // bne
            0b001 => if (rs1 != rs2) taken else next,
            // blt
            0b100 => if (@as(i64, @bitCast(rs1)) < @as(i64, @bitCast(rs2))) taken else next,
            // bge
            0b101 => if (@as(i64, @bitCast(rs1)) >= @as(i64, @bitCast(rs2))) taken else next,
            // bltu
            0b110 => if (rs1 < rs2) taken else next,
            // bgeu
            0b111 => if (rs1 >= rs2) taken else next,
            else => error.IllegalInstruction,
        };
    }

    // U: lui
    fn lui(self: *Cpu, u: Utype) void {
        self.set(u.rd, @bitCast(u.imm()));
    }

    // U: auipc
    fn auipc(self: *Cpu, u: Utype) void {
        self.set(u.rd, @bitCast(u.imm() +% @as(i64, @bitCast(self.pc))));
    }

    // J: jal
    fn jal(self: *Cpu, j: Jtype) u64 {
        self.set(j.rd, self.pc + 4);
        return self.pc +% @as(u64, @bitCast(j.imm()));
    }

    // I: jalr
    fn jalr(self: *Cpu, i: Itype) u64 {
        const target = self.get(i.rs1) +% @as(u64, @bitCast(i.imm()));
        self.set(i.rd, self.pc + 4);
        return target & ~@as(u64, 1);
    }

    // R: add sub sll slt sltu xor srl sra or and, mul div rem
    fn op(self: *Cpu, r: Rtype) Error!void {
        const rs1 = self.get(r.rs1);
        const rs2 = self.get(r.rs2);
        const key = @as(u10, r.funct7) << 3 | r.funct3;
        self.set(r.rd, switch (key) {
            // add
            0b000 => rs1 +% rs2,
            // sub
            0b0100000_000 => rs1 -% rs2,
            // sll
            0b001 => rs1 << @as(std.math.Log2Int(u64), @truncate(rs2)), //
            // slt
            0b010 => @intFromBool(@as(i64, @bitCast(rs1)) < @as(i64, @bitCast(rs2))),
            // sltu
            0b011 => @intFromBool(rs1 < rs2),
            // xor
            0b100 => rs1 ^ rs2,
            // srl
            0b101 => rs1 >> @as(std.math.Log2Int(u64), @truncate(rs2)),
            // sra
            0b0100000_101 => @as(u64, @bitCast(@as(i64, @bitCast(rs1)) >> @as(std.math.Log2Int(u64), @truncate(rs2)))),
            // or
            0b110 => rs1 | rs2,
            // and
            0b111 => rs1 & rs2,
            else => return error.IllegalInstruction,
        });
    }

    // R: addw subw sllw srlw sraw
    fn op32(self: *Cpu, r: Rtype) Error!void {
        const rs1: u32 = @truncate(self.get(r.rs1));
        const rs2: u32 = @truncate(self.get(r.rs2));
        const shamt: u5 = @truncate(rs2);
        const key = @as(u10, r.funct7) << 3 | r.funct3;
        self.set(r.rd, sext32(switch (key) {
            // addw
            0b000 => rs1 +% rs2,
            // subw
            0b0100000_000 => rs1 -% rs2,
            // sllw
            0b001 => rs1 << shamt,
            // srlw
            0b101 => rs1 >> shamt,
            // sraw
            0b0100000_101 => @bitCast(@as(i32, @bitCast(rs1)) >> shamt),
            else => return error.IllegalInstruction,
        }));
    }
};

test "formats are 32 bits" {
    inline for (.{ Rtype, Itype, Stype, Btype, Utype, Jtype }) |T|
        try std.testing.expectEqual(32, @bitSizeOf(T));
}

test "imm sign extends" {
    const ones: u32 = 0xffff_ffff;
    try std.testing.expectEqual(@as(i64, -1), @as(Itype, @bitCast(ones)).imm());
    try std.testing.expectEqual(@as(i64, -1), @as(Stype, @bitCast(ones)).imm());
    try std.testing.expectEqual(@as(i64, -2), @as(Btype, @bitCast(ones)).imm());
    try std.testing.expectEqual(@as(i64, -4096), @as(Utype, @bitCast(ones)).imm());
    try std.testing.expectEqual(@as(i64, -2), @as(Jtype, @bitCast(ones)).imm());
}

test "decode picks the group from the opcode" {
    const add = (try decode(0x00c58533)).op;
    try std.testing.expectEqual(.a0, add.rd);
    try std.testing.expectEqual(.a1, add.rs1);
    try std.testing.expectEqual(.a2, add.rs2);

    try std.testing.expectEqual(@as(i64, -1), (try decode(0xfff50513)).op_imm.imm());
    try std.testing.expectEqual(@as(i64, 8), (try decode(0x00113423)).store.imm());
    try std.testing.expectEqual(@as(i64, -4), (try decode(0xfeb50ee3)).branch.imm());
    try std.testing.expectEqual(@as(i64, -0x8000_0000), (try decode(0x80000537)).lui.imm());
    try std.testing.expectEqual(@as(i64, -4), (try decode(0xffdff06f)).jal.imm());
}

test "decode rejects unknown opcodes" {
    try std.testing.expectError(error.IllegalInstruction, decode(0));
}

fn assemble(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
    const result = try std.process.run(allocator, std.testing.io, .{ .argv = &.{
        "sh", "-c",
        \\printf '%s\n' "$1" |
        \\llvm-mc -triple=riscv64 -mattr=-relax -filetype=obj -o - |
        \\llvm-objcopy -O binary -j .text - -
        ,
        "sh", src,
    } });
    defer allocator.free(result.stderr);
    errdefer allocator.free(result.stdout);
    if (result.term != .exited or result.term.exited != 0 or result.stderr.len != 0) {
        std.debug.print("{s}", .{result.stderr});
        return error.AssembleFailed;
    }
    // std.debug.print("{any}\n", .{result.stdout});
    return result.stdout;
}

fn runProgram(cpu: *Cpu, src: []const u8) !void {
    const code = try assemble(std.testing.allocator, src);
    defer std.testing.allocator.free(code);
    try cpu.bus.write(mem.Dram.base, code);
    while (cpu.pc < mem.Dram.base + code.len) try cpu.step();
}

test "op_imm" {
    var bus = try mem.Bus.init(std.testing.allocator, 4096);
    defer bus.deinit();
    var cpu = try Cpu.init(&bus);
    try runProgram(&cpu,
        \\addi a0, zero, -1
        \\srli a1, a0, 60
        \\srai a2, a0, 60
        \\slti a3, a0, 0
        \\sltiu a4, a1, 16
        \\xori a5, a1, 0xff
        \\addi zero, zero, 5
    );
    try std.testing.expectEqual(0xffff_ffff_ffff_ffff, cpu.get(.a0));
    try std.testing.expectEqual(0xf, cpu.get(.a1));
    try std.testing.expectEqual(0xffff_ffff_ffff_ffff, cpu.get(.a2));
    try std.testing.expectEqual(1, cpu.get(.a3));
    try std.testing.expectEqual(1, cpu.get(.a4));
    try std.testing.expectEqual(0xf0, cpu.get(.a5));
    try std.testing.expectEqual(0, cpu.get(.zero));
    try std.testing.expectEqual(mem.Dram.base + 7 * 4, cpu.pc);
}

test "unimplemented group is illegal" {
    var bus = try mem.Bus.init(std.testing.allocator, 4096);
    defer bus.deinit();
    var cpu = try Cpu.init(&bus);
    // obscure instrution we will not need here
    try std.testing.expectError(Error.IllegalInstruction, runProgram(&cpu, ".word 0"));
    try std.testing.expectEqual(mem.Dram.base, cpu.pc);
}

test "op" {
    var bus = try mem.Bus.init(std.testing.allocator, 4096);
    defer bus.deinit();
    var cpu = try Cpu.init(&bus);
    try runProgram(&cpu,
        \\addi t0, zero, -1
        \\srli t1, t0, 1
        \\addi t2, zero, 1
        \\add  a0, t1, t2
        \\sub  a1, zero, t2
        \\addi t3, zero, 65
        \\sll  a2, t2, t3
        \\sra  a3, a0, t0
        \\srl  a4, a0, t0
        \\slt  a5, t0, t2
        \\sltu a6, t0, t2
        \\add  zero, t2, t2
    );
    try std.testing.expectEqual(0x8000_0000_0000_0000, cpu.get(.a0));
    try std.testing.expectEqual(0xffff_ffff_ffff_ffff, cpu.get(.a1));
    try std.testing.expectEqual(2, cpu.get(.a2));
    try std.testing.expectEqual(0xffff_ffff_ffff_ffff, cpu.get(.a3));
    try std.testing.expectEqual(1, cpu.get(.a4));
    try std.testing.expectEqual(1, cpu.get(.a5));
    try std.testing.expectEqual(0, cpu.get(.a6));
    try std.testing.expectEqual(0, cpu.get(.zero));
}

test "op: unknown funct7 is illegal" {
    inline for (.{
        ".insn r 0x33, 0, 2, a0, a1, a2",
        ".insn r 0x33, 1, 0x20, a0, a1, a2",
    }) |src| {
        var bus = try mem.Bus.init(std.testing.allocator, 4096);
        defer bus.deinit();
        var cpu = try Cpu.init(&bus);
        try std.testing.expectError(Error.IllegalInstruction, runProgram(&cpu, src));
        try std.testing.expectEqual(mem.Dram.base, cpu.pc);
    }
}

test "lui and auipc" {
    var bus = try mem.Bus.init(std.testing.allocator, 4096);
    defer bus.deinit();
    var cpu = try Cpu.init(&bus);
    try runProgram(&cpu,
        \\auipc a0, 0
        \\auipc a1, 1
        \\lui   a2, 0x80000
        \\lui   a3, 0xfffff
        \\auipc a4, 0xfffff
        \\lui   zero, 1
    );
    try std.testing.expectEqual(mem.Dram.base, cpu.get(.a0));
    try std.testing.expectEqual(mem.Dram.base + 4 + 0x1000, cpu.get(.a1));
    try std.testing.expectEqual(0xffff_ffff_8000_0000, cpu.get(.a2));
    try std.testing.expectEqual(0xffff_ffff_ffff_f000, cpu.get(.a3));
    try std.testing.expectEqual(mem.Dram.base + 16 - 0x1000, cpu.get(.a4));
    try std.testing.expectEqual(0, cpu.get(.zero));
}

test "jal and jalr" {
    var bus = try mem.Bus.init(std.testing.allocator, 4096);
    defer bus.deinit();
    var cpu = try Cpu.init(&bus);
    try runProgram(&cpu,
        \\    jal   s0, over_a0
        \\    addi  a0, zero, 1
        \\over_a0:
        \\    auipc t0, 0
        \\    addi  t0, t0, 37
        \\    jalr  s1, -20(t0)
        \\    addi  a1, zero, 1
        \\    auipc t1, 0
        \\    jalr  t1, 12(t1)
        \\    addi  a2, zero, 1
        \\    jal   zero, end
        \\    addi  a3, zero, 1
        \\end:
    );
    try std.testing.expectEqual(0, cpu.get(.a0));
    try std.testing.expectEqual(0, cpu.get(.a1));
    try std.testing.expectEqual(0, cpu.get(.a2));
    try std.testing.expectEqual(0, cpu.get(.a3));
    try std.testing.expectEqual(mem.Dram.base + 4, cpu.get(.s0));
    try std.testing.expectEqual(mem.Dram.base + 20, cpu.get(.s1));
    try std.testing.expectEqual(mem.Dram.base + 32, cpu.get(.t1));
    try std.testing.expectEqual(mem.Dram.base + 44, cpu.pc);
}

test "branch" {
    const taken = 1;
    const not_taken = 0;
    var bus = try mem.Bus.init(std.testing.allocator, 4096);
    defer bus.deinit();
    var cpu = try Cpu.init(&bus);
    try runProgram(&cpu,
        \\    li    t0, -1
        \\    li    t1, 1
        \\
        \\    # -1 == -1
        \\    li    a0, 1
        \\    beq   t0, t0, 1f
        \\    li    a0, 0
        \\1:
        \\    # -1 != -1
        \\    li    a1, 1
        \\    bne   t0, t0, 1f
        \\    li    a1, 0
        \\1:
        \\    # signed: -1 < 1
        \\    li    a2, 1
        \\    blt   t0, t1, 1f
        \\    li    a2, 0
        \\1:
        \\    # unsigned: 0xffff_ffff_ffff_ffff < 1
        \\    li    a3, 1
        \\    bltu  t0, t1, 1f
        \\    li    a3, 0
        \\1:
        \\    # signed: 1 >= 1, equal counts
        \\    li    a4, 1
        \\    bge   t1, t1, 1f
        \\    li    a4, 0
        \\1:
        \\    # unsigned: 0xffff_ffff_ffff_ffff >= 1
        \\    li    a5, 1
        \\    bgeu  t0, t1, 1f
        \\    li    a5, 0
        \\1:
        \\    # unsigned: 1 >= 1, equal counts
        \\    li    a6, 1
        \\    bgeu  t1, t1, 1f
        \\    li    a6, 0
        \\1:
        \\    # backward branch: negative offset, loops 3 times
        \\    li    t2, 3
        \\loop:
        \\    addi  s0, s0, 1
        \\    addi  t2, t2, -1
        \\    bne   t2, zero, loop
    );
    try std.testing.expectEqual(taken, cpu.get(.a0));
    try std.testing.expectEqual(not_taken, cpu.get(.a1));
    try std.testing.expectEqual(taken, cpu.get(.a2));
    try std.testing.expectEqual(not_taken, cpu.get(.a3));
    try std.testing.expectEqual(taken, cpu.get(.a4));
    try std.testing.expectEqual(taken, cpu.get(.a5));
    try std.testing.expectEqual(taken, cpu.get(.a6));
    try std.testing.expectEqual(3, cpu.get(.s0));
}

test "branch: funct3 010 is illegal" {
    var bus = try mem.Bus.init(std.testing.allocator, 4096);
    defer bus.deinit();
    var cpu = try Cpu.init(&bus);
    try std.testing.expectError(error.IllegalInstruction, runProgram(&cpu,
        \\    .insn b 0x63, 2, a0, a1, 0
    ));
}

test "load and store" {
    const all_ones: u64 = std.math.maxInt(u64);
    var bus = try mem.Bus.init(std.testing.allocator, 4096);
    defer bus.deinit();
    var cpu = try Cpu.init(&bus);
    try runProgram(&cpu,
        \\    # s0 = scratch memory, 1 KiB past the code
        \\    auipc s0, 0
        \\    addi  s0, s0, 1024
        \\    li    t0, -1
        \\
        \\    # all ones at s0+0, read back at every width
        \\    sd    t0, 0(s0)
        \\    lb    a0, 0(s0)
        \\    lbu   a1, 0(s0)
        \\    lh    a2, 0(s0)
        \\    lhu   a3, 0(s0)
        \\    lw    a4, 0(s0)
        \\    lwu   a5, 0(s0)
        \\    ld    a6, 0(s0)
        \\
        \\    # all ones, then zero only the low byte, half, word
        \\    sd    t0, 8(s0)
        \\    sb    zero, 8(s0)
        \\    ld    s1, 8(s0)
        \\    sd    t0, 16(s0)
        \\    sh    zero, 16(s0)
        \\    ld    s2, 16(s0)
        \\    sd    t0, 24(s0)
        \\    sw    zero, 24(s0)
        \\    ld    s3, 24(s0)
        \\
        \\    # negative offset reaches back to s0+0
        \\    addi  t1, s0, 8
        \\    ld    s4, -8(t1)
    );
    try std.testing.expectEqual(all_ones, cpu.get(.a0));
    try std.testing.expectEqual(0xff, cpu.get(.a1));
    try std.testing.expectEqual(all_ones, cpu.get(.a2));
    try std.testing.expectEqual(0xffff, cpu.get(.a3));
    try std.testing.expectEqual(all_ones, cpu.get(.a4));
    try std.testing.expectEqual(0xffff_ffff, cpu.get(.a5));
    try std.testing.expectEqual(all_ones, cpu.get(.a6));
    try std.testing.expectEqual(0xffff_ffff_ffff_ff00, cpu.get(.s1));
    try std.testing.expectEqual(0xffff_ffff_ffff_0000, cpu.get(.s2));
    try std.testing.expectEqual(0xffff_ffff_0000_0000, cpu.get(.s3));
    try std.testing.expectEqual(all_ones, cpu.get(.s4));
}

test "load and store: unused funct3 is illegal" {
    for ([_][]const u8{
        \\    .insn i 0x03, 7, a0, 0(a1)
        ,
        \\    .insn s 0x23, 4, a0, 0(a1)
    }) |src| {
        var bus = try mem.Bus.init(std.testing.allocator, 4096);
        defer bus.deinit();
        var cpu = try Cpu.init(&bus);
        try std.testing.expectError(error.IllegalInstruction, runProgram(&cpu, src));
    }
}

test "op_imm_32" {
    var bus = try mem.Bus.init(std.testing.allocator, 4096);
    defer bus.deinit();
    var cpu = try Cpu.init(&bus);
    try runProgram(&cpu,
        \\    # t0 = 0xffff_ffff_8000_0000, low word is the smallest i32
        \\    lui   t0, 0x80000
        \\    # t1 = 0x0000_0001_0000_0000, low word is zero
        \\    addi  t1, zero, 1
        \\    slli  t1, t1, 32
        \\
        \\    # addiw wraps at 32 bits: smallest i32 - 1 = largest i32
        \\    addiw a0, t0, -1
        \\    # sext.w drops the upper word
        \\    sext.w a1, t1
        \\    # slliw into bit 31 goes negative
        \\    addi  t2, zero, 1
        \\    slliw a2, t2, 31
        \\    # srliw by 0 still sign-extends
        \\    srliw a3, t0, 0
        \\    # srliw shifts zeros into bit 31, ignoring the upper word
        \\    srliw a4, t0, 1
        \\    # sraiw copies bit 31
        \\    sraiw a5, t0, 31
    );
    try std.testing.expectEqual(0x0000_0000_7fff_ffff, cpu.get(.a0));
    try std.testing.expectEqual(0, cpu.get(.a1));
    try std.testing.expectEqual(0xffff_ffff_8000_0000, cpu.get(.a2));
    try std.testing.expectEqual(0xffff_ffff_8000_0000, cpu.get(.a3));
    try std.testing.expectEqual(0x0000_0000_4000_0000, cpu.get(.a4));
    try std.testing.expectEqual(0xffff_ffff_ffff_ffff, cpu.get(.a5));
}

test "op_imm_32: shamt over 31 is illegal" {
    for ([_][]const u8{
        \\    .insn i 0x1b, 1, a0, a1, 32
        ,
        \\    .insn i 0x1b, 5, a0, a1, 32
    }) |src| {
        var bus = try mem.Bus.init(std.testing.allocator, 4096);
        defer bus.deinit();
        var cpu = try Cpu.init(&bus);
        try std.testing.expectError(error.IllegalInstruction, runProgram(&cpu, src));
    }
}

test "op_32" {
    var bus = try mem.Bus.init(std.testing.allocator, 4096);
    defer bus.deinit();
    var cpu = try Cpu.init(&bus);
    try runProgram(&cpu,
        \\    # t0 = 0xffff_ffff_8000_0000, low word is the smallest i32
        \\    lui   t0, 0x80000
        \\    # t1 = 0x0000_0001_0000_0001, upper word is garbage to ignore
        \\    addi  t1, zero, 1
        \\    slli  t1, t1, 32
        \\    addi  t1, t1, 1
        \\    addi  t2, zero, 33
        \\
        \\    # addw ignores the upper word: 1 + 1
        \\    addw  a0, t1, t1
        \\    # subw wraps at 32 bits: smallest i32 - 1 = largest i32
        \\    subw  a1, t0, t1
        \\    # sllw by 33 shifts by 1, only rs2[4:0] counts
        \\    sllw  a2, t1, t2
        \\    # srlw by 0 still sign-extends
        \\    srlw  a3, t0, zero
        \\    # sraw copies bit 31
        \\    sraw  a4, t0, t2
    );
    try std.testing.expectEqual(2, cpu.get(.a0));
    try std.testing.expectEqual(0x0000_0000_7fff_ffff, cpu.get(.a1));
    try std.testing.expectEqual(2, cpu.get(.a2));
    try std.testing.expectEqual(0xffff_ffff_8000_0000, cpu.get(.a3));
    try std.testing.expectEqual(0xffff_ffff_c000_0000, cpu.get(.a4));
}

test "op_32: unknown funct7 is illegal" {
    var bus = try mem.Bus.init(std.testing.allocator, 4096);
    defer bus.deinit();
    var cpu = try Cpu.init(&bus);
    try std.testing.expectError(error.IllegalInstruction, runProgram(&cpu,
        \\    .insn r 0x3b, 0, 2, a0, a1, a2
    ));
}

test "misc_mem" {
    var bus = try mem.Bus.init(std.testing.allocator, 4096);
    defer bus.deinit();
    var cpu = try Cpu.init(&bus);
    try runProgram(&cpu,
        \\    fence
        \\    fence.i
    );
    try std.testing.expectEqual(mem.Dram.base + 8, cpu.pc);

    var bad_bus = try mem.Bus.init(std.testing.allocator, 4096);
    defer bad_bus.deinit();
    var bad = try Cpu.init(&bad_bus);
    try std.testing.expectError(error.IllegalInstruction, runProgram(&bad,
        \\    .insn i 0x0f, 2, zero, zero, 0
    ));
}
