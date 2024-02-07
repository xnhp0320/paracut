const std = @import("std");
const fs = std.fs;
const print = std.debug.print;
const net = std.net; 
const expect = std.testing.expect;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

const Range = struct {
    hi : u32,
    lo : u32,
    size : u32,

    bool isLarge(self: Range) bool {
        return as(f32, (hi - lo + 1)) / size > 0.05;
    }
};

const Prefix = struct {
    prefix : u32,
    len : u6,
};

const Dim = 5;

fn RuleType(N: comptime_int) type {
    return struct {
        ranges : [N]Range,
        pri : u32,
    };
}

const Rule = RuleType(Dim);

fn prefixToRange(p: Prefix) !Range {
    if (p.len > 32)
        return error.InvalidPrefixLen;

    const lo = std.mem.readInt(u32, std.mem.asBytes(&p.prefix), .big);
    const diff = if (p.len == 0) 0xFFFFFFFF else (@as(u32, 1) << @truncate(32 - p.len)) - 1;
    const hi = lo + diff;
    return Range{.lo = lo, .hi = hi, .size = std.math.maxInt(u32)};
}

fn parseIPv4Prefix(v: []const u8) !Range {
    const p = std.mem.indexOf(u8, v, "/");   
    if (p) |pos| { 
        const addr = try net.Ip4Address.parse(v[0 .. pos], 0);
        const plen = try std.fmt.parseInt(u6, v[pos + 1 .. v.len], 10);
        return prefixToRange(Prefix{ .prefix = addr.sa.addr, .len = plen });
    } else { 
        return error.NotIPv4Prefix;
    }
}

test {
    const r1 = try parseIPv4Prefix("192.168.0.0/24");
    try expect(r1.lo == 0xc0a80000);
    try expect(r1.hi == 0xc0a800ff);

    const r2 = try parseIPv4Prefix("10.0.0.0/8");
    try expect(r2.lo == 0x0a000000);
    try expect(r2.hi == 0x0affffff);

    const r3 = try parseIPv4Prefix("0.0.0.0/0");
    try expect(r3.lo == 0x00000000);
    try expect(r3.hi == 0xffffffff);
    
    const r4 = parseIPv4Prefix("1.2.3.0/36") catch null;
    try expect(r4 == null);
}

fn parsePortRange(v: []const u8) !Range {
    var it = std.mem.split(u8, v, " : ");
    return Range{ .lo = try std.fmt.parseInt(u32, it.next().?, 10),
                  .hi = try std.fmt.parseInt(u32, it.next().?, 10),
                  .size = std.math.maxInt(u16) };
}

test {
    const r1 = try parsePortRange("1000 : 2000");
    try expect(r1.lo == 1000);
    try expect(r1.hi == 2000);
}

fn parseProtocolRange(v: []const u8) !Range {
    const p = std.mem.indexOf(u8, v, "/");
    if (p) |pos| {
        const value = try std.fmt.parseInt(u32, v[0 .. pos], 0);
        const mask = try std.fmt.parseInt(u32, v[pos+1 .. v.len], 0);
        if (mask == 0) {
            return Range{ .lo = 0, .hi = 255, .size = std.math.maxInt(u8) };
        } else {
            return Range{ .lo = value, .hi = value, .size = std.math.maxInt(u8) };
        }

    } else {
        return error.NotMaskValue;
    }
}

test {
    const r1 = try parseProtocolRange("0x11/0xFF");
    try expect(r1.lo == 0x11);
    try expect(r1.hi == 0x11);
}

fn RangeType(comptime T: type) type {
    return struct {
        lo : T,
        hi : T,
    };
}

fn truncateRange(comptime T: type, r: Range) RangeType(T) {
    switch (T) {
        u32 => return RangeType(u32) {
            .lo = r.lo,
            .hi = r.hi,
        },
        u16 => return RangeType(u16) {
            .lo = (r.lo & 0xFFFF0000) >> 16,
            .hi = (r.hi & 0xFFFF0000) >> 16,
        },

        u8 => return RangeType(u8) {
            .lo = (r.lo & 0xFF000000) >> 24,
            .hi = (r.hi & 0xFF000000) >> 24,
        }, 

        else => unreachable,
    }
}

fn parseRule(line: []const u8, pri: u32) !Rule {
    var it = std.mem.split(u8, line[1 .. line.len], "\t");  
    const rule = Rule { .ranges = [_]Range { 
        try parseIPv4Prefix(it.next().?),
        try parseIPv4Prefix(it.next().?),
        try parsePortRange(it.next().?),
        try parsePortRange(it.next().?),
        try parseProtocolRange(it.next().?) }, .pri = pri };

    return rule;
}

const ParaCuts = union(enum) {
    u8x16: struct {
        cuts: @Vector(u8, 16), 
        shift: [17]u8,
    },

    u16x8: struct {
        cuts: @Vector(u16, 8),
        shift: [9]u8,
    },

    u32x4: struct {
        cuts: @Vector(u32, 4),
        shift: [5]u8,
    },
};

const ParaNode = struct {
    cuts : ParaCuts,
    dim : u8,
    is_leaf: bool,
    next: []ParaNode,
    rules: std.ArrayList(*Rule),
};

const Seg = struct {
    range : Range,
    weight: usize = 1,
};

const ParaTree = struct {
    root: ParaNode,

    fn genSegs() void {

    }

    fn segCmp(_ : anytype, a: Seg, b: Seg) bool {
        return a.lo < b.lo;
    }

    fn uniqSegs(seg_list : *std.ArrayList(Seg)) void {
        std.sort.block(Seg, seg_list.items, {}, segCmp);
        var idx:usize = 0;
        var uniq:usize = 0;

        while (idx < seg_list.items.len) : (idx += 1) {
            seg_list.items[

        }
    }

    fn chooseDimension(self: *ParaTree, dim_ranges: *[dim]std.ArrayList(Seg)) u8 {
        var i:usize = 0;
        while (i < dim) : (i += 1) {
            dim_ranges[i] = std.ArrayList(*Range).init(allocator);
            for (self.root.rules) |r| {
                dim_ranges[i].append(Seg{ .range = r.ranges[i] });
            }
            uniqSegs(&dim_ranges[i]);
        }
    }

    fn build(self: *ParaTree) void {
        var dim_ranges : [dim]std.ArrayList(Seg) = undefined;
        defer {
            var i = 0;
            while (i < dim) : (i += 1) {
                dim_ranges[i].deinit();
            }
        };

        const dim = chooseDimension(self, &dim_ranges)

    }
};

fn paraCut(rule_list : *std.ArrayList(Rule)) ParaTree {
    var tree: ParaTree = undefined;
    tree.root.rules = std.ArrayList(*Rule).init(allocator);
    
    for (rule_list.items) |*r| {
        tree.root.rules.append(r);
    }

    tree.build();
    return tree;
}

pub fn main() !void {
    defer _ = gpa.deinit();

    const file = try fs.cwd().openFile("fw1K", .{});
    defer file.close();

    const rdr = file.reader();
    var line_no:u32 = 0;
    var rule_list = std.ArrayList(Rule).init(allocator); 
    defer rule_list.deinit();

    while (try rdr.readUntilDelimiterOrEofAlloc(allocator, '\n', 4096)) |line| {
        defer allocator.free(line);
        if (line[0] != '@') {
            continue;
        }
        const rule = try parseRule(line, line_no);
        rule_list.append(rule);
        line_no += 1;
    }

    paraCut(&rule_list);
}

