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
    size : u32 = std.math.maxInt(u32),

    fn isLarge(self: Range) bool {
        return @as(f32, (self.hi - self.lo + 1)) / self.size > 0.05;
    }

    fn eq(self: Range, other: Range) bool {
        return self.hi == other.hi and self.lo == other.lo;
    }

    fn lessThan(self: Range, other:Range) bool {
        return self.lo < other.lo;
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
        cuts: @Vector(16, u8),
        shift: [17]u8,
    },

    u16x8: struct {
        cuts: @Vector(8, u16),
        shift: [9]u8,
    },

    u32x4: struct {
        cuts: @Vector(4, u32),
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

    fn eq(self: Seg, other: Seg) bool {
        return self.range.eq(other.range);
    }

    fn lessThan(self: Seg, other: Seg) bool {
        return self.range.lessThan(other.range);
    }
};

fn getUniq(comptime T: type) type {
    return struct {
        fn cmp(_: void, a: T, b: T) bool {
            return a.lessThan(b);
        }

        fn uniq(list : *std.ArrayList(T)) void {
            std.sort.block(T, list.items, {}, cmp);
            var idx:usize = 1;
            var u:usize = 0;

            while (idx < list.items.len) : (idx += 1) {
                if (!list.items[idx].eq(list.items[u])) {
                    u += 1;
                    if (u != idx) {
                        list.items[u] = list.items[idx];
                    }
                } else {
                    list.items[u].weight += 1;
                }
            }
            list.shrinkAndFree(u + 1);
        }
    };
}

test {
    var list = std.ArrayList(Seg).init(allocator);
    defer list.deinit();
    try list.append(Seg{ .range = .{ .lo = 1, .hi = 2} });
    try list.append(Seg{ .range = .{ .lo = 0, .hi = 1} });
    try list.append(Seg{ .range = .{ .lo = 2, .hi = 3} });
    try list.append(Seg{ .range = .{ .lo = 0, .hi = 1} });
    getUniq(Seg).uniq(&list);
    try expect(list.items.len == 3);
    try expect(list.items[0].eq(Seg{ .range = .{ .lo = 0, .hi = 1}}));
    try expect(list.items[0].weight == 2);
}

test {
    _ = ParaTree;
}

const ParaTree = struct {
    root: ParaNode,

    const Order = std.math.Order;
    fn lessThan(_ : void, a: u32, b: u32) Order {
        return std.math.order(a, b);
    }

    const PQlt = std.PriorityQueue(u32, void, lessThan);

    fn genNonOverlappedSegs(seg_list: *std.ArrayList(Seg)) !std.ArrayList(Seg) {
        var list = std.ArrayList(Seg).init(allocator);
        var h = PQlt.init(allocator, {});
        const items = seg_list.items;


        var idx:usize = 1;
        var curr:u32 = items[0].range.lo;
        try h.add(items[0].range.hi);

        while (idx < items.len) : (idx += 1) {
            const r = &items[idx].range;
            if (r.lo < h.peek().?) {
                // We should be careful about the [A, A] (the hi and lo are equal) and [A, B].
                // We need the results to be [A, A] and [A+1, B].
                if (r.lo == curr and r.lo == r.hi) {
                    try list.append(Seg{ .range = .{ .lo = curr, .hi = r.hi } });
                    curr = r.hi + 1;
                } else {
                    if (curr < r.lo) {
                        try list.append(Seg{ .range = .{ .lo = curr, .hi = r.lo - 1} });
                        curr = r.lo;
                    }
                    try h.add(items[idx].range.hi);
                }
            } else {
                while (h.peek()) |top| {
                    // r.lo >= top
                    if (r.lo == top) {

                        // we need a seg: [r.lo, top], as the current range r overlaps with a
                        // previous range (in the heap).
                        if (r.lo > curr) {
                            try list.append(Seg{.range = .{.lo = curr, .hi = r.lo - 1}});
                            curr = r.lo;
                        }

                        // [B, B] and [A, B], we needs a [B, B] and [A, B-1]
                        if (curr == top) {
                            // if r.lo == curr == top, we need a [r.lo, top]
                            // we will only add once in case there are multiple same `top'
                            try list.append(Seg{.range = .{ .lo = r.lo, .hi = top }});
                            curr = r.lo + 1;
                        }
                    } else if (r.lo > top) {
                        // r.lo > top, and since there are values in heap, there are overlapped
                        // ranges.
                        if (curr < top) {
                            try list.append(Seg{.range = .{ .lo = curr, .hi = top} });
                            curr = top + 1;
                        }
                    } else {
                        break;
                    }

                    _ = h.remove();
                }

                if (h.count() == 0 and curr < r.lo) {
                    curr = r.lo;
                }
                try h.add(items[idx].range.hi);
            }
        }

        while (h.peek()) |top| {
            if (curr <= top) {
                try list.append(Seg{.range = .{ .lo = curr, .hi = top }});
                curr = top + 1;
            }
            _ = h.remove();
        }
        return list;
    }

    test {
        var l = std.ArrayList(Seg).init(allocator);
        defer l.deinit();
        // [0, 0] and [0, 1]
        try l.append(Seg{ .range = .{ .lo = 0, .hi = 0}});
        try l.append(Seg{ .range = .{ .lo = 0, .hi = 1}});
        var g = try genNonOverlappedSegs(&l);
        try expect(g.items[0].eq(Seg{ .range = .{ .lo = 0, .hi = 0 }}));
        try expect(g.items[1].eq(Seg{ .range = .{ .lo = 1, .hi = 1 }}));
        try expect(g.items.len == 2);
        g.deinit();
        l.clearAndFree();


        // [0, 1] and [0, 0]
        try l.append(Seg{ .range = .{ .lo = 0, .hi = 1}});
        try l.append(Seg{ .range = .{ .lo = 0, .hi = 0}});
        g = try genNonOverlappedSegs(&l);
        try expect(g.items[0].eq(Seg{ .range = .{ .lo = 0, .hi = 0 }}));
        try expect(g.items[1].eq(Seg{ .range = .{ .lo = 1, .hi = 1 }}));
        try expect(g.items.len == 2);
        g.deinit();
        l.clearAndFree();

        // [0, 1] and [1, 1]
        try l.append(Seg{ .range = .{ .lo = 0, .hi = 1}});
        try l.append(Seg{ .range = .{ .lo = 1, .hi = 1}});
        g = try genNonOverlappedSegs(&l);
        try expect(g.items[0].eq(Seg{ .range = .{ .lo = 0, .hi = 0 }}));
        try expect(g.items[1].eq(Seg{ .range = .{ .lo = 1, .hi = 1 }}));
        try expect(g.items.len == 2);
        g.deinit();
        l.clearAndFree();

        // [0, 3], [1, 2]
        try l.append(Seg{ .range = .{ .lo = 0, .hi = 3}});
        try l.append(Seg{ .range = .{ .lo = 1, .hi = 2}});
        g = try genNonOverlappedSegs(&l);
        try expect(g.items[0].eq(Seg{ .range = .{ .lo = 0, .hi = 0 }}));
        try expect(g.items[1].eq(Seg{ .range = .{ .lo = 1, .hi = 2 }}));
        try expect(g.items[2].eq(Seg{ .range = .{ .lo = 3, .hi = 3 }}));
        try expect(g.items.len == 3);
        g.deinit();
        l.clearAndFree();

        // [0, 1], [2, 3]
        try l.append(Seg{ .range = .{ .lo = 0, .hi = 1}});
        try l.append(Seg{ .range = .{ .lo = 2, .hi = 3}});
        g = try genNonOverlappedSegs(&l);
        try expect(g.items[0].eq(Seg{ .range = .{ .lo = 0, .hi = 1 }}));
        try expect(g.items[1].eq(Seg{ .range = .{ .lo = 2, .hi = 3 }}));
        try expect(g.items.len == 2);
        g.deinit();
        l.clearAndFree();

        // [0, 1], [3, 5]
        try l.append(Seg{ .range = .{ .lo = 0, .hi = 1}});
        try l.append(Seg{ .range = .{ .lo = 3, .hi = 5}});
        g = try genNonOverlappedSegs(&l);
        try expect(g.items[0].eq(Seg{ .range = .{ .lo = 0, .hi = 1 }}));
        try expect(g.items[1].eq(Seg{ .range = .{ .lo = 3, .hi = 5 }}));
        try expect(g.items.len == 2);
        g.deinit();
        l.clearAndFree();

        // [0, 4], [3, 5]
        try l.append(Seg{ .range = .{ .lo = 0, .hi = 4}});
        try l.append(Seg{ .range = .{ .lo = 3, .hi = 5}});
        g = try genNonOverlappedSegs(&l);
        try expect(g.items[0].eq(Seg{ .range = .{ .lo = 0, .hi = 2 }}));
        try expect(g.items[1].eq(Seg{ .range = .{ .lo = 3, .hi = 4 }}));
        try expect(g.items[2].eq(Seg{ .range = .{ .lo = 5, .hi = 5 }}));
        try expect(g.items.len == 3);
        g.deinit();
        l.clearAndFree();
    }


    fn chooseDimension(self: *ParaTree, dim_ranges: *[Dim]std.ArrayList(Seg)) u8 {
        var i:usize = 0;
        while (i < Dim) : (i += 1) {
            dim_ranges[i] = std.ArrayList(*Range).init(allocator);
            for (self.root.rules) |r| {
                dim_ranges[i].append(Seg{ .range = r.ranges[i] });
            }
            getUniq(Seg).uniq(&dim_ranges[i]);
        }
        return 0;
    }

    //fn build(self: *ParaTree) void {
    //    var dim_ranges : [Dim]std.ArrayList(Seg) = undefined;
    //    defer {
    //        var i = 0;
    //        while (i < Dim) : (i += 1) {
    //            dim_ranges[i].deinit();
    //        }
    //    }

    //    const dim = chooseDimension(self, &dim_ranges);
    //}
};

fn paraCut(rule_list : *std.ArrayList(Rule)) !ParaTree {
    var tree: ParaTree = undefined;
    tree.root.rules = std.ArrayList(*Rule).init(allocator);

    for (rule_list.items) |*r| {
        try tree.root.rules.append(r);
    }

    //tree.build();
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
        try rule_list.append(rule);
        line_no += 1;
    }

    _  = try paraCut(&rule_list);
}

