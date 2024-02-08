const std = @import("std");
const fs = std.fs;
const print = std.debug.print;
const net = std.net;
const expect = std.testing.expect;

var gpa = std.heap.GeneralPurposeAllocator(.{.safety = false}){};
const allocator = gpa.allocator();

const Range = struct {
    lo : u32,
    hi : u32,

    fn eq(self: Range, other: Range) bool {
        return self.hi == other.hi and self.lo == other.lo;
    }

    fn lessThan(self: Range, other:Range) bool {
        if (self.lo == other.lo)
            return self.hi < other.hi;
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
    return Range{.lo = lo, .hi = hi};
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
                  .hi = try std.fmt.parseInt(u32, it.next().?, 10)};
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
            return Range{ .lo = 0, .hi = 255 };
        } else {
            return Range{ .lo = value, .hi = value };
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
        size : T,

        fn isLarge(self: @This()) bool {
            // 0.05 ~ 1/16 is a /4 prefix for u8, u16 and u32 is large enough.
            return @as(f32, @floatFromInt(self.hi - self.lo +| 1)) / @as(f32, @floatFromInt(self.size)) > 0.05;
        }
    };
}

fn truncateRange(comptime T: type, r: Range) RangeType(T) {
    switch (T) {
        u32 => return RangeType(u32) {
            .lo = r.lo,
            .hi = r.hi,
            .size = std.math.maxInt(u32),
        },
        u16 => return RangeType(u16) {
            .lo = @truncate((r.lo & 0xFFFF0000) >> 16),
            .hi = @truncate((r.hi & 0xFFFF0000) >> 16),
            .size = std.math.maxInt(u16),
        },

        u8 => return RangeType(u8) {
            .lo = @truncate((r.lo & 0xFF000000) >> 24),
            .hi = @truncate((r.hi & 0xFF000000) >> 24),
            .size = std.math.maxInt(u8),
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

const CutTag = enum {
    u8x16,
    u16x8,
    u32x4,
};

const ParaCuts = union(CutTag) {
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
    weight: usize = 0,

    fn eq(self: Seg, other: Seg) bool {
        return self.range.eq(other.range);
    }

    fn lessThan(self: Seg, other: Seg) bool {
        return self.range.lessThan(other.range);
    }

    fn overlap(self: *const Seg, other: *const Seg) bool {
        const s = &self.range;
        const o = &other.range;
        if (s.hi < o.lo or s.lo > o.hi) {
            return false;
        }
        return true;
    }
};

fn getUniq(comptime T: type) type {
    return struct {
        fn cmp(_: void, a: T, b: T) bool {
            return a.lessThan(b);
        }

        fn uniq(list : *std.ArrayList(T), weighted: bool) void {
            if (list.items.len == 0)
                return;

            std.sort.block(T, list.items, {}, cmp);
            var idx:usize = 1;
            var u:usize = 0;

            if (!weighted) {
                list.items[u].weight = 1;
            }

            while (idx < list.items.len) : (idx += 1) {
                const w = if (!weighted) 1 else list.items[idx].weight;
                if (!list.items[idx].eq(list.items[u])) {
                    u += 1;
                    if (u != idx) {
                        list.items[u] = list.items[idx];
                    }
                    list.items[u].weight = w;
                } else {
                    list.items[u].weight += w;
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
    getUniq(Seg).uniq(&list, false);
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

    fn genNonOverlappedSegs(seg_list: *const std.ArrayList(Seg)) !std.ArrayList(Seg) {
        var list = std.ArrayList(Seg).init(allocator);
        var h = PQlt.init(allocator, {});
        defer h.deinit();
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
                        if (curr <= top) {
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
                curr = top +% 1;
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

        // [0, 4], [3, 4]
        try l.append(Seg{ .range = .{ .lo = 0, .hi = 4}});
        try l.append(Seg{ .range = .{ .lo = 3, .hi = 4}});
        g = try genNonOverlappedSegs(&l);
        try expect(g.items[0].eq(Seg{ .range = .{ .lo = 0, .hi = 2 }}));
        try expect(g.items[1].eq(Seg{ .range = .{ .lo = 3, .hi = 4 }}));
        try expect(g.items.len == 2);
        g.deinit();
        l.clearAndFree();

        // [0, 4], [0, 1]
        try l.append(Seg{ .range = .{ .lo = 0, .hi = 4}});
        try l.append(Seg{ .range = .{ .lo = 0, .hi = 1}});
        g = try genNonOverlappedSegs(&l);
        try expect(g.items[0].eq(Seg{ .range = .{ .lo = 0, .hi = 1 }}));
        try expect(g.items[1].eq(Seg{ .range = .{ .lo = 2, .hi = 4 }}));
        try expect(g.items.len == 2);
        g.deinit();
        l.clearAndFree();

        // [0, 0], [2, 2]
        try l.append(Seg{ .range = .{ .lo = 0, .hi = 0}});
        try l.append(Seg{ .range = .{ .lo = 2, .hi = 2}});
        g = try genNonOverlappedSegs(&l);
        try expect(g.items[0].eq(Seg{ .range = .{ .lo = 0, .hi = 0 }}));
        try expect(g.items[1].eq(Seg{ .range = .{ .lo = 2, .hi = 2 }}));
        try expect(g.items.len == 2);
        g.deinit();
        l.clearAndFree();

    }

    fn dumpSegs(segs: *const std.ArrayList(Seg)) void {
        for (segs.items) |s| {
            print("{}\n", .{s});
        }
    }

    fn genWeightedSeg(segs: *std.ArrayList(Seg)) !std.ArrayList(Seg) {
        getUniq(Seg).uniq(segs, true);
        //print("origin segs:\n", .{});
        //dumpSegs(segs);
        const non_overlapped = try genNonOverlappedSegs(segs);
        for (segs.items) |*seg| {
            var overlapped = false;
            for (non_overlapped.items) |*n| {
                if (seg.overlap(n)) {
                    n.weight += seg.weight;
                    overlapped = true;
                } else {
                    if (overlapped) {
                        break;
                    }
                }
            }
        }
        return non_overlapped;
    }

    test {
        var segs = std.ArrayList(Seg).init(allocator);
        defer segs.deinit();
        try segs.append(Seg{.range = .{.lo = 0, .hi = std.math.maxInt(u32)}, .weight = 10});
        try segs.append(Seg{.range = .{.lo = 0, .hi = 0}, .weight = 20});
        const non = try genWeightedSeg(&segs);
        defer non.deinit();
        try expect(non.items.len == 2);
        try expect(non.items[0].weight == 30);
        try expect(non.items[1].weight == 10);
    }

    fn calAverageWeight(segs: *std.ArrayList(Seg)) f32 {
        if (segs.items.len == 0)
            return 0.0;
        var sum:usize = 0;
        for (segs.items) |s| {
            sum += s.weight;
        }
        return @as(f32, @floatFromInt(sum)) / @as(f32, @floatFromInt(segs.items.len));
    }

    fn calEff(comptime T:type, segs: *const std.ArrayList(Seg)) !CutInfo {
        var large_segs = std.ArrayList(Seg).init(allocator);
        defer large_segs.deinit();
        var small_segs = std.ArrayList(Seg).init(allocator);
        defer small_segs.deinit();
        var n_large:usize = 0;
        var n_small:usize = 0;

        for (segs.items) |seg| {
            const r = truncateRange(T, seg.range);
            if (r.isLarge()) {
                try large_segs.append(Seg{.range = .{.lo = r.lo, .hi = r.hi}, .weight = seg.weight});
                n_large += seg.weight;
            } else {
                try small_segs.append(Seg{.range = .{.lo = r.lo, .hi = r.hi}, .weight = seg.weight});
                n_small += seg.weight;
            }
        }

        var eff:f32 = 0;
        var large: ?std.ArrayList(Seg) = null;
        var small: ?std.ArrayList(Seg) = null;
        //print("large: {}\n", .{large_segs.items.len});
        if (large_segs.items.len != 0) {
            large = try genWeightedSeg(&large_segs);
            //print("non\n", .{});
            //dumpSegs(&large.?);
            const large_ratio = @as(f32, @floatFromInt(n_large)) / @as(f32, @floatFromInt(n_large + n_small));
            eff += calAverageWeight(&large.?) * large_ratio;
        }

        //print("small: {}\n", .{small_segs.items.len});
        if (small_segs.items.len != 0) {
            small = try genWeightedSeg(&small_segs);
            //print("non\n", .{});
            //dumpSegs(&small.?);
            const small_ratio = @as(f32, @floatFromInt(n_small)) / @as(f32, @floatFromInt(n_large + n_small));
            eff += calAverageWeight(&small.?) * small_ratio;
        }

        return CutInfo{.eff = eff, .large_non = large, .small_non = small};
    }

    test {
        var segs = std.ArrayList(Seg).init(allocator);
        defer segs.deinit();
        try segs.append(Seg{.range = .{.lo = 0, .hi = std.math.maxInt(u32)}, .weight = 10});
        try segs.append(Seg{.range = .{.lo = 0, .hi = 0}, .weight = 20});
        const cutinfo = try calEff(u8, &segs);
        cutinfo.large_non.?.deinit();
        cutinfo.small_non.?.deinit();

        try expect(cutinfo.eff - 16.66666 < 0.00001);
    }

    const CutInfo = struct {
        large_non : ?std.ArrayList(Seg),
        small_non : ?std.ArrayList(Seg),
        eff: f32,
    };

    const cut_kinds = @typeInfo(CutTag).Enum.fields.len;
    fn vectorizedCut(segs: *const std.ArrayList(Seg)) ![cut_kinds]CutInfo {
        var idx:usize = 0;
        var cut_info:[cut_kinds]CutInfo = undefined;

        while (idx < cut_kinds) : (idx += 1) {

            const cut:CutTag = @enumFromInt(idx);
            switch (cut) {
                .u8x16 => cut_info[idx] = try calEff(u8, segs),
                .u16x8 => cut_info[idx] = try calEff(u16, segs),
                .u32x4 => cut_info[idx] = try calEff(u32, segs),
            }
        }
        for (0 .. cut_kinds) |i| {
            print("{} {}\n", .{@as(CutTag, @enumFromInt(i)), cut_info[i].eff});
        }

        return cut_info;
    }

    test {
        var segs = std.ArrayList(Seg).init(allocator);
        defer segs.deinit();
        try segs.append(Seg{.range = .{.lo = 0, .hi = std.math.maxInt(u32)}, .weight = 10});
        try segs.append(Seg{.range = .{.lo = 0, .hi = 0}, .weight = 20});
        const cut = try vectorizedCut(&segs);
        try expect(cut[0].eff - 16.66666 < 0.00001);
        try expect(cut[1].eff - 16.66666 < 0.00001);
        try expect(cut[2].eff - 16.66666 < 0.00001);
        cut[0].large_non.?.deinit();
        cut[0].small_non.?.deinit();

        cut[1].large_non.?.deinit();
        cut[1].small_non.?.deinit();

        cut[2].large_non.?.deinit();
        cut[2].small_non.?.deinit();
    }

    const DimCut = struct {
        dim: u8,
        cut: CutTag,
        eff: f32,
        large_non: ?std.ArrayList(Seg),
        small_non: ?std.ArrayList(Seg),
    };

    fn pickDim(dc: *?DimCut, cut_infos: []const CutInfo, dim: u8) void {
        var min:f32 = std.math.floatMax(f32);
        var idx:usize = 0;
        for(0.., cut_infos) |i, ci| {
            if (min > ci.eff) {
                min = ci.eff;
                idx = i;
            }
        }

        for (0.., cut_infos) |i, *ci| {
            if (i != idx) {
                if (ci.large_non) |a| {
                    a.deinit();
                }
                if (ci.small_non) |a| {
                    a.deinit();
                }
            }
        }

        if (((dc.* != null) and (min < dc.*.?.eff)) or dc.* == null) {
            dc.* = DimCut{.dim = dim, .cut = @enumFromInt(idx),
                .large_non = cut_infos[idx].large_non,
                .small_non = cut_infos[idx].small_non,
                .eff = min};
        }
    }

    fn choose(self: *ParaTree, dim_segs: *[Dim]std.ArrayList(Seg)) !DimCut {
        var i:u8 = 0;
        var dc: ?DimCut = null;

        while (i < Dim) : (i += 1) {
            dim_segs[i] = std.ArrayList(Seg).init(allocator);
            for (self.root.rules.items) |r| {
                try dim_segs[i].append(Seg{ .range = r.ranges[i] });
            }
            getUniq(Seg).uniq(&dim_segs[i], false);
            print("dim {}\n", .{i});
            const cut_infos = try vectorizedCut(&dim_segs[i]);
            pickDim(&dc, &cut_infos, i);
        }
        return dc.?;
    }

    fn build(self: *ParaTree) !void {
        var dim_segs : [Dim]std.ArrayList(Seg) = undefined;
        defer {
            var i:usize = 0;
            while (i < Dim) : (i += 1) {
                dim_segs[i].deinit();
            }
        }

        const dim = try choose(self, &dim_segs);
        _ = dim;
    }
};

fn paraCut(rule_list : *std.ArrayList(Rule)) !ParaTree {
    var tree: ParaTree = undefined;
    tree.root.rules = std.ArrayList(*Rule).init(allocator);

    for (rule_list.items) |*r| {
        try tree.root.rules.append(r);
    }

    try tree.build();
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

