const std = @import("std");
const fs = std.fs;
const print = std.debug.print;
const net = std.net;
const expect = std.testing.expect;
const Error = std.mem.Allocator.Error;

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

    fn isLarge(self: Range, size: u32) bool {
        // 0.05 ~ 1/16 is a /4 prefix for u8, u16 and u32 is large enough.
        return @as(f32, @floatFromInt(self.hi - self.lo +| 1)) / @as(f32, @floatFromInt(size)) > 0.05;
    }

    fn overlap(self: *const Range, other: *const Range) bool {
        if (self.hi < other.lo or self.lo > other.hi) {
            return false;
        }
        return true;
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

fn mapInto(r: *const Range, t: *const Range) Range {
    const lo = @max(r.lo, t.lo);
    const hi = @min(r.hi, t.hi);

    return Range{ .lo = lo - t.lo,
                  .hi = hi - t.lo };
}

fn truncateRange(comptime T: type, r: *const Range, size: u32, di: *const DimInfo) Range {
    //print("trunc {} {}\n", .{r.*, di.r});
    std.debug.assert(r.overlap(&di.r));
    const range = mapInto(r, &di.r);

    if (std.math.maxInt(T) >= size) {
        return range;
    }

    const hi = range.hi;
    const lo = range.lo;

    switch (T) {
        u32 => return Range {
            .lo = lo,
            .hi = hi,
        },

        u16 => return Range {
            .lo = @truncate((lo & 0xFFFF0000) >> 16),
            .hi = @truncate((hi & 0xFFFF0000) >> 16),
        },

        u8 => return Range {
            .lo = @truncate((lo & 0xFF000000) >> 24),
            .hi = @truncate((hi & 0xFF000000) >> 24),
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
    },

    u16x8: struct {
        cuts: @Vector(8, u16),
    },

    u32x4: struct {
        cuts: @Vector(4, u32),
    },

    fn dump(self:*ParaCuts) void {
        print("{}\n", .{self.*});
    }
};

const Seg = struct {
    range : Range,
    weight: u32 = 0,

    fn eq(self: Seg, other: Seg) bool {
        return self.range.eq(other.range);
    }

    fn lessThan(self: Seg, other: Seg) bool {
        return self.range.lessThan(other.range);
    }

    fn overlap(self: *const Seg, other: *const Seg) bool {
        const s = &self.range;
        const o = &other.range;
        return s.overlap(o);
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
    _ = ParaNode;
}

const NextCut = struct {
    const W = struct {
        v : u32,
        w : u32,
    };

    const Order = std.math.Order;
    fn lessThan(_ : void, a: W, b: W) Order {
        return std.math.order(a.v, b.v);
    }

    const PQlt = std.PriorityQueue(W, void, lessThan);

    curr_rules: u32 = 0,
    cut: Range = undefined,
    seg_idx: usize = 0,
    start_idx: usize = 0,
    h: PQlt = undefined,

    fn init(self: *NextCut) void {
        self.h = PQlt.init(allocator, {});
    }

    fn deinit(self: *NextCut) void {
        self.h.deinit();
    }

    fn doCut(self: *NextCut, segs: *const std.ArrayList(Seg)) Error!void {
        while(self.h.peek()) |top| {
            if (top.v < self.cut.lo) {
                const w = self.h.remove();
                self.curr_rules -= w.w;
            } else {
                break;
            }
        }

        while (self.seg_idx < segs.items.len) : (self.seg_idx += 1) {
            const seg = &segs.items[self.seg_idx];
            if (seg.range.lo <= self.cut.hi) {
                self.curr_rules += seg.weight;
                try self.h.add(W{.v = seg.range.hi, .w = seg.weight});
            } else {
                break;
            }
        }
    }

    fn nextCutLo(self: *NextCut, non: *const std.ArrayList(Seg)) void {
        self.cut.lo = non.items[self.start_idx].range.lo;
    }

    fn nextCutHi(self: *NextCut, non: *const std.ArrayList(Seg), last_cut: bool) void {
        if (self.start_idx == non.items.len - 1 or last_cut) {
            const last_hi = non.items[non.items.len - 1].range.hi;
            self.cut.hi = last_hi;
        } else {
            //print("start_idx {} {}\n", .{self.start_idx, non.items[self.start_idx + 1].range});
            self.cut.hi = non.items[self.start_idx + 1].range.lo - 1;
        }
        self.start_idx += 1;
    }

    fn hasNext(self: *NextCut, non: *const std.ArrayList(Seg)) bool {
        return self.start_idx < non.items.len;

    }

    fn searchCut(self: *NextCut, segs: *const std.ArrayList(Seg),
        non: *const std.ArrayList(Seg), t: f32, last_cut: bool) Error!void {
        self.nextCutLo(non);

        while (true) {
           self.nextCutHi(non, last_cut);
           try self.doCut(segs);
           //print("cuts {} {} {}\n", .{self.curr_rules, self.cut, self.start_idx});

           if (@as(f32, @floatFromInt(self.curr_rules)) >= t
               or !self.hasNext(non)) {
               break;
           }
        }
    }
};

const ParaFlag = packed struct(u32) {
    large_cut : u1,
    trunc_flag: u1,
    unused: u14,
    small_mask: u16,

    fn dump(self: *ParaFlag) void {
        print("Flag: large_cut {} trunc_flag: {} small_mask: 0x{x:02}\n",
            .{self.large_cut, self.trunc_flag, self.small_mask});

    }
};

const ParaNode = struct {
    const LeafNode = 255;
    dim : u8 = LeafNode,
    offset: u32 = 0,
    flags: ParaFlag = undefined,
    cuts : ParaCuts = undefined,
    next: []ParaNode = undefined,
    rules: std.ArrayList(*Rule) = std.ArrayList(*Rule).init(allocator),

    const Order = std.math.Order;
    fn lessThan(_ : void, a: u32, b: u32) Order {
        return std.math.order(a, b);
    }

    const PQlt = std.PriorityQueue(u32, void, lessThan);

    fn genNonOverlappedSegs(seg_list: *const std.ArrayList(Seg)) Error!std.ArrayList(Seg) {
        var list = std.ArrayList(Seg).init(allocator);
        var h = PQlt.init(allocator, {});
        defer h.deinit();
        const items = seg_list.items;


        var idx:usize = 1;
        var curr:usize = items[0].range.lo;
        try h.add(items[0].range.hi);

        while (idx < items.len) : (idx += 1) {
            const r = &items[idx].range;
            if (r.lo < h.peek().?) {
                // We should be careful about the [A, A] (the hi and lo are equal) and [A, B].
                // We need the results to be [A, A] and [A+1, B].
                if (r.lo == curr and r.lo == r.hi) {
                    try list.append(Seg{ .range = .{ .lo = @truncate(curr), .hi = r.hi } });
                    curr = r.hi + 1;
                } else {
                    if (curr < r.lo) {
                        try list.append(Seg{ .range = .{ .lo = @truncate(curr), .hi = r.lo - 1} });
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
                            try list.append(Seg{.range = .{.lo = @truncate(curr), .hi = r.lo - 1}});
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
                            try list.append(Seg{.range = .{ .lo = @truncate(curr), .hi = top} });
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
                try list.append(Seg{.range = .{ .lo = @truncate(curr), .hi = top }});
                curr = @as(usize, @intCast(top)) + 1;
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

        // [0, std.math.maxInt(u32)], [2, std.math.maxInt(u32)]
        try l.append(Seg{ .range = .{ .lo = 0, .hi = std.math.maxInt(u32)}});
        try l.append(Seg{ .range = .{ .lo = 2, .hi = std.math.maxInt(u32)}});
        g = try genNonOverlappedSegs(&l);
        try expect(g.items[0].eq(Seg{ .range = .{ .lo = 0, .hi = 1 }}));
        try expect(g.items[1].eq(Seg{ .range = .{ .lo = 2, .hi = std.math.maxInt(u32) }}));
        try expect(g.items.len == 2);
        g.deinit();
        l.clearAndFree();
    }

    fn dumpSegs(segs: *const std.ArrayList(Seg), desc: []const u8) void {
        print("{s}\n", .{desc});
        for (segs.items) |s| {
            print("{}\n", .{s});
        }
    }

    fn searchCuts(segs: *std.ArrayList(Seg), n_cuts: u8, n_rules: usize) Error!std.ArrayList(Seg) {
        getUniq(Seg).uniq(segs, true);
        //dumpSegs(segs, "uniq");
        const non = try genNonOverlappedSegs(segs);
        //dumpSegs(&non, "non");

        const t:f32 = @as(f32, @floatFromInt(n_rules)) / @as(f32, @floatFromInt(n_cuts + 1));
        //print("t {d:.2}\n", .{t});
        var i:usize = 0;

        var nextcut = NextCut{};
        nextcut.init();
        defer nextcut.deinit();

        var cut_segs = std.ArrayList(Seg).init(allocator);

        while (i < n_cuts + 1 and nextcut.hasNext(&non)) : (i += 1) {
            try nextcut.searchCut(segs, &non, t, i == n_cuts);
            try cut_segs.append(Seg{ .range = nextcut.cut, .weight = nextcut.curr_rules});
        }

        return cut_segs;
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

    const nLargeCuts = 1;

    fn truncateSize(comptime T: type, size: u32) u32 {
        return @min(size, std.math.maxInt(T));
    }

    fn cutDim(comptime T:type, segs: *const std.ArrayList(Seg), di: *const DimInfo, n_cuts: u8) Error!CutInfo {
        var large_segs = std.ArrayList(Seg).init(allocator);
        defer large_segs.deinit();
        var small_segs = std.ArrayList(Seg).init(allocator);
        defer small_segs.deinit();
        var n_large:usize = 0;
        var n_small:usize = 0;

        const size = di.size();
        const trunc_size = truncateSize(T, size);

        //FIXME: we do not consider nLargeCuts == 0, if equals to 0, the below code is not correct.
        std.debug.assert(nLargeCuts > 0);
        for (segs.items) |seg| {
            const r = truncateRange(T, &seg.range, size, di);
            if (r.isLarge(trunc_size)) {
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

        var n_large_cuts:u8 = 0;
        var n_small_cuts:u8 = 0;

        if (large_segs.items.len != 0 and small_segs.items.len != 0) {
            n_large_cuts = nLargeCuts;
            n_small_cuts = n_cuts - nLargeCuts;
        } else if (large_segs.items.len != 0) {
            n_large_cuts = n_cuts;
        } else {
            n_small_cuts = n_cuts;
        }
        //print("{} {}\n", .{n_large_cuts, n_small_cuts});

        if (n_large_cuts != 0) {
            large = try searchCuts(&large_segs, n_large_cuts, n_large);
            //dumpSegs(&large.?, "large cut");
            const large_ratio = @as(f32, @floatFromInt(n_large)) / @as(f32, @floatFromInt(n_large + n_small));
            eff += calAverageWeight(&large.?) * large_ratio;
        }

        if (n_small_cuts != 0) {
            small = try searchCuts(&small_segs,  n_small_cuts, n_small);
            //dumpSegs(&small.?, "small cut");
            const small_ratio = @as(f32, @floatFromInt(n_small)) / @as(f32, @floatFromInt(n_large + n_small));
            eff += calAverageWeight(&small.?) * small_ratio;
        }

        return CutInfo{.eff = eff, .large_cuts = large, .small_cuts = small};
    }

    test {
        var segs = std.ArrayList(Seg).init(allocator);
        defer segs.deinit();
        try segs.append(Seg{.range = .{.lo = 0, .hi = std.math.maxInt(u32)}, .weight = 10});
        try segs.append(Seg{.range = .{.lo = 0, .hi = 0}, .weight = 20});
        const di = DimInfo{ .r = .{ .lo = 0, .hi = std.math.maxInt(u32) } };
        const cutinfo = try cutDim(u8, &segs, &di, 2);
        cutinfo.large_cuts.?.deinit();
        cutinfo.small_cuts.?.deinit();

        try expect(cutinfo.eff - 16.66666 < 0.00001);
    }

    const CutInfo = struct {
        large_cuts : ?std.ArrayList(Seg) = null,
        small_cuts : ?std.ArrayList(Seg) = null,
        eff: f32 = std.math.floatMax(f32),
    };


    const nCuts = [_]u8{ 16, 8, 4};
    const cut_kinds = @typeInfo(CutTag).Enum.fields.len;
    fn vectorizedCut(segs: *const std.ArrayList(Seg), dim_info:*const DimInfo) Error![cut_kinds]CutInfo {
        var idx:usize = 0;
        var cut_info = [_]CutInfo{.{}} ** cut_kinds;
        var kinds:usize = undefined;

        if (dim_info.size() > std.math.maxInt(u16)) {
            kinds = 3;
        } else if (dim_info.size() > std.math.maxInt(u8)) {
            kinds = 2;
        } else {
            kinds = 1;
        }

        while (idx < kinds) : (idx += 1) {
            const cut:CutTag = @enumFromInt(idx);
            switch (cut) {
                .u8x16 => cut_info[idx] = try cutDim(u8, segs, dim_info, nCuts[idx]),
                .u16x8 => cut_info[idx] = try cutDim(u16, segs, dim_info, nCuts[idx]),
                .u32x4 => cut_info[idx] = try cutDim(u32, segs, dim_info, nCuts[idx]),
            }
        }
        //for (0 .. cut_kinds) |i| {
        //    print("{} {d:.2}\n", .{@as(CutTag, @enumFromInt(i)), cut_info[i].eff});
        //}

        return cut_info;
    }

    test {
        var segs = std.ArrayList(Seg).init(allocator);
        defer segs.deinit();
        try segs.append(Seg{.range = .{.lo = 0, .hi = std.math.maxInt(u32)}, .weight = 10});
        try segs.append(Seg{.range = .{.lo = 0, .hi = 0}, .weight = 20});
        const cut = try vectorizedCut(&segs, &DimInfo{.r = .{.lo =0, .hi = std.math.maxInt(u32)}});
        try expect(cut[0].eff - 16.66666 < 0.00001);
        try expect(cut[1].eff - 16.66666 < 0.00001);
        try expect(cut[2].eff - 16.66666 < 0.00001);
        cut[0].large_cuts.?.deinit();
        cut[0].small_cuts.?.deinit();

        cut[1].large_cuts.?.deinit();
        cut[1].small_cuts.?.deinit();

        cut[2].large_cuts.?.deinit();
        cut[2].small_cuts.?.deinit();
    }

    const DimCut = struct {
        dim: u8,
        cut: CutTag,
        eff: f32,
        large_cuts: ?std.ArrayList(Seg),
        small_cuts: ?std.ArrayList(Seg),

        fn clear(self: *DimCut) void {
            if (self.large_cuts) |l| {
                l.deinit();
            }

            if (self.small_cuts) |s| {
                s.deinit();
            }
        }
    };

    fn pickCut(dc: *?DimCut, cut_infos: []const CutInfo, dim: u8) void {
        var min:f32 = std.math.floatMax(f32);
        var idx:usize = 0;
        for(0.., cut_infos) |i, ci| {
            // NOTE: >= means we prefer "deep" cut to "shallow" one.
            if (min >= ci.eff) {
                min = ci.eff;
                idx = i;
            }
        }

        for (0.., cut_infos) |i, *ci| {
            if (i != idx) {
                if (ci.large_cuts) |a| {
                    a.deinit();
                }
                if (ci.small_cuts) |a| {
                    a.deinit();
                }
            }
        }

        if (((dc.* != null) and (min < dc.*.?.eff)) or dc.* == null) {
            dc.* = DimCut{.dim = dim, .cut = @enumFromInt(idx),
                .large_cuts = cut_infos[idx].large_cuts,
                .small_cuts = cut_infos[idx].small_cuts,
                .eff = min};
        }
    }

    fn choose(self: *ParaNode, dim_segs: *[Dim]std.ArrayList(Seg), dim_info: []const DimInfo) Error!DimCut {
        var i:u8 = 0;
        var dc: ?DimCut = null;

        while (i < Dim) : (i += 1) {
            for (self.rules.items) |r| {
                try dim_segs[i].append(Seg{ .range = r.ranges[i] });
            }
            getUniq(Seg).uniq(&dim_segs[i], false);
            //dumpSegs(&dim_segs[i], "orignal");
            //print("dim {} {any}\n", .{i, dim_info});
            const cut_infos = try vectorizedCut(&dim_segs[i], &dim_info[i]);
            pickCut(&dc, &cut_infos, i);
        }
        //print("pick {} {} {d:.2}\n", .{dc.?.dim, dc.?.cut, dc.?.eff});
        return dc.?;
    }

    fn dumpChildRules(self: *ParaNode, verbose: bool) void {
        if (self.dim == LeafNode)
            return;

        for (0 .., self.next) |idx, *n| {
            print("The {} node: {}\n", .{idx, n.rules.items.len});
            if (!verbose)
                continue;

            for (n.rules.items) |r| {
                print("{}\n", .{r.*});
            }
        }
    }

    const binRules = 8;
    fn build(self: *ParaNode, dim_info:[]const DimInfo) Error!void {
        if (self.rules.items.len < binRules) {
            return;
        }

        var dim_segs : [Dim]std.ArrayList(Seg) = undefined;
        for (0..Dim) |i| {
            dim_segs[i] = std.ArrayList(Seg).init(allocator);
        }

        defer {
            for (&dim_segs) |seg| {
                seg.deinit();
            }
        }

        var dc = try choose(self, &dim_segs, dim_info);
        try self.pushRules(&dc, dim_info);
    }

    const zu8x16: @Vector(16, u8) = [_]u8{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    const zu16x8: @Vector(8, u16) = [_]u16{0,0,0,0,0,0,0,0};
    const zu32x4: @Vector(4, u32) = [_]u32{0,0,0,0};

    fn loadVector(cuts: *ParaCuts, tag: CutTag, large_cuts: ?std.ArrayList(Seg),
                  small_cuts: ?std.ArrayList(Seg)) void {
        const offset = if (small_cuts) |s| s.items.len - 1 else 0;
        switch (tag) {
            .u8x16 => {
                cuts.* = ParaCuts{ .u8x16 = .{ .cuts = zu8x16}};
                if (small_cuts) |s| {
                    for (0 .. s.items.len - 1) |i| {
                        cuts.u8x16.cuts[i] = @truncate(s.items[i+1].range.lo);
                    }
                }
                if (large_cuts) |l| {
                    for (0 .. l.items.len - 1) |i| {
                        cuts.u8x16.cuts[i + offset] = @truncate(l.items[i+1].range.lo);
                    }
                }
            },
            .u16x8 => {
                cuts.* = ParaCuts{ .u16x8 = .{ .cuts = zu16x8}};
                if (small_cuts) |s| {
                    for (0 .. s.items.len - 1) |i| {
                        cuts.u16x8.cuts[i] = @truncate(s.items[i+1].range.lo);
                    }
                }
                if (large_cuts) |l| {
                    for (0 .. l.items.len - 1) |i| {
                        cuts.u16x8.cuts[i + offset] = @truncate(l.items[i+1].range.lo);
                    }
                }
            },
            .u32x4 => {
                cuts.* = ParaCuts{ .u32x4 = .{ .cuts = zu32x4}};
                if (small_cuts) |s| {
                    for (0 .. s.items.len - 1) |i| {
                        cuts.u32x4.cuts[i] = @truncate(s.items[i+1].range.lo);
                    }
                }
                if (large_cuts) |l| {
                    for (0 .. l.items.len - 1) |i| {
                        cuts.u32x4.cuts[i + offset] = @truncate(l.items[i+1].range.lo);
                    }
                }
            },
        }
    }

    fn truncFlag(dc: *const DimCut, di: *const DimInfo) u1 {
        const size = di.size();
        switch (dc.cut) {
            .u8x16 => {
                if (size > std.math.maxInt(u8)) {
                    return 1;
                } else {
                    return 0;
                }
            },
            .u16x8 => {
                if (size > std.math.maxInt(u16)) {
                    return 1;
                } else {
                    return 0;
                }
            },
            .u32x4 => return 0,
        }
    }

    fn initChildNode(self: *ParaNode) void {
        for (self.next) |*n| {
            n.* = ParaNode{};
        }
    }

    fn fromDimCut(self: *ParaNode, dc: *const DimCut, di: *const DimInfo) !void {
        const large_len = if (dc.large_cuts) |l| l.items.len else 0;
        const small_len = if (dc.small_cuts) |s| s.items.len else 0;
        //print("allocate {} nodes, large {} small {}\n", .{ large_len + small_len, large_len, small_len });

        self.next = try allocator.alloc(ParaNode, large_len + small_len);
        self.dim = dc.dim;
        self.flags = ParaFlag{.small_mask = if (small_len != 0) (@as(u16, 1) << @truncate(small_len - 1)) - 1 else 0,
                              .large_cut = if (large_len != 0) 1 else 0,
                              .trunc_flag = truncFlag(dc, di), .unused = 0};
        self.offset = di.r.lo;
        self.initChildNode();
        loadVector(&self.cuts, dc.cut, dc.large_cuts, dc.small_cuts);
    }

    fn truncFromTag(size: u32, tag: CutTag) u32 {
        switch (tag) {
            .u8x16 => return truncateSize(u8, size),
            .u16x8 => return truncateSize(u16, size),
            .u32x4 => return truncateSize(u32, size),
        }
    }

    fn truncRangeFromTag(tag: CutTag, size: u32, di :*const DimInfo, r: *const Range) Range {
        switch (tag) {
            .u8x16 => return truncateRange(u8,  r, size, di),
            .u16x8 => return truncateRange(u16, r, size, di),
            .u32x4 => return truncateRange(u32, r, size, di),
        }
    }

    fn expandRange(tag: CutTag, r: *const Range, di: *const DimInfo) Range {
        const size = di.size();
        switch (tag) {
            .u8x16 => {
                if (size > std.math.maxInt(u8)) {
                    const hi = (r.hi << 24) + 0x00FFFFFF + di.r.lo;
                    return .{ .lo = (r.lo << 24) + di.r.lo, .hi = hi };
                }
            },
            .u16x8 => {
                if (size > std.math.maxInt(u16)) {
                    const hi = (r.hi << 16) + 0x0000FFFF + di.r.lo;
                    return .{ .lo = (r.lo << 16) + di.r.lo, .hi = hi};
                }
            },
            .u32x4 => return .{ .lo = r.lo + di.r.lo, .hi = r.hi + di.r.lo },
        }
        return .{ .lo = r.lo + di.r.lo, .hi = r.hi + di.r.lo };
    }

    fn pushRules(self: *ParaNode, dc: *DimCut, cube: []const DimInfo) Error!void {
        const di = &cube[dc.dim];
        try self.fromDimCut(dc, di);

        const large_offset = if (dc.small_cuts) |s| s.items.len else 0;

        //NOTE: if nLargeCuts == 0, we do not need to seprate ranges into
        //large/small size, just push it down to child nodes.
        std.debug.assert(nLargeCuts > 0);

        const trunc_size = truncFromTag(di.size(), dc.cut);
        for (self.rules.items) |rule| {
            const range = &rule.ranges[dc.dim];
            const r = truncRangeFromTag(dc.cut, di.size(), di, range);

            if (!r.isLarge(trunc_size)) {
                for (0 .. , dc.small_cuts.?.items) |idx, cut_seg| {
                    if (cut_seg.range.overlap(&r)) {
                        try self.next[idx].rules.append(rule);
                    }
                }
            } else {
                for (0 .., dc.large_cuts.?.items) |idx, cut_seg| {
                    if (cut_seg.range.overlap(&r)) {
                        try self.next[large_offset + idx].rules.append(rule);
                    }
                }
            }
        }

        //self.dumpChildRules(true);

        var newcube = [_]DimInfo{undefined} ** Dim;
        @memcpy(&newcube, cube);

        if (dc.small_cuts) |s| {
            for (0 .., s.items) |idx, seg| {
                newcube[dc.dim].r = expandRange(dc.cut, &seg.range, di);
                try self.next[idx].build(&newcube);
            }
        }

        if (dc.large_cuts) |l| {
            for (0 .., l.items) |idx, seg| {
                newcube[dc.dim].r = expandRange(dc.cut, &seg.range, di);
                try self.next[large_offset + idx].build(&newcube);
            }
        }

        defer dc.clear();
        defer self.rules.clearAndFree();
    }

    fn dump(self: *ParaNode, verbose: bool) void {
        if (self.dim == LeafNode) {
            print("LeafNode\n", .{});
            return;
        }

        print("dim {}\n", .{self.dim});
        print("offset {}\n", .{self.offset});
        self.flags.dump();
        self.cuts.dump();
        print("next {}\n", .{self.next.len});
        print("rules {}\n", .{self.rules.items.len});
        if (verbose) {
            for (self.rules.items) |r| {
                print("{}\n", .{r.*});
            }
        }
    }

    fn deinit(self: *ParaNode) void {
        if (self.dim != LeafNode) {
            for (self.next) |*n| {
                n.deinit();
            }
        }
        allocator.free(self.next);
    }

    fn countLeaves(self: *const ParaNode, val: *usize) void {
        if (self.dim == LeafNode) {
            val.* += 1;
        } else {
            for (self.next) |*n| {
                n.countLeaves(val);
            }
        }
    }
};

const ParaTree = struct {
    root: ParaNode,

    fn build(self: *ParaTree, dim_info:[]const DimInfo) !void {
        try self.root.build(dim_info);
    }

    fn deinit(self: *ParaTree) void {
        self.root.deinit();
    }

    fn countLeaves(self: *ParaTree) usize {
        var leaves:usize = 0;
        self.root.countLeaves(&leaves);
        return leaves;
    }
};

const DimInfo = struct {
    r : Range,

    fn size(self: *const DimInfo) u32 {
        return self.r.hi - self.r.lo +| 1;
    }
};

fn paraCut(rule_list : *std.ArrayList(Rule)) !ParaTree {
    var tree: ParaTree = .{ .root = .{}};
    for (rule_list.items) |*r| {
        try tree.root.rules.append(r);
    }

    const dim_info = [_]DimInfo{ .{ .r = .{.lo = 0, .hi = std.math.maxInt(u32)}},
                               .{ .r = .{.lo = 0, .hi = std.math.maxInt(u32)}},
                               .{ .r = .{.lo = 0, .hi = std.math.maxInt(u16)}},
                               .{ .r = .{.lo = 0, .hi = std.math.maxInt(u16)}},
                               .{ .r = .{.lo = 0, .hi = std.math.maxInt(u8)}} };

    try tree.build(&dim_info);
    return tree;
}

pub fn main() !void {
    defer _ = gpa.deinit();

    const file = try fs.cwd().openFile("fw1K", .{});
    defer file.close();

    var buf_reader = std.io.bufferedReader(file.reader());
    const reader = buf_reader.reader();

    var line_no:u32 = 0;
    var rule_list = std.ArrayList(Rule).init(allocator);
    defer rule_list.deinit();

    var line = std.ArrayList(u8).init(allocator);
    defer line.deinit();

    const writer = line.writer();

    while (reader.streamUntilDelimiter(writer, '\n', null)) {
        // Clear the line so we can reuse it.
        defer line.clearRetainingCapacity();

        if (line.items[0] != '@') {
            continue;
        }
        const rule = try parseRule(line.items, line_no);
        try rule_list.append(rule);
        line_no += 1;
    } else |err| switch (err) {
        error.EndOfStream => {}, // Continue on
        else => return err, // Propagate error
    }

    var t = try paraCut(&rule_list);
    //print("{}\n", .{t.countLeaves()});
    t.deinit();
}

