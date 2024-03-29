const std = @import("std");
const fs = std.fs;
const print = std.debug.print;
const net = std.net;
const expect = std.testing.expect;
const Error = std.mem.Allocator.Error;

var gpa = std.heap.GeneralPurposeAllocator(.{.safety = true}){};
const allocator = gpa.allocator();

const RndGen = std.rand.DefaultPrng;
var rnd = RndGen.init(0);

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

    fn cover(self: *const Range, other: *const Range) bool {
        if (@min(self.lo, other.lo) == self.lo and
            @max(self.hi, other.hi) == self.hi) {
            return true;
        }
        return false;
    }

    fn coverValue(self: *const Range, v: u32) bool {
        return v >= self.lo and v <= self.hi;
    }

    fn intersect(self: *const Range, other: *const Range) Range {
        const lo = @max(self.lo, other.lo);
        const hi = @min(self.hi, other.hi);
        return Range{ .lo = lo, .hi = hi };
    }

    fn random(self: *const Range) u32 {
        const v = rnd.random().int(u32);
        const w = @as(u64, @intCast(self.hi - self.lo)) + 1;
        return  @intCast(v % w + self.lo);
    }
};

const Prefix = struct {
    prefix : u32,
    len : u6,
};

const SearchKey = struct {
    keys: [Dim]u32 = undefined,

    fn sampleRule(self: *SearchKey, rule: *const Rule) void {
        for (0 .. Dim) |i| {
            self.keys[i] = rule.ranges[i].random();
        }
    }
};

const Dim = 5;

fn RuleType(N: comptime_int) type {
    return struct {
        ranges : [N]Range,
        pri : u32,
        const Self = @This();

        fn cover(self: *const Self, other: *const Self, di: []const DimInfo) bool {
            for (0 .. N) |idx| {
                const r = &self.ranges[idx];
                const o = &other.ranges[idx];
                const scope = &di[idx].r;

                const inter = r.intersect(scope);
                if (!inter.cover(o)) {
                    return false;
                }
            }
            return true;
        }

        fn match(self: *const Self, key: *const SearchKey) bool {
            for (0 .. Dim) |i| {
                if (!self.ranges[i].coverValue(key.keys[i]))
                    return false;
            }
            return true;
        }
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
    const range = r.intersect(t);
    const lo = range.lo;
    const hi = range.hi;

    return Range{ .lo = lo - t.lo,
                  .hi = hi - t.lo };
}

fn truncateRange(comptime T: type, r: *const Range, size: u32, di: *const DimInfo) Range {
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

    fn dump(self:*const ParaCuts) void {
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

const SearchPolicy = union(enum) {
    PreAverage: f32,
    Average : struct {
        n_rules: u32,
        const Self = @This();

        fn next_target(self: *Self, passed_rules: usize, n_cuts: u8) f32 {
            const rules = self.n_rules - passed_rules;
            const t = @as(f32, @floatFromInt(rules)) / @as(f32, @floatFromInt(n_cuts + 1));
            return t;
        }
    },
};

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
    pass_rules: u32 = 0,
    cut: Range = undefined,
    seg_idx: usize = 0,
    start_idx: usize = 0,
    h: PQlt = undefined,
    policy: SearchPolicy = undefined,

    fn init(self: *NextCut, policy: SearchPolicy) void {
        self.h = PQlt.init(allocator, {});
        self.policy = policy;
    }

    fn deinit(self: *NextCut) void {
        self.h.deinit();
    }

    fn doCut(self: *NextCut, segs: *const std.ArrayList(Seg)) Error!void {
        while(self.h.peek()) |top| {
            if (top.v < self.cut.lo) {
                const w = self.h.remove();
                self.curr_rules -= w.w;
                self.pass_rules += w.w;
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
        non: *const std.ArrayList(Seg), n_cuts:u8, last_cut: bool) Error!void {
        self.nextCutLo(non);
        const t:f32 = switch (self.policy) {
            .PreAverage => self.policy.PreAverage,
            .Average => self.policy.Average.next_target(self.pass_rules, n_cuts),
        };

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

const nLargeCuts = 1;
const ParaFlag = packed struct(u32) {
    extra_range : u1,
    trunc_flag: u1,
    extra_mask: u1,
    unused: u13,
    cut_mask: u16,

    fn dump(self: *const ParaFlag) void {
        print("Flag: extra_range {} trunc_flag: {} extra_mask:0x{x:1} cut_mask: 0x{x:02}\n",
            .{self.extra_range, self.trunc_flag, self.extra_mask, self.cut_mask});

    }

    comptime {
        // to make sure large_mask is u1.
        std.debug.assert(nLargeCuts == 1);
    }
};

const TreeStat = struct {
    nodes: usize = 0,
    leaves: usize = 0,
    max_depth: usize = 0,
    depth: usize = 0,
    avg_depth: f32 = 0.0,
    sum: usize = 0,
    max_nodes: usize = 0,
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

    fn searchCuts(segs: *std.ArrayList(Seg), n_cuts: u8, n_rules: u32) Error!std.ArrayList(Seg) {
        const non = try genNonOverlappedSegs(segs);
        defer non.deinit();
        //dumpSegs(&non, "non");

        //print("t {d:.2}\n", .{t});
        var i:usize = 0;
        const policy:SearchPolicy = .{ .PreAverage = @as(f32, @floatFromInt(n_rules)) / @as(f32, @floatFromInt(n_cuts + 1)) };
        //const policy:SearchPolicy = .{ .Average = .{ .n_rules = n_rules }};

        var nextcut = NextCut{};
        nextcut.init(policy);
        defer nextcut.deinit();

        var cut_segs = std.ArrayList(Seg).init(allocator);

        while (i < n_cuts + 1 and nextcut.hasNext(&non)) : (i += 1) {
            try nextcut.searchCut(segs, &non, @truncate(n_cuts - i), i == n_cuts);
            try cut_segs.append(Seg{ .range = nextcut.cut, .weight = nextcut.curr_rules});
        }

        return cut_segs;
    }

    fn calAverageWeight(segs: *std.ArrayList(Seg)) f32 {
        std.debug.assert(segs.items.len > 0);
        var sum:usize = 0;
        for (segs.items) |s| {
            sum += s.weight;
        }
        return @as(f32, @floatFromInt(sum)) / @as(f32, @floatFromInt(segs.items.len));
    }


    fn truncateSize(comptime T: type, size: u32) u32 {
        return @min(size, std.math.maxInt(T));
    }

    fn cutDim(comptime T:type, segs: *const std.ArrayList(Seg), di: *const DimInfo, n_cuts: u8) Error!CutInfo {
        var large_segs = std.ArrayList(Seg).init(allocator);
        defer large_segs.deinit();
        var small_segs = std.ArrayList(Seg).init(allocator);
        defer small_segs.deinit();
        var n_large:u32 = 0;
        var n_small:u32 = 0;

        const size = di.size();
        const trunc_size = truncateSize(T, size);

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

        getUniq(Seg).uniq(&large_segs, true);
        getUniq(Seg).uniq(&small_segs, true);

        var eff:f32 = 0;
        var large: ?std.ArrayList(Seg) = null;
        var small: ?std.ArrayList(Seg) = null;

        var n_large_cuts:u8 = undefined;
        var n_small_cuts:u8 = undefined;

        if (large_segs.items.len > 1 and small_segs.items.len > 1) {
            n_large_cuts = nLargeCuts;
            n_small_cuts = n_cuts - nLargeCuts;
        } else {
            n_large_cuts = if (large_segs.items.len > 1) n_cuts else 0;
            n_small_cuts = if (small_segs.items.len > 1) n_cuts else 0;
        }
        if (n_large_cuts == 0 and n_small_cuts == 0) {
            return CutInfo{};
        }

        if (large_segs.items.len != 0) {
            large = try searchCuts(&large_segs, n_large_cuts, n_large);
            //dumpSegs(&large.?, "large cut");
            const large_ratio = @as(f32, @floatFromInt(n_large)) / @as(f32, @floatFromInt(n_large + n_small));
            eff += calAverageWeight(&large.?) * large_ratio;
        }

        if (small_segs.items.len != 0) {
            small = try searchCuts(&small_segs,  n_small_cuts, n_small);
            //dumpSegs(&small.?, "small cut");
            const small_ratio = @as(f32, @floatFromInt(n_small)) / @as(f32, @floatFromInt(n_large + n_small));
            eff += calAverageWeight(&small.?) * small_ratio;
        }

        if (large != null and small != null and
            small.?.items.len == 1 and large.?.items.len == 1) {
            //if both cut_segs are only 1, this dim is useless.
            eff = std.math.floatMax(f32);
        }

        return CutInfo{.eff = eff, .large_cuts = large, .small_cuts = small};
    }

    test {
        var segs = std.ArrayList(Seg).init(allocator);
        defer segs.deinit();
        try segs.append(Seg{.range = .{.lo = 0, .hi = std.math.maxInt(u32)}, .weight = 10});
        try segs.append(Seg{.range = .{.lo = 0, .hi = 0}, .weight = 20});
        const di = DimInfo{ .r = .{ .lo = 0, .hi = std.math.maxInt(u32) } };
        var cutinfo = try cutDim(u8, &segs, &di, 2);
        defer cutinfo.deinit();

        try expect(cutinfo.eff == std.math.floatMax(f32));
    }

    const CutInfo = struct {
        large_cuts : ?std.ArrayList(Seg) = null,
        small_cuts : ?std.ArrayList(Seg) = null,
        eff: f32 = std.math.floatMax(f32),

        fn deinit(self: *CutInfo) void {
            if (self.large_cuts) |l| {
                l.deinit();
            }

            if (self.small_cuts) |s| {
                s.deinit();
            }
        }
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
        var cut = try vectorizedCut(&segs, &DimInfo{.r = .{.lo =0, .hi = std.math.maxInt(u32)}});
        try expect(cut[0].eff == std.math.floatMax(f32));
        try expect(cut[1].eff == std.math.floatMax(f32));
        try expect(cut[2].eff == std.math.floatMax(f32));

        for (0 .. 3) |idx| {
            cut[idx].deinit();
        }
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

    fn pickCut(dc: *?DimCut, cut_infos: []CutInfo, dim: u8) void {
        var min:f32 = std.math.floatMax(f32);
        var idx:usize = 0;
        for(0.., cut_infos) |i, *ci| {
            // NOTE: >= means we prefer "deep" cut to "shallow" one.
            if (min >= ci.eff) {
                min = ci.eff;
                idx = i;
            }
        }

        for (0.., cut_infos) |i, *ci| {
            if (i != idx) {
                ci.deinit();
            }
        }

        if ((dc.* != null) and (min < dc.*.?.eff)) {
            dc.*.?.clear();
            dc.* = DimCut{.dim = dim, .cut = @enumFromInt(idx),
                .large_cuts = cut_infos[idx].large_cuts,
                .small_cuts = cut_infos[idx].small_cuts,
                .eff = min};
        } else if (dc.* == null) {
            dc.* = DimCut{.dim = dim, .cut = @enumFromInt(idx),
                .large_cuts = cut_infos[idx].large_cuts,
                .small_cuts = cut_infos[idx].small_cuts,
                .eff = min};
        } else {
            cut_infos[idx].deinit();
        }
    }

    const binRules = 8;
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
            var cut_infos = [_]CutInfo{.{}} ** cut_kinds;

            //skip the dim which has only 1 seg but with more than binRules.
            if (dim_segs[i].items.len > 1) {
                cut_infos = try vectorizedCut(&dim_segs[i], &dim_info[i]);
            }
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

    fn removeRedund(rules: *std.ArrayList(*Rule), dim_info:[]const DimInfo) void {
        var idx:usize = rules.items.len - 1;

        while (idx > 0) : (idx -= 1) {
            var cover = false;
            const rule = rules.items[idx];
            for (0 .. idx) |cover_idx| {
                const cover_rule = rules.items[cover_idx];
                if (cover_rule.cover(rule, dim_info)) {
                    cover = true;
                    break;
                }
            }
            if (cover) {
                 _ = rules.orderedRemove(idx);
            }
        }
    }

    test {
        const dim_info = &([_]DimInfo{ .{ .r = .{ .lo = 0, .hi = std.math.maxInt(u32)}}} ** Dim);
        var rules = std.ArrayList(*Rule).init(allocator);
        defer rules.deinit();
        var  rules_alloc = [_]Rule{.{.ranges = [_]Range{ .{.lo = 0, .hi = std.math.maxInt(u32)} } ** Dim, .pri = 0},
                                   .{.ranges = [_]Range{ .{.lo = 0, .hi = std.math.maxInt(u32)} } ** Dim, .pri = 1}};
        try rules.append(&rules_alloc[0]);
        try rules.append(&rules_alloc[1]);
        removeRedund(&rules, dim_info);
        try expect(rules.items.len == 1);
    }

    fn build(self: *ParaNode, dim_info:[]const DimInfo) Error!void {
        if (self.rules.items.len <= binRules) {
            return;
        }

        if (self.rules.items.len < 2 * binRules) {
            removeRedund(&self.rules, dim_info);
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

        //for (dim_info) |d| {
        //    print("{} ", .{d.r});
        //}
        //print("\n", .{});
        var dc = try choose(self, &dim_segs, dim_info);
        if (dc.eff != std.math.floatMax(f32)) {
            try self.pushRules(&dc, dim_info);
        }
        dc.clear();
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
                        cuts.u32x4.cuts[i] = s.items[i+1].range.lo;
                    }
                }
                if (large_cuts) |l| {
                    for (0 .. l.items.len - 1) |i| {
                        cuts.u32x4.cuts[i + offset] = l.items[i+1].range.lo;
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
        //could be only large/small cuts.
        const large_len = if (dc.large_cuts) |l| l.items.len else 0;
        const small_len = if (dc.small_cuts) |s| s.items.len else 0;
        const cut_len = @max(large_len, small_len);
        const extra_len = @min(large_len, small_len);
        std.debug.assert(cut_len > 0);
        //print("allocate {} nodes, large {} small {}\n", .{ large_len + small_len, large_len, small_len });

        self.next = try allocator.alloc(ParaNode, large_len + small_len);
        self.dim = dc.dim;
        self.flags = ParaFlag{.cut_mask = (@as(u16, 1) << @truncate(cut_len - 1)) - 1,
                              .extra_mask = if (extra_len > 1) 1 else 0,
                              .extra_range = if (extra_len != 0) 1 else 0,
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

    fn pushRules(self: *ParaNode, dc: *const DimCut, cube: []const DimInfo) Error!void {
        const di = &cube[dc.dim];
        try self.fromDimCut(dc, di);

        const large_offset = if (dc.small_cuts) |s| s.items.len else 0;

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
        //self.dump(false);
        //self.dumpChildRules(false);
        defer self.rules.clearAndFree();
    }

    fn dump(self: *const ParaNode, verbose: bool) void {
        if (self.dim == LeafNode) {
            print("LeafNode\n", .{});
            return;
        }

        print("dim {} {*}\n", .{self.dim, self});
        print("offset {}\n", .{self.offset});
        self.flags.dump();
        self.cuts.dump();
        print("next {}\n", .{self.next.len});
        for (0 .. self.next.len) |i| {
            print("{*} ", .{self.next.ptr + i});
        }
        print("\n", .{});
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
        } else {
            self.rules.deinit();
        }
        allocator.free(self.next);
    }

    fn stat(self: *const ParaNode, s: *TreeStat) void {
        if (self.dim == LeafNode) {
            s.leaves += 1;
            s.sum += s.max_depth;
        } else {
            s.nodes += 1;
            s.max_depth += 1;
            s.depth = @max(s.max_depth, s.depth);
            for (self.next) |*n| {
                n.stat(s);
            }
            s.max_depth -= 1;
        }
    }

    fn path(self: *const ParaNode) usize {
        if (self.dim == LeafNode) {
            return 1;
        }

        var smallmax:usize = 0;
        const large_offset = @popCount(self.flags.cut_mask) + 1;
        for (0 .. large_offset) |i| {
            smallmax = @max(self.next[i].path(), smallmax);
        }

        var largemax:usize = 0;
        if (self.flags.extra_range == 1) {
            const large_end = if (self.flags.extra_mask != 0) large_offset + 2 else large_offset + 1;
            for (large_offset .. large_end) |i| {
                largemax = @max(self.next[i].path(), largemax);
            }
        }
        return 1 + smallmax + largemax;
    }

    const shift = [cut_kinds]u5{24, 16, 0};
    fn getNext(self: *const ParaNode, key: *const SearchKey, cand: *[2]?*const ParaNode) u8 {
        //step 1: extract the value;
        var k = key.keys[self.dim];
        if (k < self.offset) {
            return 0;
        }
        //step 2: minus the offset
        k -= self.offset;
        //step 3: truncate
        const tag = @as(CutTag, self.cuts);
        k = if (self.flags.trunc_flag != 0) k >> shift[@intFromEnum(tag)] else k;
        var bitmask:u16 = undefined;

        switch (self.cuts) {
            .u8x16 => |c| {
                const v:@Vector(16, u8) = @splat(@truncate(k));
                const bits = @as(u16, @bitCast(v >= c.cuts));
                bitmask = bits;
            },
            .u16x8 => |c| {
                const v:@Vector(8, u16) = @splat(@truncate(k));
                const bits = @as(u8, @bitCast(v >= c.cuts));
                bitmask = @as(u16, @intCast(bits));
            },
            .u32x4 => |c| {
                const v:@Vector(4, u32) = @splat(@truncate(k));
                const bits = @as(u4, @bitCast(v >= c.cuts));
                bitmask = @as(u16, @intCast(bits));
            },
        }

        const node_off = @popCount(bitmask & self.flags.cut_mask);
        cand[0] = &self.next[node_off];

        if (self.flags.extra_range != 0) {
            var extra_off = @popCount(self.flags.cut_mask);

            if (self.flags.extra_mask != 0) {
                if ((bitmask & (@as(u16, 1) << @truncate(extra_off))) != 0) {
                    extra_off += 1;
                }
            }
            cand[1] = &self.next[extra_off + 1];
            return 2;
        }
        return 1;
    }

    test {
        var node = ParaNode{};
        node.dim = 1;
        node.flags = ParaFlag{.extra_range = 1, .trunc_flag = 1, .extra_mask = 1, .cut_mask = 0x1f, .unused = 0};
        node.cuts = ParaCuts{.u16x8 = .{ .cuts = [_]u16{16308, 16697, 16911, 37554, 53780, 16384, 0, 0 }}};
        node.next = try allocator.alloc(ParaNode, 8);
        defer allocator.free(node.next);

        for (0 .. 8) |i| {
            node.next[i] = ParaNode{};
        }
        const key = SearchKey{.keys = [_]u32{ 0} ++ [_]u32{16697 << 16} ++ [_]u32{0} ** 3};
        const key2 = SearchKey{.keys = [_]u32{ 0} ++ [_]u32{16307 << 16} ++ [_]u32{0} ** 3};
        var cand = [_]?*const ParaNode{null, null};
        try expect(node.getNext(&key, &cand) == 2);
        try expect(cand[0] == &node.next[2]);
        try expect(cand[1] == &node.next[7]);

        cand = [_]?*const ParaNode{null, null};
        try expect(node.getNext(&key2, &cand) == 2);
        try expect(cand[0] == &node.next[0]);
        try expect(cand[1] == &node.next[6]);
    }

    fn search(self: *const ParaNode, key: *const SearchKey) ?*Rule {
        for (self.rules.items) |r| {
            if (r.match(key)) {
                return r;
            }
        }
        return null;
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

    fn stat(self: *ParaTree, s: *TreeStat) void {
        self.root.stat(s);
        s.avg_depth = @as(f32, @floatFromInt(s.sum)) / @as(f32, @floatFromInt(s.leaves));
        s.max_nodes = self.root.path();
    }

    const Fifo = struct {
        const size = 16;
        s: u32 = 0,
        e: u32 = 0,
        buffer: [size]?*const ParaNode = undefined,

        fn push(self: *Fifo, p:*const ParaNode) void {
            self.buffer[self.e & (size - 1)] = p;
            self.e +%= 1;
        }

        fn pop(self: *Fifo) ?*const ParaNode {
            if (self.s == self.e) {
                return null;
            }
            const p = self.buffer[self.s & (size - 1)];
            self.s +%= 1;
            return p;
        }
    };

    //Search only middle nodes achieve 20Mpps, still slow
    //fn searchHalf(self: *const ParaTree, key: *const SearchKey) void {
    //    var f = Fifo{};
    //    f.push(&self.root);

    //    while(f.pop()) |n| {
    //        if (n.dim != ParaNode.LeafNode) {
    //            var cand = [_]?*const ParaNode{null} ** 2;
    //            const n_node = n.getNext(key, &cand);
    //            for (0 .. n_node) |i| {
    //                f.push(cand[i].?);
    //            }
    //        }
    //    }
    //}

    fn search(self: *const ParaTree, key: *const SearchKey) ?*const Rule {
        var f = Fifo{};
        f.push(&self.root);
        var final:?*const Rule = null;

        while(f.pop()) |n| {
            if (n.dim == ParaNode.LeafNode) {
                if (n.search(key)) |rule| {
                    if (final == null) {
                        final = rule;
                    } else if (rule.pri < final.?.pri) {
                        final = rule;
                    }
                }
            } else {
                var cand = [_]?*const ParaNode{null} ** 2;
                const n_node = n.getNext(key, &cand);
                for (0 .. n_node) |i| {
                    f.push(cand[i].?);
                }
            }
        }

        return final;
    }
};

const LinearSearch = struct {
    ruleset: *const std.ArrayList(Rule),
    fn search(self: *const LinearSearch, key: *const SearchKey) ?*const Rule {
        for (self.ruleset.items) |*r| {
            if (r.match(key))
                return r;
        }
        return null;
    }
};

test {
    var ruleset = std.ArrayList(Rule).init(allocator);
    defer ruleset.deinit();
    try ruleset.append(.{ .ranges = [_]Range{ .{ .lo = 2, .hi = std.math.maxInt(u32) }} ** Dim,
                          .pri = 1});
    try ruleset.append(.{ .ranges = [_]Range{ .{ .lo = 0, .hi = std.math.maxInt(u32) / 2 }} ** Dim,
                          .pri = 2});
    const lr = LinearSearch{ .ruleset = &ruleset };
    const k = SearchKey{.keys = [_]u32{1} ** Dim};
    try expect(lr.search(&k) == &ruleset.items[1]);

    var k1 = SearchKey{};
    k1.sampleRule(&ruleset.items[0]);
    for (0 .. Dim) |i| {
        try expect(ruleset.items[0].ranges[i].coverValue(k1.keys[i]));
    }

}

const DimInfo = struct {
    r : Range,

    fn size(self: *const DimInfo) u32 {
        return self.r.hi - self.r.lo +| 1;
    }
};

test {
    const x1:u32 = 0;
    try expect(@popCount(x1) == 0);
    const x:u16 = 0x7;
    try expect(@popCount(x) == 3);

    const v:@Vector(8, u16) = [_]u16{1} ** 4 ++ [_]u16{2} ** 4;
    const v1:@Vector(8, u16) = @splat(1);
    const bits = @as(u8, @bitCast(v1 >= v));
    const up = @as(u32, @intCast(bits));
    try expect(up == 0b00001111);
}

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

fn prepareKeys(num: usize, ruleset: *const std.ArrayList(Rule)) []SearchKey {
    var keys = allocator.alloc(SearchKey, num * ruleset.items.len) catch unreachable;
    for (0 .. , ruleset.items) |idx, *rule| {
        for (0 .. num) |i| {
            keys[idx * num + i].sampleRule(rule);
        }
    }
    return keys;
}

fn validation(t: *const ParaTree, num: usize, ruleset: *const std.ArrayList(Rule)) void {
    const keys = prepareKeys(num, ruleset);
    defer allocator.free(keys);
    print("allocating {} keys for validation\n", .{ num * ruleset.items.len});
    const lr = LinearSearch{.ruleset = ruleset};

    for (keys) |*key| {
        const rule1 = lr.search(key);
        const rule2 = t.search(key);
        if (rule1 != rule2) {
            print("linear search is {*} our search is {*}\n", .{rule1, rule2});
            if (rule1) |r| {
                print("rule1 {}\n", .{r});
            }
            if (rule2) |r| {
                print("rule2 {}\n", .{r});
            }
        }
    }
}

const clock = std.time.Timer;

fn bench(t: *const ParaTree, num: usize, ruleset: *const std.ArrayList(Rule)) void {
    var timer  = clock.start() catch unreachable;
    const keys = prepareKeys(num, ruleset);
    defer allocator.free(keys);
    timer.reset();
    for (keys) |*key| {
        const rule = t.search(key);
        std.mem.doNotOptimizeAway(rule);
    }
    const elapsed = timer.read();
    print("{}ns passed for {} keys, around {d:.2} Mpps\n",
        .{ elapsed, keys.len, @as(f32, @floatFromInt(keys.len)) * 1e3 / @as(f32, @floatFromInt(elapsed)) });
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
    var stat = TreeStat{};
    t.stat(&stat);
    print("{}\n", .{stat});
    validation(&t, 1000, &rule_list);
    bench(&t, 100, &rule_list);
    t.deinit();
}

