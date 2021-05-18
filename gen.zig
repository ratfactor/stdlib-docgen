const std = @import("std");
const ast = std.zig.ast;
const util = @import("utils.zig");
const source_url = "https://github.com/ziglang/zig/blob/master/lib/std/";

const out_fname_html = "index.html";
const in_fname_head = "includes/html_head.html";
const max_read_filesize = 2 * 1024 * 1024 * 1024;

var tree: ast.Tree = undefined;

const DeclInfoLists = struct {
    fields: std.ArrayList(DeclInfo),
    types: std.ArrayList(DeclInfo),
    funcs: std.ArrayList(DeclInfo),
    values: std.ArrayList(DeclInfo),

    pub fn init(alloc: *std.mem.Allocator) !@This() {
        return @This(){
            .fields = std.ArrayList(DeclInfo).init(alloc),
            .types = std.ArrayList(DeclInfo).init(alloc),
            .funcs = std.ArrayList(DeclInfo).init(alloc),
            .values = std.ArrayList(DeclInfo).init(alloc),
        };
    }
    pub fn deinit(self: *const @This(), alloc: *std.mem.Allocator) void {
        inline for (comptime std.meta.fieldNames(@This())) |n| {
            for (@field(self, n).items) |*info| {
                info.deinit(alloc);
            }
            @field(self, n).deinit();
        }
    }
    pub fn htmlStringify(self: DeclInfoLists, writer: anytype) std.fs.File.WriteError!void {
        // cur_file is set in global, makes life easier
        try writer.print("<div class=\"module\"><h2>{s}</h2>", .{cur_file});
        inline for (.{"fields", "funcs", "types", "values"}) |n| {
            if (@field(self, n).items.len != 0) {
                try writer.print("<b>{s}</b>", .{n});
                for (@field(self, n).items) |decl| {
                    try decl.htmlStringify(writer);
                }
            }
        }
        try writer.writeAll("</div>"); // end of module
    }
};

const DeclInfo = struct {
    name: []const u8,
    tag: std.zig.ast.Node.Tag,
    sub_cont_ty: ?[]const u8 = null,
    decl_info_lists: ?DeclInfoLists,
    src_line: usize,

    fn deinit(self: *const @This(), alloc: *std.mem.Allocator) void {
        if (self.decl_info_lists) |*m|
            m.deinit(alloc);
        alloc.free(self.name);
        if (self.sub_cont_ty) |s|
            alloc.free(s);
    }

    pub fn htmlStringify(self: DeclInfo, writer: anytype) std.fs.File.WriteError!void {
        // If this decl contains inner decls, enclose the lot in a container
        if (self.decl_info_lists != null)
            try writer.writeAll("<div class=\"inner-container\">");

        try writer.print("<a class=\"decl\" target=\"_blank\" href=\"{s}{s}#L{}\">{s}</a> ", .{
            source_url,
            cur_file,
            self.src_line+1, // always one off - is it 0 indexed?
            self.name,
});

        if (self.decl_info_lists != null) {
            if (self.decl_info_lists.?.funcs.items.len > 0) {
                for (self.decl_info_lists.?.funcs.items) |decl| {
                    try decl.htmlStringify(writer);
                }
            }
            if (self.decl_info_lists.?.fields.items.len > 0) {
                for (self.decl_info_lists.?.fields.items) |decl| {
                    try decl.htmlStringify(writer);
                }
            }
            if (self.decl_info_lists.?.types.items.len > 0) {
                for (self.decl_info_lists.?.types.items) |decl| {
                    try decl.htmlStringify(writer);
                }
            }
            if (self.decl_info_lists.?.values.items.len > 0) {
                for (self.decl_info_lists.?.values.items) |decl| {
                    try decl.htmlStringify(writer);
                }
            }
            try writer.writeAll("</div>"); // End container
        }
    }
};

var cur_file: []const u8 = undefined;

fn removeTrailingSlash(n: [:0]u8) []u8 {
    if (std.mem.endsWith(u8, n, "/"))
        return n[0 .. n.len - 1];
    return n;
}

pub fn main() (error{ OutOfMemory, Overflow, InvalidCmdLine, TimerUnsupported } || std.os.UnexpectedError || std.os.WriteError)!void {
    var general_pa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 8 }){};
    defer _ = general_pa.deinit();

    const alloc = &general_pa.allocator;

    const args = try std.process.argsAlloc(alloc);
    defer alloc.free(args);

    if (args.len < 2) fatal("The first argument must be a directory path.");

    const dirname = removeTrailingSlash(args[1]);

    var walker = std.fs.walkPath(alloc, dirname) catch |e| fatalArgs("Could not read directory: {s}: {}", .{ dirname, e });
    defer walker.deinit();

    var filename_hash = std.StringHashMap(DeclInfoLists).init(alloc);
    defer {
        var iter = filename_hash.iterator();
        while (iter.next()) |entry| {
            entry.value.deinit(alloc);
            alloc.free(entry.key);
        }
        filename_hash.deinit();
    }

    // Terminal progress indicator
    var progress: std.Progress = .{};
    var progress_main = try progress.start("", 0);
    progress_main.activate();
    defer progress_main.end();
    var progress_analysis = progress_main.start("Reading library...", 0);
    progress_analysis.activate();

    // Loop through files in input directory
    while (walker.next() catch |e| fatalArgs("Could not read next file: {}", .{e})) |entry| {
        if (!std.mem.endsWith(u8, entry.path, ".zig")) continue;

        // Chop the dirname + "/" from the front of the path
        const filename = entry.path[dirname.len+1..];

        // Do we already have this one?
        if (filename_hash.contains(filename)) continue;

        const str = try alloc.dupe(u8, filename);

        // Show current file as progress
        var progress_file = progress_analysis.start(filename, 1);
        progress_file.activate();
        defer progress_file.end();

        // Store decl lists in hashmap by filename
        const list = try getDeclsFromFile(alloc, entry.path);
        const pogr = try filename_hash.put(str, list);
    }
    progress_analysis.end();

    var progress_writing = progress_main.start("Writing HTML...", 0);
    progress_writing.activate();
    defer progress_writing.end();

    const output_file = std.fs.cwd().createFile(out_fname_html, .{ .read = true }) catch |e| fatalArgs("Could not open {s} for writing: {}", .{out_fname_html, e});
    defer output_file.close();
    const w = output_file.writer();

    const html_head = std.fs.cwd().readFileAlloc(alloc, in_fname_head, max_read_filesize) catch |e| {
         fatalArgs("Could not read file {s}: {}", .{in_fname_head, e});
    };
    defer alloc.free(html_head);

    try w.writeAll(html_head);

//        \\<html>
//        \\  <head>
//        \\    <title>zig stdlib map</title>
//        \\    <style>
//        \\      .body { font-size: 12px; font-family: sans-serif; color: #333; }
//        \\      .boss-div { display: flex; flex-wrap: wrap; }
//        \\      .comment { text-style: italic; }
//        \\      .module {
//        \\          max-width: 400px; flex: 1; min-width: 200px;
//        \\          margin: 5px;
//        \\      }
//        \\      .module h2 { background: #FFBB4D; font-size: 16px; margin: 0; padding: 5px; }
//        \\      .inner-container { margin: 5px; }
//        \\      .inner-container>a:first-child { display: block; background-color: #DDD; margin: 2px; }
//        \\    </style>
//        \\  </head>
//        \\<body>
//        \\<div class="boss-div">
//    );
//
    var iter = filename_hash.iterator();
    while (iter.next()) |entry| {
        cur_file = entry.key;
        try entry.value.htmlStringify(w); // value is a DeclInfoLists
    }

    try w.writeAll("</div></body></html>");
}

fn getTextFromFile(
    alloc: *std.mem.Allocator,
    fname: []const u8,
) error{OutOfMemory}!DeclInfoLists {

    defer tree.deinit(alloc);
    const decls = tree.rootDecls();

    const decl_list = try getDeclInfoList(alloc, decls);

    return decl_list;
}


fn getDeclsFromFile(
    alloc: *std.mem.Allocator,
    fname: []const u8,
) error{OutOfMemory}!DeclInfoLists {
    const zig_code = std.fs.cwd().readFileAlloc(alloc, fname, max_read_filesize) catch |e| {
         fatalArgs("Could not read lib source file {s}: {}", .{fname, e});
    };
    defer alloc.free(zig_code);

    tree = std.zig.parse(alloc, zig_code) catch |e| {
        fatalArgs("Could not parse lib source file {s}: {}", .{ fname, e });
    };
    defer tree.deinit(alloc);
    const decls = tree.rootDecls();

    const decl_list = try getDeclInfoList(alloc, decls);

    return decl_list;
}

fn getDeclInfoList(
    alloc: *std.mem.Allocator,
    list_d: []const ast.Node.Index,
) error{OutOfMemory}!DeclInfoLists {
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const token_starts = tree.tokens.items(.start);

    var list = try DeclInfoLists.init(alloc);

    for (list_d) |member| {
        if (!util.isNodePublic(tree, member)) continue;

        const tag = node_tags[member]; // Tag

        // We're only concerned about these types. Looks like just
        // test and comptime being skipped currently, but an inclusion
        // list will be easier to keep current, maybe?
        if (tag != .local_var_decl and
            tag != .global_var_decl and
            tag != .simple_var_decl and
            tag != .aligned_var_decl and
            tag != .fn_proto and
            tag != .fn_proto_multi and
            tag != .fn_proto_one and
            tag != .fn_proto_simple and
            tag != .fn_decl and
            tag != .container_field and
            tag != .container_field_init and
            tag != .container_field_align and
            tag != .identifier and
            tag != .error_value)
        {
            continue;
        }


        const decl_addr = member;
        const q_ftoken = tree.firstToken(member);
        const q_ltoken = tree.lastToken(member);
        const q_start = token_starts[q_ftoken];
        const q_end = token_starts[q_ltoken + 1];

        var decl_info_lists: ?DeclInfoLists = null;

        var destination_list = &list.fields;

        if (tag == .fn_decl) {
            // We are only interested in "type functions" which
            // create and return a type.
            destination_list = &list.funcs;
            decl_info_lists = getFunctionDecls(alloc, decl_addr);
        }

        if (tag == .global_var_decl or
                    tag == .local_var_decl or
                    tag == .simple_var_decl or
                    tag == .aligned_var_decl)
                {
            destination_list = &list.values;
            decl_info_lists = getVarDecls(alloc, decl_addr);

            if (decl_info_lists) |_| {
                destination_list = &list.types;
            }
        }

        try destination_list.append(.{
            .decl_info_lists = decl_info_lists,
            .src_line = std.zig.findLineColumn(tree.source, q_start).line,
            .name = try alloc.dupe(u8, util.getDeclName(tree, member).?),
            .tag = tag,
        });
    }

    return list;
}



fn getVarDecls(alloc: *std.mem.Allocator, decl_addr: ast.Node.Index) ?DeclInfoLists {
    const vardecl = util.varDecl(tree, decl_addr).?;

    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const token_starts = tree.tokens.items(.start);

    const name_loc = vardecl.ast.mut_token + 1;
    const name = tree.tokenSlice(name_loc);

    const init = node_datas[decl_addr].rhs;
    const rhst = node_tags[init];

    // we find if the var is a container, we dont wanna display the full thing if it is
    // then we recurse over it
    var buf: [2]ast.Node.Index = undefined;
    var cd = getContainer(node_datas[decl_addr].rhs, &buf);
    if (cd) |container_decl| {
        const offset = if (container_decl.ast.enum_token != null)
            if (rhst == .tagged_union_enum_tag or rhst == .tagged_union_enum_tag_trailing)
                @as(u32, 7)
            else
                @as(u32, 4)
        else
            @as(u32, 1);
        return getDeclInfoList(alloc, container_decl.ast.members) catch null;
    }

    return null;
}

fn getFunctionDecls(alloc: *std.mem.Allocator, decl_addr: ast.Node.Index) ?DeclInfoLists {
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const token_starts = tree.tokens.items(.start);

    const proto = node_datas[decl_addr].lhs;
    const block = node_datas[decl_addr].rhs;
    var params: [1]ast.Node.Index = undefined;

    const fn_proto = util.fnProto(
        tree,
        proto,
        &params,
    ).?;

    const sig = util.getFunctionSignature(tree, fn_proto);

    var sub_cont_ty: ?[]const u8 = null;
    return if (util.isTypeFunction(tree, fn_proto)) blk: {
        const ret = util.findReturnStatement(tree, fn_proto, block) orelse break :blk null;
        if (node_datas[ret].lhs == 0) break :blk null;
        var buf: [2]ast.Node.Index = undefined;
        const container = getContainer(node_datas[ret].lhs, &buf) orelse break :blk null;

        const offset = if (container.ast.enum_token != null)
            if (node_tags[node_datas[ret].lhs] == .tagged_union_enum_tag or
                node_tags[node_datas[ret].lhs] == .tagged_union_enum_tag_trailing)
                @as(u32, 7)
            else
                @as(u32, 4)
        else
            @as(u32, 1);

        sub_cont_ty = tree.source[token_starts[tree.firstToken(node_datas[ret].lhs)]..token_starts[
            main_tokens[node_datas[ret].lhs] + offset
        ]];

        break :blk getDeclInfoList(alloc, container.ast.members) catch |e| {
            return null;
        };
    } else null;
}

fn getContainer(decl_addr: ast.Node.Index, buf: *[2]ast.Node.Index) ?ast.full.ContainerDecl {
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const token_starts = tree.tokens.items(.start);

    const rhst = node_tags[decl_addr];

    // Recurse over it
    return if (rhst == .container_decl or rhst == .container_decl_trailing) tree.containerDecl(decl_addr) else if (rhst == .container_decl_arg or rhst == .container_decl_arg_trailing)
        tree.containerDeclArg(decl_addr)
    else if (rhst == .container_decl_two or rhst == .container_decl_two_trailing) blk: {
        break :blk tree.containerDeclTwo(buf, decl_addr);
    } else if (rhst == .tagged_union or rhst == .tagged_union_trailing)
        tree.taggedUnion(decl_addr)
    else if (rhst == .tagged_union_two or rhst == .tagged_union_two_trailing) blk: {
        break :blk tree.taggedUnionTwo(buf, decl_addr);
    } else if (rhst == .tagged_union_enum_tag or rhst == .tagged_union_enum_tag_trailing)
        tree.taggedUnionEnumTag(decl_addr)
    else
        null;
}

fn fatal(s: []const u8) noreturn {
    std.log.emerg("{s}\n", .{s});
    std.process.exit(1);
}

fn fatalArgs(comptime s: []const u8, args: anytype) noreturn {
    std.log.emerg(s, args);
    std.process.exit(1);
}
