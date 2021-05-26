const std = @import("std");
const ast = std.zig.ast;
const util = @import("utils.zig");
const source_url = "https://github.com/ziglang/zig/blob/master/lib/std/";

const out_fname_html = "index.html";
const in_fname_head = "html_head.html";
const in_fname_entries = "entries.json";
const max_read_filesize = 20 * 1024 * 1024; // 20Mb I mean, really.

const JsonEntry = struct {
    name: []const u8 = undefined,
    description: ?[]const u8 = null,
    hide: bool = false,
    compact: bool = false,
};

var tree: ast.Tree = undefined;

const DeclInfoLists = struct {
    name: []const u8 = undefined,
    fields: std.ArrayList(DeclInfo),
    types: std.ArrayList(DeclInfo),
    funcs: std.ArrayList(DeclInfo),
    values: std.ArrayList(DeclInfo),
    json_entry: JsonEntry = undefined,

    pub fn init(alloc: *std.mem.Allocator) !@This() {
        return @This(){
            .fields = std.ArrayList(DeclInfo).init(alloc),
            .types = std.ArrayList(DeclInfo).init(alloc),
            .funcs = std.ArrayList(DeclInfo).init(alloc),
            .values = std.ArrayList(DeclInfo).init(alloc),
        };
    }

    pub fn htmlStringify(self: DeclInfoLists, writer: anytype) std.fs.File.WriteError!void {
        if (self.json_entry.hide) {
            // Ignore hidden items. I tried minimizing or explaining hidden items, but there
            // is already so much stuff, they were just adding to the clutter.
            return;
        }

        // On one hand, this won't work for Windows paths. On the other
        // hand, the '/' slash works for the source URLs as-is, so...
        const in_subdir = std.mem.containsAtLeast(u8, self.name, 1, "/");
        const subdir_class = if (in_subdir) "subdir" else "";
        const hidden_class = if (self.json_entry.hide) "hidden" else "";

        try writer.print(
            \\ <div class="module {s} {s}">
            \\ <h2><a class="decl" target="_blank" href="{s}{s}">{s}</a></h2>
            \\ <div class="module-inner">
            , .{
                subdir_class,
                hidden_class,
                source_url,
                self.name,
                self.name
        });

        if (self.json_entry.description) |desc| {
            try writer.print("<p>{s}</p>", .{self.json_entry.description});
        }
        inline for (.{"fields", "funcs", "types", "values"}) |n| {
            try writer.print("<span class=\"kind-{s}\">", .{n});
            const this_list = @field(self, n).items;
            for (this_list) |decl, count| {
                try decl.htmlStringify(writer, self.json_entry.compact);

                if (self.json_entry.compact and count > 5) {
                    try writer.print(" {} more...", .{this_list.len-5});
                    break;
                }
            }
            try writer.writeAll("</span>");
        }
        try writer.writeAll("</div></div>"); // end of module
    }
};

const DeclKind = enum { field, func, type, value };

const DeclInfo = struct {
    kind: DeclKind,
    name: []const u8,
    tag: std.zig.ast.Node.Tag,
    sub_cont_ty: ?[]const u8 = null,
    decl_info_lists: ?DeclInfoLists,
    src_line: usize,

    pub fn htmlStringify(self: DeclInfo, writer: anytype, compact: bool) std.fs.File.WriteError!void {
        // If this decl contains inner decls, enclose the lot in a container
        if (self.decl_info_lists != null)
            try writer.writeAll("<div class=\"inner-container\">");

        var fn_parens = if (self.kind == .func) "()" else "";
        var kind_str = switch (self.kind) {
            .field => "field",
            .func => "func",
            .type => "type",
            .value => "value",
        };

        try writer.print("<a class=\"decl kind-{s}\" target=\"_blank\" href=\"{s}{s}#L{}\">{s}{s}</a> ", .{
            kind_str,
            source_url,
            cur_file,
            self.src_line+1, // always one off - is it 0 indexed?
            self.name,
            fn_parens,
        });

        if (self.decl_info_lists != null) {
            inline for (.{"fields", "funcs", "types", "values"}) |n| {
                const this_list = @field(self.decl_info_lists.?, n).items;
                for (this_list) |decl, count| {
                    try decl.htmlStringify(writer, compact);

                    if (compact and count > 5) {
                        try writer.print(" {} more...", .{this_list.len});
                        break;
                    }
                }
            }
            try writer.writeAll("</div>"); // End container started way up at the top of fn
        }
    }
};

var cur_file: []const u8 = undefined;

fn removeTrailingSlash(n: [:0]u8) []u8 {
    if (std.mem.endsWith(u8, n, "/"))
        return n[0 .. n.len - 1];
    return n;
}

pub fn main() !void {
//    var general_pa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 8 }){};
//    const alloc = &general_pa.allocator;

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = &arena.allocator;

    const args = try std.process.argsAlloc(alloc);

    if (args.len < 2) fatal("The first argument must be a directory path.");

    const dirname = removeTrailingSlash(args[1]);

    var walker = std.fs.walkPath(alloc, dirname) catch |e| fatalArgs("Could not read directory: {s}: {}", .{ dirname, e });
//    defer walker.deinit();

    // Store the decl lists for each file mapped by filename
    var decls_by_filename = std.StringHashMap(DeclInfoLists).init(alloc);

    // Read json data
    const info_json = std.fs.cwd().readFileAlloc(alloc, in_fname_entries, max_read_filesize) catch |e| {
         fatalArgs("Could not read file {s}: {}", .{in_fname_entries, e});
    };

    // Now parse those tasty JSON potatoes.
    // Used ziglearn to understand how to parse into a data type:
    //   https://ziglearn.org/chapter-2/#json
    // Used laddercraft to understand how to loop over the token stream:
    //   https://github.com/wozeparrot/laddercraft/blob/master/utils/item_registry_generator.zig


    // Store the entries hashed by filename (corresponds with library file names)
    var json_entries = std.StringHashMap(JsonEntry).init(alloc);

    var json_stream = std.json.TokenStream.init(info_json);

    const context = .{.allocator = alloc};

    std.debug.assert((try json_stream.next()).? == .ObjectBegin); // '{' <--- at the very beginning


    while (true) {
        // So, ideally we could peek at the next token to see if it's a string
        // or an ObjectEnd '}' (expected when we're out of entries). But for
        // this kind of one-off utility, let's just assume the inability to
        // parse another entry means we've come to the end.
        const my_name = std.json.parse([]const u8, &json_stream, context) catch break;

        var my_value = try std.json.parse(JsonEntry, &json_stream, context);
        my_value.name = my_name;

        try json_entries.put(my_name, my_value);

//        my_value.print();
    }

//    std.debug.print("Read {} entries from {s}\n", .{json_entries.count(), in_fname_entries});
    
    // Terminal progress indicator
    var progress: std.Progress = .{};
    var progress_main = try progress.start("", 0);
    progress_main.activate();
    defer progress_main.end();
    var progress_analysis = progress_main.start("Reading library...", 0);
    progress_analysis.activate();

    // So we can sort em
    var filenames = std.ArrayList([]const u8,).init(alloc);
//    defer filenames.deinit();

    // Loop through files in input directory
    while (walker.next() catch |e| fatalArgs("Could not read next file: {}", .{e})) |entry| {
        if (!std.mem.endsWith(u8, entry.path, ".zig")) continue;

        // Chop the dirname + "/" from the front of the path
        const filename = entry.path[dirname.len+1..];

        // Do we already have this one?
        if (decls_by_filename.contains(filename)) continue;

        const my_filename = try alloc.dupe(u8, filename);

        // Show current file as progress
        var progress_file = progress_analysis.start(filename, 1);
        progress_file.activate();
        defer progress_file.end();

        // Store decl lists in hashmap by filename and store filename itself
        var list = try getDeclsFromFile(alloc, entry.path);
        list.name = my_filename;

        if (json_entries.contains(my_filename) ) {
            list.json_entry = json_entries.get(my_filename).?;
        }
        
        try decls_by_filename.put(my_filename, list);
        try filenames.append(my_filename);
    }
    progress_analysis.end();

    // Sort the filenames
    std.sort.sort( []const u8, filenames.items, {}, stringAsc);

    var progress_writing = progress_main.start("Writing HTML...", 0);
    progress_writing.activate();
    defer progress_writing.end();

    const output_file = std.fs.cwd().createFile(out_fname_html, .{ .read = true }) catch |e| fatalArgs("Could not open {s} for writing: {}", .{out_fname_html, e});
    defer output_file.close();
    const w = output_file.writer();

    const html_head = std.fs.cwd().readFileAlloc(alloc, in_fname_head, max_read_filesize) catch |e| {
         fatalArgs("Could not read file {s}: {}", .{in_fname_head, e});
    };

    try w.writeAll(html_head);

//    std.debug.print("{s}\n", .{filenames.items});

    for (filenames.items) |fname| {
        cur_file = fname;
        try decls_by_filename.get(fname).?.htmlStringify(w);
    }

    try w.writeAll("</div></body></html>");
}


// Comparison function for filename string sorting
pub fn stringAsc(context: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.lessThan(u8, lhs, rhs);
}

fn getDeclsFromFile(
    alloc: *std.mem.Allocator,
    fname: []const u8,
) error{OutOfMemory}!DeclInfoLists {
    const zig_code = std.fs.cwd().readFileAlloc(alloc, fname, max_read_filesize) catch |e| {
         fatalArgs("Could not read lib source file {s}: {}", .{fname, e});
    };

    tree = std.zig.parse(alloc, zig_code) catch |e| {
        fatalArgs("Could not parse lib source file {s}: {}", .{ fname, e });
    };
//    defer tree.deinit(alloc);
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
        var kind = DeclKind.field;

        if (tag == .fn_decl) {
            // We are only interested in "type functions" which
            // create and return a type.
            destination_list = &list.funcs;
            decl_info_lists = getFunctionDecls(alloc, decl_addr);
            kind = DeclKind.func;
        }

        if (tag == .global_var_decl or
                    tag == .local_var_decl or
                    tag == .simple_var_decl or
                    tag == .aligned_var_decl)
                {
            destination_list = &list.values;
            kind = DeclKind.value;
            decl_info_lists = getVarDecls(alloc, decl_addr);

            if (decl_info_lists) |_| {
                destination_list = &list.types;
                kind = DeclKind.type;
            }
        }

        try destination_list.append(.{
            .kind = kind,
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
