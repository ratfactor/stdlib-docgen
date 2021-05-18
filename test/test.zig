a_field: usize,

pub extern fn extern_fn() c_int;
pub extern fn extern_fn2(a: c_int, b: c_int, z: c_int) c_int;

pub fn functionX() void { return; }

pub export fn functionY() void {}

pub fn ZTypeFn() type {
    return union(enum) {
        field_a: u32,
        field_b: usize,
        field_d: u32,
        pub fn fnNest() nested {
            return "bruh";
        }
        pub const z_const = fnNest();
    };
}

pub const PUBLIC_CONST = 1;
const PRIVATE_CONST = 2;

pub const MyUnionType = union(enum) {
    my_field: u32,

    pub fn mySweetFn(self: @This()) u32 {
        return 1;
    }

    pub const innerDeclStruct = struct {
        pub fn innerFn() void {
            return;
        }
    };
};

pub const V = union(enum(u32)) {
    pub const A = u32;
};

pub const MyStructType = struct {
    field1: u32,
    field2: u32,

    pub fn myFoo(self: MyStructType) MyStructType {
        return self;
    }
};
