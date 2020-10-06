/* This file contains recursive predicates */
:- use_module(library(clpfd)).
:- use_module(reif).
:- style_check(-singleton).

isTrue([X, Y]):-
    X == 49.

isTrue([X|Tail]):-
    isTrue(Tail).

log(File_name, Name, Addr, Base):-
    Offset #= Addr - Base,
    open(File_name, append, Stream),
    write(Stream, Name),
    write(Stream, ':'),
    write(Stream, Offset),
    nl(Stream),
    close(Stream).

possible_task_struct(Base_addr) :-
    get_time(Current),
    current_predicate(string_val/1),
    pointer(Ptr),
    string_val(Str),
    int(Int),
    Ptr_profile = ([
        [MM2_addr, MM2_val],
        [Tasks_addr, Tasks_val],
        [Parent_addr, Parent_val],
        [Real_parent_addr, Real_parent_val],
        [Child_addr, Child_val],
        [Group_leader_addr, Group_leader_val],
        [Thread_group_addr, Thread_group_val],
        [Cred_addr, Cred_val],
        [FS_struct_addr, FS_struct_val]
    ]),
    Str_profile = ([
        [Comm_addr, Comm_val]    
    ]),
    Int_profile = ([
        [Pid_addr, Pid_val],
        [Tgid_addr, Tgid_val]    
    ]),
    chain([Tasks_addr, MM2_addr, Pid_addr, Tgid_addr, Real_parent_addr, Parent_addr , Child_addr, 
           Group_leader_addr, Thread_group_addr, Cred_addr, Comm_addr, FS_struct_addr], #<),
    %MM2_addr #> Base_addr + 1000,
    Tasks_addr #> MM2_addr - 100,
    %FS_struct_addr #< Base_addr + 4000,
    Tgid_addr #= Pid_addr + 4,
    Real_parent_addr #< Tgid_addr + 20,
    Real_parent_addr #= Parent_addr - 8,
    Child_addr #= Parent_addr + 8,
    %FIXME This may be too strong
    Group_leader_addr #=< Child_addr +32,
    %Comm_addr #= Base_addr + 1656,
    %Tasks_addr #= Base_addr + 1072,
    %FS_struct_addr #= Base_addr + 2640,


    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    tuples_in(Int_profile, Int),

    label([MM2_addr, MM2_val]),
    % make query after labeling
    MM2_val #> 0,
    integer(MM2_val),
    
    query_mm_struct(MM2_val),
    labeling([enum], [Tasks_addr, Tasks_val,  Comm_addr, Comm_val ]),

    Comm_offset #= Comm_addr - Base_addr,
    Tasks_offset #= Tasks_addr - Base_addr,
    Tasks_val #> 0,
    query_list_head(Tasks_val, Comm_offset, Tasks_offset),

    labeling([enum], [Real_parent_addr, Real_parent_val, Group_leader_addr, Group_leader_val]),
    Real_parent_val #> 0,
    Group_leader_val #> 0,
    query_ts(Real_parent_val, Comm_offset, Tasks_offset),
    query_ts(Group_leader_val, Comm_offset, Tasks_offset),

    labeling([enum], [Cred_addr, Cred_val]),
    Cred_val #> 0,
    query_cred(Cred_val),

    labeling([enum], [FS_struct_addr, FS_struct_val]),
    FS_struct_val #> 0,
    %query_fs_struct(FS_struct_val),



    get_time(End),
    Time_past is End - Current,
    MM_offset #= MM2_addr - Base_addr,
    Real_parent_offset #= Real_parent_addr - Base_addr,
    Group_leader_offset #= Group_leader_addr - Base_addr,
    log("profile.txt", "tasks", Tasks_addr, Base_addr),
    log("profile.txt", "mm_struct", MM2_addr, Base_addr),
    log("profile.txt", "comm", Comm_addr, Base_addr),
    log("profile.txt", "parent", Parent_addr, Base_addr),
    log("profile.txt", "group_leader", Group_leader_addr, Base_addr),
    log("profile.txt", "cred", Cred_addr, Base_addr),

    
    print_nl('tasks offset', Tasks_offset),
    print_nl('mm offset', MM_offset),
    print_nl('comm offset', Comm_offset),
    print_nl('real_parent', Real_parent_offset),
    print_nl('group_leader', Group_leader_offset),
    print_nl("Finished, total time", Time_past).

possible_string_pointer(Base_addr) :-
    /* Verify if this pointer points to a stirng */
    string_val(Str),
    Str_profile = [
        [Name_addr, Name_val]
    ],
    tuples_in(Str_profile, Str),
    Name_addr #= Base_addr.

query_string_pointer(Val) :- 
    process_create(path('python'),
                    ['subquery.py', Val, "string_pointer"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_mount_struct(Base_addr, Offset) :-
    pointer(Ptr),
    Ptr_profile = ([
        [Mnt_devname_addr, Mnt_devname_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    Mnt_devname_addr #= Base_addr + Offset,
    labeling([enum], [Mnt_devname_addr, Mnt_devname_val]),
    query_string_pointer(Mnt_devname_val).



possible_kernel_param(Base_addr) :-
    string_val(Str),
    Str_profile = [
        [Name_addr, Name_val]
    ],
    tuples_in(Str_profile, Str),
    Name_addr #= Base_addr.

possible_in_device(Base_addr) :-
    /* in_ifaddr remains the same across kernel versions 
       but we need this query to find ip_ptr in net_device struct
    */
    /*
        struct net_device *dev;
        int               refcnt;
        int               dead;
        struct in_ifaddr  *ifa_list;
    */
    pointer(Ptr),
    int(Int),
    Ptr_profile = ([
        [Dev_addr, Dev_val],
        [Ifa_list_addr, Ifa_list_val]
    ]),
    Int_profile = ([
        [Refcnt_addr, Refcnt_val],
        [Dead_addr, Dead_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Int_profile, Int),
    Dead_addr #= Refcnt_addr + 4,
    chain([Dev_addr, Refcnt_addr, Dead_addr, Ifa_list_addr], #<),
    Dev_addr #= Base_addr,
    Ifa_list_addr #= Base_addr + 16,
    labeling([enum], [Ifa_list_addr, Ifa_list_val]),

    process_create(path('python'),
                    ['subquery.py', Ifa_list_val, "in_ifaddr"],
                    [stdout(pipe(In))]),
    print(In),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_in_ifaddr(Base_addr) :-
    /* in_ifaddr remains the same across kernel versions */
    pointer(Ptr),
    Ptr_profile = ([
        [Hash_addr, Hash_val],
        [Ifa_next_addr, Ifa_next_val],
        [Ifa_dev_addr, Ifa_dev_val],
        [Rcu_head_addr, Rcu_head_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    chain([Hash_addr, Ifa_next_addr, Ifa_dev_addr, Rcu_head_addr], #<),
    Hash_addr #= Base_addr,
    Ifa_next_addr #= Hash_addr + 16,
    Ifa_dev_addr #= Ifa_next_addr + 8,
    Rcu_head_addr #= Ifa_dev_addr + 8,
    labeling([enum], [Hash_addr, Ifa_next_addr, Ifa_dev_addr, Rcu_head_addr]).



possible_mm_struct(Current_addr) :- 
    statistics(real_time, [Start|_]),
    pointer(Ptr),
    long(Ulg),
    % TODO: ADD vm_area_struct *mmap
    Ptr_profile = [
        [Mmap_addr, Mmap_val],
        [Pgd_addr, Pgd_val]  
    ],
    Ulong_profile = [
        [Mmap_base_addr, Mmap_base_val],
        [Mmap_legacy_base_addr, Mmap_legacy_base_val],
        [Task_size_addr, Task_size_val],
        [High_vm_end_addr, High_vm_end_val],
        [Start_brk_addr, Start_brk_val],
        [Brk_addr, Brk_val],
        [Start_stack_addr, Start_stack_val],
        [ARG_start_addr, ARG_start_val]
    ],
    Mmap_addr #= Current_addr,


    Mmap_base_addr #> Mmap_addr,
    %FIXME mmap_base need more value constraint, because we removed mmap_legacy_base and highest_vm_end.
    Mmap_base_val #> 0x7f0000000000,
    %FIXME in old linux version, e.g., there is no mmap_legacy_base and highest_vm_enb
    %chain([Mmap_base_addr, Mmap_legacy_base_addr, Task_size_addr, High_vm_end_addr, Pgd_addr], #<),
    chain([Mmap_base_addr, Task_size_addr, Pgd_addr], #<),

    %FIXME: This rule may be too strong
    %High_vm_end_addr #= Mmap_base_addr + 24, 
    Pgd_addr #> Task_size_addr,
    Pgd_addr #=< Task_size_addr + 40,
    %FIXME: This rule may not be true for other mm_struct.
    Task_size_val #>= 0x7ffffffff000,

    %Mmap_base_addr #= Current_addr + 40,
    %Mmap_legacy_base_addr #= Current_addr + 40,
    %Task_size_addr #= Current_addr + 48,
    %High_vm_end_addr #= Current_addr + 72,

    Start_brk_addr #> Pgd_addr,
    Start_stack_val #> 0x7ff000000000,
    % TODO: Convert this to index comparison. 
    ARG_start_addr #< Current_addr + 500,
    chain([Start_brk_addr, Brk_addr, Start_stack_addr, ARG_start_addr], #<),
    ARG_start_addr #= Start_brk_addr + 24,
    Brk_val #< 0x7ff000000000,
    ARG_start_val #> 0x7ff000000000,
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Ulong_profile, Ulg),


    labeling([enum], [Mmap_addr, Mmap_val, Mmap_base_addr, Pgd_addr, Pgd_val]),
    Mmap_val #> 0,
    Pgd_val #> 0,
    
    process_create(path('python'),
                    ['subquery.py', Mmap_val, "vm_area_struct", 2],
                    [stdout(pipe(In))]),
    print(In),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),
    label([Start_brk_addr, Brk_addr, Start_stack_addr, ARG_start_addr]),
    statistics(real_time, [End|_]),

    log("profile.txt", "mmap", Mmap_addr, Current_addr),
    log("profile.txt", "mmap_base", Mmap_base_addr, Current_addr),
    log("profile.txt", "pgd", Pgd_addr, Current_addr),
    log("profile.txt", "start_brk", Start_brk_addr, Current_addr),
    log("profile.txt", "brk", Brk_addr, Current_addr),
    log("profile.txt", "start_stack", Start_stack_addr, Current_addr),
    log("profile.txt", "arg_start", ARG_start_addr, Current_addr).
    %log("profile.txt", "mm_struct time", End, Start).


possible_vm_area_struct(Base_addr, Level) :-
    statistics(real_time, [Start|_]),
    pointer(Ptr),
    long(Ulg),
    Ptr_profile = [
        [VM_next_addr, VM_next_val],
        [VM_file_addr, VM_file_val]
    ],
    Ulong_profile = [
        [VM_start_addr, VM_start_val],
        [VM_end_addr, VM_end_val],
        [VM_flag_addr, VM_flag_val]
        %VM_pgoff is 0, and we do not consider 0 as ulong
        %[VM_pgoff_addr, VM_pgoff_val]
    ],
    VM_start_addr #>= Base_addr,
    chain([VM_start_addr, VM_end_addr, VM_next_addr, VM_flag_addr, VM_file_addr], #<),
    VM_end_addr #= VM_start_addr + 8,
    VM_next_addr #= VM_end_addr + 8,
    VM_next_addr #< Base_addr + 32,
    VM_file_addr #< Base_addr + 180,
    VM_pgoff_addr #= VM_file_addr - 8,
    %VM_file_addr #= Base_addr + 160,

    tuples_in(Ptr_profile, Ptr),
    tuples_in(Ulong_profile, Ulg),
    %FIXME: VM_flag may need value constraints.

    label([VM_next_addr, VM_next_val]),
    /*if_(Level = 2,
        call(check_vm_area_struct, VM_next_val, 1),
        1 = 1),*/
    %Level #> 1 #==> check_vm_area_struct(VM_next_val, 1),

    labeling([enum], [VM_start_addr, VM_end_addr, VM_flag_addr, VM_pgoff_addr, VM_file_addr, VM_file_val]),
    
    VM_file_val #> 0,
    process_create(path('python'),
                ['subquery.py', VM_file_val, "vm_file"],
                [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),
    statistics(real_time, [End|_]),

    log("profile.txt", "vm_start", VM_start_addr, Base_addr),
    log("profile.txt", "vm_end", VM_end_addr, Base_addr),
    log("profile.txt", "vm_next", VM_next_addr, Base_addr),
    log("profile.txt", "vm_flag", VM_flag_addr, Base_addr),
    log("profile.txt", "vm_pgoff", VM_pgoff_addr, Base_addr),
    log("profile.txt", "vm_file", VM_file_addr, Base_addr).
    %log("profile.txt", "vm_area_struct time", End, Start).

check_vm_area_struct(Base_addr, Level) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "vm_area_struct", Level],
                    [stdout(pipe(In))]),
    print(In),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_vm_file(Base_addr) :-
    pointer(Ptr),
    long(Ulg),
    Ptr_profile = [
        [Vfs_mount_addr, Vfs_mount_val],
        [Dentry_addr, Dentry_val]
    ],
    Vfs_mount_addr #> Base_addr,
    Dentry_addr #= Vfs_mount_addr + 8,
    Dentry_addr #< Base_addr + 40,
    tuples_in(Ptr_profile, Ptr),
    label([Vfs_mount_val, Dentry_val]),
    Vfs_mount_val #>0,
    Dentry_val #> 0,
    %FIXME seems like we do not need this, make sure the string is not addr=0
/*
    process_create(path('python'),
                    ['subquery.py', Vfs_mount_val, "vfs_mount"],
                    [stdout(pipe(NewIn))]),
    read_string(NewIn, Len, X),
    string_codes(X, Result),
    close(NewIn),
    isTrue(Result),*/
    
    process_create(path('python'),
                    ['subquery.py', Dentry_val, "dentry"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_name_pointer(Val, Name_offset) :-
    /* The value at val+name_offset is a string pointer */
    current_predicate(pointer/1),
    pointer(Ptr),
    Ptr_profile = ([
        [Name_addr, Name_val]
    ]),
    Name_addr #= Val + Name_offset,
    tuples_in(Ptr_profile, Ptr),
    labeling([enum], [Name_addr, Name_val]),
    query_string_pointer(Name_val).

possible_vfs_mount(Base_addr) :-
    pointer(Ptr),
    int(Int),
    Ptr_profile = [
        [Dentry_addr, Dentry_val]
    ],
    Int_profile = [
        [Mnt_flags_addr, Mnt_flags_val]
    ],
    
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Int_profile, Int),
    Dentry_addr #= Base_addr,
    Dentry_val #> 0,
    Mnt_flags_addr #= Dentry_addr + 16,
    Mnt_flags_val #>= 0,
    label([Dentry_addr, Dentry_val, Mnt_flags_addr, Mnt_flags_val]).
/*
    process_create(path('python'),
                    ['subquery.py', Dentry_val, "dentry"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).
  */  
possible_dentry(Base_addr) :-
    /*
        struct dentry *d_parent;
        struct qstr d_name -> char *name; it's a name pointer
        struct inode *d_inode;
        unsigned char d_iname[LEN];
        const struct dentry_operations *d_op;
        struct list_head d_child;
        struct list_head d_subdirs;
        union {
	        struct hlist_node d_alias;
	        struct rcu_head d_rcu;
        } d_u;
    */

    
    statistics(real_time, [Start|_]),
    pointer(Ptr),
    string_val(Str),
    Ptr_profile = [
        [Dparent_addr, Dparent_val],
        [Dname_addr, Dname_val],
        [D_inode_addr, D_inode_val],
        [D_op_addr, D_op_val],
        [Dchild_addr, Dchild_val],
        [D_subdirs_addr, D_subdirs_val]
    ],
    Str_profile = [
        [D_iname_addr, D_iname_val]
    ],
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    Dparent_addr #> Base_addr,
    chain([Dparent_addr, Dname_addr, D_inode_addr, D_iname_addr, 
            D_op_addr, Dchild_addr, D_subdirs_addr], #<),
    D_subdirs_addr #= Dchild_addr + 16,
    D_subdirs_addr #< Base_addr + 200,
    Dparent_val #> 0,
    labeling([enum], [Dname_addr, Dname_val]),
    query_string_pointer(Dname_val),
    labeling([enum], [D_iname_addr, D_iname_val]),
    D_iname_offset #= D_iname_addr - Base_addr,
    Dname_offset #= Dname_addr - Base_addr,
    labeling([enum], [Dparent_addr, Dparent_val]),
    Parent_dname #= Dparent_val + Dname_offset,
    process_create(path('python'),
                    ['subquery.py', Parent_dname, "name_pointer", Dname_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),

    labeling([enum], [Dchild_addr, Dchild_val]),
    Dchild_offset #= Dchild_addr - Base_addr,
    Dchild_init #= Dchild_val - Dchild_offset,
    query_name_pointer(Dchild_init, Dname_offset),

    /* This can be hardcoded as d_child_addr + 16 */
    labeling([enum], [D_subdirs_addr, D_subdirs_val]),
    Dsubdirs_offset #= D_subdirs_addr - Base_addr,
    D_subdirs_init #= D_subdirs_val - Dsubdirs_offset,
    query_name_pointer(D_subdirs_init, Dname_offset),


    log("./profile/dentry", "parent", Dparent_addr, Base_addr),
    log("./profile/dentry", "d_iname", D_iname_addr, Base_addr),
    log("./profile/dentry", "dchild", Dchild_addr, Base_addr),
    log("./profile/dentry", "d_subdirs", D_subdirs_addr, Base_addr).

    
query_name_pointer(Base_addr, Offset) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "name_pointer", Offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_inode_operations(Base_addr) :-
    /* a bunch of function pointers. */
    pointer(Ptr),
    Ptr_profile = ([
        [_L1_addr, _L1_val],
        [_L2_addr, _L2_val],
        [_L3_addr, _L3_val],
        [_L4_addr, _L4_val],
        [_L5_addr, _L5_val],
        [_L6_addr, _L6_val],
        [_L7_addr, _L7_val],
        [_L8_addr, _L8_val],
        [_L9_addr, _L9_val],
        [_L10_addr, _L10_val],
        [_L11_addr, _L11_val],
        [_L12_addr, _L12_val]
    ]),
    tuples_in(Ptr_profile, Ptr),
    chain([_L1_addr, _L2_addr, _L3_addr, _L4_addr, _L5_addr, _L6_addr, _L7_addr,
           _L8_addr, _L9_addr, _L10_addr, _L11_addr, _L12_addr], #<),
    _L1_addr #= Base_addr,
    _L12_addr #= Base_addr + 88.




possible_nothing() :-

    %log("profile.txt", "dentry addr", Base_addr, 0),
    Dparent_addr #> Base_addr,
    Dname_addr #> 0,
    Dname_addr #< Base_addr + 200,
    %Dname_addr #= Base_addr + 160,
    %FIXME This child rule is not applicable for old kernel version. 
    %chain([Dparent_addr, Dname_addr, Dchild_addr], #<),
    %Dchild_addr #< Base_addr + 200,
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    labeling([enum], [Dparent_addr, Dparent_val, Dname_addr, Dchild_addr, Dchild_val]),
    Dname_offset #= Dname_addr - Base_addr,
    integer(Dname_offset),
    Dparent_val #> 0,
    
    %FIXME d_parent may not be initialized
    /*process_create(path('python'),
                ['subquery.py', Dparent_val, "d_entry", Dname_offset],
                [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),*/

    %FIXME: may need to find another way for all list_head. 
    /*Dchild_offset #= Dchild_addr - Base_addr,
    integer(Dchild_offset),
    Dchild_base #= Dchild_val - Dchild_offset,
    integer(Dchild_base),
    Dchild_base #> 0,
    process_create(path('python'),
                ['subquery.py', Dchild_base, "d_entry", Dname_offset],
                [stdout(pipe(NewIn))]),
    read_string(NewIn, Len, X),
    string_codes(X, Result),
    close(NewIn),
    isTrue(Result),*/
    log("profile.txt", "d_iname", Dname_addr, Base_addr),
    statistics(real_time, [End|_]).
/*
    log("profile.txt", "d_iname", Dname_addr, Base_addr),
    log("profile.txt", "d_parent", Dparent_addr, Base_addr),
    log("profile.txt", "d_child", Dchild_addr, Base_addr),
    log("profile.txt", "dentry time", End, Start).
*/
possible_d_entry(Base_addr, Dname_offset) :-
    current_predicate(string_val/1),
    string_val(Str),
    Str_profile = [
        [Dname_addr, Dname_val]
    ],
    Dname_addr #= Base_addr + Dname_offset,
    tuples_in(Str_profile, Str),
    label([Dname_addr]).

possible_list_head(Tasks_val, Comm_offset, Tasks_offset) :-
    string_val(Str),
    pointer(Ptr),
    Ptr_profile = [
        [Tasks_val, Tasks_addr]
    ],
    Str_profile = [
        [Comm_addr, Comm_val]
    ],
    Comm_addr #= Tasks_val - Tasks_offset + Comm_offset,
    Tasks_addr #\= Tasks_val,
    tuples_in(Str_profile, Str),
    tuples_in(Ptr_profile, Ptr),
    label([Comm_addr]).

possible_ts(Base_addr, Comm_offset, Tasks_offset) :-
    string_val(Str),
    pointer(Ptr),
    Ptr_profile = [
        [Tasks_addr, Tasks_val]
    ],
    Str_profile = [
        [Comm_addr, Comm_val]
    ],

    Comm_addr #= Base_addr + Comm_offset,
    Tasks_addr #= Base_addr + Tasks_offset,
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),

    label([Tasks_val]),
    
    process_create(path('python'),
                    ['subquery.py', Tasks_val, "list_head", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_cred(Base_addr) :-
    statistics(real_time, [Start|_]),

    int(Int),
    long(Ulg),
    Int_profile = [
        [Addr1, Val1],
        [Addr2, Val2],
        [Addr3, Val3],
        [Addr4, Val4],
        [Addr5, Val5],
        [Addr6, Val6],
        [Addr7, Val7],
        [Addr8, Val8],
        [Addr9, Val9]
    ],
    %FIXME For now, this rule is hard-coded because we do not consider 0 as a unsign long number. 
    %So that for cred whos val10 is 0, this rule does not apply.
    /*Ulong_profile = [
        [Addr10, Val10],
        [Addr11, Val11]
    ],*/
    Addr1 #> Base_addr,
    %chain([Addr1, Addr2, Addr3, Addr4, Addr5, Addr6, Addr7, Addr8, Addr9, Addr10, Addr11], #<),
    chain([Addr1, Addr2, Addr3, Addr4, Addr5, Addr6, Addr7, Addr8, Addr9], #<),
    Addr1 #= Base_addr + 4,
    Addr9 #= Addr1 + 32,
    %Addr11 #< Base_addr + 120,
    tuples_in(Int_profile, Int),
    %tuples_in(Ulong_profile, Ulg),
    statistics(real_time, [End|_]),
    labeling([enum], [Addr1, Addr2, Addr5, Addr6]),
    log("profile.txt", "cred time", End, Start),
    log('profile.txt', "uid", Addr1, Base_addr),
    log('profile.txt', "gid", Addr2, Base_addr),
    log('profile.txt', "euid", Addr5, Base_addr),
    log('profile.txt', "egid", Addr6, Base_addr).

possible_fs_struct(Base_addr) :-
    statistics(real_time, [Start|_]),
    int(Int),
    pointer(Ptr),
    Int_profile = [
        [Addr1, Val1],
        [Addr2, Val2],
        [Addr3, Val3]
    ],
    Ptr_profile = [
        [Root_addr, Root_val],
        [PWD_addr, PWD_val]
    ],
    Addr1 #>= Base_addr,
    chain([Addr1, Addr2, Addr3, Root_addr, PWD_addr], #<),
    PWD_addr #= Root_addr + 16,
    PWD_addr #< Base_addr + 50,
    tuples_in(Int_profile, Int),
    tuples_in(Ptr_profile, Ptr),
    Root_val #> 0,
    PWD_val #> 0,
    label([Root_addr, Root_val]),
    
    process_create(path('python'),
                    ['subquery.py', Root_val, "dentry"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),

    label([PWD_addr, PWD_val]),
    process_create(path('python'),
                    ['subquery.py', PWD_val, "dentry"],
                    [stdout(pipe(NewIn))]),
    read_string(NewIn, Len, X),
    string_codes(X, Result),
    close(NewIn),
    isTrue(Result),

    statistics(real_time, [End|_]),
    log("profile.txt", "fs time", End, Start),
    log('profile.txt', "Root", Root_addr, Base_addr),
    log('profile.txt', "pwd", PWD_addr, Base_addr).
