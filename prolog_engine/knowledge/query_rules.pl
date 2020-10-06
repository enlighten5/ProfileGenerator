:- use_module(library(clpfd)).

isTrue([X, _]):-
    X == 49.

isTrue([_|Tail]):-
    isTrue(Tail).

log(File_name, Name, Addr, Base):-
    Offset #= Addr - Base,
    open(File_name, append, Stream),
    write(Stream, Name),
    write(Stream, ':'),
    write(Stream, Offset),
    nl(Stream),
    close(Stream).

start_query(Base_addr) :- 
    pointer(Ptr),
    string_val(Str),
    Ptr_profile = ([
        [MM2_addr, MM2_val],
        [Real_parent_addr, Real_parent_val],
        [Cred_addr, Cred_val],
        [FS_struct_addr, FS_struct_val]
    ]),
    Str_profile = ([
        [Comm_addr, Comm_val]    
    ]),
    chain([MM2_addr, Real_parent_addr, Cred_addr, Comm_addr, FS_struct_addr], #<),
    Real_parent_addr #> Comm_addr - 500,
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    labeling([enum], [Real_parent_addr, Real_parent_val,  Comm_addr, Comm_val]),
    process_create(path('python'),
                ['subquery.py', Real_parent_val, "task_struct"],
                [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

    

query_task_struct(Base_addr) :-
    get_time(Current),
    %current_predicate(string_val/1),
    pointer(Ptr),
    string_val(Str),
    int(Int),
    Ptr_profile = ([
        [MM_addr, MM_val],
        [MM2_addr, MM2_val],
        [Tasks_addr, Tasks_val],
        [Parent_addr, Parent_val],
        [Real_parent_addr, Real_parent_val],
        [Child_addr, Child_val],
        [Group_leader_addr, Group_leader_val],
        [Thread_group_addr, Thread_group_val],
        [Real_cred_addr, Real_cred_val],
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
    chain([Tasks_addr, MM_addr, MM2_addr, Pid_addr, Tgid_addr, Real_parent_addr, Parent_addr , Child_addr, 
           Group_leader_addr, Thread_group_addr, Real_cred_addr, Cred_addr, Comm_addr, FS_struct_addr], #<),
    %MM2_addr #> Base_addr + 1000,
    MM2_addr #= MM_addr + 8,
    Tasks_addr #> MM2_addr - 100,
    %FS_struct_addr #< Base_addr + 4000,
    Tgid_addr #= Pid_addr + 4,
    Real_parent_addr #< Tgid_addr + 20,
    Real_parent_addr #= Parent_addr - 8,
    Child_addr #= Parent_addr + 8,
    %FIXME This may be too strong
    %Children next and prev 16 
    %Sibling next and prev  16
    Group_leader_addr #=< Child_addr +32,
    Cred_addr #= Real_cred_addr + 8,
    /*MM2_addr #= Base_addr + 1160,
    Comm_addr #= Base_addr + 1656,
    Tasks_addr #= Base_addr + 1096,*/
    %FS_struct_addr #= Base_addr + 2640,


    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    tuples_in(Int_profile, Int),

    label([MM2_addr, MM2_val]),
    label([MM_addr, MM_val]),
    % make query after labeling
    MM2_val #> 0,
    integer(MM2_val),
    %Is it safe to do this?
    %query_mm_struct(MM_val),
    query_mm_struct(MM2_val),
    labeling([enum], [Tasks_addr, Tasks_val, Comm_addr, Comm_val, Pid_addr, Tgid_addr]),
/*
    Comm_offset #= Comm_addr - Base_addr,
    Tasks_offset #= Tasks_addr - Base_addr,
    Tasks_val #> 0,
    query_list_head(Tasks_val, Comm_offset, Tasks_offset),

    labeling([enum], [Real_parent_addr, Real_parent_val, Group_leader_addr, Group_leader_val, Child_addr, Child_val]),
    Real_parent_val #> 0,
    Group_leader_val #> 0,
    query_ts(Real_parent_val, Comm_offset, Tasks_offset),
    %query_list_head(Child_val-16, Comm_offset, Tasks_offset),
    query_ts(Group_leader_val, Comm_offset, Tasks_offset),

    labeling([enum], [Real_cred_addr, Real_cred_val, Cred_addr, Cred_val]),
    Cred_val #> 0,
    query_cred(Real_cred_val),
    query_cred(Cred_val),
*/
/*
    labeling([enum], [FS_struct_addr, FS_struct_val]),
    FS_struct_val #> 0,
    %query_fs_struct(FS_struct_val),
*/


    get_time(End),
    Time_past is End - Current,
    MM_offset #= MM2_addr - Base_addr,
    Real_parent_offset #= Real_parent_addr - Base_addr,
    Group_leader_offset #= Group_leader_addr - Base_addr,
    log("profile.txt", "tasks", Tasks_addr, Base_addr),
    log("profile.txt", "active_mm_struct", MM2_addr, Base_addr),
    log("profile.txt", "comm", Comm_addr, Base_addr),
    log("profile.txt", "parent", Parent_addr, Base_addr),
    log("profile.txt", "group_leader", Group_leader_addr, Base_addr),
    log("profile.txt", "cred", Cred_addr, Base_addr),
    log("profile.txt", "pid", Pid_addr, Base_addr),


    
    print_nl('tasks offset', Tasks_offset),
    print_nl('mm offset', MM_offset),
    print_nl('comm offset', Comm_offset),
    print_nl('real_parent', Real_parent_offset),
    print_nl('group_leader', Group_leader_offset),
    print_nl("Finished, total time", Time_past).

query_module(Base_addr) :-
    /* struct list_head list;
       char name[LEN]; 
       struct kernel_param *kp;
       struct module_layout core_layout;
       struct module_layout init_layout; 
       unsigned int core_size, init_size;
       unsigned int init_text_size, core_text_size;
    */
    get_time(Current),
    pointer(Ptr),
    string_val(Str),
    int(Int),
    /* Type Invariants */
    Ptr_profile = ([
        [List_addr, List_val],
        [KP_addr, KP_val],
        [Core_base_addr, Core_base_val]
    ]),
    Str_profile = ([
        [Name_addr, Name_val]    
    ]),
    Int_profile = ([
        [Core_size_addr, Core_size_val],
        [Core_text_size_addr, Core_text_size_val],
        [RO_size_addr, RO_size_val],
        [RO_init_size_addr, RO_init_size_val]
    ]),    
    
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    tuples_in(Int_profile, Int),
    /* Order Invariants */
    chain([List_addr, Name_addr, KP_addr, Core_base_addr, Core_size_addr, 
            Core_text_size_addr, RO_size_addr, RO_init_size_addr], #<),
    RO_init_size_addr - Base_addr #< 1000,
    
    labeling([enum], [Name_addr, Name_val]),
    List_addr #= Name_addr - 16,
    labeling([enum], [List_addr, List_val]),
    Name_offset #= Name_addr - Base_addr,
    List_offset #= List_addr - Base_addr,
    query_list_head(List_val, Name_offset, List_offset),
    KP_val #> 0,
    labeling([enum], [KP_addr, KP_val]),
    query_kernel_param(KP_val),
    Core_size_addr #= Core_base_addr + 8,
    Core_size_val #> 0,
    Core_text_size_addr #= Core_size_addr + 4,
    Core_text_size_val #> 0,
    RO_size_addr #= Core_text_size_addr + 4,
    RO_init_size_addr #= RO_size_addr + 4,

    labeling([enum], [Core_base_addr, Core_size_addr, 
            Core_text_size_addr, RO_size_addr, RO_init_size_addr]),

    get_time(End),
    Time_past is End - Current,
    log("module", "list", List_addr, Base_addr),
    log("module", "name", Name_addr, Base_addr),
    log("module", "kp", KP_addr, Base_addr),
    log("module", "core_base", Core_base_addr, Base_addr),
    log("module", "core_size", Core_size_addr, Base_addr),
    log("module", "core_text_size", Core_text_size_addr, Base_addr).

query_mount(Base_addr) :-
    /* struct hlist_head mnt_hash;
       struct mount *mnt_parent; 
       struct vfsmount mnt;
       struct list_head mnt_mounts;
       struct list_head mnt_child;
       struct list_head mnt_instance;
       const char *mnt_devname;
       struct list_head mnt_list;
    */
    get_time(Current),
    pointer(Ptr),
    string_val(Str),
    int(Int),
    /* Type Invariants */
    Ptr_profile = ([
        [Mnt_hash_addr, Mnt_hash_val],
        [Mnt_parent_addr, Mnt_parent_val],
        [Vfsmount_addr, Vfsmount_val],
        [Mnt_child_addr, Mnt_child_val],
        [Mnt_devname_addr, Mnt_devname_val],
        [Mnt_list_addr, Mnt_list_val]
    ]),
    Int_profile = ([
        [Mnt_flags_addr, Mnt_flags_val]
    ]),    
    
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Int_profile, Int),
    /* Order Invariants */
    chain([Mnt_hash_addr, Mnt_parent_addr, Vfsmount_addr, Mnt_flags_addr,
            Mnt_child_addr, Mnt_devname_addr, Mnt_list_addr], #<),
    Mnt_hash_addr #= Base_addr,
    /* mnt_hash_addr is a list_head */
    Mnt_parent_addr #> Base_addr + 8,
    Mnt_list_addr - Base_addr #< 200,
    labeling([enum], [Mnt_devname_addr, Mnt_devname_val]),
    query_string_pointer(Mnt_devname_val),
    Mnt_devname_offset #= Mnt_devname_addr - Base_addr,
    /* the offset from mnt_mounts to mnt_list remains the same, so it's safe to use fixed offsets. */
    Mnt_child_addr #= Mnt_devname_addr - 32,
    Mnt_list_addr #= Mnt_devname_addr + 8,
    Mnt_flags_addr #= Vfsmount_addr + 16,
    labeling([enum], [Mnt_child_addr, Mnt_list_addr, Vfsmount_addr, Vfsmount_val]),
    /* Seems unnecessary 
    Mnt_list_offset #= Mnt_list_addr - Base_addr,
    Mnt_list #= Mnt_list_val - Mnt_list_offset,
    Mnt_list #> 0,
    query_mount_struct(Mnt_list, Mnt_devname_offset),
    */
    Vfsmount_val #>= 0,
    /* Here we can infer layout of dentry structure 
       Maybe need to infer using another dentry, somehow it may not be initialized. 
    */
    Vfsmount_addr #> 0,
    %query_dentry(Vfsmount_addr),

    labeling([enum], [Mnt_parent_addr, Mnt_parent_val]),
    /* To verify another mount struct, only one-level query, so it does not direct call query_mount recursively */
    
    query_mount_struct(Mnt_parent_val, Mnt_devname_offset),
    

    get_time(End),
    Time_past is End - Current,

    log("mount", "mnt_hash", Mnt_hash_addr, Base_addr),
    log("mount", "mnt_parent", Mnt_parent_addr, Base_addr),
    log("mount", "mnt_child", Mnt_child_addr, Base_addr),
    log("mount", "mnt_devname", Mnt_devname_addr, Base_addr),
    log("mount", "mnt_list", Mnt_list_addr, Base_addr).

query_net_device(Base_addr) :- 
    /*
        char             name[NAMSIZ];
        struct list_head dev_list;
        unsigned char    addr_len;
        unsigned int     promiscuity;
        struct in_device *ip_ptr;
    */
    get_time(Current),
    pointer(Ptr),
    string_val(Str),
    int(Int),
    /* Type Invariants */
    Ptr_profile = ([
        [Dev_list_addr, Dev_list_val],
        [IP_ptr_addr, IP_ptr_val]
    ]),
    Str_profile = ([
        [Name_addr, Name_val]
    ]),
    Int_profile = ([
        [Promisc_addr, Promisc_val],
        [Addr_len_addr, Addr_len_val]
    ]),    
    
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    tuples_in(Int_profile, Int),
    /* Hard to determine offsets for addr_len and promisc */
    chain([Name_addr, Dev_list_addr, Addr_len_addr, Promisc_addr, IP_ptr_addr], #<),
    Name_addr #>= Base_addr,
    Name_offset #= Name_addr - Base_addr,
    IP_ptr_addr #< Base_addr + 1000,
    /* dev_list offset can be hardcoded since it remains the same */
    Dev_list_addr #= Base_addr + 80,
    labeling([enum], [Name_addr, Dev_list_addr, Dev_list_val]),
    /* do not have a good constrain to narrow down ip_ptr, use its rough offset
       to reduce the search space. 
     */
    IP_ptr_addr #> Base_addr + 700,
    IP_ptr_val #> 0,
    labeling([enum], [IP_ptr_addr, IP_ptr_val]),
    query_in_device(IP_ptr_val),

    get_time(End),
    Time_past is End - Current,

    log("net_device", "name", Name_addr, Base_addr),
    log("net_device", "ip_ptr", IP_ptr_addr, Base_addr),
    log("net_device", "dev_list", Dev_list_addr, Base_addr).


query_inet_sock(Base_addr) :-
    /* As defined in source code, sk and pinet6 has to be 
       the first two members of inet_sock, which means we
       can hardcode this rule.
    */
    /*skc_family at offset 16 short contained in a unsigned number 
     First half of sock_common can be viewed as unchanged, so it's safe to use
       some hardcoded ruels to help pinpoint some offsets.  
    sk_buff_head, two non-zero pointers, one unsigned long, one integer.
    sk_protocol is a unsigned long number after sk_write_buffer, and they have the same offset. */
    get_time(Current),
    pointer(Ptr),
    long(Ulg),
    int(Int),
    /* Type Invariants */
    Ptr_profile = ([
        [Sk_receive_queue_addr, Sk_receive_queue_val],
        [Sk_receive_queue_prev_addr, Sk_receive_queue_prev_val],
        [Sk_write_queue_addr, Sk_write_queue_val],
        [Sk_write_queue_prev_addr, Sk_write_queue_prev_val]
    ]),
    Ulong_profile = ([
        [Skc_family_addr, Skc_family_val],
        [Sk_protocol_addr, Sk_protocol_val]
    ]),
    Int_profile = ([
        [Receive_lock_addr, Receive_lock_val],
        [Write_lock_addr, Write_lock_val],
        [Qlen_receive_addr, Qlen_receive_val],
        [Qlen_write_addr, Qlen_write_val]
    ]),    
    
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Ulong_profile, Ulg),
    tuples_in(Int_profile, Int),

    Sk_protocol_val #> 0,
    Skc_family_addr #= Base_addr + 16,
    Skc_family_val #> 0,
    Sk_receive_queue_val #> 0,
    Sk_receive_queue_prev_val #> 0,
    Sk_write_queue_val #> 0,
    Sk_write_queue_prev_val #> 0,
    chain([Skc_family_addr, Sk_receive_queue_addr, Sk_receive_queue_prev_addr, Qlen_receive_addr, Receive_lock_addr,
          Sk_write_queue_addr, Sk_write_queue_prev_addr, Qlen_write_addr, Write_lock_addr,
          Sk_protocol_addr], #<),
    /* sock_common is at least 136 */
    Sk_receive_queue_addr #> Base_addr + 136,
    Sk_protocol_addr #< Base_addr + 700,
    Sk_receive_queue_prev_addr #= Sk_receive_queue_addr + 8,
    Qlen_receive_addr #= Sk_receive_queue_prev_addr + 8,
    Receive_lock_addr #= Qlen_receive_addr + 4,

    Sk_write_queue_prev_addr #= Sk_write_queue_addr + 8,
    Qlen_write_addr #= Sk_write_queue_prev_addr + 8,
    Write_lock_addr #= Qlen_write_addr + 4,

    labeling([enum], [Skc_family_addr, Sk_receive_queue_addr, Sk_write_queue_addr, Sk_protocol_addr]),

    get_time(End),
    Time_past is End - Current,

    log("inet_sock", "sk_receive_queue", Sk_receive_queue_addr, Base_addr),
    log("inet_sock", "Sk_write_queue", Sk_write_queue_addr, Base_addr),
    log("inet_sock", "Skc_family", Skc_family_addr, Base_addr),
    log("inet_sock", "Sk_protocol", Sk_protocol_addr, Base_addr).

query_resource(Base_addr) :-
    /*
        start
        end
        *name
        *parent
        *sibling
        *child -> non-zero
    */
    /* This structure remains unchanged, thus we can have some
       hardcoded rules to help inference. */

    get_time(Current),
    pointer(Ptr),
    long(Ulg),
    int(Int),
    /* Type Invariants */
    Ptr_profile = ([
        [Name_addr, Name_val],
        [Parent_addr, Parent_val],
        [Sibling_addr, Sibling_val],
        [Child_addr, Child_val]
    ]),
    Ulong_profile = ([
        [End_addr, End_val],
        [Flags_addr, Flags_val]
    ]),
    Int_profile = ([
        [Start_addr, Start_val]
    ]),    
    
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Ulong_profile, Ulg),
    tuples_in(Int_profile, Int),

    Child_val #> 0,
    chain([Start_addr, End_addr, Name_addr, Flags_addr, Parent_addr, Sibling_addr, Child_addr], #<),
    %Name_addr #= Base_addr + 16,
    Child_addr #=< Base_addr + 64,
    labeling([enum], [Name_addr, Name_val]),
    query_string_pointer(Name_val),
    Name_offset #= Name_addr - Base_addr,
    labeling([enum], [Child_addr, Child_val]),
    query_name_pointer(Child_val, Name_offset),

    get_time(End),
    Time_past is End - Current,

    log("resource", "Start_addr", Start_addr, Base_addr),
    log("resource", "End_addr", End_addr, Base_addr),
    log("resource", "Name_addr", Name_addr, Base_addr),
    log("resource", "Child_addr", Child_addr, Base_addr).

query_inode(Base_addr) :-
    /*
        struct inode_operations *i_op;
        struct super_block      *i_sb;
        struct address_space    *i_mapping;
    */
    get_time(Current),
    pointer(Ptr),
    long(Ulg),
    int(Int),
    /* Type Invariants */
    Ptr_profile = ([
        [I_op_addr, I_op_val],
        [I_sb_addr, I_sb_val],
        [I_mapping_addr, I_mapping_val],
        [I_fop_addr, I_fop_val]
    ]),
    Ulong_profile = ([
        /* i_mode is actually not long type. */
        [I_mode_addr, I_mode_val],
        [I_ino_addr, I_ino_val],
        [I_size_addr, I_size_val],
        [I_atime_addr, I_atime_val],
        [_I_atime_addr, _I_atime_val],
        [I_mtime_addr, I_mtime_val],
        [I_ctime_addr, I_ctime_val],
        [_I_ctime_addr, _I_ctime_val]
    ]),
    Int_profile = ([
        [I_uid_addr, I_uid_val],
        [I_gid_addr, I_gid_val]
    ]),    
    
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Ulong_profile, Ulg),
    tuples_in(Int_profile, Int),

    chain([I_mode_addr, I_uid_addr, I_gid_addr, I_op_addr, I_sb_addr, I_mapping_addr, I_ino_addr,
           I_size_addr, I_atime_addr, _I_atime_addr, I_mtime_addr, I_ctime_addr, _I_ctime_addr, I_fop_addr], #<),

    I_mode_addr #= Base_addr,
    I_mode_val #> 0,
    I_gid_addr #= I_mode_addr + 8,
    %I_op_addr #= Base_addr + 32,
    I_op_val #> 0,
    labeling([enum], [I_op_addr, I_op_val]),
    query_inode_operations(I_op_val),

    I_sb_addr #= I_op_addr + 8,
    I_mapping_addr #= I_sb_addr + 8,
    I_atime_addr #= I_size_addr + 8,
    I_mtime_addr #= I_atime_addr + 16,
    I_ctime_addr #= I_mtime_addr + 16,
    _I_ctime_addr #= I_ctime_addr + 8,
    I_size_val #> 0,
    I_atime_val #> 4096,
    I_mtime_val #> 4096,
    I_ctime_val #> 4096,
    I_fop_addr #< Base_addr + 400,
    labeling([enum], [I_sb_addr, I_mapping_addr, I_atime_addr, I_mtime_addr, I_ctime_addr]),


    labeling([enum], [I_fop_addr, I_fop_val]),
    I_fop_val #> 0,
    query_inode_operations(I_fop_val),

    log("./profile/inode", "I_mode_addr", I_mode_addr, Base_addr),
    log("./profile/inode", "I_uid_addr", I_uid_addr, Base_addr),
    log("./profile/inode", "I_gid_addr", I_gid_addr, Base_addr),
    log("./profile/inode", "I_op_addr", I_op_addr, Base_addr),
    log("./profile/inode", "I_sb_addr", I_sb_addr, Base_addr),
    log("./profile/inode", "I_mapping_addr", I_mapping_addr, Base_addr),
    log("./profile/inode", "I_size_addr", I_size_addr, Base_addr),
    log("./profile/inode", "I_atime_addr", I_atime_addr, Base_addr),
    log("./profile/inode", "I_mtime_addr", I_mtime_addr, Base_addr),
    log("./profile/inode", "I_ctime_addr", I_ctime_addr, Base_addr),
    log("./profile/inode", "I_fop_addr", I_fop_addr, Base_addr).


test(Base_addr) :-
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
    chain([Tasks_addr, MM2_addr, Pid_addr, Tgid_addr, Parent_addr, Real_parent_addr, Child_addr, 
           Group_leader_addr, Thread_group_addr, Cred_addr, Comm_addr, FS_struct_addr], #<),
    MM2_addr #> Base_addr + 1000,
    Tasks_addr #> MM2_addr - 100,
    FS_struct_addr #< Base_addr + 3000,
    Tgid_addr #= Pid_addr + 4,
    Parent_addr #< Tgid_addr + 20,
    Real_parent_addr #= Parent_addr + 8,
    Child_addr #= Real_parent_addr +8,
    Group_leader_addr #=< Child_addr +32,
    %Comm_addr #= Base_addr + 2584,
    %Tasks_addr #= Base_addr + 1904,
    %FS_struct_addr #= Base_addr + 2640,


    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    tuples_in(Int_profile, Int),

    label([MM2_addr, MM2_val]),
    % make query after labeling
    MM2_val #> 0,
    query_mm_struct(MM2_val),
    labeling([enum], [Tasks_addr, Tasks_val,  Comm_addr, Comm_val ]),
    %Tasks_addr #= Base_addr + 2040,
    Comm_offset #= Comm_addr - Base_addr,
    Tasks_offset #= Tasks_addr - Base_addr,
    Tasks_val #> 0,
    query_list_head(Tasks_val, Comm_offset, Tasks_offset),

    


    get_time(End),
    Time_past is End - Current,
    MM_offset #= MM2_addr - Base_addr,
    Real_parent_offset #= Real_parent_addr - Base_addr,
    Group_leader_offset #= Group_leader_addr - Base_addr,
    
    print_nl('tasks offset', Tasks_offset),
    print_nl('mm offset', MM_offset),
    print_nl('comm offset', Comm_offset),
    print_nl('real_parent', Real_parent_offset),
    print_nl('group_leader', Group_leader_offset),
    print_nl("Finished, total time", Time_past).


query_string_pointer(Val) :- 
    process_create(path('python'),
                    ['subquery.py', Val, "string_pointer"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_name_pointer(Val, Name_offset) :-
    process_create(path('python'),
                    ['subquery.py', Val, "name_pointer", Name_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).


query_mount_struct(Val, Offset) :- 
    process_create(path('python'),
                    ['subquery.py', Val, "mount_struct", Offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_vfs_mount(Vfsmount_val) :-
    process_create(path('python'),
                    ['subquery.py', Vfsmount_val, "vfs_mount"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_dentry(Dentry_val) :-
    process_create(path('python'),
                    ['subquery.py', Dentry_val, "dentry"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_kernel_param(KP_val) :-
    process_create(path('python'),
                    ['subquery.py', KP_val, "kernel_param"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_in_device(IP_ptr_val) :-
    process_create(path('python'),
                    ['subquery.py', IP_ptr_val, "in_device"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_inode_operations(Base_addr) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "inode_operations"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_mm_struct(MM2_val) :-
    process_create(path('python'),
                    ['subquery.py', MM2_val, "mm_struct"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_list_head(Tasks_val, Comm_offset, Tasks_offset) :-
    process_create(path('python'),
                    ['subquery.py', Tasks_val, "list_head", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_ts(Base_addr, Comm_offset, Tasks_offset) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "ts", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

query_cred(Base_addr) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "cred"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).
query_fs_struct(Base_addr) :-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "fs_struct"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

print_nl(Name, Content):- 
    print(Name),
    print(':'),
    print(Content),
    nl.
