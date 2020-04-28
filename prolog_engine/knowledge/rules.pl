% use_module(library(clpfd)).
:- style_check(-singleton).

isTrue([X, Y]):-
    X == 49.

isTrue([X|Tail]):-
    isTrue(Tail).

possible_task_struct(Base_addr) :- 
    /* void *stack */
    ispointer(Base_addr, Stack_offset, Stack_value),
    

    /* sched_info sched_info */
    
    ispointer(Base_addr, Sched_info_offset, Sched_info_value),
    Sched_info_offset > Stack_offset,
    possible_sched_info(Sched_info_value),
    

    /* list_head tasks */
    ispointer(Base_addr, Tasks_offset, Task_value),
    Tasks_offset > Sched_info_offset,
    possible_list_head(Task_value), 

    isint(Base_addr, Pid_offset, Value),
    isint(Base_addr, Tgid_offset, Value2),
    Tgid_offset is Pid_offset + 4,
    Tgid_offset > Tasks_offset,

    
    ispointer(Base_addr, MM_offset, MM_pointer),
    MM_offset < Tgid_offset,
    MM_offset > 400,
    
    ispointer(Base_addr, MM_offset2, MM_pointer),
    MM_offset2 is MM_offset + 8,
    possible_mm_struct(MM_pointer),


    /* comm */

    isstring(Base_addr, Comm_offset, Comm_value),
    Comm_offset > MM_offset2,


    /* task_struct *parent */
    ispointer(Base_addr, Parent_offset, Parent_value),
    Parent_offset > Tgid_offset,
    Parent_offset < Tgid_offset + 20,
    print_nl('parent', Parent_offset).
/*
    print_nl("pointer", Parent_value),
    possible_task_struct(Parent_value),
    print_nl('stack', Stack_offset),
    print_nl('task', Tasks_offset),
    print_nl('pid', Pid_offset),
    print_nl('mm_struct', MM_offset2).
*/

    

possible_mm_struct(Current_addr) :- 
    get_time(Current),
    ispointer(Addr1, Value1),
    Addr1 is Current_addr,
    %FIXME Ad check_vm_area_struct
    check_vm_area_struct(Value1),
    ispointer(Addr2, Value2),
    Addr2 is Addr1 + 8,
    ispointer(Addr3, Value3),
    Addr3 is Addr2 + 16,

    islong(Mmap_base_addr, Mmap_base_value),
    Mmap_base_addr > Addr3,
    Mmap_base_addr < Addr3 + 17,
    islong(Task_size_addr, Task_size_value),
    Task_size_addr > Mmap_base_addr,
    Task_size_addr < Mmap_base_addr + 33,

    ispointer(Pgd_addr, Pgd_value),
    Pgd_addr > Task_size_addr,
    Pgd_addr < Task_size_addr + 17,

    
    %    unsigned long start_code, end_code, start_data, end_data;
    %    unsigned long start_brk, brk, start_stack;
    %    unsigned long arg_start, arg_end, env_start, env_end;

    islong(Addr4, Value4),
    Addr4 > Pgd_addr,
    islong(Addr5, Value5),
    Addr5 is Addr4 + 8,
    Value5 > Value4,
    islong(Addr6, Value6),
    Addr6 is Addr5 + 8,
    islong(Addr7, Value7),
    Addr7 is Addr6 + 8,
    Value7 > Value6,
    islong(Addr8, Value8),
    Addr8 is Addr7 + 8,
    islong(Addr9, Value9),
    Addr9 is Addr8 + 8,
    islong(Addr10, Value10),
    Addr10 is Addr9 + 8,

    islong(ARG_start_addr, ARG_start_value),
    ARG_start_addr is Addr10 + 8,
    ARG_start_value > 0x7fffffff0000,
    islong(ARG_end_addr, ARG_end_value),
    ARG_end_addr is ARG_start_addr + 8,
    ARG_end_value > ARG_start_value,
    islong(ENV_start_addr, ENV_start_value),
    ENV_start_addr is ARG_end_addr + 8,
    ENV_start_value > 0x7fffffff0000,
    islong(ENV_end_addr, ENV_end_value),
    ENV_end_addr is ENV_start_addr + 8,
    ENV_end_value > ENV_start_value,

    get_time(End),
    Time_past is End - Current,
    log('profile.txt', 'mm_struct_base', Current_addr),
    log('profile.txt', 'mmap', Addr1),
    log('profile.txt', 'pgd', Pgd_addr),
    log('profile.txt', 'arg_start', ARG_start_addr),
    log('profile.txt', 'start_brk', Addr8),
    log('profile.txt', 'brk', Addr9),
    log('profile.txt', 'start_stack', Addr10),
    log('profile.txt', "mm_struct query time", Time_past).

possible_sched_info(Base_addr) :- 
    islong(Base_addr, Offset1, Value1),
    Offset1 < 10.

% base_addr -> list_head
possible_list_head(Base_addr, Comm_offset, Tasks_offset) :- 
    ispointer(Base_addr, Value1),
    ispointer(Base_addr2, Value2),
    Base_addr2 is Base_addr + 8,
    /* create process to reason about whether Value1 points to another task struct */
    not(Value1 is Base_addr),
    process_create(path('python'),
                    ['subquery.py', Value1, "list_head_ts", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).
    /*list_head_next(Value1, Offset1),*/

possible_list_head_no_order(Base_addr, Comm_offset, Tasks_offset) :- 
    /* print_nl('find list_head', ''), */
    ispointer(Base_addr, Offset1, Value1),
    Offset1 is 0,
    /* create process to reason about whether Value1 points to another task struct */
    not(Value1 is Base_addr),
    Value2 is Value1 - Tasks_offset,
    process_create(path('python'),
                    ['subquery.py', Value2, "list_head_ts2", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).
    /*list_head_next(Value1, Offset1),*/

possible_list_head_tg(Base_addr, Comm_offset, Tasks_offset) :- 
    /* print_nl('find list_head', ''), */
    ispointer(Base_addr, Offset1, Value1),
    Offset1 is 0,
    ispointer(Base_addr, Offset2, Value2),
    Offset2 is Offset1 + 8,
    /* create process to reason about whether Value1 points to another task struct */
    process_create(path('python'),
                    ['subquery.py', Value1, "list_head_ts", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

list_head_next(Base_addr, List_head_offset, Comm_offset) :- 
    /* the knowled  ge base does not have task struct that contains value1 */

    /* get the *next list head pointer in value1 */
    ispointer(Base_addr, Offset1, Value1),
    Offset1 is 0,
    ispointer(Base_addr, Offset2, Value2),
    Offset2 is Offset1 + 8,
    /* *next should be a pointer in another task structure at the same list head offset */
    ispointer(Task_struct_addr, List_head_offset, Value1),
    print_nl('task struct', Task_struct_addr),
    /* a simple rule to make sure task_struct_addr is a task structure by checking whether comm_offset is a string */
    isstring(Task_struct_addr, Comm_offset, String),
    print_nl("next one", 'is list head').

possible_fs_struct(Base_addr) :- 
    /* 3 integers */
    get_time(Current),
    log("profile.txt", "start", "fs_struct"),
    isint(Base_addr, Value1),
    isint(Addr2, Value2),
    Addr2 > Base_addr,
    Addr2 < Base_addr + 10,
    isint(Addr3, Value3),
    Addr3 > Addr2,
    Addr3 < Addr2 + 10,

    ispointer(Root_addr, Root_value),
    Root_addr > Addr3,

    process_create(path('python'),
                    ['subquery.py', Root_value, "dentry"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),

    ispointer(PWD_addr, PWD_value),
    PWD_addr > Root_addr,
    PWD_addr is Root_addr + 16,

    process_create(path('python'),
                    ['subquery.py', PWD_value, "dentry"],
                    [stdout(pipe(NewIn))]),
    read_string(NewIn, Len, X),
    string_codes(X, Result),
    close(NewIn),
    isTrue(Result),
    get_time(End),
    Time_past is End - Current,
    log("profile.txt", "fs_struct_base", Base_addr),
    log("profile.txt", "offset3", Addr3),
    log("profile.txt", "Root_offset", Root_addr),
    log("profile.txt", "PWD_offset", PWD_addr),
    log("profile.txt", "fs_struct query time", Time_past).

possible_dentry(Base_addr) :- 
    get_time(Current),
    ispointer(D_parent_addr, D_parent_value),
    D_parent_addr > Base_addr,
    isstring(D_iname_addr, D_iname_value),
    D_iname_addr < Base_addr + 200,
    D_parent_addr < D_iname_addr,
    D_iname_offset is D_iname_addr - Base_addr,
    D_iname_offset > 0,
    process_create(path('python'),
                ['subquery.py', D_parent_value, "d_entry", D_iname_offset],
                [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),

    ispointer(D_child_addr, D_child_value),
    D_child_addr > D_parent_addr,
    D_child_addr < Base_addr + 200,

    D_child_offset is D_child_addr - Base_addr,
    D_child_base is D_child_value - D_child_offset,
    %not(D_child_base is Base_addr),
    D_child_base > 0,
    process_create(path('python'),
                ['subquery.py', D_child_base, "d_entry", D_iname_offset],
                [stdout(pipe(NewIn))]),
    read_string(NewIn, Len, X),
    string_codes(X, Result),
    close(NewIn),
    isTrue(Result),
    get_time(End),
    Time_past is End - Current,
    log("profile.txt", "dentry_base", Base_addr),
    log("profile.txt", "d_iname", D_iname_offset),
    log("profile.txt", "d_parent", D_parent_addr),
    log("profile.txt", "d_child", D_child_addr),
    log("profile.txt", "dentry query time", Time_past).


possible_d_entry(Base_addr, D_iname_offset) :-
    D_iname_addr is Base_addr + D_iname_offset,
    isstring(D_iname_addr, D_iname_value).
    

possible_module(Base_addr, Name_offset, Init_offset) :- 
    isstring(Base_addr, Name_offset, Name_value).
    /*unknownpointer(Base_addr, Init_offset, Init_value).*/

possible_tlbflush_unmap_batch(Base_addr):- 
    ispointer(Base_addr, Offset, Value).

possible_ts(Base_addr, Comm_offset, Tasks_offset):-
    Comm_addr is Base_addr + Comm_offset,
    isstring(Comm_addr, Comm_value),
    Tasks_addr is Base_addr + Tasks_offset,
    ispointer(Tasks_addr, Tasks_value),
    process_create(path('python'),
                    ['subquery.py', Tasks_value, "list_head", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_ts_no_order(Base_addr, Comm_offset, Tasks_offset):-
    isstring(Base_addr, Comm_offset, Comm_value),
    ispointer(Base_addr, Tasks_offset, Tasks_value),
    process_create(path('python'),
                    ['subquery.py', Tasks_value, "list_head_no_order", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_group_leader(Base_addr, Comm_offset, Tasks_offset):-
    isstring(Base_addr, Comm_offset, Comm_value),
    ispointer(Base_addr, Tasks_offset, Tasks_value),
    process_create(path('python'),
                    ['subquery.py', Tasks_value, "list_head_gl", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_thread_group(Base_addr, Comm_offset, Tasks_offset):-
    ispointer(Base_addr, Value1),
    ispointer(Base_addr2, Value2),
    Base_addr2 is Base_addr + 8,

    /* create process to reason about whether Value1 points to another task struct */
    process_create(path('python'),
                    ['subquery.py', Value1, "list_head_ts", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_thread_group_no_order(Base_addr, Comm_offset, Tasks_offset):-
     /* print_nl('find list_head', ''), */
    ispointer(Base_addr, Offset1, Value1),
    Offset1 is 0,
    Value2 is Value1 - Tasks_offset,
    /* create process to reason about whether Value1 points to another task struct */
    process_create(path('python'),
                    ['subquery.py', Value2, "list_head_ts2", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).


possible_cred(Base_addr):-
    isint(Addr1, Value1),
    Addr1 is Base_addr + 4,
    isint(Addr2, Value2),
    Addr2 is Addr1 + 4,
    isint(Addr3, Value3),
    Addr3 is Addr2 + 4,
    isint(Addr4, Value4),
    Addr4 is Addr3 + 4,
    isint(Addr5, Value5),
    Addr5 is Addr4 + 4,
    isint(Addr6, Value6),
    Addr6 is Addr5 + 4,
    isint(Addr7, Value7),
    Addr7 is Addr6 + 4,
    isint(Addr8, Value8),
    Addr8 is Addr7 + 4,
    isint(Addr9, Value9),
    Addr9 is Addr8 + 4,

    islong(Addr10, Value10),
    Addr10 > Addr9,
    Addr10 < Addr9 + 17,
    islong(Addr11, Value11),
    Addr11 is Addr10 + 8,

    log('profile.txt', 'cred', Base_addr),
    log('profile.txt', 'uid', Addr1),
    log('profile.txt', 'gid', Addr2),
    log('profile.txt', 'euid', Addr5),
    log('profile.txt', 'egid', Addr6),
    log('profile.txt', 'cred_end', Base_addr).


possible_vm_area_struct(Base_addr):-
    get_time(Current),
    islong(VM_start_addr, VM_start_value),
    VM_start_addr > Base_addr - 1,
    VM_start_addr < Base_addr + 20,
    islong(VM_end_addr, VM_end_value),
    VM_end_addr is VM_start_addr + 8,
    ispointer(VM_next_addr, VM_next_value),
    VM_next_addr is VM_end_addr + 8,

    ispointer(VM_file_addr, VM_file_value),
    VM_file_addr > VM_next_addr,
    process_create(path('python'),
                    ['subquery.py', VM_file_value, "vm_file"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),
    get_time(End),
    Time_past is End - Current,
    
    log('profile.txt', 'vm_area_struct_base', Base_addr),
    log('profile.txt', 'vm_start', VM_start_addr),
    log('profile.txt', 'vm_end', VM_end_addr),
    log('profile.txt', 'vm_next', VM_next_addr),
    log('profile.txt', 'vm_file', VM_file_addr),
    log('profile.txt', 'vm_area_struct_end', Base_addr),
    log('profile.txt', 'vm_area_struct query time', Time_past).


    /* leave this recursive query for now */
    /* check_vm_area_struct(VM_next_value),*/

/*    ispointer(Base_addr, VM_mm_offset, VM_mm_value),
    VM_mm_offset > VM_next_offset,


    islong(Base_addr, VM_flag_offset, VM_flag_value),
    VM_flag_offset > VM_mm_offset,
    VM_flag_offset < 200,*/

    /*ispointer(Base_addr, Anon_vma_offset, Anon_vma_value),
    Anon_vma_offset > VM_flag_offset,
    ispointer(Base_addr, VM_ops_offset, VM_ops_value),
    VM_ops_offset is Anon_vma_offset + 8,*/

/*    isint(Base_addr, VM_pgoff_offset1, VM_pgoff_value1),
    VM_pgoff_offset1 > VM_flag_offset,
    isint(Base_addr, VM_pgoff_offset2, VM_pgoff_value2),
    VM_pgoff_offset2 is VM_pgoff_offset1 + 4,*/

    /*islong(Base_addr, VM_pgoff_offset1, VM_pgoff_value1),
    VM_pgoff_offset1 > VM_flag_offset,*/

    /*ispointer(Base_addr, VM_file_offset, VM_file_value),
    VM_file_offset is VM_pgoff_offset1 + 8,
    VM_file_offset < 200,*/

possible_vm_file(Base_addr) :-
    ispointer(Dentry_addr, Dentry_value),
    Dentry_addr > Base_addr,
    Dentry_addr < Base_addr + 40,
    process_create(path('python'),
                    ['subquery.py', Dentry_value, "dentry"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

check_vm_area_struct(Base_addr) :- 
    process_create(path('python'),
                    ['subquery.py', Base_addr, "vm_area_struct"],
                    [stdout(pipe(In))]),
    print(In),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_list_head_ts(Base_addr, Comm_offset, Tasks_offset) :- 
    New_offset is Comm_offset - Tasks_offset,
    Comm_addr is Base_addr + New_offset,
    isstring(Comm_addr, Comm_value).

possible_list_head_ts2(Base_addr, Comm_offset, Tasks_offset) :- 
    isstring(Base_addr, Comm_offset, Comm_value),
    not(Comm_value is 3418906600723806067).



log(File_name, Name, Offset):-
    open(File_name, append, Stream),
    write(Stream, Name),
    write(Stream, ':'),
    write(Stream, Offset),
    nl(Stream),
    close(Stream).

print_nl(Name, Content) :- 
    print(Name),
    print(':'),
    print(Content),
    nl.