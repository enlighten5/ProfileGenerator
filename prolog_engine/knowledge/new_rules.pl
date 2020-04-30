:- use_module(library(clpfd)).
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
    Mmap_addr #>= Current_addr,


    Mmap_base_addr #> Mmap_addr,
    Mmap_base_val #\= 0,
    chain([Mmap_base_addr, Mmap_legacy_base_addr, Task_size_addr, High_vm_end_addr], #<),
    High_vm_end_addr #= Mmap_base_addr + 24, 
    Pgd_addr #> Task_size_addr,
    Pgd_addr #=< Task_size_addr + 40,
    %FIXME: This rule may not be true for other mm_struct.
    Task_size_val #>= 0x7ffffffff000,
    
    Start_brk_addr #> Pgd_addr,
    Start_stack_val #> 0x7fffffff0000,
    % TODO: Convert this to index comparison. 
    ARG_start_addr #< Current_addr + 500,
    chain([Start_brk_addr, Brk_addr, Start_stack_addr, ARG_start_addr], #<),
    ARG_start_addr #= Start_brk_addr + 24,
    Brk_val #< 0x7fffffff0000,
    ARG_start_val #> 0x7fffffff0000,
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Ulong_profile, Ulg),


    label([Mmap_addr, Mmap_val, Mmap_base_addr, Pgd_addr, Start_brk_addr, Brk_addr, Start_stack_addr, ARG_start_addr]),
    integer(Mmap_val),
    
    process_create(path('python'),
                    ['subquery.py', Mmap_val, "vm_area_struct"],
                    [stdout(pipe(In))]),
    print(In),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),

    statistics(real_time, [End|_]),

    log("profile.txt", "mmap", Mmap_addr, Current_addr),
    log("profile.txt", "mmap_base", Mmap_base_addr, Current_addr),
    log("profile.txt", "pgd", Pgd_addr, Current_addr),
    log("profile.txt", "start_brk", Start_brk_addr, Current_addr),
    log("profile.txt", "brk", Brk_addr, Current_addr),
    log("profile.txt", "start_stack", Start_stack_addr, Current_addr),
    log("profile.txt", "arg_start", ARG_start_addr, Current_addr),
    log("profile.txt", "mm_struct time", End, Start).


possible_vm_area_struct(Base_addr) :-
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
    VM_file_addr #< Base_addr + 180,

    %VM_file_addr #= Base_addr + 160,

    tuples_in(Ptr_profile, Ptr),
    tuples_in(Ulong_profile, Ulg),
    %FIXME: VM_flag may need value constraints.
    label([VM_start_addr, VM_end_addr, VM_next_addr, VM_flag_addr, VM_file_addr, VM_file_val]),
    VM_pgoff_addr #= VM_file_addr - 8,
    
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
    log("profile.txt", "vm_file", VM_file_addr, Base_addr),
    log("profile.txt", "vm_area_struct time", End, Start).

possible_vm_file(Base_addr) :-
    pointer(Ptr),
    long(Ulg),
    Ptr_profile = [
        [Dentry_addr, Dentry_val]
    ],
    Dentry_addr #> Base_addr,
    Dentry_addr #< Base_addr + 40,
    %Dentry_addr #= Base_addr + 24,
    tuples_in(Ptr_profile, Ptr),
    label([Dentry_val]),
    
    process_create(path('python'),
                    ['subquery.py', Dentry_val, "dentry"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_dentry(Base_addr) :-
    statistics(real_time, [Start|_]),
    pointer(Ptr),
    string_val(Str),
    Ptr_profile = [
        [Dparent_addr, Dparent_val],
        [Dchild_addr, Dchild_val]
    ],
    Str_profile = [
        [Dname_addr, Dname_val]
    ],
    %log("profile.txt", "dentry addr", Base_addr, 0),
    Dparent_addr #> Base_addr,
    chain([Dparent_addr, Dname_addr, Dchild_addr], #<),
    Dchild_addr #< Base_addr + 200,
    tuples_in(Ptr_profile, Ptr),
    tuples_in(Str_profile, Str),
    label([Dparent_addr, Dparent_val, Dname_addr, Dchild_addr, Dchild_val]),
    Dname_offset #= Dname_addr - Base_addr,
    integer(Dname_offset),
    process_create(path('python'),
                ['subquery.py', Dparent_val, "d_entry", Dname_offset],
                [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),

    %FIXME: may need to find another way for all list_head. 
    Dchild_offset #= Dchild_addr - Base_addr,
    integer(Dchild_offset),
    Dchild_base #= Dchild_val - Dchild_offset,
    integer(Dchild_base),
    process_create(path('python'),
                ['subquery.py', Dchild_base, "d_entry", Dname_offset],
                [stdout(pipe(NewIn))]),
    read_string(NewIn, Len, X),
    string_codes(X, Result),
    close(NewIn),
    isTrue(Result),

    statistics(real_time, [End|_]),
    log("profile.txt", "d_iname", Dname_addr, Base_addr),
    log("profile.txt", "d_parent", Dparent_addr, Base_addr),
    log("profile.txt", "d_child", Dchild_addr, Base_addr),
    log("profile.txt", "dentry time", End, Start).

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
    Str_profile = [
        [Comm_addr, Comm_val]
    ],
    Comm_addr #= Tasks_val - Tasks_offset + Comm_offset,
    tuples_in(Str_profile, Str),
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
    Ulong_profile = [
        [Addr10, Val10],
        [Addr11, Val11]
    ],
    Addr1 #> Base_addr,
    chain([Addr1, Addr2, Addr3, Addr4, Addr5, Addr6, Addr7, Addr8, Addr9, Addr10, Addr11], #<),
    Addr9 #= Addr1 + 32,
    Addr11 #< Base_addr + 120,
    tuples_in(Int_profile, Int),
    tuples_in(Ulong_profile, Ulg),
    label([Addr1, Addr2, Addr5, Addr6]),
    log('profile.txt', "uid", Addr1, Base_addr),
    log('profile.txt', "gid", Addr2, Base_addr),
    log('profile.txt', "euid", Addr5, Base_addr),
    log('profile.txt', "egid", Addr6, Base_addr).

possible_fs_struct(Base_addr) :-
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
    label([Root_addr, Root_val]),
    
    process_create(path('python'),
                    ['subquery.py', Root_val, "dentry"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),

    label([PWD_addr, PWD_val]),
/*    process_create(path('python'),
                    ['subquery.py', PWD_val, "dentry"],
                    [stdout(pipe(NewIn))]),
    read_string(NewIn, Len, X),
    string_codes(X, Result),
    close(NewIn),
    isTrue(Result),
*/
    log('profile.txt', "Root", Root_addr, Base_addr),
    log('profile.txt', "pwd", PWD_addr, Base_addr).
