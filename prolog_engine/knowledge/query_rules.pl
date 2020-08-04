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
    current_predicate(string_val/1),
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
    labeling([enum], [Tasks_addr, Tasks_val,  Comm_addr, Comm_val, Pid_addr, Tgid_addr ]),

    Comm_offset #= Comm_addr - Base_addr,
    Tasks_offset #= Tasks_addr - Base_addr,
    Tasks_val #> 0,
    query_list_head(Tasks_val, Comm_offset, Tasks_offset),

    labeling([enum], [Real_parent_addr, Real_parent_val, Group_leader_addr, Group_leader_val]),
    Real_parent_val #> 0,
    Group_leader_val #> 0,
    query_ts(Real_parent_val, Comm_offset, Tasks_offset),
    query_ts(Group_leader_val, Comm_offset, Tasks_offset),

    labeling([enum], [Real_cred_addr, Real_cred_val, Cred_addr, Cred_val]),
    Cred_val #> 0,
    query_cred(Real_cred_val),
    query_cred(Cred_val),
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
    log("profile.txt", "mm_struct", MM2_addr, Base_addr),
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
