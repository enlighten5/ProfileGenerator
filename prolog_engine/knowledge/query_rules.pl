isTrue([X, _]):-
    X == 49.

isTrue([_|Tail]):-
    isTrue(Tail).

query_task_struct(Base_addr) :-
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
    query_mm_struct(MM2_val),
    label([Tasks_addr, Tasks_val,  Comm_addr, Comm_val ]),

    Comm_offset #= Comm_addr - Base_addr,
    Tasks_offset #= Tasks_addr - Base_addr,
    query_list_head(Tasks_val, Comm_offset, Tasks_offset),

    label([Real_parent_addr, Real_parent_val, Group_leader_addr, Group_leader_val]),
    query_ts(Real_parent_val, Comm_offset, Tasks_offset),
    query_ts(Group_leader_val, Comm_offset, Tasks_offset),

    label([Cred_addr, Cred_val]),
    query_cred(Cred_val),

    label([FS_struct_addr, FS_struct_val]),
    query_fs_struct(FS_struct_val),
    


    get_time(End),
    Time_past is End - Current,
    MM_offset #= MM2_addr - Base_addr,
    Real_parent_offset #= Real_parent_addr - Base_addr,
    Group_leader_offset #= Group_leader_addr - Base_addr,
    /*
    print_nl('tasks offset', Tasks_offset),
    print_nl('comm offset', Comm_offset),
    print_nl('real_parent', Real_parent_offset),
    print_nl('group_leader', Group_leader_offset),*/
    print_nl("Finished, total time", Time_past).


test(Base_addr, Ptr) :-
    MM_structs = [[MM_addr, _MM_value],
                  [MM2_addr, MM2_value]],
    MM2_addr #= MM_addr + 8,
    MM2_value #\= 0,
    MM2_addr #> Base_addr + 1000,
    MM2_addr #< Base_addr + 2000,
    tuples_in(MM_structs, Ptr),
    label([MM2_addr, MM2_value]),
    
    print(MM2_addr).


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
