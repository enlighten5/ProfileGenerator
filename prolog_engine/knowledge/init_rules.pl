% use_module(library(clpfd)).
:- style_check(-singleton).


isTrue([X, Y]):-
    X == 49.

isTrue([X|Tail]):-
    isTrue(Tail).

possible_anything(Base_addr) :- 
    get_time(Current),
    % void *stack 
    %ispointer(Base_addr, Stack_offset, Stack_value),
    
    % sched_info sched_info 
    
    /* we need to use sched_info to help locate task */
    %ispointer(Base_addr, Sched_info_offset, Sched_info_value),
    %Sched_info_offset > Stack_offset,
    % possible_sched_info(Sched_info_value),

    
    ispointer(Base_addr, MM_offset, MM_pointer),
    ispointer(Base_addr, MM_offset2, MM_pointer2),
    MM_offset2 is MM_offset + 8,
    possible_mm_struct(MM_pointer2),

    ispointer(Base_addr, Tasks_offset, Task_value),
    % Tasks_offset > 1888,
    %Tasks_offset > Sched_info_offset,
    Tasks_offset > MM_offset2 - 100,
    Tasks_offset < MM_offset,


    isint(Base_addr, Pid_offset, Value),
    Pid_offset > MM_offset2,
    isint(Base_addr, Tgid_offset, Value2),
    Tgid_offset is Pid_offset + 4,
    Tgid_offset > Tasks_offset,

    ispointer(Base_addr, Parent_offset, Parent_value),
    Parent_offset > Tgid_offset,
    Parent_offset < Tgid_offset + 20,

    ispointer(Base_addr, Parent_offset2, Parent_value2),
    Parent_offset2 is Parent_offset + 8,

    ispointer(Base_addr, Child_offset, Child_value),
    Child_offset is Parent_offset2 + 8,

    /* task_struct *group_leader */

    ispointer(Base_addr, Group_leader_offset, Group_leader_value),
    Group_leader_offset > Child_offset,
    Group_leader_offset < Child_offset + 33,


    isstring(Base_addr, Comm_offset, Comm_value),
    Comm_offset > Child_offset,

    possible_ts(Parent_value, Comm_offset, Tasks_offset),
    possible_list_head(Task_value, Comm_offset, Tasks_offset),
    possible_ts(Parent_value2, Comm_offset, Tasks_offset),
    possible_ts(Group_leader_value, Comm_offset, Tasks_offset),


    ispointer(Base_addr, Thread_group_offset, Thread_group_value),
    Thread_group_offset > Group_leader_offset,

    /* This rule is very ad hoc */

    Thread_group_offset < Group_leader_offset + 150,
    possible_thread_group(Thread_group_value, Comm_offset, Thread_group_offset),

    ispointer(Base_addr, Cred_offset1, Cred_value1),
    Cred_offset1 > Group_leader_offset,
    Cred_offset1 < Comm_offset,
    ispointer(Base_addr, Cred_offset2, Cred_value2),
    Cred_offset2 is Cred_offset1 + 8,
    Cred_offset2 < Comm_offset,
    possible_cred(Cred_value1),

    ispointer(Base_addr, FS_struct_offset, FS_struct_value),
    FS_struct_offset > Comm_offset,
    FS_struct_offset < 3000,
    possible_fs_struct(FS_struct_value),

    get_time(End),
    Time_past is End - Current,
    log('profile.txt', 'task_struct', Current),
    /*log('profile.txt', 'stack', Stack_offset),
    log('profile.txt', 'Sched_info_offset', Sched_info_offset),*/
    log('profile.txt', 'task', Tasks_offset),
    log('profile.txt', 'mm_struct', MM_offset2),
    log('profile.txt', 'pid', Pid_offset),
    log('profile.txt', 'parent', Parent_offset),
    log('profile.txt', 'group_leader', Group_leader_offset),
    log('profile.txt', 'thread_group', Thread_group_offset),
    log('profile.txt', 'cred', Cred_offset1),
    log('profile.txt', 'comm', Comm_offset),
    log('profile.txt', 'fs', FS_struct_offset),
    log('profile.txt', 'end', Time_past),
    
    /*print_nl('stack', Stack_offset),
    print_nl('Sched_info_offset', Sched_info_offset),*/
    print_nl('task', Tasks_offset),
    print_nl('mm_struct', MM_offset2),
    print_nl('pid', Pid_offset),
    print_nl('parent', Parent_offset),
    print_nl('group_leader', Group_leader_offset),
    print_nl('thread_group', Thread_group_offset),
    print_nl('cred', Cred_offset1),
    print_nl('comm', Comm_offset),
    print('----------------------------'), nl.

possible_anything_no_order(Base_addr) :- 
    get_time(Current),

    % ispointer(Base_addr, MM_offset2, MM_pointer2),
    % possible_mm_struct(MM_pointer2),

    ispointer(Base_addr, Tasks_offset, Task_value),


    /*ispointer(Base_addr, Parent_offset, Parent_value),

    ispointer(Base_addr, Parent_offset2, Parent_value2),

    ispointer(Base_addr, Child_offset, Child_value),*/

    /* task_struct *group_leader */

    ispointer(Base_addr, Group_leader_offset, Group_leader_value),

    isstring(Base_addr, Comm_offset, Comm_value),

    possible_list_head_no_order(Task_value, Comm_offset, Tasks_offset),

/*
    possible_ts_no_order(Parent_value, Comm_offset, Tasks_offset),
    possible_list_head_no_order(Task_value, Comm_offset, Tasks_offset),
    possible_ts_no_order(Parent_value2, Comm_offset, Tasks_offset),
    possible_ts_no_order(Group_leader_value, Comm_offset, Tasks_offset),

    ispointer(Base_addr, Thread_group_offset, Thread_group_value),

    possible_thread_group_no_order(Thread_group_value, Comm_offset, Thread_group_offset),
*/
    % ispointer(Base_addr, Cred_offset1, Cred_value1),
    % possible_cred(Cred_value1),

 
    get_time(End),
    Time_past is End - Current,
    log('profile.txt', 'new answer', Current),
    log('profile.txt', 'task', Tasks_offset),
    log('profile.txt', 'mm_struct', MM_offset2),
    log('profile.txt', 'parent', Parent_offset),
    log('profile.txt', 'group_leader', Group_leader_offset),
    log('profile.txt', 'thread_group', Thread_group_offset),
    log('profile.txt', 'cred', Cred_offset1),
    log('profile.txt', 'comm', Comm_offset),
    log('profile.txt', 'end', Time_past),

    print_nl('stack', Stack_offset),
    print_nl('Sched_info_offset', Sched_info_offset),
    print_nl('task', Tasks_offset),
    print_nl('mm_struct', MM_offset2),
    print_nl('pid', Pid_offset),
    print_nl('parent', Parent_offset),
    print_nl('group_leader', Group_leader_offset),
    print_nl('thread_group', Thread_group_offset),
    print_nl('cred', Cred_offset1),
    print_nl('comm', Comm_offset),
    print('----------------------------'), nl.

possible_module(Base_addr) :- 
    ispointer(Base_addr, List_offset, List_value),
    isstring(Base_addr, M_name_offset, M_name_value),
    M_name_offset > List_offset,
    unknownpointer(Base_addr, Init_offset, Init_value),
    Init_offset > M_name_offset,
    Init_offset < 800,
    List_base is List_value - List_offset,
    List_base > 0,
    process_create(path('python'),
                    ['subquery.py', List_base, "module", M_name_offset, Init_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result),

    log("profile.txt", "-----", "module"),
    log("profile.txt", "list", List_offset),
    log("profile.txt", "name", M_name_offset),
    log("profile.txt", "init", Init_offset).

log(File_name, Name, Offset):-
    open(File_name, append, Stream),
    write(Stream, Name),
    write(Stream, ':'),
    write(Stream, Offset),
    nl(Stream),
    close(Stream).
% 
possible_task_struct(Current_addr) :- 
    get_time(Current),
    pagebase(Base_addr),

    ispointer(MM_addr, MM_pointer),
    MM_addr > Current_addr,
    ispointer(MM2_addr, MM2_pointer),
    MM2_addr is MM_addr + 8,
    possible_mm_struct(MM2_pointer),
    %1992

    ispointer(Tasks_addr, Tasks_value),
    Tasks_addr > MM2_addr - 100,
    Tasks_addr < MM_addr,
%1904
    isint(Pid_addr, Pid_value),%2160
    Pid_addr > MM2_addr,
    isint(Tgid_addr, Tgid_value),
    Tgid_addr is Pid_addr + 4,
%2176
    ispointer(Parent_addr, Parent_value),
    Parent_addr > Tgid_addr,
    Parent_addr < Tgid_addr + 20,

    ispointer(Parent2_addr, Parent2_value),
    Parent2_addr is Parent_addr + 8,

    ispointer(Child_addr, Child_value),
    Child_addr is Parent2_addr + 8,

    % task_struct group_leader
    ispointer(Group_leader_addr, Group_leader_value),
    Group_leader_addr > Child_addr,
    Group_leader_addr < Child_addr + 33,


    isstring(Comm_addr, Comm_value),
    Comm_addr > Child_addr,
    Comm_offset is Comm_addr - Current_addr,
    Tasks_offset is Tasks_addr - Current_addr,

    possible_ts(Parent_value, Comm_offset, Tasks_offset),
    possible_list_head(Tasks_value, Comm_offset, Tasks_offset),
    possible_ts(Parent2_value, Comm_offset, Tasks_offset),
    possible_ts(Group_leader_value, Comm_offset, Tasks_offset),


    ispointer(Thread_group_addr, Thread_group_value),
    Thread_group_addr > Group_leader_addr,
    % This rule is very ad hoc 
    Thread_group_addr < Group_leader_addr + 150,
    Thread_group_offset is Thread_group_addr - Current_addr,
    possible_thread_group(Thread_group_value, Comm_offset, Thread_group_offset),
    get_time(End),
    Time_past is End - Current,
    log('profile.txt', 'finish thread_group', Time_past),

    ispointer(Cred_addr, Cred_value),
    Cred_addr > Group_leader_addr,
    Cred_addr < Comm_addr,
    ispointer(Cred_addr2, Cred_value2),
    Cred_addr2 is Cred_addr + 8,
    possible_cred(Cred_value),

    ispointer(FS_struct_addr, FS_struct_value),
    FS_struct_addr > Comm_addr,
    FS_struct_addr is Current_addr + 2640,
    possible_fs_struct(FS_struct_value),

    get_time(End),
    Time_past is End - Current,
    log('profile.txt', 'task_struct', Current),
    log('profile.txt', 'task', Tasks_addr),
    log('profile.txt', 'mm_struct', MM2_addr),
    log('profile.txt', 'pid', Pid_addr),
    log('profile.txt', 'real_parent', Parent_addr),
    log('profile.txt', 'group_leader', Group_leader_addr),
    log('profile.txt', 'thread_group', Thread_group_addr),
    log('profile.txt', 'cred', Cred_addr),
    log('profile.txt', 'comm', Comm_addr),
    log('profile.txt', 'fs', FS_struct_addr),
    log('profile.txt', 'end', Time_past),

    print_nl('task', Tasks_addr),
    print_nl('mm_struct', MM2_addr),
    print_nl('pid', Pid_addr),
    print_nl('parent', Parent_addr),
    print_nl('group_leader', Group_leader_addr),
    print_nl('thread_group', Thread_group_addr),
    print_nl('cred', Cred_addr),
    print_nl('comm', Comm_addr),
    print('----------------------------'), nl.


test(Current_addr) :-
    get_time(Current),
    statistics(real_time, [Start|_]),
    
    isstring(Comm_addr, Comm_value),
    Comm_addr is Current_addr + 2584,
    ispointer(Tasks_addr, Tasks_value),
    Tasks_addr > Current_addr + 1900,
    Tasks_addr < Current_addr + 2048,
    get_time(End),
    Time_past is End - Current,
    print_nl('before ts', Time_past),
    print_nl('Tasks_addr', Tasks_addr),
    Comm_offset is Comm_addr - Current_addr,
    Tasks_offset is Tasks_addr - Current_addr,
    possible_list_head(Tasks_value, Comm_offset, Tasks_offset),
    possible_list_head(Tasks_value, Comm_offset, Tasks_offset),
    
    statistics(real_time, [Ended|_]),
    statistics(atoms, [Ato|_]),
    print_nl("atom", Ato),

    Time is Ended - Start,
    print_nl("start", Start),
    print_nl('Ended', Ended),
    print_nl('finish one ts', Time),
    false.


    

possible_mm_struct(Base_addr) :- 
    process_create(path('python'),
                    ['subquery.py', Base_addr, "mm_struct"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).


possible_sched_info(Base_addr) :- 
    process_create(path('python'),
                    ['subquery.py', Base_addr, "sched_info"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_list_head(Base_addr, Comm_offset, Tasks_offset) :- 
    process_create(path('python'),
                    ['subquery.py', Base_addr, "list_head", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_list_head_no_order(Base_addr, Comm_offset, Tasks_offset) :- 
    process_create(path('python'),
                    ['subquery.py', Base_addr, "list_head_no_order", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

task_struct_r(Base_addr):-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "task_struct"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    isTrue(Result),
    write(X), nl.

list_head_next(Base_addr, List_head_offset) :- 
    Task_addr is Base_addr - List_head_offset,
    task_struct_r(Task_addr).


possible_fs_struct(Base_addr) :- 
    process_create(path('python'),
                    ['subquery.py', Base_addr, "fs_struct"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_tlbflush_unmap_batch(Base_addr):- 
    process_create(path('python'),
                    ['subquery.py', Base_addr, "tlbflush_unmap_batch"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_ts(Base_addr, Comm_offset, Tasks_offset):-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "ts", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_ts_no_order(Base_addr, Comm_offset, Tasks_offset):-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "ts_no_order", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_group_leader(Base_addr, Comm_offset, Tasks_offset):-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "group_leader", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_thread_group(Base_addr, Comm_offset, Tasks_offset):-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "thread_group", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_thread_group_no_order(Base_addr, Comm_offset, Tasks_offset):-
    process_create(path('python'),
                    ['subquery.py', Base_addr, "thread_group_no_order", Comm_offset, Tasks_offset],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    close(In),
    isTrue(Result).

possible_cred(Base_addr) :- 
    process_create(path('python'),
                    ['subquery.py', Base_addr, "cred"],
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
