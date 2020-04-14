% use_module(library(clpfd)).
:- style_check(-singleton).

isTrue([X, Y]):-
    X == 49.

isTrue([X|Tail]):-
    isTrue(Tail).

possible_anything(Base_addr) :- 
    get_time(Current),
    % void *stack 
    ispointer(Base_addr, Stack_offset, Stack_value),
    
    % sched_info sched_info 
    
    /* we need to use sched_info to help locate task */
    ispointer(Base_addr, Sched_info_offset, Sched_info_value),
    Sched_info_offset > Stack_offset,
    % possible_sched_info(Sched_info_value),

    
    ispointer(Base_addr, MM_offset, MM_pointer),
    ispointer(Base_addr, MM_offset2, MM_pointer2),
    MM_offset2 is MM_offset + 8,
    possible_mm_struct(MM_pointer2),

    ispointer(Base_addr, Tasks_offset, Task_value),
    % Tasks_offset > 1888,
    Tasks_offset > Sched_info_offset,
    Tasks_offset > MM_offset2 - 100,


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



    % possible_ts(Child_value, Comm_offset),

    % This did not pass the test
    % task_struct_r(Parent_value),
    get_time(End),
    Time_past is End - Current,
    log('profile.txt', 'new answer', Current),
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

log(File_name, Name, Offset):-
    open(File_name, append, Stream),
    write(Stream, Name),
    write(Stream, ':'),
    write(Stream, Offset),
    nl(Stream),
    close(Stream).

possible_task_struct(Base_addr) :- 
    % void *stack 
    ispointer(Base_addr, Stack_offset, Stack_value),
    
    % sched_info sched_info 
    
    ispointer(Base_addr, Sched_info_offset, Sched_info_value),
    Sched_info_offset > Stack_offset,
    possible_sched_info(Sched_info_value),
    
    % list_head tasks 

    
    ispointer(Base_addr, Tasks_offset, Task_value),
    Tasks_offset > Sched_info_offset,
    possible_list_head(Task_value), 

    isint(Base_addr, Pid_offset, Value),
    isint(Base_addr, Tgid_offset, Value2),
    Tgid_offset is Pid_offset + 4,
    Tgid_offset > Tasks_offset,
    

    ispointer(Base_addr, MM_offset, MM_pointer),
    MM_offset < Tgid_offset,
    
    ispointer(Base_addr, MM_offset2, MM_pointer),
    MM_offset2 is MM_offset + 8,
    possible_mm_struct(MM_pointer),



    /*list_head_next(Task_value, List_head_offset),*/


    /* task_struct *real_parent 
       task_struct *parent
       task_struct *children
    */
    
    ispointer(Base_addr, Parent_offset, Parent_value),
    Parent_offset > Tgid_offset,
    Parent_offset < Tgid_offset + 20,

    ispointer(Base_addr, Parent_offset2, Parent_value2),
    Parent_offset2 is Parent_offset + 8,

    ispointer(Base_addr, Child_offset, Child_value),
    Child_offset is Parent_offset2 + 8,

    isstring(Base_addr, Comm_offset, Comm_value),
    Comm_offset > Child_offset,

    possible_ts(Parent_value, Comm_offset),
    % possible_ts(Parent_value2, Comm_offset),
    % possible_ts(Child_value, Comm_offset),

    % This did not pass the test
    % task_struct_r(Parent_value),

    print_nl('stack', Stack_offset),
    print_nl('task', Tasks_offset),
    print_nl('pid', Pid_offset),
    print_nl('parent', Parent_offset),
    print_nl('comm', Comm_offset),
    print_nl('mm_struct', MM_offset2),
    print('------------------------------------'), nl.


    

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