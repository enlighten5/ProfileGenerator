% use_module(library(clpfd)).
:- style_check(-singleton).

isTrue([E|ES]) :- 
    E == 49.

possible_anything(Base_addr) :- 
    % void *stack 
    ispointer(Base_addr, Stack_offset, Stack_value),
    
    % sched_info sched_info 
    
    /* we need to use sched_info to help locate task */
    ispointer(Base_addr, Sched_info_offset, Sched_info_value),
    Sched_info_offset > Stack_offset,
    possible_sched_info(Sched_info_value),

    
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

    isstring(Base_addr, Comm_offset, Comm_value),
    Comm_offset > Child_offset,

    possible_ts(Parent_value, Comm_offset, Tasks_offset),
    possible_list_head(Task_value, Comm_offset, Tasks_offset),
    possible_ts(Parent_value2, Comm_offset, Tasks_offset),


    % possible_ts(Child_value, Comm_offset),

    % This did not pass the test
    % task_struct_r(Parent_value),

    print_nl('parent', Parent_offset),
    print_nl('stack', Stack_offset),
    print_nl('Sched_info_offset', Sched_info_offset),
    print_nl('task', Tasks_offset),
    print_nl('pid', Pid_offset),
    print_nl('comm', Comm_offset),
    print_nl('mm_struct', MM_offset2).


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

    print_nl('parent', Parent_offset),
    print_nl('stack', Stack_offset),
    print_nl('task', Tasks_offset),
    print_nl('pid', Pid_offset),
    print_nl('comm', Comm_offset),
    print_nl('mm_struct', MM_offset2).


    

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

print_nl(Name, Content) :- 
    print(Name),
    print(':'),
    print(Content),
    nl.