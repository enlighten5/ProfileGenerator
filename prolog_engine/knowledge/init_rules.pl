% use_module(library(clpfd)).
:- style_check(-singleton).

isTrue([E|ES]) :- 
    E == 49.

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
    MM_offset > 400,
    
    ispointer(Base_addr, MM_offset2, MM_pointer),
    MM_offset2 is MM_offset + 8,
    possible_mm_struct(MM_pointer),


    /* comm */
/*
    isstring(Base_addr, Comm_offset, Comm_value),
    Comm_offset > MM_offset2,*/

    /*list_head_next(Task_value, List_head_offset),*/


    /* task_struct *parent */
    
    ispointer(Base_addr, Parent_offset, Parent_value),
    Parent_offset > Tgid_offset,
    Parent_offset < Tgid_offset + 20,
    % This did not pass the test
    % task_struct_r(Parent_value),

    print_nl('parent', Parent_offset),
    print_nl('stack', Stack_offset),
    print_nl('task', Tasks_offset),
    print_nl('pid', Pid_offset),
    print_nl('mm_struct', MM_offset2).


    

possible_mm_struct(Base_addr) :- 
    process_create(path('python'),
                    ['query.py', Base_addr, "mm_struct"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    isTrue(Result).


possible_sched_info(Base_addr) :- 
    process_create(path('python'),
                    ['query.py', Base_addr, "sched_info"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    isTrue(Result).

possible_list_head(Base_addr) :- 
    process_create(path('python'),
                    ['query.py', Base_addr, "list_head"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    isTrue(Result).


task_struct_r(Base_addr):-
    process_create(path('python'),
                    ['query.py', Base_addr, "task_struct"],
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
                    ['query.py', Base_addr, "fs_struct"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    isTrue(Result).

possible_tlbflush_unmap_batch(Base_addr):- 
    process_create(path('python'),
                    ['query.py', Base_addr, "tlbflush_unmap_batch"],
                    [stdout(pipe(In))]),
    read_string(In, Len, X),
    string_codes(X, Result),
    isTrue(Result).

print_nl(Name, Content) :- 
    print(Name),
    print(':'),
    print(Content),
    nl.