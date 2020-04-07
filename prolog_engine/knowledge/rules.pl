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

    

possible_mm_struct(Base_addr) :- 
    /* five pointers */
    ispointer(Base_addr, Offset1, Value1),
    Offset1 = 0,
    check_vm_area_struct(Value1),
    ispointer(Base_addr, Offset2, Value2),
    Offset2 is Offset1 + 8,
    /* comment this because it does not hold for new kernel*/
    /*ispointer(Base_addr, Offset3, Value3),
    Offset3 is Offset2 + 8, */
    ispointer(Base_addr, Offset4, Value4),
    Offset4 is Offset2 + 16,
    /* comment this because it does not hold for new kernel*/
    /*ispointer(Base_addr, Offset5, Value5),
    Offset5 is Offset4 + 8,*/

    islong(Base_addr, Mmap_base_offset, Mmap_base_value),
    Mmap_base_offset < Offset4 + 17,
    islong(Base_addrm, Task_size_offset, Task_size_value),
    Task_size_offset < Mmap_base_offset + 33,

    ispointer(Base_addr, Pgd_offset, Pgd_value),
    Pgd_offset > Task_size_offset,
    Pgd_offset < Task_size_offset + 17,

    /*
        unsigned long start_code, end_code, start_data, end_data;
        unsigned long start_brk, brk, start_stack;
        unsigned long arg_start, arg_end, env_start, env_end;
    
    */
    islong(Base_addr, Offset6, Value6),
    islong(Base_addr, Offset7, Value7),
    Offset7 is Offset6 + 8,
    Value7 > Value6,
    islong(Base_addr, Offset8, Value8),
    Offset8 is Offset7 + 8,
    islong(Base_addr, Offset9, Value9),
    Offset9 is Offset8 + 8,
    Value9 > Value8,

    islong(Base_addr, Offset10, Value10),
    Offset10 is Offset9 + 8,
    islong(Base_addr, Offset11, Value11),
    Offset11 is Offset10 + 8,
    islong(Base_addr, Offset12, Value12),
    Offset12 is Offset11 + 8,

    islong(Base_addr, ARG_start_offset, ARG_start_value),
    ARG_start_offset < 2000,
    ARG_start_offset is Offset12 + 8,
    islong(Base_addr, ARG_end_offset, ARG_end_value),
    ARG_end_offset is ARG_start_offset + 8,
    ARG_end_value > ARG_start_value,
    islong(Base_addr, ENV_start_offset, ENV_start_value),
    ENV_start_offset is ARG_end_offset + 8,
    islong(Base_addr, ENV_end_offset, ENV_end_value),
    ENV_end_offset is ENV_start_offset + 8,
    ENV_end_value > ENV_start_value,

    log('profile.txt', 'mm_struct', Base_addr),
    log('profile.txt', 'mmap', Offset1),
    log('profile.txt', 'pgd', Pgd_offset),
    log('profile.txt', 'arg_start', ARG_start_offset),
    log('profile.txt', 'start_brk', Offset10),
    log('profile.txt', 'brk', Offset11),
    log('profile.txt', 'start_stack', Offset12),
    log('profile.txt', "mm_struct_end", Base_addr).

possible_sched_info(Base_addr) :- 
    islong(Base_addr, Offset1, Value1),
    Offset1 < 10.


possible_list_head(Base_addr, Comm_offset, Tasks_offset) :- 
    /* print_nl('find list_head', ''), */
    ispointer(Base_addr, Offset1, Value1),
    Offset1 is 0,
    ispointer(Base_addr, Offset2, Value2),
    Offset2 is Offset1 + 8,
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
    isint(Base_addr, Offset1, Value1),
    Offset1 is 0,
    isint(Base_addr, Offset2, Value2),
    Offset2 > Offset1,
    isint(Base_addr, Offset3, Value3),
    Offset3 < Offset2 + 10.

possible_tlbflush_unmap_batch(Base_addr):- 
    ispointer(Base_addr, Offset, Value).

possible_ts(Base_addr, Comm_offset, Tasks_offset):-
    isstring(Base_addr, Comm_offset, Comm_value),
    ispointer(Base_addr, Tasks_offset, Tasks_value),
    process_create(path('python'),
                    ['subquery.py', Tasks_value, "list_head", Comm_offset, Tasks_offset],
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

possible_cred(Base_addr):-
    isint(Base_addr, Offset1, Value1),
    Offset1 < 25,
    isint(Base_addr, Offset2, Value2),
    Offset2 is Offset1 + 4,
    isint(Base_addr, Offset3, Value3),
    Offset3 is Offset2 + 4,
    isint(Base_addr, Offset4, Value4),
    Offset4 is Offset3 + 4,
    isint(Base_addr, Offset5, Value5),
    Offset5 is Offset4 + 4,
    isint(Base_addr, Offset6, Value6),
    Offset6 is Offset5 + 4,
    isint(Base_addr, Offset7, Value7),
    Offset7 is Offset6 + 4,
    isint(Base_addr, Offset8, Value8),
    Offset8 is Offset7 + 4,
    isint(Base_addr, Offset9, Value9),
    Offset9 is Offset8 + 4,

    islong(Base_addr, Offset10, Value10),
    Offset10 > Offset9,
    Offset10 < Offset9 + 17,
    islong(Base_addr, Offset11, Value11),
    Offset11 is Offset10 + 8,

    log('profile.txt', 'cred', Base_addr),
    log('profile.txt', 'uid', Offset1),
    log('profile.txt', 'gid', Offset2),
    log('profile.txt', 'euid', Offset5),
    log('profile.txt', 'egid', Offset6),
    log('profile.txt', 'cred_end', Base_addr).


possible_vm_area_struct(Base_addr):-
    islong(Base_addr, VM_start_offset, VM_start_value),
    VM_start_offset < 20,
    islong(Base_addr, VM_end_offset, VM_end_value),
    VM_end_offset is VM_start_offset + 8,
    ispointer(Base_addr, VM_next_offset, VM_next_value),
    VM_next_offset is VM_end_offset + 8,

    log('profile.txt', 'vm_area_struct', Base_addr),
    log('profile.txt', 'vm_start', VM_start_offset),
    log('profile.txt', 'vm_end', VM_end_offset),
    log('profile.txt', 'vm_next', VM_next_offset),
    log('profile.txt', 'vm_area_struct_end', Base_addr).


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
    isstring(Base_addr, New_offset, Comm_value).

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