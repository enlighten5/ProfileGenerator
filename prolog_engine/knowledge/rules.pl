% use_module(library(clpfd)).
:- style_check(-singleton).


/*possible_task_struct(530138944).*/
/*possible_task_struct(23121952).*/

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
    ispointer(Base_addr, Offset2, Value2),
    Offset2 is Offset1 + 8,
    ispointer(Base_addr, Offset3, Value3),
    Offset3 is Offset2 + 8,
    ispointer(Base_addr, Offset4, Value4),
    Offset4 is Offset3 + 8,
    ispointer(Base_addr, Offset5, Value5),
    Offset5 is Offset4 + 8,
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
    ARG_start_offset is Offset12 + 8,
    islong(Base_addr, ARG_end_offset, ARG_end_value),
    ARG_end_offset is ARG_start_offset + 8,
    ARG_end_value > ARG_start_value,
    islong(Base_addr, ENV_start_offset, ENV_start_value),
    ENV_start_offset is ARG_end_offset + 8,
    islong(Base_addr, ENV_end_offset, ENV_end_value),
    ENV_end_offset is ENV_start_offset + 8,
    ENV_end_value > ENV_start_value.

possible_sched_info(Base_addr) :- 
    islong(Base_addr, Offset1, Value1),
    Offset1 < 10.


possible_list_head(Base_addr) :- 
    /*print_nl('find list_head', ''),*/
    ispointer(Base_addr, Offset1, Value1),
    Offset1 is 0,
    ispointer(Base_addr, Offset2, Value2),
    Offset2 is Offset1 + 8.
    /*list_head_next(Value1, Offset1),*/

list_head_next(Base_addr, List_head_offset, Comm_offset) :- 
    /* the knowledge base does not have task struct that contains value1 */

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

print_nl(Name, Content) :- 
    print(Name),
    print(':'),
    print(Content),
    nl.