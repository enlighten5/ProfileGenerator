use_module(library(clpfd)).
:- discontiguous(ispointer/3).
:- discontiguous(isint/3).
:- discontiguous(isstring/3).

:- discontiguous(islong/3).

ispointer(472350848,8,493486080).
ispointer(472350848,64,20992672).
ispointer(472350848,112,472350960).
ispointer(472350848,120,472350960).
ispointer(472350848,184,495007728).
ispointer(472350848,200,472351048).
ispointer(472350848,208,472351048).
ispointer(472350848,240,24531440).
ispointer(472350848,368,449446384).
ispointer(472350848,376,467790384).
ispointer(472350848,392,472351240).
ispointer(472350848,400,472351240).
ispointer(472350848,408,472351256).
ispointer(472350848,416,472351256).
ispointer(472350848,424,526256192).
ispointer(472350848,432,526256192).
ispointer(472350848,504,530138944).
ispointer(472350848,512,530138944).
ispointer(472350848,520,480577944).
ispointer(472350848,528,527356504).
ispointer(472350848,536,449446552).
ispointer(472350848,544,467790552).
ispointer(472350848,552,472350848).
ispointer(472350848,560,472351408).
ispointer(472350848,568,472351408).
ispointer(472350848,576,472351424).
ispointer(472350848,584,472351424).
ispointer(472350848,600,467748168).
ispointer(472350848,608,467748160).
ispointer(472350848,624,480578024).
ispointer(472350848,632,467748160).
ispointer(472350848,648,480578048).
ispointer(472350848,656,467748160).
ispointer(472350848,664,472351512).
ispointer(472350848,672,472351512).
ispointer(472350848,848,472351696).
ispointer(472350848,856,472351696).
ispointer(472350848,864,472351712).
ispointer(472350848,872,472351712).
ispointer(472350848,880,472351728).
ispointer(472350848,888,472351728).
ispointer(472350848,896,459288320).
ispointer(472350848,904,459288320).
ispointer(472350848,984,493494272).
ispointer(472350848,992,493492488).
isint(472350848,0,1).
isint(472350848,22,64).
isint(472350848,48,120).
isint(472350848,52,120).
isint(472350848,56,120).
isint(472350848,72,1024).
isint(472350848,82,64).
isint(472350848,87,256).
isint(472350848,140,2208).
isint(472350848,147,39).
isint(472350848,155,5022).
isint(472350848,163,39).
isint(472350848,224,250).
isint(472350848,228,64).
isint(472350848,337,37).
isint(472350848,346,2714).
isint(472350848,356,2208).
isint(472350848,447,256).
isint(472350848,463,4352).
isint(472350848,484,2254).
isint(472350848,488,2254).
isint(472350848,499,45).
isint(472350848,703,512).
isint(472350848,711,1280).
isint(472350848,719,512).
isint(472350848,727,1280).
isint(472350848,761,37).
isint(472350848,767,1024).
isint(472350848,775,1280).
isint(472350848,787,40).
isint(472350848,791,1280).
isint(472350848,803,40).
isint(472350848,808,1204).
isint(472350848,815,256).
isint(472350848,926,50).
isint(472350848,939,256).
isstring(472350848,920,string).
isstring(472350848,1002,string).
islong(472350848,11,3298527019037).
islong(472350848,68,4402341478399).
islong(472350848,122,281472963451943).
islong(472350848,136,9485050880539).
islong(472350848,142,43487313657856).
islong(472350848,151,21570927869440).
islong(472350848,158,43482730725376).
islong(472350848,186,281472963452289).
islong(472350848,210,281472963451943).
islong(472350848,242,281474976678262).
islong(472350848,342,11658602741760).
islong(472350848,352,9485050810609).
islong(472350848,379,155031131652123).
islong(472350848,435,60473131663391).
islong(472350848,586,281472963451943).
islong(472350848,610,281472963451873).
islong(472350848,634,281472963451873).
islong(472350848,674,281472963451943).
islong(472350848,688,140233131371024).
islong(472350848,696,140233131371024).
islong(472350848,699,2199031614097).
islong(472350848,782,44813829472256).
islong(472350848,798,44813829472256).
islong(472350848,906,281472963451744).
islong(472350848,921,55411124429168).
islong(472350848,1000,140735144035176).

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