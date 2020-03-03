use_module(library(clpfd)).
:- discontiguous(ispointer/3).
:- discontiguous(isint/3).
:- discontiguous(isstring/3).

:- discontiguous(islong/3).

ispointer(526256192,0,476403208).
ispointer(526256192,8,468779376).
ispointer(526256192,16,468822744).
ispointer(526256192,24,16848709).
ispointer(526256192,32,17652825).
ispointer(526256192,72,467877888).
ispointer(526256192,112,526256304).
ispointer(526256192,120,526256304).
ispointer(526256192,128,473512000).
ispointer(526256192,136,526637120).
ispointer(526256192,696,23259456).
ispointer(526256192,792,526256984).
ispointer(526256192,800,526256984).
ispointer(526256192,872,472350848).
ispointer(526256192,880,521624512).
ispointer(526256192,960,468232216).
ispointer(526256192,968,72033328).
ispointer(526256192,976,468668552).
ispointer(526256192,984,16848709).
ispointer(526256192,992,17652825).
isint(526256192,45,127).
isint(526256192,69,127).
isint(526256192,83,256).
isint(526256192,88,145).
isint(526256192,94,84).
isint(526256192,144,886).
isint(526256192,153,70).
isint(526256192,161,70).
isint(526256192,185,67).
isint(526256192,192,890).
isint(526256192,199,8704).
isint(526256192,224,40).
isint(526256192,261,127).
isint(526256192,269,127).
isint(526256192,320,33).
isint(526256192,336,16).
isint(526256192,346,4011).
isint(526256192,351,1536).
isint(526256192,360,4096).
isint(526256192,367,4352).
isint(526256192,376,100).
isint(526256192,383,768).
isint(526256192,399,1024).
isint(526256192,408,56).
isint(526256192,415,1280).
isint(526256192,423,2304).
isint(526256192,431,1792).
isint(526256192,447,2048).
isint(526256192,463,2304).
isint(526256192,479,2816).
isint(526256192,495,3072).
isint(526256192,511,3328).
isint(526256192,527,3584).
isint(526256192,543,5888).
isint(526256192,559,6400).
isint(526256192,576,31).
isint(526256192,592,15).
isint(526256192,672,406).
isint(526256192,680,176).
isint(526256192,688,254).
isint(526256192,783,256).
isint(526256192,824,7).
isint(526256192,831,1792).
isint(526256192,840,205).
isint(526256192,1005,127).
isint(526256192,1017,8464).
isstring(526256192,602,string).
islong(526256192,40,140233131958272).
islong(526256192,48,140737488351232).
islong(526256192,64,140233129422848).
islong(526256192,75,2199015391259).
islong(526256192,140,3809635960832).
islong(526256192,232,140233131487232).
islong(526256192,240,140233131957852).
islong(526256192,248,140233134056944).
islong(526256192,256,140233134079976).
islong(526256192,264,140233142370304).
islong(526256192,272,140233142505472).
islong(526256192,280,140735144036032).
islong(526256192,288,140735144042210).
islong(526256192,296,140735144042237).
islong(526256192,304,140735144042237).
islong(526256192,312,140735144042470).
islong(526256192,315,36283892105076).
islong(526256192,328,140735145734144).
islong(526256192,331,17592194432884).
islong(526256192,342,17231341617152).
islong(526256192,392,140233131487296).
islong(526256192,395,4398054869649).
islong(526256192,440,140233129250816).
islong(526256192,443,8796101380753).
islong(526256192,472,140233131691836).
islong(526256192,475,12094636264082).
islong(526256192,568,140735144036457).
islong(526256192,571,34084868849524).
islong(526256192,584,140735144042470).
islong(526256192,587,16492682805108).
islong(526256192,600,140735144036473).
islong(526256192,698,281474976678242).
islong(526256192,802,281472963452766).
islong(526256192,816,140735145734144).
islong(526256192,819,7696589782900).
islong(526256192,883,4398038646815).
islong(526256192,912,47229380259840).
islong(526256192,1000,139981142900736).
islong(526256192,1008,140737488351232).

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