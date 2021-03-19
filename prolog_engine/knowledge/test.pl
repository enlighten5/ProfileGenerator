:- use_module(reif).
:- use_module(library(clpfd)).
:- table(test/2).
hailstone(N, N).
hailstone(N0, N) :-
        R is N0 mod 2,
        if_(R = 0,
            N0 is 2*N1,
            N1 is 3*N0 + 1),
        hailstone(N1, N).

toy(X, Y) :- 
    if_(X = 0,
        Y = 2,
        Y = 1),
    print(Y).
    

as([]).
as([L]) :-
    L = a.
as([L|Ls]) :-
    if_(L = a,
        Ls = [b|Ls],
        Ls = [a|Ls]),
    as([Ls]).

test(X, Y) :- 
    Vars = [X, Y],
    X in 0..10,
    Y in 0..8,
    X #> Y,
    labeling([ff, up, enum], Vars),
    if_(X = 5,
        call(toy, X, Y),
        1 = 1).

    %label(Vars).

foo(X) :- X in 1..3 .
foo(X) :- X in 5..7 .
foo(X) :- X in 8..12 .

puzzle([S,E,N,D] + [M,O,R,E] = [M,O,N,E,Y]) :-
        Vars = [S,E,N,D,M,O,R,Y],
        Vars ins 0..9,
        all_different(Vars),
                  S*1000 + E*100 + N*10 + D + 
                  M*1000 + O*100 + R*10 + E #=
        M*10000 + O*1000 + N*100 + E*10 + Y,
        M #\= 0, S #\= 0,
		label(Vars). 
/*
increase([]).
increase([L1, L2]):-
    L1 < L2.

increase([L1,L2|Ls]) :- 
    L1 ins 0..10,
    L1 < L2,   
    label([L1, L2]),
    increase(Ls).
*/

increase([_L1, _L2, _L3, _L4]) :-
    Vars = [_L1, _L2, _L3, _L4],
    chain(Vars, #<),
    label(Vars).
test_len(X, Y) :-
    integer(Y),
    length(X, Y),
    X ins 0..4,
    all_different(X),
    X = [H|_T],
    H #\= 0,
    label(X).

number(X, Y, Z):-
    X in 0..2,
    Y in 1..2,
    Z in 1..2,
    all_different([X, Y, Z]),
    label([X, Y, Z]).

trains([[1,2,0,1], % from station, to station, departs at, arrives at
        [2,3,4,5],
        [2,3,0,1],
        [3,4,5,6],
        [3,4,2,3],
        [3,4,8,9]]).

threepath(A, D, Ps) :-
    Ps = [[A,B,_T0,T1],[B,C,T2,T3],[C,D,T4,_T5]],
    T2 #> T1,
    T4 #> T3,
    trains(Ts),
    tuples_in(Ps, Ts).

flirt_constraint(Suzy, FlirtPeriods) :-
	length(Suzy, 6),
	length(Nathan, 6),
	length(John, 6),
	Suzy ins 1..6,
	Nathan ins 1..6,
	John ins 1..6,
	all_different(Suzy),
	all_different(Nathan),
	all_different(John),
	FlirtPeriods = [A,B,C],
	FlirtPeriods ins 1..6,
	A #< B,    % remove unwanted symmetry
	B #< C,
	flirty_period(A, Suzy, Nathan, John),
	flirty_period(B, Suzy, Nathan, John),
	flirty_period(C, Suzy, Nathan, John),
	label(Suzy),
	label(FlirtPeriods).

flirty_period(Period, Suzy, Nathan, John) :-
	Class in 1..6,
    DiffClass #\= Class,
    DiffClass #\= 0,
	element(Period, Suzy, Class),
	element(Period, Nathan, Class),
	element(Period, John, DiffClass).

string_val([
    [0, 0]
    ]).

test_val(X) :-
    current_predicate(string_val/1),
    X = 1.

foo(X) :- X in 1..3.
foo(X) :- X in 5..7.
foo(X) :- X in 8..12.