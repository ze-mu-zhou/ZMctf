; benchmark generated from python API
(set-info :status unknown)
(declare-fun w () Int)
(declare-fun i () Int)
(declare-fun eol () Int)
(declare-fun n () Int)
(declare-fun length () Int)
(assert
 (>= w 0))
(assert
 (<= w i))
(assert
 (<= i eol))
(assert
 (<= eol n))
(assert
 (<= n 4294967295))
(assert
 (>= length 0))
(assert
 (let ((?x599 (- eol i)))
 (<= length ?x599)))
(assert
 (let (($x11632 (and (>= (+ w length) 0) (<= (+ w length) 4294967295))))
(not $x11632)))
(check-sat)
