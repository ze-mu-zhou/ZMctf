; benchmark generated from python API
(set-info :status unknown)
(declare-fun N () Int)
(declare-fun x () Int)
(assert
 (> N 0))
(assert
 (<= N 4294967295))
(assert
 (>= x 0))
(assert
 (< x N))
(assert
 (> N 65536))
(assert
 (< N 16777216))
(assert
 (let ((?x448 (- N 65536)))
 (<= ?x448 x)))
(assert
 (let (($x16 (< x N)))
(let ((?x448 (- N 65536)))
(let (($x171 (<= ?x448 x)))
(let (($x181 (and $x171 $x16 (<= 16777216 x))))
(let (($x317 (< x ?x448)))
(let (($x202 (or $x317 $x181)))
(not $x202))))))))
(check-sat)
