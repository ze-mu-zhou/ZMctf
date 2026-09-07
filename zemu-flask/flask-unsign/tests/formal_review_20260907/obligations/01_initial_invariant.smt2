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
 (let (($x35 (< x 0)))
(let (($x36 (=> false $x35)))
(let (($x16 (< x N)))
(let (($x34 (= $x16 true)))
(let (($x33 (<= N N)))
(let (($x32 (>= N 0)))
(let (($x37 (and true true $x32 $x32 $x33 true true $x34 $x36)))
(not $x37)))))))))
(check-sat)
