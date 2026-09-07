; benchmark generated from python API
(set-info :status unknown)
(declare-fun N () Int)
(declare-fun x () Int)
(declare-fun H () Int)
(declare-fun cs () Int)
(declare-fun T () Int)
(declare-fun R () Int)
(assert
 (> N 0))
(assert
 (<= N 4294967295))
(assert
 (>= x 0))
(assert
 (< x N))
(assert
 (let (($x24 (<= cs 3)))
 (let (($x22 (>= cs 0)))
 (let (($x20 (>= T 0)))
 (let (($x19 (<= H N)))
 (let (($x18 (<= R H)))
 (let (($x17 (>= R 0)))
 (and $x17 $x18 $x19 $x20 (<= T N) $x22 $x24 (= (= cs 0) (< x T)) (=> (= cs 3) (< x H))))))))))
(assert
 (> T 0))
(assert
 (let (($x29 (< x H)))
(let ((?x59 (ite (and (<= (ite (> T 65536) (- T 65536) 0) x) (< x T)) 1 cs)))
(let (($x19 (<= H N)))
(let (($x18 (<= R H)))
(let (($x17 (>= R 0)))
(let (($x116 (and $x17 $x18 $x19 (>= (ite (> T 65536) (- T 65536) 0) 0) (<= (ite (> T 65536) (- T 65536) 0) N) (>= ?x59 0) (<= ?x59 3) (= (= ?x59 0) (< x (ite (> T 65536) (- T 65536) 0))) (=> (= ?x59 3) $x29))))
(not $x116))))))))
(check-sat)
