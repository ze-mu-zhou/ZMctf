; benchmark generated from python API
(set-info :status unknown)
(declare-fun N () Int)
(declare-fun x () Int)
(declare-fun H () Int)
(declare-fun cs () Int)
(declare-fun T () Int)
(declare-fun R () Int)
(declare-fun seenH () Int)
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
 (let (($x21 (<= T N)))
 (let (($x20 (>= T 0)))
 (let (($x19 (<= H N)))
 (let (($x18 (<= R H)))
 (let (($x17 (>= R 0)))
 (and $x17 $x18 $x19 $x20 $x21 $x22 $x24 (= (= cs 0) (< x T)) (=> (= cs 3) (< x H)))))))))))
(assert
 (= cs 1))
(assert
 (< x seenH))
(assert
 (>= seenH 0))
(assert
 (<= seenH H))
(assert
 (let (($x29 (< x H)))
(let (($x39 (=> true $x29)))
(let (($x26 (< x T)))
(let (($x95 (= $x26 false)))
(let (($x21 (<= T N)))
(let (($x20 (>= T 0)))
(let (($x19 (<= H N)))
(let (($x18 (<= R H)))
(let (($x17 (>= R 0)))
(let (($x53 (and $x17 $x18 $x19 $x20 $x21 true true $x95 $x39)))
(not $x53))))))))))))
(check-sat)
