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
 (let (($x17 (>= R 0)))
 (and $x17 (<= R H) (<= H N) $x20 (<= T N) $x22 $x24 (= (= cs 0) (< x T)) (=> (= cs 3) (< x H))))))))
(assert
 (>= H N))
(assert
 (let (($x348 (>= H T)))
(not $x348)))
(check-sat)
