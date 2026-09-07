; benchmark generated from python API
(set-info :status unknown)
(declare-fun N () Int)
(declare-fun x () Int)
(declare-fun H () Int)
(declare-fun cs () Int)
(declare-fun T () Int)
(declare-fun R () Int)
(declare-fun seenT () Int)
(assert
 (> N 0))
(assert
 (<= N 4294967295))
(assert
 (>= x 0))
(assert
 (< x N))
(assert
 (let (($x26 (< x T)))
 (let (($x25 (= cs 0)))
 (let (($x27 (= $x25 $x26)))
 (let (($x24 (<= cs 3)))
 (let (($x22 (>= cs 0)))
 (let (($x21 (<= T N)))
 (let (($x20 (>= T 0)))
 (let (($x17 (>= R 0)))
 (and $x17 (<= R H) (<= H N) $x20 $x21 $x22 $x24 $x27 (=> (= cs 3) (< x H))))))))))))
(assert
 (< H N))
(assert
 (< H seenT))
(assert
 (<= T seenT))
(assert
 (<= seenT N))
(assert
 (let ((?x281 (+ H 16777216)))
(let (($x371 (< ?x281 N)))
(let ((?x252 (ite $x371 ?x281 N)))
(let (($x163 (> ?x252 seenT)))
(let ((?x182 (ite $x163 seenT ?x252)))
(let (($x28 (= cs 3)))
(let (($x26 (< x T)))
(let (($x25 (= cs 0)))
(let (($x27 (= $x25 $x26)))
(let (($x24 (<= cs 3)))
(let (($x22 (>= cs 0)))
(let (($x21 (<= T N)))
(let (($x20 (>= T 0)))
(let (($x17 (>= R 0)))
(let (($x183 (and $x17 (<= R ?x182) (<= ?x182 N) $x20 $x21 $x22 $x24 $x27 (=> $x28 (< x ?x182)))))
(not $x183)))))))))))))))))
(check-sat)
