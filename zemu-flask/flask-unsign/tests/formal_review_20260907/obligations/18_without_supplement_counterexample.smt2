; benchmark generated from python API
(set-info :status unknown)
(declare-fun N () Int)
(declare-fun x () Int)
(declare-fun H () Int)
(declare-fun cs () Int)
(declare-fun T () Int)
(declare-fun R () Int)
(declare-fun eligible () Bool)
(declare-fun supplemented () Bool)
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
 (>= H T))
(assert
 (= R H))
(assert
 (and (distinct cs 1) true))
(assert
 (not eligible))
(assert
 (not supplemented))
(assert
 (= N 65537))
(assert
 (= x 0))
(assert
 (= H 1))
(assert
 (= T 1))
(assert
 (= R 1))
(assert
 (= cs 0))
(assert
 (let (($x287 (not eligible)))
(let (($x136 (and $x287 supplemented)))
(let (($x346 (and eligible (< x R))))
(let (($x232 (= cs 2)))
(let (($x86 (or $x232 $x346 $x136)))
(not $x86)))))))
(check-sat)
