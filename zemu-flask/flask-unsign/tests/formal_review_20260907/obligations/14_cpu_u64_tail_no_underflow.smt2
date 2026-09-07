; benchmark generated from python API
(set-info :status unknown)
(declare-fun u () (_ BitVec 64))
(assert
 (bvugt u (_ bv0 64)))
(assert
 (let ((?x1294 (bvsub u (_ bv65536 64))))
(let (($x1110 (bvugt u (_ bv65536 64))))
(let ((?x472 (ite $x1110 ?x1294 (_ bv0 64))))
(let (($x793 (bvult ?x472 u)))
(not $x793))))))
(check-sat)
