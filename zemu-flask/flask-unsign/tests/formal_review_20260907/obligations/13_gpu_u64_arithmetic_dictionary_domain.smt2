; benchmark generated from python API
(set-info :status unknown)
(declare-fun bN () (_ BitVec 64))
(declare-fun bH () (_ BitVec 64))
(declare-fun bT () (_ BitVec 64))
(assert
 (bvugt bN (_ bv0 64)))
(assert
 (bvule bN (_ bv4294967295 64)))
(assert
 (bvult bH bN))
(assert
 (bvult bH bT))
(assert
 (bvule bT bN))
(assert
 (let ((?x452 (bvadd bH (_ bv16777216 64))))
(let (($x151 (bvult ?x452 bN)))
(let ((?x388 (ite $x151 ?x452 bN)))
(let (($x486 (bvugt ?x388 bT)))
(let ((?x424 (ite $x486 bT ?x388)))
(let (($x405 (and (bvugt ?x424 bH) (bvule ?x424 bN) (bvule ?x424 bT))))
(not $x405))))))))
(check-sat)
