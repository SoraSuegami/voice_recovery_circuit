// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract Verifier {
    function verify(
        uint256[] memory pubInputs,
        bytes memory proof
    ) public view returns (bool) {
        bool success = true;
        bytes32[564] memory transcript;
        assembly {
            let
                f_p
            := 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
            let
                f_q
            := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
            function validate_ec_point(x, y) -> valid {
                {
                    let x_lt_p := lt(
                        x,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    let y_lt_p := lt(
                        y,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    valid := and(x_lt_p, y_lt_p)
                }
                {
                    let x_is_zero := eq(x, 0)
                    let y_is_zero := eq(y, 0)
                    let x_or_y_is_zero := or(x_is_zero, y_is_zero)
                    let x_and_y_is_not_zero := not(x_or_y_is_zero)
                    valid := and(x_and_y_is_not_zero, valid)
                }
                {
                    let y_square := mulmod(
                        y,
                        y,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    let x_square := mulmod(
                        x,
                        x,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    let x_cube := mulmod(
                        x_square,
                        x,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    let x_cube_plus_3 := addmod(
                        x_cube,
                        3,
                        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    )
                    let y_square_eq_x_cube_plus_3 := eq(x_cube_plus_3, y_square)
                    valid := and(y_square_eq_x_cube_plus_3, valid)
                }
            }
            mstore(add(transcript, 0x20), mod(mload(add(pubInputs, 0x20)), f_q))
            mstore(add(transcript, 0x40), mod(mload(add(pubInputs, 0x40)), f_q))
            mstore(add(transcript, 0x60), mod(mload(add(pubInputs, 0x60)), f_q))
            mstore(add(transcript, 0x80), mod(mload(add(pubInputs, 0x80)), f_q))
            mstore(add(transcript, 0xa0), mod(mload(add(pubInputs, 0xa0)), f_q))
            mstore(add(transcript, 0xc0), mod(mload(add(pubInputs, 0xc0)), f_q))
            mstore(add(transcript, 0xe0), mod(mload(add(pubInputs, 0xe0)), f_q))
            mstore(
                add(transcript, 0x0),
                12358111550043178518259213886218074335550007843026468564669891643576637359908
            )
            {
                let x := mload(add(proof, 0x20))
                mstore(add(transcript, 0x100), x)
                let y := mload(add(proof, 0x40))
                mstore(add(transcript, 0x120), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(add(transcript, 0x140), keccak256(add(transcript, 0x0), 320))
            {
                let hash := mload(add(transcript, 0x140))
                mstore(add(transcript, 0x160), mod(hash, f_q))
                mstore(add(transcript, 0x180), hash)
            }
            {
                let x := mload(add(proof, 0x60))
                mstore(add(transcript, 0x1a0), x)
                let y := mload(add(proof, 0x80))
                mstore(add(transcript, 0x1c0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0xa0))
                mstore(add(transcript, 0x1e0), x)
                let y := mload(add(proof, 0xc0))
                mstore(add(transcript, 0x200), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x220),
                keccak256(add(transcript, 0x180), 160)
            )
            {
                let hash := mload(add(transcript, 0x220))
                mstore(add(transcript, 0x240), mod(hash, f_q))
                mstore(add(transcript, 0x260), hash)
            }
            mstore8(add(transcript, 0x280), 1)
            mstore(
                add(transcript, 0x280),
                keccak256(add(transcript, 0x260), 33)
            )
            {
                let hash := mload(add(transcript, 0x280))
                mstore(add(transcript, 0x2a0), mod(hash, f_q))
                mstore(add(transcript, 0x2c0), hash)
            }
            {
                let x := mload(add(proof, 0xe0))
                mstore(add(transcript, 0x2e0), x)
                let y := mload(add(proof, 0x100))
                mstore(add(transcript, 0x300), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x120))
                mstore(add(transcript, 0x320), x)
                let y := mload(add(proof, 0x140))
                mstore(add(transcript, 0x340), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x160))
                mstore(add(transcript, 0x360), x)
                let y := mload(add(proof, 0x180))
                mstore(add(transcript, 0x380), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x3a0),
                keccak256(add(transcript, 0x2c0), 224)
            )
            {
                let hash := mload(add(transcript, 0x3a0))
                mstore(add(transcript, 0x3c0), mod(hash, f_q))
                mstore(add(transcript, 0x3e0), hash)
            }
            {
                let x := mload(add(proof, 0x1a0))
                mstore(add(transcript, 0x400), x)
                let y := mload(add(proof, 0x1c0))
                mstore(add(transcript, 0x420), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x1e0))
                mstore(add(transcript, 0x440), x)
                let y := mload(add(proof, 0x200))
                mstore(add(transcript, 0x460), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x220))
                mstore(add(transcript, 0x480), x)
                let y := mload(add(proof, 0x240))
                mstore(add(transcript, 0x4a0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x260))
                mstore(add(transcript, 0x4c0), x)
                let y := mload(add(proof, 0x280))
                mstore(add(transcript, 0x4e0), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x500),
                keccak256(add(transcript, 0x3e0), 288)
            )
            {
                let hash := mload(add(transcript, 0x500))
                mstore(add(transcript, 0x520), mod(hash, f_q))
                mstore(add(transcript, 0x540), hash)
            }
            mstore(add(transcript, 0x560), mod(mload(add(proof, 0x2a0)), f_q))
            mstore(add(transcript, 0x580), mod(mload(add(proof, 0x2c0)), f_q))
            mstore(add(transcript, 0x5a0), mod(mload(add(proof, 0x2e0)), f_q))
            mstore(add(transcript, 0x5c0), mod(mload(add(proof, 0x300)), f_q))
            mstore(add(transcript, 0x5e0), mod(mload(add(proof, 0x320)), f_q))
            mstore(add(transcript, 0x600), mod(mload(add(proof, 0x340)), f_q))
            mstore(add(transcript, 0x620), mod(mload(add(proof, 0x360)), f_q))
            mstore(add(transcript, 0x640), mod(mload(add(proof, 0x380)), f_q))
            mstore(add(transcript, 0x660), mod(mload(add(proof, 0x3a0)), f_q))
            mstore(add(transcript, 0x680), mod(mload(add(proof, 0x3c0)), f_q))
            mstore(add(transcript, 0x6a0), mod(mload(add(proof, 0x3e0)), f_q))
            mstore(add(transcript, 0x6c0), mod(mload(add(proof, 0x400)), f_q))
            mstore(add(transcript, 0x6e0), mod(mload(add(proof, 0x420)), f_q))
            mstore(add(transcript, 0x700), mod(mload(add(proof, 0x440)), f_q))
            mstore(add(transcript, 0x720), mod(mload(add(proof, 0x460)), f_q))
            mstore(add(transcript, 0x740), mod(mload(add(proof, 0x480)), f_q))
            mstore(add(transcript, 0x760), mod(mload(add(proof, 0x4a0)), f_q))
            mstore(add(transcript, 0x780), mod(mload(add(proof, 0x4c0)), f_q))
            mstore(add(transcript, 0x7a0), mod(mload(add(proof, 0x4e0)), f_q))
            mstore(
                add(transcript, 0x7c0),
                keccak256(add(transcript, 0x540), 640)
            )
            {
                let hash := mload(add(transcript, 0x7c0))
                mstore(add(transcript, 0x7e0), mod(hash, f_q))
                mstore(add(transcript, 0x800), hash)
            }
            {
                let x := mload(add(proof, 0x500))
                mstore(add(transcript, 0x820), x)
                let y := mload(add(proof, 0x520))
                mstore(add(transcript, 0x840), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x540))
                mstore(add(transcript, 0x860), x)
                let y := mload(add(proof, 0x560))
                mstore(add(transcript, 0x880), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x580))
                mstore(add(transcript, 0x8a0), x)
                let y := mload(add(proof, 0x5a0))
                mstore(add(transcript, 0x8c0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x5c0))
                mstore(add(transcript, 0x8e0), x)
                let y := mload(add(proof, 0x5e0))
                mstore(add(transcript, 0x900), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x600))
                mstore(add(transcript, 0x920), x)
                let y := mload(add(proof, 0x620))
                mstore(add(transcript, 0x940), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x960),
                keccak256(add(transcript, 0x800), 352)
            )
            {
                let hash := mload(add(transcript, 0x960))
                mstore(add(transcript, 0x980), mod(hash, f_q))
                mstore(add(transcript, 0x9a0), hash)
            }
            mstore(
                add(transcript, 0x9c0),
                mulmod(
                    mload(add(transcript, 0x520)),
                    mload(add(transcript, 0x520)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x9e0),
                mulmod(
                    mload(add(transcript, 0x9c0)),
                    mload(add(transcript, 0x9c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xa00),
                mulmod(
                    mload(add(transcript, 0x9e0)),
                    mload(add(transcript, 0x9e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xa20),
                mulmod(
                    mload(add(transcript, 0xa00)),
                    mload(add(transcript, 0xa00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xa40),
                mulmod(
                    mload(add(transcript, 0xa20)),
                    mload(add(transcript, 0xa20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xa60),
                mulmod(
                    mload(add(transcript, 0xa40)),
                    mload(add(transcript, 0xa40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xa80),
                mulmod(
                    mload(add(transcript, 0xa60)),
                    mload(add(transcript, 0xa60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xaa0),
                mulmod(
                    mload(add(transcript, 0xa80)),
                    mload(add(transcript, 0xa80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xac0),
                mulmod(
                    mload(add(transcript, 0xaa0)),
                    mload(add(transcript, 0xaa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xae0),
                mulmod(
                    mload(add(transcript, 0xac0)),
                    mload(add(transcript, 0xac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xb00),
                mulmod(
                    mload(add(transcript, 0xae0)),
                    mload(add(transcript, 0xae0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xb20),
                mulmod(
                    mload(add(transcript, 0xb00)),
                    mload(add(transcript, 0xb00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xb40),
                mulmod(
                    mload(add(transcript, 0xb20)),
                    mload(add(transcript, 0xb20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xb60),
                mulmod(
                    mload(add(transcript, 0xb40)),
                    mload(add(transcript, 0xb40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xb80),
                mulmod(
                    mload(add(transcript, 0xb60)),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xba0),
                mulmod(
                    mload(add(transcript, 0xb80)),
                    mload(add(transcript, 0xb80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xbc0),
                mulmod(
                    mload(add(transcript, 0xba0)),
                    mload(add(transcript, 0xba0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xbe0),
                mulmod(
                    mload(add(transcript, 0xbc0)),
                    mload(add(transcript, 0xbc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xc00),
                mulmod(
                    mload(add(transcript, 0xbe0)),
                    mload(add(transcript, 0xbe0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xc20),
                mulmod(
                    mload(add(transcript, 0xc00)),
                    mload(add(transcript, 0xc00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xc40),
                addmod(
                    mload(add(transcript, 0xc20)),
                    21888242871839275222246405745257275088548364400416034343698204186575808495616,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xc60),
                mulmod(
                    mload(add(transcript, 0xc40)),
                    21888221997584217086951279548962733484243966294447177135413498358668068307201,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xc80),
                mulmod(
                    mload(add(transcript, 0xc60)),
                    3021657639704125634180027002055603444074884651778695243656177678924693902744,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xca0),
                addmod(
                    mload(add(transcript, 0x520)),
                    18866585232135149588066378743201671644473479748637339100042026507651114592873,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xcc0),
                mulmod(
                    mload(add(transcript, 0xc60)),
                    13315224328250071823986980334210714047804323884995968263773489477577155309695,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xce0),
                addmod(
                    mload(add(transcript, 0x520)),
                    8573018543589203398259425411046561040744040515420066079924714708998653185922,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xd00),
                mulmod(
                    mload(add(transcript, 0xc60)),
                    6852144584591678924477440653887876563116097870276213106119596023961179534039,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xd20),
                addmod(
                    mload(add(transcript, 0x520)),
                    15036098287247596297768965091369398525432266530139821237578608162614628961578,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xd40),
                mulmod(
                    mload(add(transcript, 0xc60)),
                    6363119021782681274480715230122258277189830284152385293217720612674619714422,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xd60),
                addmod(
                    mload(add(transcript, 0x520)),
                    15525123850056593947765690515135016811358534116263649050480483573901188781195,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xd80),
                mulmod(
                    mload(add(transcript, 0xc60)),
                    495188420091111145957709789221178673495499187437761988132837836548330853701,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xda0),
                addmod(
                    mload(add(transcript, 0x520)),
                    21393054451748164076288695956036096415052865212978272355565366350027477641916,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xdc0),
                mulmod(
                    mload(add(transcript, 0xc60)),
                    14686510910986211321976396297238126901237973400949744736326777596334651355305,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xde0),
                addmod(
                    mload(add(transcript, 0x520)),
                    7201731960853063900270009448019148187310390999466289607371426590241157140312,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe00),
                mulmod(
                    mload(add(transcript, 0xc60)),
                    15402826414547299628414612080036060696555554914079673875872749760617770134879,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe20),
                addmod(
                    mload(add(transcript, 0x520)),
                    6485416457291975593831793665221214391992809486336360467825454425958038360738,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe40),
                mulmod(mload(add(transcript, 0xc60)), 1, f_q)
            )
            mstore(
                add(transcript, 0xe60),
                addmod(
                    mload(add(transcript, 0x520)),
                    21888242871839275222246405745257275088548364400416034343698204186575808495616,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe80),
                mulmod(
                    mload(add(transcript, 0xc60)),
                    19032961837237948602743626455740240236231119053033140765040043513661803148152,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xea0),
                addmod(
                    mload(add(transcript, 0x520)),
                    2855281034601326619502779289517034852317245347382893578658160672914005347465,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xec0),
                mulmod(
                    mload(add(transcript, 0xc60)),
                    5854133144571823792863860130267644613802765696134002830362054821530146160770,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xee0),
                addmod(
                    mload(add(transcript, 0x520)),
                    16034109727267451429382545614989630474745598704282031513336149365045662334847,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf00),
                mulmod(
                    mload(add(transcript, 0xc60)),
                    9697063347556872083384215826199993067635178715531258559890418744774301211662,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf20),
                addmod(
                    mload(add(transcript, 0x520)),
                    12191179524282403138862189919057282020913185684884775783807785441801507283955,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf40),
                mulmod(
                    mload(add(transcript, 0xc60)),
                    6955697244493336113861667751840378876927906302623587437721024018233754910398,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf60),
                addmod(
                    mload(add(transcript, 0x520)),
                    14932545627345939108384737993416896211620458097792446905977180168342053585219,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf80),
                mulmod(
                    mload(add(transcript, 0xc60)),
                    5289443209903185443361862148540090689648485914368835830972895623576469023722,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xfa0),
                addmod(
                    mload(add(transcript, 0x520)),
                    16598799661936089778884543596717184398899878486047198512725308562999339471895,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xfc0),
                mulmod(
                    mload(add(transcript, 0xc60)),
                    4509404676247677387317362072810231899718070082381452255950861037254608304934,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xfe0),
                addmod(
                    mload(add(transcript, 0x520)),
                    17378838195591597834929043672447043188830294318034582087747343149321200190683,
                    f_q
                )
            )
            {
                let prod := mload(add(transcript, 0xca0))
                prod := mulmod(mload(add(transcript, 0xce0)), prod, f_q)
                mstore(add(transcript, 0x1000), prod)
                prod := mulmod(mload(add(transcript, 0xd20)), prod, f_q)
                mstore(add(transcript, 0x1020), prod)
                prod := mulmod(mload(add(transcript, 0xd60)), prod, f_q)
                mstore(add(transcript, 0x1040), prod)
                prod := mulmod(mload(add(transcript, 0xda0)), prod, f_q)
                mstore(add(transcript, 0x1060), prod)
                prod := mulmod(mload(add(transcript, 0xde0)), prod, f_q)
                mstore(add(transcript, 0x1080), prod)
                prod := mulmod(mload(add(transcript, 0xe20)), prod, f_q)
                mstore(add(transcript, 0x10a0), prod)
                prod := mulmod(mload(add(transcript, 0xe60)), prod, f_q)
                mstore(add(transcript, 0x10c0), prod)
                prod := mulmod(mload(add(transcript, 0xea0)), prod, f_q)
                mstore(add(transcript, 0x10e0), prod)
                prod := mulmod(mload(add(transcript, 0xee0)), prod, f_q)
                mstore(add(transcript, 0x1100), prod)
                prod := mulmod(mload(add(transcript, 0xf20)), prod, f_q)
                mstore(add(transcript, 0x1120), prod)
                prod := mulmod(mload(add(transcript, 0xf60)), prod, f_q)
                mstore(add(transcript, 0x1140), prod)
                prod := mulmod(mload(add(transcript, 0xfa0)), prod, f_q)
                mstore(add(transcript, 0x1160), prod)
                prod := mulmod(mload(add(transcript, 0xfe0)), prod, f_q)
                mstore(add(transcript, 0x1180), prod)
                prod := mulmod(mload(add(transcript, 0xc40)), prod, f_q)
                mstore(add(transcript, 0x11a0), prod)
            }
            mstore(add(transcript, 0x11e0), 32)
            mstore(add(transcript, 0x1200), 32)
            mstore(add(transcript, 0x1220), 32)
            mstore(add(transcript, 0x1240), mload(add(transcript, 0x11a0)))
            mstore(
                add(transcript, 0x1260),
                21888242871839275222246405745257275088548364400416034343698204186575808495615
            )
            mstore(
                add(transcript, 0x1280),
                21888242871839275222246405745257275088548364400416034343698204186575808495617
            )
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x5,
                        add(transcript, 0x11e0),
                        0xc0,
                        add(transcript, 0x11c0),
                        0x20
                    ),
                    1
                ),
                success
            )
            {
                let inv := mload(add(transcript, 0x11c0))
                let v
                v := mload(add(transcript, 0xc40))
                mstore(
                    add(transcript, 0xc40),
                    mulmod(mload(add(transcript, 0x1180)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0xfe0))
                mstore(
                    add(transcript, 0xfe0),
                    mulmod(mload(add(transcript, 0x1160)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0xfa0))
                mstore(
                    add(transcript, 0xfa0),
                    mulmod(mload(add(transcript, 0x1140)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0xf60))
                mstore(
                    add(transcript, 0xf60),
                    mulmod(mload(add(transcript, 0x1120)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0xf20))
                mstore(
                    add(transcript, 0xf20),
                    mulmod(mload(add(transcript, 0x1100)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0xee0))
                mstore(
                    add(transcript, 0xee0),
                    mulmod(mload(add(transcript, 0x10e0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0xea0))
                mstore(
                    add(transcript, 0xea0),
                    mulmod(mload(add(transcript, 0x10c0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0xe60))
                mstore(
                    add(transcript, 0xe60),
                    mulmod(mload(add(transcript, 0x10a0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0xe20))
                mstore(
                    add(transcript, 0xe20),
                    mulmod(mload(add(transcript, 0x1080)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0xde0))
                mstore(
                    add(transcript, 0xde0),
                    mulmod(mload(add(transcript, 0x1060)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0xda0))
                mstore(
                    add(transcript, 0xda0),
                    mulmod(mload(add(transcript, 0x1040)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0xd60))
                mstore(
                    add(transcript, 0xd60),
                    mulmod(mload(add(transcript, 0x1020)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0xd20))
                mstore(
                    add(transcript, 0xd20),
                    mulmod(mload(add(transcript, 0x1000)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0xce0))
                mstore(
                    add(transcript, 0xce0),
                    mulmod(mload(add(transcript, 0xca0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                mstore(add(transcript, 0xca0), inv)
            }
            mstore(
                add(transcript, 0x12a0),
                mulmod(
                    mload(add(transcript, 0xc80)),
                    mload(add(transcript, 0xca0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x12c0),
                mulmod(
                    mload(add(transcript, 0xcc0)),
                    mload(add(transcript, 0xce0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x12e0),
                mulmod(
                    mload(add(transcript, 0xd00)),
                    mload(add(transcript, 0xd20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1300),
                mulmod(
                    mload(add(transcript, 0xd40)),
                    mload(add(transcript, 0xd60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1320),
                mulmod(
                    mload(add(transcript, 0xd80)),
                    mload(add(transcript, 0xda0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1340),
                mulmod(
                    mload(add(transcript, 0xdc0)),
                    mload(add(transcript, 0xde0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1360),
                mulmod(
                    mload(add(transcript, 0xe00)),
                    mload(add(transcript, 0xe20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1380),
                mulmod(
                    mload(add(transcript, 0xe40)),
                    mload(add(transcript, 0xe60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x13a0),
                mulmod(
                    mload(add(transcript, 0xe80)),
                    mload(add(transcript, 0xea0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x13c0),
                mulmod(
                    mload(add(transcript, 0xec0)),
                    mload(add(transcript, 0xee0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x13e0),
                mulmod(
                    mload(add(transcript, 0xf00)),
                    mload(add(transcript, 0xf20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1400),
                mulmod(
                    mload(add(transcript, 0xf40)),
                    mload(add(transcript, 0xf60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1420),
                mulmod(
                    mload(add(transcript, 0xf80)),
                    mload(add(transcript, 0xfa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1440),
                mulmod(
                    mload(add(transcript, 0xfc0)),
                    mload(add(transcript, 0xfe0)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x1380)),
                    mload(add(transcript, 0x20)),
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x13a0)),
                        mload(add(transcript, 0x40)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x13c0)),
                        mload(add(transcript, 0x60)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x13e0)),
                        mload(add(transcript, 0x80)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x1400)),
                        mload(add(transcript, 0xa0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x1420)),
                        mload(add(transcript, 0xc0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x1440)),
                        mload(add(transcript, 0xe0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x1460), result)
            }
            mstore(
                add(transcript, 0x1480),
                mulmod(
                    mload(add(transcript, 0x5a0)),
                    mload(add(transcript, 0x580)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x14a0),
                addmod(
                    mload(add(transcript, 0x560)),
                    mload(add(transcript, 0x1480)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x14c0),
                addmod(
                    mload(add(transcript, 0x14a0)),
                    sub(f_q, mload(add(transcript, 0x5c0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x14e0),
                mulmod(
                    mload(add(transcript, 0x14c0)),
                    mload(add(transcript, 0x640)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1500),
                mulmod(
                    mload(add(transcript, 0x3c0)),
                    mload(add(transcript, 0x14e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1520),
                addmod(1, sub(f_q, mload(add(transcript, 0x6e0))), f_q)
            )
            mstore(
                add(transcript, 0x1540),
                mulmod(
                    mload(add(transcript, 0x1520)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1560),
                addmod(
                    mload(add(transcript, 0x1500)),
                    mload(add(transcript, 0x1540)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1580),
                mulmod(
                    mload(add(transcript, 0x3c0)),
                    mload(add(transcript, 0x1560)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x15a0),
                mulmod(
                    mload(add(transcript, 0x6e0)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x15c0),
                addmod(
                    mload(add(transcript, 0x15a0)),
                    sub(f_q, mload(add(transcript, 0x6e0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x15e0),
                mulmod(
                    mload(add(transcript, 0x15c0)),
                    mload(add(transcript, 0x12a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1600),
                addmod(
                    mload(add(transcript, 0x1580)),
                    mload(add(transcript, 0x15e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1620),
                mulmod(
                    mload(add(transcript, 0x3c0)),
                    mload(add(transcript, 0x1600)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1640),
                addmod(1, sub(f_q, mload(add(transcript, 0x12a0))), f_q)
            )
            mstore(
                add(transcript, 0x1660),
                addmod(
                    mload(add(transcript, 0x12c0)),
                    mload(add(transcript, 0x12e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1680),
                addmod(
                    mload(add(transcript, 0x1660)),
                    mload(add(transcript, 0x1300)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x16a0),
                addmod(
                    mload(add(transcript, 0x1680)),
                    mload(add(transcript, 0x1320)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x16c0),
                addmod(
                    mload(add(transcript, 0x16a0)),
                    mload(add(transcript, 0x1340)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x16e0),
                addmod(
                    mload(add(transcript, 0x16c0)),
                    mload(add(transcript, 0x1360)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1700),
                addmod(
                    mload(add(transcript, 0x1640)),
                    sub(f_q, mload(add(transcript, 0x16e0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1720),
                mulmod(
                    mload(add(transcript, 0x680)),
                    mload(add(transcript, 0x240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1740),
                addmod(
                    mload(add(transcript, 0x5e0)),
                    mload(add(transcript, 0x1720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1760),
                addmod(
                    mload(add(transcript, 0x1740)),
                    mload(add(transcript, 0x2a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1780),
                mulmod(
                    mload(add(transcript, 0x6a0)),
                    mload(add(transcript, 0x240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x17a0),
                addmod(
                    mload(add(transcript, 0x560)),
                    mload(add(transcript, 0x1780)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x17c0),
                addmod(
                    mload(add(transcript, 0x17a0)),
                    mload(add(transcript, 0x2a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x17e0),
                mulmod(
                    mload(add(transcript, 0x17c0)),
                    mload(add(transcript, 0x1760)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1800),
                mulmod(
                    mload(add(transcript, 0x6c0)),
                    mload(add(transcript, 0x240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1820),
                addmod(
                    mload(add(transcript, 0x1460)),
                    mload(add(transcript, 0x1800)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1840),
                addmod(
                    mload(add(transcript, 0x1820)),
                    mload(add(transcript, 0x2a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1860),
                mulmod(
                    mload(add(transcript, 0x1840)),
                    mload(add(transcript, 0x17e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1880),
                mulmod(
                    mload(add(transcript, 0x1860)),
                    mload(add(transcript, 0x700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x18a0),
                mulmod(1, mload(add(transcript, 0x240)), f_q)
            )
            mstore(
                add(transcript, 0x18c0),
                mulmod(
                    mload(add(transcript, 0x520)),
                    mload(add(transcript, 0x18a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x18e0),
                addmod(
                    mload(add(transcript, 0x5e0)),
                    mload(add(transcript, 0x18c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1900),
                addmod(
                    mload(add(transcript, 0x18e0)),
                    mload(add(transcript, 0x2a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1920),
                mulmod(
                    4131629893567559867359510883348571134090853742863529169391034518566172092834,
                    mload(add(transcript, 0x240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1940),
                mulmod(
                    mload(add(transcript, 0x520)),
                    mload(add(transcript, 0x1920)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1960),
                addmod(
                    mload(add(transcript, 0x560)),
                    mload(add(transcript, 0x1940)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1980),
                addmod(
                    mload(add(transcript, 0x1960)),
                    mload(add(transcript, 0x2a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x19a0),
                mulmod(
                    mload(add(transcript, 0x1980)),
                    mload(add(transcript, 0x1900)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x19c0),
                mulmod(
                    8910878055287538404433155982483128285667088683464058436815641868457422632747,
                    mload(add(transcript, 0x240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x19e0),
                mulmod(
                    mload(add(transcript, 0x520)),
                    mload(add(transcript, 0x19c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a00),
                addmod(
                    mload(add(transcript, 0x1460)),
                    mload(add(transcript, 0x19e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a20),
                addmod(
                    mload(add(transcript, 0x1a00)),
                    mload(add(transcript, 0x2a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a40),
                mulmod(
                    mload(add(transcript, 0x1a20)),
                    mload(add(transcript, 0x19a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a60),
                mulmod(
                    mload(add(transcript, 0x1a40)),
                    mload(add(transcript, 0x6e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a80),
                addmod(
                    mload(add(transcript, 0x1880)),
                    sub(f_q, mload(add(transcript, 0x1a60))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1aa0),
                mulmod(
                    mload(add(transcript, 0x1a80)),
                    mload(add(transcript, 0x1700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ac0),
                addmod(
                    mload(add(transcript, 0x1620)),
                    mload(add(transcript, 0x1aa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ae0),
                mulmod(
                    mload(add(transcript, 0x3c0)),
                    mload(add(transcript, 0x1ac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b00),
                addmod(1, sub(f_q, mload(add(transcript, 0x720))), f_q)
            )
            mstore(
                add(transcript, 0x1b20),
                mulmod(
                    mload(add(transcript, 0x1b00)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b40),
                addmod(
                    mload(add(transcript, 0x1ae0)),
                    mload(add(transcript, 0x1b20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b60),
                mulmod(
                    mload(add(transcript, 0x3c0)),
                    mload(add(transcript, 0x1b40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1b80),
                mulmod(
                    mload(add(transcript, 0x720)),
                    mload(add(transcript, 0x720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ba0),
                addmod(
                    mload(add(transcript, 0x1b80)),
                    sub(f_q, mload(add(transcript, 0x720))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1bc0),
                mulmod(
                    mload(add(transcript, 0x1ba0)),
                    mload(add(transcript, 0x12a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1be0),
                addmod(
                    mload(add(transcript, 0x1b60)),
                    mload(add(transcript, 0x1bc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c00),
                mulmod(
                    mload(add(transcript, 0x3c0)),
                    mload(add(transcript, 0x1be0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c20),
                addmod(
                    mload(add(transcript, 0x760)),
                    mload(add(transcript, 0x240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c40),
                mulmod(
                    mload(add(transcript, 0x1c20)),
                    mload(add(transcript, 0x740)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c60),
                addmod(
                    mload(add(transcript, 0x7a0)),
                    mload(add(transcript, 0x2a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1c80),
                mulmod(
                    mload(add(transcript, 0x1c60)),
                    mload(add(transcript, 0x1c40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ca0),
                mulmod(
                    mload(add(transcript, 0x560)),
                    mload(add(transcript, 0x620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1cc0),
                addmod(
                    mload(add(transcript, 0x1ca0)),
                    mload(add(transcript, 0x240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ce0),
                mulmod(
                    mload(add(transcript, 0x1cc0)),
                    mload(add(transcript, 0x720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d00),
                addmod(
                    mload(add(transcript, 0x600)),
                    mload(add(transcript, 0x2a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d20),
                mulmod(
                    mload(add(transcript, 0x1d00)),
                    mload(add(transcript, 0x1ce0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d40),
                addmod(
                    mload(add(transcript, 0x1c80)),
                    sub(f_q, mload(add(transcript, 0x1d20))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d60),
                mulmod(
                    mload(add(transcript, 0x1d40)),
                    mload(add(transcript, 0x1700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1d80),
                addmod(
                    mload(add(transcript, 0x1c00)),
                    mload(add(transcript, 0x1d60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1da0),
                mulmod(
                    mload(add(transcript, 0x3c0)),
                    mload(add(transcript, 0x1d80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1dc0),
                addmod(
                    mload(add(transcript, 0x760)),
                    sub(f_q, mload(add(transcript, 0x7a0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1de0),
                mulmod(
                    mload(add(transcript, 0x1dc0)),
                    mload(add(transcript, 0x1380)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1e00),
                addmod(
                    mload(add(transcript, 0x1da0)),
                    mload(add(transcript, 0x1de0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1e20),
                mulmod(
                    mload(add(transcript, 0x3c0)),
                    mload(add(transcript, 0x1e00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1e40),
                mulmod(
                    mload(add(transcript, 0x1dc0)),
                    mload(add(transcript, 0x1700)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1e60),
                addmod(
                    mload(add(transcript, 0x760)),
                    sub(f_q, mload(add(transcript, 0x780))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1e80),
                mulmod(
                    mload(add(transcript, 0x1e60)),
                    mload(add(transcript, 0x1e40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ea0),
                addmod(
                    mload(add(transcript, 0x1e20)),
                    mload(add(transcript, 0x1e80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ec0),
                mulmod(
                    mload(add(transcript, 0xc20)),
                    mload(add(transcript, 0xc20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1ee0),
                mulmod(
                    mload(add(transcript, 0x1ec0)),
                    mload(add(transcript, 0xc20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1f00),
                mulmod(
                    mload(add(transcript, 0x1ee0)),
                    mload(add(transcript, 0xc20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1f20),
                mulmod(1, mload(add(transcript, 0xc20)), f_q)
            )
            mstore(
                add(transcript, 0x1f40),
                mulmod(1, mload(add(transcript, 0x1ec0)), f_q)
            )
            mstore(
                add(transcript, 0x1f60),
                mulmod(1, mload(add(transcript, 0x1ee0)), f_q)
            )
            mstore(
                add(transcript, 0x1f80),
                mulmod(
                    mload(add(transcript, 0x1ea0)),
                    mload(add(transcript, 0xc40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1fa0),
                mulmod(
                    mload(add(transcript, 0x980)),
                    mload(add(transcript, 0x980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1fc0),
                mulmod(
                    mload(add(transcript, 0x1fa0)),
                    mload(add(transcript, 0x980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1fe0),
                mulmod(
                    mload(add(transcript, 0x1fc0)),
                    mload(add(transcript, 0x980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2000),
                mulmod(
                    mload(add(transcript, 0x1fe0)),
                    mload(add(transcript, 0x980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2020),
                mulmod(
                    mload(add(transcript, 0x7e0)),
                    mload(add(transcript, 0x7e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2040),
                mulmod(
                    mload(add(transcript, 0x2020)),
                    mload(add(transcript, 0x7e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2060),
                mulmod(
                    mload(add(transcript, 0x2040)),
                    mload(add(transcript, 0x7e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2080),
                mulmod(
                    mload(add(transcript, 0x2060)),
                    mload(add(transcript, 0x7e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x20a0),
                mulmod(
                    mload(add(transcript, 0x2080)),
                    mload(add(transcript, 0x7e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x20c0),
                mulmod(
                    mload(add(transcript, 0x20a0)),
                    mload(add(transcript, 0x7e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x20e0),
                mulmod(
                    mload(add(transcript, 0x20c0)),
                    mload(add(transcript, 0x7e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2100),
                mulmod(
                    mload(add(transcript, 0x20e0)),
                    mload(add(transcript, 0x7e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2120),
                mulmod(
                    mload(add(transcript, 0x2100)),
                    mload(add(transcript, 0x7e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2140),
                mulmod(
                    mload(add(transcript, 0x2120)),
                    mload(add(transcript, 0x7e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2160),
                mulmod(
                    mload(add(transcript, 0x2140)),
                    mload(add(transcript, 0x7e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2180),
                mulmod(
                    mload(add(transcript, 0x2160)),
                    mload(add(transcript, 0x7e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x21a0),
                mulmod(
                    mload(add(transcript, 0x2180)),
                    mload(add(transcript, 0x7e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x21c0),
                mulmod(sub(f_q, mload(add(transcript, 0x560))), 1, f_q)
            )
            mstore(
                add(transcript, 0x21e0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x6e0))),
                    mload(add(transcript, 0x7e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2200),
                mulmod(1, mload(add(transcript, 0x7e0)), f_q)
            )
            mstore(
                add(transcript, 0x2220),
                addmod(
                    mload(add(transcript, 0x21c0)),
                    mload(add(transcript, 0x21e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2240),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x720))),
                    mload(add(transcript, 0x2020)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2260),
                mulmod(1, mload(add(transcript, 0x2020)), f_q)
            )
            mstore(
                add(transcript, 0x2280),
                addmod(
                    mload(add(transcript, 0x2220)),
                    mload(add(transcript, 0x2240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x22a0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x760))),
                    mload(add(transcript, 0x2040)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x22c0),
                mulmod(1, mload(add(transcript, 0x2040)), f_q)
            )
            mstore(
                add(transcript, 0x22e0),
                addmod(
                    mload(add(transcript, 0x2280)),
                    mload(add(transcript, 0x22a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2300),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x7a0))),
                    mload(add(transcript, 0x2060)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2320),
                mulmod(1, mload(add(transcript, 0x2060)), f_q)
            )
            mstore(
                add(transcript, 0x2340),
                addmod(
                    mload(add(transcript, 0x22e0)),
                    mload(add(transcript, 0x2300)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2360),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x5e0))),
                    mload(add(transcript, 0x2080)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2380),
                mulmod(1, mload(add(transcript, 0x2080)), f_q)
            )
            mstore(
                add(transcript, 0x23a0),
                addmod(
                    mload(add(transcript, 0x2340)),
                    mload(add(transcript, 0x2360)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x23c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x600))),
                    mload(add(transcript, 0x20a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x23e0),
                mulmod(1, mload(add(transcript, 0x20a0)), f_q)
            )
            mstore(
                add(transcript, 0x2400),
                addmod(
                    mload(add(transcript, 0x23a0)),
                    mload(add(transcript, 0x23c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2420),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x620))),
                    mload(add(transcript, 0x20c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2440),
                mulmod(1, mload(add(transcript, 0x20c0)), f_q)
            )
            mstore(
                add(transcript, 0x2460),
                addmod(
                    mload(add(transcript, 0x2400)),
                    mload(add(transcript, 0x2420)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2480),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x640))),
                    mload(add(transcript, 0x20e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x24a0),
                mulmod(1, mload(add(transcript, 0x20e0)), f_q)
            )
            mstore(
                add(transcript, 0x24c0),
                addmod(
                    mload(add(transcript, 0x2460)),
                    mload(add(transcript, 0x2480)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x24e0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x680))),
                    mload(add(transcript, 0x2100)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2500),
                mulmod(1, mload(add(transcript, 0x2100)), f_q)
            )
            mstore(
                add(transcript, 0x2520),
                addmod(
                    mload(add(transcript, 0x24c0)),
                    mload(add(transcript, 0x24e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2540),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x6a0))),
                    mload(add(transcript, 0x2120)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2560),
                mulmod(1, mload(add(transcript, 0x2120)), f_q)
            )
            mstore(
                add(transcript, 0x2580),
                addmod(
                    mload(add(transcript, 0x2520)),
                    mload(add(transcript, 0x2540)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x25a0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x6c0))),
                    mload(add(transcript, 0x2140)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x25c0),
                mulmod(1, mload(add(transcript, 0x2140)), f_q)
            )
            mstore(
                add(transcript, 0x25e0),
                addmod(
                    mload(add(transcript, 0x2580)),
                    mload(add(transcript, 0x25a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2600),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x1f80))),
                    mload(add(transcript, 0x2160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2620),
                mulmod(1, mload(add(transcript, 0x2160)), f_q)
            )
            mstore(
                add(transcript, 0x2640),
                mulmod(
                    mload(add(transcript, 0x1f20)),
                    mload(add(transcript, 0x2160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2660),
                mulmod(
                    mload(add(transcript, 0x1f40)),
                    mload(add(transcript, 0x2160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2680),
                mulmod(
                    mload(add(transcript, 0x1f60)),
                    mload(add(transcript, 0x2160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x26a0),
                addmod(
                    mload(add(transcript, 0x25e0)),
                    mload(add(transcript, 0x2600)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x26c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x660))),
                    mload(add(transcript, 0x2180)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x26e0),
                mulmod(1, mload(add(transcript, 0x2180)), f_q)
            )
            mstore(
                add(transcript, 0x2700),
                addmod(
                    mload(add(transcript, 0x26a0)),
                    mload(add(transcript, 0x26c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2720),
                mulmod(mload(add(transcript, 0x2700)), 1, f_q)
            )
            mstore(
                add(transcript, 0x2740),
                mulmod(mload(add(transcript, 0x2200)), 1, f_q)
            )
            mstore(
                add(transcript, 0x2760),
                mulmod(mload(add(transcript, 0x2260)), 1, f_q)
            )
            mstore(
                add(transcript, 0x2780),
                mulmod(mload(add(transcript, 0x22c0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x27a0),
                mulmod(mload(add(transcript, 0x2320)), 1, f_q)
            )
            mstore(
                add(transcript, 0x27c0),
                mulmod(mload(add(transcript, 0x2380)), 1, f_q)
            )
            mstore(
                add(transcript, 0x27e0),
                mulmod(mload(add(transcript, 0x23e0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x2800),
                mulmod(mload(add(transcript, 0x2440)), 1, f_q)
            )
            mstore(
                add(transcript, 0x2820),
                mulmod(mload(add(transcript, 0x24a0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x2840),
                mulmod(mload(add(transcript, 0x2500)), 1, f_q)
            )
            mstore(
                add(transcript, 0x2860),
                mulmod(mload(add(transcript, 0x2560)), 1, f_q)
            )
            mstore(
                add(transcript, 0x2880),
                mulmod(mload(add(transcript, 0x25c0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x28a0),
                mulmod(mload(add(transcript, 0x2620)), 1, f_q)
            )
            mstore(
                add(transcript, 0x28c0),
                mulmod(mload(add(transcript, 0x2640)), 1, f_q)
            )
            mstore(
                add(transcript, 0x28e0),
                mulmod(mload(add(transcript, 0x2660)), 1, f_q)
            )
            mstore(
                add(transcript, 0x2900),
                mulmod(mload(add(transcript, 0x2680)), 1, f_q)
            )
            mstore(
                add(transcript, 0x2920),
                mulmod(mload(add(transcript, 0x26e0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x2940),
                mulmod(sub(f_q, mload(add(transcript, 0x580))), 1, f_q)
            )
            mstore(
                add(transcript, 0x2960),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x700))),
                    mload(add(transcript, 0x7e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2980),
                addmod(
                    mload(add(transcript, 0x2940)),
                    mload(add(transcript, 0x2960)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29a0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x740))),
                    mload(add(transcript, 0x2020)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29c0),
                addmod(
                    mload(add(transcript, 0x2980)),
                    mload(add(transcript, 0x29a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29e0),
                mulmod(
                    mload(add(transcript, 0x29c0)),
                    mload(add(transcript, 0x980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a00),
                mulmod(1, mload(add(transcript, 0x980)), f_q)
            )
            mstore(
                add(transcript, 0x2a20),
                mulmod(
                    mload(add(transcript, 0x2200)),
                    mload(add(transcript, 0x980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a40),
                mulmod(
                    mload(add(transcript, 0x2260)),
                    mload(add(transcript, 0x980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a60),
                addmod(
                    mload(add(transcript, 0x2720)),
                    mload(add(transcript, 0x29e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a80),
                addmod(1, mload(add(transcript, 0x2a00)), f_q)
            )
            mstore(
                add(transcript, 0x2aa0),
                addmod(
                    mload(add(transcript, 0x2740)),
                    mload(add(transcript, 0x2a20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ac0),
                addmod(
                    mload(add(transcript, 0x2760)),
                    mload(add(transcript, 0x2a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ae0),
                mulmod(sub(f_q, mload(add(transcript, 0x5a0))), 1, f_q)
            )
            mstore(
                add(transcript, 0x2b00),
                mulmod(
                    mload(add(transcript, 0x2ae0)),
                    mload(add(transcript, 0x1fa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b20),
                mulmod(1, mload(add(transcript, 0x1fa0)), f_q)
            )
            mstore(
                add(transcript, 0x2b40),
                addmod(
                    mload(add(transcript, 0x2a60)),
                    mload(add(transcript, 0x2b00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b60),
                addmod(
                    mload(add(transcript, 0x2a80)),
                    mload(add(transcript, 0x2b20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b80),
                mulmod(sub(f_q, mload(add(transcript, 0x5c0))), 1, f_q)
            )
            mstore(
                add(transcript, 0x2ba0),
                mulmod(
                    mload(add(transcript, 0x2b80)),
                    mload(add(transcript, 0x1fc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2bc0),
                mulmod(1, mload(add(transcript, 0x1fc0)), f_q)
            )
            mstore(
                add(transcript, 0x2be0),
                addmod(
                    mload(add(transcript, 0x2b40)),
                    mload(add(transcript, 0x2ba0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c00),
                addmod(
                    mload(add(transcript, 0x2b60)),
                    mload(add(transcript, 0x2bc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c20),
                mulmod(sub(f_q, mload(add(transcript, 0x780))), 1, f_q)
            )
            mstore(
                add(transcript, 0x2c40),
                mulmod(
                    mload(add(transcript, 0x2c20)),
                    mload(add(transcript, 0x1fe0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c60),
                mulmod(1, mload(add(transcript, 0x1fe0)), f_q)
            )
            mstore(
                add(transcript, 0x2c80),
                addmod(
                    mload(add(transcript, 0x2be0)),
                    mload(add(transcript, 0x2c40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ca0),
                addmod(
                    mload(add(transcript, 0x2780)),
                    mload(add(transcript, 0x2c60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2cc0),
                mulmod(1, mload(add(transcript, 0x520)), f_q)
            )
            mstore(
                add(transcript, 0x2ce0),
                mulmod(1, mload(add(transcript, 0x2cc0)), f_q)
            )
            mstore(
                add(transcript, 0x2d00),
                mulmod(
                    19032961837237948602743626455740240236231119053033140765040043513661803148152,
                    mload(add(transcript, 0x520)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d20),
                mulmod(
                    mload(add(transcript, 0x2a00)),
                    mload(add(transcript, 0x2d00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d40),
                mulmod(
                    5854133144571823792863860130267644613802765696134002830362054821530146160770,
                    mload(add(transcript, 0x520)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d60),
                mulmod(
                    mload(add(transcript, 0x2b20)),
                    mload(add(transcript, 0x2d40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d80),
                mulmod(
                    9697063347556872083384215826199993067635178715531258559890418744774301211662,
                    mload(add(transcript, 0x520)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2da0),
                mulmod(
                    mload(add(transcript, 0x2bc0)),
                    mload(add(transcript, 0x2d80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2dc0),
                mulmod(
                    15402826414547299628414612080036060696555554914079673875872749760617770134879,
                    mload(add(transcript, 0x520)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2de0),
                mulmod(
                    mload(add(transcript, 0x2c60)),
                    mload(add(transcript, 0x2dc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e00),
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            mstore(
                add(transcript, 0x2e20),
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            mstore(add(transcript, 0x2e40), mload(add(transcript, 0x2c80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x2e00),
                        0x60,
                        add(transcript, 0x2e00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x2e60), mload(add(transcript, 0x100)))
            mstore(add(transcript, 0x2e80), mload(add(transcript, 0x120)))
            mstore(add(transcript, 0x2ea0), mload(add(transcript, 0x2c00)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x2e60),
                        0x60,
                        add(transcript, 0x2e60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x2ec0), mload(add(transcript, 0x2e00)))
            mstore(add(transcript, 0x2ee0), mload(add(transcript, 0x2e20)))
            mstore(add(transcript, 0x2f00), mload(add(transcript, 0x2e60)))
            mstore(add(transcript, 0x2f20), mload(add(transcript, 0x2e80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x2ec0),
                        0x80,
                        add(transcript, 0x2ec0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x2f40), mload(add(transcript, 0x2e0)))
            mstore(add(transcript, 0x2f60), mload(add(transcript, 0x300)))
            mstore(add(transcript, 0x2f80), mload(add(transcript, 0x2aa0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x2f40),
                        0x60,
                        add(transcript, 0x2f40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x2fa0), mload(add(transcript, 0x2ec0)))
            mstore(add(transcript, 0x2fc0), mload(add(transcript, 0x2ee0)))
            mstore(add(transcript, 0x2fe0), mload(add(transcript, 0x2f40)))
            mstore(add(transcript, 0x3000), mload(add(transcript, 0x2f60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x2fa0),
                        0x80,
                        add(transcript, 0x2fa0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3020), mload(add(transcript, 0x320)))
            mstore(add(transcript, 0x3040), mload(add(transcript, 0x340)))
            mstore(add(transcript, 0x3060), mload(add(transcript, 0x2ac0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x3020),
                        0x60,
                        add(transcript, 0x3020),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3080), mload(add(transcript, 0x2fa0)))
            mstore(add(transcript, 0x30a0), mload(add(transcript, 0x2fc0)))
            mstore(add(transcript, 0x30c0), mload(add(transcript, 0x3020)))
            mstore(add(transcript, 0x30e0), mload(add(transcript, 0x3040)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x3080),
                        0x80,
                        add(transcript, 0x3080),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3100), mload(add(transcript, 0x1a0)))
            mstore(add(transcript, 0x3120), mload(add(transcript, 0x1c0)))
            mstore(add(transcript, 0x3140), mload(add(transcript, 0x2ca0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x3100),
                        0x60,
                        add(transcript, 0x3100),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3160), mload(add(transcript, 0x3080)))
            mstore(add(transcript, 0x3180), mload(add(transcript, 0x30a0)))
            mstore(add(transcript, 0x31a0), mload(add(transcript, 0x3100)))
            mstore(add(transcript, 0x31c0), mload(add(transcript, 0x3120)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x3160),
                        0x80,
                        add(transcript, 0x3160),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x31e0), mload(add(transcript, 0x1e0)))
            mstore(add(transcript, 0x3200), mload(add(transcript, 0x200)))
            mstore(add(transcript, 0x3220), mload(add(transcript, 0x27a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x31e0),
                        0x60,
                        add(transcript, 0x31e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3240), mload(add(transcript, 0x3160)))
            mstore(add(transcript, 0x3260), mload(add(transcript, 0x3180)))
            mstore(add(transcript, 0x3280), mload(add(transcript, 0x31e0)))
            mstore(add(transcript, 0x32a0), mload(add(transcript, 0x3200)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x3240),
                        0x80,
                        add(transcript, 0x3240),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x32c0),
                0x0995f93a54b0e285369916a264f8c0ae83cc3518d6345ab15f039bb1bf42b11a
            )
            mstore(
                add(transcript, 0x32e0),
                0x2abde374611d234f945070bb971bd2ba1bd5646fe88b26624a4a53947823106d
            )
            mstore(add(transcript, 0x3300), mload(add(transcript, 0x27c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x32c0),
                        0x60,
                        add(transcript, 0x32c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3320), mload(add(transcript, 0x3240)))
            mstore(add(transcript, 0x3340), mload(add(transcript, 0x3260)))
            mstore(add(transcript, 0x3360), mload(add(transcript, 0x32c0)))
            mstore(add(transcript, 0x3380), mload(add(transcript, 0x32e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x3320),
                        0x80,
                        add(transcript, 0x3320),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x33a0),
                0x07f70134a46bee8e3af2e041b227b82910d50e5d1e5201a7ad5c117aa140c47b
            )
            mstore(
                add(transcript, 0x33c0),
                0x15a2a99b119d10c38cd3e59076e6229b229849700bbbbefc0ba78b5b40e22439
            )
            mstore(add(transcript, 0x33e0), mload(add(transcript, 0x27e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x33a0),
                        0x60,
                        add(transcript, 0x33a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3400), mload(add(transcript, 0x3320)))
            mstore(add(transcript, 0x3420), mload(add(transcript, 0x3340)))
            mstore(add(transcript, 0x3440), mload(add(transcript, 0x33a0)))
            mstore(add(transcript, 0x3460), mload(add(transcript, 0x33c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x3400),
                        0x80,
                        add(transcript, 0x3400),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x3480),
                0x13eaa429a93802360d3caacadbfef206f830f6d99d1711ff0f7b9bfd57a2a59a
            )
            mstore(
                add(transcript, 0x34a0),
                0x006b98dc9d8030d70a88db44b0577c46ae29021db5b61a224fd287b4f32bc29d
            )
            mstore(add(transcript, 0x34c0), mload(add(transcript, 0x2800)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x3480),
                        0x60,
                        add(transcript, 0x3480),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x34e0), mload(add(transcript, 0x3400)))
            mstore(add(transcript, 0x3500), mload(add(transcript, 0x3420)))
            mstore(add(transcript, 0x3520), mload(add(transcript, 0x3480)))
            mstore(add(transcript, 0x3540), mload(add(transcript, 0x34a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x34e0),
                        0x80,
                        add(transcript, 0x34e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x3560),
                0x15a2ba003053e21561696aa11486d6d6971f080296124435bdd92f9c47e0251b
            )
            mstore(
                add(transcript, 0x3580),
                0x09d27c24548e7af1ac99e4b3de2ff072710d18dabe754fed3ec16fec8f823608
            )
            mstore(add(transcript, 0x35a0), mload(add(transcript, 0x2820)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x3560),
                        0x60,
                        add(transcript, 0x3560),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x35c0), mload(add(transcript, 0x34e0)))
            mstore(add(transcript, 0x35e0), mload(add(transcript, 0x3500)))
            mstore(add(transcript, 0x3600), mload(add(transcript, 0x3560)))
            mstore(add(transcript, 0x3620), mload(add(transcript, 0x3580)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x35c0),
                        0x80,
                        add(transcript, 0x35c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x3640),
                0x2f822012fe3f287ed55243bfaf1b10a645e2594e1a57a294a669aa1d8006e677
            )
            mstore(
                add(transcript, 0x3660),
                0x1b79d5fc3f6d85ca366e491fe04d23b1a10d719d8f48e18e2f78aa16c46804e5
            )
            mstore(add(transcript, 0x3680), mload(add(transcript, 0x2840)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x3640),
                        0x60,
                        add(transcript, 0x3640),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x36a0), mload(add(transcript, 0x35c0)))
            mstore(add(transcript, 0x36c0), mload(add(transcript, 0x35e0)))
            mstore(add(transcript, 0x36e0), mload(add(transcript, 0x3640)))
            mstore(add(transcript, 0x3700), mload(add(transcript, 0x3660)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x36a0),
                        0x80,
                        add(transcript, 0x36a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x3720),
                0x0edc13d4445da674079a8d70ec5780a2a8b661e084e87b3720f1f61f30c7a190
            )
            mstore(
                add(transcript, 0x3740),
                0x13a48652fd49d60374251fa0166d3399938f68d2769508abad8588de8a980f3c
            )
            mstore(add(transcript, 0x3760), mload(add(transcript, 0x2860)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x3720),
                        0x60,
                        add(transcript, 0x3720),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3780), mload(add(transcript, 0x36a0)))
            mstore(add(transcript, 0x37a0), mload(add(transcript, 0x36c0)))
            mstore(add(transcript, 0x37c0), mload(add(transcript, 0x3720)))
            mstore(add(transcript, 0x37e0), mload(add(transcript, 0x3740)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x3780),
                        0x80,
                        add(transcript, 0x3780),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x3800),
                0x16468a9cad37b40ae434b8735b65067af6dd8571f56151c599b856faef3531d1
            )
            mstore(
                add(transcript, 0x3820),
                0x0e33db5f797bdc53032f11f163dd2927cbb96e589197943d10237de4196476d1
            )
            mstore(add(transcript, 0x3840), mload(add(transcript, 0x2880)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x3800),
                        0x60,
                        add(transcript, 0x3800),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3860), mload(add(transcript, 0x3780)))
            mstore(add(transcript, 0x3880), mload(add(transcript, 0x37a0)))
            mstore(add(transcript, 0x38a0), mload(add(transcript, 0x3800)))
            mstore(add(transcript, 0x38c0), mload(add(transcript, 0x3820)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x3860),
                        0x80,
                        add(transcript, 0x3860),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x38e0), mload(add(transcript, 0x400)))
            mstore(add(transcript, 0x3900), mload(add(transcript, 0x420)))
            mstore(add(transcript, 0x3920), mload(add(transcript, 0x28a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x38e0),
                        0x60,
                        add(transcript, 0x38e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3940), mload(add(transcript, 0x3860)))
            mstore(add(transcript, 0x3960), mload(add(transcript, 0x3880)))
            mstore(add(transcript, 0x3980), mload(add(transcript, 0x38e0)))
            mstore(add(transcript, 0x39a0), mload(add(transcript, 0x3900)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x3940),
                        0x80,
                        add(transcript, 0x3940),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x39c0), mload(add(transcript, 0x440)))
            mstore(add(transcript, 0x39e0), mload(add(transcript, 0x460)))
            mstore(add(transcript, 0x3a00), mload(add(transcript, 0x28c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x39c0),
                        0x60,
                        add(transcript, 0x39c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3a20), mload(add(transcript, 0x3940)))
            mstore(add(transcript, 0x3a40), mload(add(transcript, 0x3960)))
            mstore(add(transcript, 0x3a60), mload(add(transcript, 0x39c0)))
            mstore(add(transcript, 0x3a80), mload(add(transcript, 0x39e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x3a20),
                        0x80,
                        add(transcript, 0x3a20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3aa0), mload(add(transcript, 0x480)))
            mstore(add(transcript, 0x3ac0), mload(add(transcript, 0x4a0)))
            mstore(add(transcript, 0x3ae0), mload(add(transcript, 0x28e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x3aa0),
                        0x60,
                        add(transcript, 0x3aa0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3b00), mload(add(transcript, 0x3a20)))
            mstore(add(transcript, 0x3b20), mload(add(transcript, 0x3a40)))
            mstore(add(transcript, 0x3b40), mload(add(transcript, 0x3aa0)))
            mstore(add(transcript, 0x3b60), mload(add(transcript, 0x3ac0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x3b00),
                        0x80,
                        add(transcript, 0x3b00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3b80), mload(add(transcript, 0x4c0)))
            mstore(add(transcript, 0x3ba0), mload(add(transcript, 0x4e0)))
            mstore(add(transcript, 0x3bc0), mload(add(transcript, 0x2900)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x3b80),
                        0x60,
                        add(transcript, 0x3b80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3be0), mload(add(transcript, 0x3b00)))
            mstore(add(transcript, 0x3c00), mload(add(transcript, 0x3b20)))
            mstore(add(transcript, 0x3c20), mload(add(transcript, 0x3b80)))
            mstore(add(transcript, 0x3c40), mload(add(transcript, 0x3ba0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x3be0),
                        0x80,
                        add(transcript, 0x3be0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3c60), mload(add(transcript, 0x360)))
            mstore(add(transcript, 0x3c80), mload(add(transcript, 0x380)))
            mstore(add(transcript, 0x3ca0), mload(add(transcript, 0x2920)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x3c60),
                        0x60,
                        add(transcript, 0x3c60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3cc0), mload(add(transcript, 0x3be0)))
            mstore(add(transcript, 0x3ce0), mload(add(transcript, 0x3c00)))
            mstore(add(transcript, 0x3d00), mload(add(transcript, 0x3c60)))
            mstore(add(transcript, 0x3d20), mload(add(transcript, 0x3c80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x3cc0),
                        0x80,
                        add(transcript, 0x3cc0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3d40), mload(add(transcript, 0x820)))
            mstore(add(transcript, 0x3d60), mload(add(transcript, 0x840)))
            mstore(add(transcript, 0x3d80), mload(add(transcript, 0x2ce0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x3d40),
                        0x60,
                        add(transcript, 0x3d40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3da0), mload(add(transcript, 0x3cc0)))
            mstore(add(transcript, 0x3dc0), mload(add(transcript, 0x3ce0)))
            mstore(add(transcript, 0x3de0), mload(add(transcript, 0x3d40)))
            mstore(add(transcript, 0x3e00), mload(add(transcript, 0x3d60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x3da0),
                        0x80,
                        add(transcript, 0x3da0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3e20), mload(add(transcript, 0x860)))
            mstore(add(transcript, 0x3e40), mload(add(transcript, 0x880)))
            mstore(add(transcript, 0x3e60), mload(add(transcript, 0x2d20)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x3e20),
                        0x60,
                        add(transcript, 0x3e20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3e80), mload(add(transcript, 0x3da0)))
            mstore(add(transcript, 0x3ea0), mload(add(transcript, 0x3dc0)))
            mstore(add(transcript, 0x3ec0), mload(add(transcript, 0x3e20)))
            mstore(add(transcript, 0x3ee0), mload(add(transcript, 0x3e40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x3e80),
                        0x80,
                        add(transcript, 0x3e80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3f00), mload(add(transcript, 0x8a0)))
            mstore(add(transcript, 0x3f20), mload(add(transcript, 0x8c0)))
            mstore(add(transcript, 0x3f40), mload(add(transcript, 0x2d60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x3f00),
                        0x60,
                        add(transcript, 0x3f00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3f60), mload(add(transcript, 0x3e80)))
            mstore(add(transcript, 0x3f80), mload(add(transcript, 0x3ea0)))
            mstore(add(transcript, 0x3fa0), mload(add(transcript, 0x3f00)))
            mstore(add(transcript, 0x3fc0), mload(add(transcript, 0x3f20)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x3f60),
                        0x80,
                        add(transcript, 0x3f60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3fe0), mload(add(transcript, 0x8e0)))
            mstore(add(transcript, 0x4000), mload(add(transcript, 0x900)))
            mstore(add(transcript, 0x4020), mload(add(transcript, 0x2da0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x3fe0),
                        0x60,
                        add(transcript, 0x3fe0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4040), mload(add(transcript, 0x3f60)))
            mstore(add(transcript, 0x4060), mload(add(transcript, 0x3f80)))
            mstore(add(transcript, 0x4080), mload(add(transcript, 0x3fe0)))
            mstore(add(transcript, 0x40a0), mload(add(transcript, 0x4000)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4040),
                        0x80,
                        add(transcript, 0x4040),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x40c0), mload(add(transcript, 0x920)))
            mstore(add(transcript, 0x40e0), mload(add(transcript, 0x940)))
            mstore(add(transcript, 0x4100), mload(add(transcript, 0x2de0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x40c0),
                        0x60,
                        add(transcript, 0x40c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4120), mload(add(transcript, 0x4040)))
            mstore(add(transcript, 0x4140), mload(add(transcript, 0x4060)))
            mstore(add(transcript, 0x4160), mload(add(transcript, 0x40c0)))
            mstore(add(transcript, 0x4180), mload(add(transcript, 0x40e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4120),
                        0x80,
                        add(transcript, 0x4120),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x41a0), mload(add(transcript, 0x860)))
            mstore(add(transcript, 0x41c0), mload(add(transcript, 0x880)))
            mstore(add(transcript, 0x41e0), mload(add(transcript, 0x2a00)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x41a0),
                        0x60,
                        add(transcript, 0x41a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4200), mload(add(transcript, 0x820)))
            mstore(add(transcript, 0x4220), mload(add(transcript, 0x840)))
            mstore(add(transcript, 0x4240), mload(add(transcript, 0x41a0)))
            mstore(add(transcript, 0x4260), mload(add(transcript, 0x41c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4200),
                        0x80,
                        add(transcript, 0x4200),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4280), mload(add(transcript, 0x8a0)))
            mstore(add(transcript, 0x42a0), mload(add(transcript, 0x8c0)))
            mstore(add(transcript, 0x42c0), mload(add(transcript, 0x2b20)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4280),
                        0x60,
                        add(transcript, 0x4280),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x42e0), mload(add(transcript, 0x4200)))
            mstore(add(transcript, 0x4300), mload(add(transcript, 0x4220)))
            mstore(add(transcript, 0x4320), mload(add(transcript, 0x4280)))
            mstore(add(transcript, 0x4340), mload(add(transcript, 0x42a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x42e0),
                        0x80,
                        add(transcript, 0x42e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4360), mload(add(transcript, 0x8e0)))
            mstore(add(transcript, 0x4380), mload(add(transcript, 0x900)))
            mstore(add(transcript, 0x43a0), mload(add(transcript, 0x2bc0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4360),
                        0x60,
                        add(transcript, 0x4360),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x43c0), mload(add(transcript, 0x42e0)))
            mstore(add(transcript, 0x43e0), mload(add(transcript, 0x4300)))
            mstore(add(transcript, 0x4400), mload(add(transcript, 0x4360)))
            mstore(add(transcript, 0x4420), mload(add(transcript, 0x4380)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x43c0),
                        0x80,
                        add(transcript, 0x43c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4440), mload(add(transcript, 0x920)))
            mstore(add(transcript, 0x4460), mload(add(transcript, 0x940)))
            mstore(add(transcript, 0x4480), mload(add(transcript, 0x2c60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4440),
                        0x60,
                        add(transcript, 0x4440),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x44a0), mload(add(transcript, 0x43c0)))
            mstore(add(transcript, 0x44c0), mload(add(transcript, 0x43e0)))
            mstore(add(transcript, 0x44e0), mload(add(transcript, 0x4440)))
            mstore(add(transcript, 0x4500), mload(add(transcript, 0x4460)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x44a0),
                        0x80,
                        add(transcript, 0x44a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4520), mload(add(transcript, 0x4120)))
            mstore(add(transcript, 0x4540), mload(add(transcript, 0x4140)))
            mstore(
                add(transcript, 0x4560),
                0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
            )
            mstore(
                add(transcript, 0x4580),
                0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
            )
            mstore(
                add(transcript, 0x45a0),
                0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
            )
            mstore(
                add(transcript, 0x45c0),
                0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
            )
            mstore(add(transcript, 0x45e0), mload(add(transcript, 0x44a0)))
            mstore(add(transcript, 0x4600), mload(add(transcript, 0x44c0)))
            mstore(
                add(transcript, 0x4620),
                0x1a841de4ef28295bb0f595db8ba843466c05ba433095a9bf6603d334a58fa4a0
            )
            mstore(
                add(transcript, 0x4640),
                0x0ed2763108f401e9a91572f9a492ffff2c1c48e8230c2f39297a278ed1316bd5
            )
            mstore(
                add(transcript, 0x4660),
                0x24b642f23220c156d35570de68511f3a2540741cd5cd485ffc3e1ff3599c00f2
            )
            mstore(
                add(transcript, 0x4680),
                0x25cdb46289be9daf2bd56f895e4f15101e47481acaf36c393c08bd0de206ca05
            )
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x8,
                        add(transcript, 0x4520),
                        0x180,
                        add(transcript, 0x4520),
                        0x20
                    ),
                    1
                ),
                success
            )
            success := and(eq(mload(add(transcript, 0x4520)), 1), success)
        }
        return success;
    }
}
