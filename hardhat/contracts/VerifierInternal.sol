// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract VerifierInternal {
    function verify(
        uint256[] memory pubInputs,
        bytes memory proof
    ) public view returns (bool) {
        bool success = true;
        bytes32[704] memory transcript;
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
                add(transcript, 0x100),
                mod(mload(add(pubInputs, 0x100)), f_q)
            )
            mstore(
                add(transcript, 0x120),
                mod(mload(add(pubInputs, 0x120)), f_q)
            )
            mstore(
                add(transcript, 0x140),
                mod(mload(add(pubInputs, 0x140)), f_q)
            )
            mstore(
                add(transcript, 0x160),
                mod(mload(add(pubInputs, 0x160)), f_q)
            )
            mstore(
                add(transcript, 0x180),
                mod(mload(add(pubInputs, 0x180)), f_q)
            )
            mstore(
                add(transcript, 0x1a0),
                mod(mload(add(pubInputs, 0x1a0)), f_q)
            )
            mstore(
                add(transcript, 0x1c0),
                mod(mload(add(pubInputs, 0x1c0)), f_q)
            )
            mstore(
                add(transcript, 0x1e0),
                mod(mload(add(pubInputs, 0x1e0)), f_q)
            )
            mstore(
                add(transcript, 0x200),
                mod(mload(add(pubInputs, 0x200)), f_q)
            )
            mstore(
                add(transcript, 0x220),
                mod(mload(add(pubInputs, 0x220)), f_q)
            )
            mstore(
                add(transcript, 0x240),
                mod(mload(add(pubInputs, 0x240)), f_q)
            )
            mstore(
                add(transcript, 0x260),
                mod(mload(add(pubInputs, 0x260)), f_q)
            )
            mstore(
                add(transcript, 0x280),
                mod(mload(add(pubInputs, 0x280)), f_q)
            )
            mstore(add(transcript, 0x2a0), mod(mload(add(proof, 0x20)), f_q))
            mstore(add(transcript, 0x2c0), mod(mload(add(proof, 0x40)), f_q))
            mstore(add(transcript, 0x2e0), mod(mload(add(proof, 0x60)), f_q))
            mstore(add(transcript, 0x300), mod(mload(add(proof, 0x80)), f_q))
            mstore(add(transcript, 0x320), mod(mload(add(proof, 0xa0)), f_q))
            mstore(add(transcript, 0x340), mod(mload(add(proof, 0xc0)), f_q))
            mstore(add(transcript, 0x360), mod(mload(add(proof, 0xe0)), f_q))
            mstore(add(transcript, 0x380), mod(mload(add(proof, 0x100)), f_q))
            mstore(add(transcript, 0x3a0), mod(mload(add(proof, 0x120)), f_q))
            mstore(add(transcript, 0x3c0), mod(mload(add(proof, 0x140)), f_q))
            mstore(add(transcript, 0x3e0), mod(mload(add(proof, 0x160)), f_q))
            mstore(add(transcript, 0x400), mod(mload(add(proof, 0x180)), f_q))
            mstore(add(transcript, 0x420), mod(mload(add(proof, 0x1a0)), f_q))
            mstore(add(transcript, 0x440), mod(mload(add(proof, 0x1c0)), f_q))
            mstore(add(transcript, 0x460), mod(mload(add(proof, 0x1e0)), f_q))
            mstore(
                add(transcript, 0x0),
                17926999494198467412118256602507877937845791544163809932907480898415559187714
            )
            {
                let x := mload(add(proof, 0x200))
                mstore(add(transcript, 0x480), x)
                let y := mload(add(proof, 0x220))
                mstore(add(transcript, 0x4a0), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x4c0),
                keccak256(add(transcript, 0x0), 1216)
            )
            {
                let hash := mload(add(transcript, 0x4c0))
                mstore(add(transcript, 0x4e0), mod(hash, f_q))
                mstore(add(transcript, 0x500), hash)
            }
            {
                let x := mload(add(proof, 0x240))
                mstore(add(transcript, 0x520), x)
                let y := mload(add(proof, 0x260))
                mstore(add(transcript, 0x540), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x280))
                mstore(add(transcript, 0x560), x)
                let y := mload(add(proof, 0x2a0))
                mstore(add(transcript, 0x580), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x5a0),
                keccak256(add(transcript, 0x500), 160)
            )
            {
                let hash := mload(add(transcript, 0x5a0))
                mstore(add(transcript, 0x5c0), mod(hash, f_q))
                mstore(add(transcript, 0x5e0), hash)
            }
            mstore8(add(transcript, 0x600), 1)
            mstore(
                add(transcript, 0x600),
                keccak256(add(transcript, 0x5e0), 33)
            )
            {
                let hash := mload(add(transcript, 0x600))
                mstore(add(transcript, 0x620), mod(hash, f_q))
                mstore(add(transcript, 0x640), hash)
            }
            {
                let x := mload(add(proof, 0x2c0))
                mstore(add(transcript, 0x660), x)
                let y := mload(add(proof, 0x2e0))
                mstore(add(transcript, 0x680), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x300))
                mstore(add(transcript, 0x6a0), x)
                let y := mload(add(proof, 0x320))
                mstore(add(transcript, 0x6c0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x340))
                mstore(add(transcript, 0x6e0), x)
                let y := mload(add(proof, 0x360))
                mstore(add(transcript, 0x700), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x720),
                keccak256(add(transcript, 0x640), 224)
            )
            {
                let hash := mload(add(transcript, 0x720))
                mstore(add(transcript, 0x740), mod(hash, f_q))
                mstore(add(transcript, 0x760), hash)
            }
            {
                let x := mload(add(proof, 0x380))
                mstore(add(transcript, 0x780), x)
                let y := mload(add(proof, 0x3a0))
                mstore(add(transcript, 0x7a0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x3c0))
                mstore(add(transcript, 0x7c0), x)
                let y := mload(add(proof, 0x3e0))
                mstore(add(transcript, 0x7e0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x400))
                mstore(add(transcript, 0x800), x)
                let y := mload(add(proof, 0x420))
                mstore(add(transcript, 0x820), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x440))
                mstore(add(transcript, 0x840), x)
                let y := mload(add(proof, 0x460))
                mstore(add(transcript, 0x860), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0x880),
                keccak256(add(transcript, 0x760), 288)
            )
            {
                let hash := mload(add(transcript, 0x880))
                mstore(add(transcript, 0x8a0), mod(hash, f_q))
                mstore(add(transcript, 0x8c0), hash)
            }
            mstore(add(transcript, 0x8e0), mod(mload(add(proof, 0x480)), f_q))
            mstore(add(transcript, 0x900), mod(mload(add(proof, 0x4a0)), f_q))
            mstore(add(transcript, 0x920), mod(mload(add(proof, 0x4c0)), f_q))
            mstore(add(transcript, 0x940), mod(mload(add(proof, 0x4e0)), f_q))
            mstore(add(transcript, 0x960), mod(mload(add(proof, 0x500)), f_q))
            mstore(add(transcript, 0x980), mod(mload(add(proof, 0x520)), f_q))
            mstore(add(transcript, 0x9a0), mod(mload(add(proof, 0x540)), f_q))
            mstore(add(transcript, 0x9c0), mod(mload(add(proof, 0x560)), f_q))
            mstore(add(transcript, 0x9e0), mod(mload(add(proof, 0x580)), f_q))
            mstore(add(transcript, 0xa00), mod(mload(add(proof, 0x5a0)), f_q))
            mstore(add(transcript, 0xa20), mod(mload(add(proof, 0x5c0)), f_q))
            mstore(add(transcript, 0xa40), mod(mload(add(proof, 0x5e0)), f_q))
            mstore(add(transcript, 0xa60), mod(mload(add(proof, 0x600)), f_q))
            mstore(add(transcript, 0xa80), mod(mload(add(proof, 0x620)), f_q))
            mstore(add(transcript, 0xaa0), mod(mload(add(proof, 0x640)), f_q))
            mstore(add(transcript, 0xac0), mod(mload(add(proof, 0x660)), f_q))
            mstore(add(transcript, 0xae0), mod(mload(add(proof, 0x680)), f_q))
            mstore(add(transcript, 0xb00), mod(mload(add(proof, 0x6a0)), f_q))
            mstore(add(transcript, 0xb20), mod(mload(add(proof, 0x6c0)), f_q))
            mstore(
                add(transcript, 0xb40),
                keccak256(add(transcript, 0x8c0), 640)
            )
            {
                let hash := mload(add(transcript, 0xb40))
                mstore(add(transcript, 0xb60), mod(hash, f_q))
                mstore(add(transcript, 0xb80), hash)
            }
            {
                let x := mload(add(proof, 0x6e0))
                mstore(add(transcript, 0xba0), x)
                let y := mload(add(proof, 0x700))
                mstore(add(transcript, 0xbc0), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x720))
                mstore(add(transcript, 0xbe0), x)
                let y := mload(add(proof, 0x740))
                mstore(add(transcript, 0xc00), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x760))
                mstore(add(transcript, 0xc20), x)
                let y := mload(add(proof, 0x780))
                mstore(add(transcript, 0xc40), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x7a0))
                mstore(add(transcript, 0xc60), x)
                let y := mload(add(proof, 0x7c0))
                mstore(add(transcript, 0xc80), y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(add(proof, 0x7e0))
                mstore(add(transcript, 0xca0), x)
                let y := mload(add(proof, 0x800))
                mstore(add(transcript, 0xcc0), y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(
                add(transcript, 0xce0),
                keccak256(add(transcript, 0xb80), 352)
            )
            {
                let hash := mload(add(transcript, 0xce0))
                mstore(add(transcript, 0xd00), mod(hash, f_q))
                mstore(add(transcript, 0xd20), hash)
            }
            mstore(
                add(transcript, 0xd40),
                mulmod(
                    mload(add(transcript, 0x8a0)),
                    mload(add(transcript, 0x8a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xd60),
                mulmod(
                    mload(add(transcript, 0xd40)),
                    mload(add(transcript, 0xd40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xd80),
                mulmod(
                    mload(add(transcript, 0xd60)),
                    mload(add(transcript, 0xd60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xda0),
                mulmod(
                    mload(add(transcript, 0xd80)),
                    mload(add(transcript, 0xd80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xdc0),
                mulmod(
                    mload(add(transcript, 0xda0)),
                    mload(add(transcript, 0xda0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xde0),
                mulmod(
                    mload(add(transcript, 0xdc0)),
                    mload(add(transcript, 0xdc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe00),
                mulmod(
                    mload(add(transcript, 0xde0)),
                    mload(add(transcript, 0xde0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe20),
                mulmod(
                    mload(add(transcript, 0xe00)),
                    mload(add(transcript, 0xe00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe40),
                mulmod(
                    mload(add(transcript, 0xe20)),
                    mload(add(transcript, 0xe20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe60),
                mulmod(
                    mload(add(transcript, 0xe40)),
                    mload(add(transcript, 0xe40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xe80),
                mulmod(
                    mload(add(transcript, 0xe60)),
                    mload(add(transcript, 0xe60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xea0),
                mulmod(
                    mload(add(transcript, 0xe80)),
                    mload(add(transcript, 0xe80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xec0),
                mulmod(
                    mload(add(transcript, 0xea0)),
                    mload(add(transcript, 0xea0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xee0),
                mulmod(
                    mload(add(transcript, 0xec0)),
                    mload(add(transcript, 0xec0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf00),
                mulmod(
                    mload(add(transcript, 0xee0)),
                    mload(add(transcript, 0xee0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf20),
                mulmod(
                    mload(add(transcript, 0xf00)),
                    mload(add(transcript, 0xf00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf40),
                mulmod(
                    mload(add(transcript, 0xf20)),
                    mload(add(transcript, 0xf20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf60),
                mulmod(
                    mload(add(transcript, 0xf40)),
                    mload(add(transcript, 0xf40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xf80),
                mulmod(
                    mload(add(transcript, 0xf60)),
                    mload(add(transcript, 0xf60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xfa0),
                mulmod(
                    mload(add(transcript, 0xf80)),
                    mload(add(transcript, 0xf80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0xfc0),
                addmod(
                    mload(add(transcript, 0xfa0)),
                    21888242871839275222246405745257275088548364400416034343698204186575808495616,
                    f_q
                )
            )
            mstore(
                add(transcript, 0xfe0),
                mulmod(
                    mload(add(transcript, 0xfc0)),
                    21888221997584217086951279548962733484243966294447177135413498358668068307201,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1000),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    3021657639704125634180027002055603444074884651778695243656177678924693902744,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1020),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    18866585232135149588066378743201671644473479748637339100042026507651114592873,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1040),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    13315224328250071823986980334210714047804323884995968263773489477577155309695,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1060),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    8573018543589203398259425411046561040744040515420066079924714708998653185922,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1080),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    6852144584591678924477440653887876563116097870276213106119596023961179534039,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x10a0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    15036098287247596297768965091369398525432266530139821237578608162614628961578,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x10c0),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    6363119021782681274480715230122258277189830284152385293217720612674619714422,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x10e0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    15525123850056593947765690515135016811358534116263649050480483573901188781195,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1100),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    495188420091111145957709789221178673495499187437761988132837836548330853701,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1120),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    21393054451748164076288695956036096415052865212978272355565366350027477641916,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1140),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    14686510910986211321976396297238126901237973400949744736326777596334651355305,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1160),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    7201731960853063900270009448019148187310390999466289607371426590241157140312,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1180),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    15402826414547299628414612080036060696555554914079673875872749760617770134879,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x11a0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    6485416457291975593831793665221214391992809486336360467825454425958038360738,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x11c0),
                mulmod(mload(add(transcript, 0xfe0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x11e0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    21888242871839275222246405745257275088548364400416034343698204186575808495616,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1200),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    19032961837237948602743626455740240236231119053033140765040043513661803148152,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1220),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    2855281034601326619502779289517034852317245347382893578658160672914005347465,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1240),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    5854133144571823792863860130267644613802765696134002830362054821530146160770,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1260),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    16034109727267451429382545614989630474745598704282031513336149365045662334847,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1280),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    9697063347556872083384215826199993067635178715531258559890418744774301211662,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x12a0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    12191179524282403138862189919057282020913185684884775783807785441801507283955,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x12c0),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    6955697244493336113861667751840378876927906302623587437721024018233754910398,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x12e0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    14932545627345939108384737993416896211620458097792446905977180168342053585219,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1300),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    5289443209903185443361862148540090689648485914368835830972895623576469023722,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1320),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    16598799661936089778884543596717184398899878486047198512725308562999339471895,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1340),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    4509404676247677387317362072810231899718070082381452255950861037254608304934,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1360),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    17378838195591597834929043672447043188830294318034582087747343149321200190683,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1380),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    2579947959091681244170407980400327834520881737801886423874592072501514087543,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x13a0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    19308294912747593978075997764856947254027482662614147919823612114074294408074,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x13c0),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    21846745818185811051373434299876022191132089169516983080959277716660228899818,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x13e0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    41497053653464170872971445381252897416275230899051262738926469915579595799,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1400),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    1459528961030896569807206253631725410868595642414057264270714861278164633285,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1420),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    20428713910808378652439199491625549677679768758001977079427489325297643862332,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1440),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    21594472933355353940227302948201802990541640451776958309590170926766063614527,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1460),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    293769938483921282019102797055472098006723948639076034108033259809744881090,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1480),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    9228489335593836417731216695316971397516686186585289059470421738439643366942,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x14a0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    12659753536245438804515189049940303691031678213830745284227782448136165128675,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x14c0),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    13526759757306252939732186602630155490343117803221487512984160143178057306805,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x14e0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    8361483114533022282514219142627119598205246597194546830714044043397751188812,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1500),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    16722112256235738599640138637711059524347378135686596767512885208913020182609,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1520),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    5166130615603536622606267107546215564200986264729437576185318977662788313008,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1540),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    13098481875020205420942233016824212164786287930169045450599302794675261377069,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1560),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    8789760996819069801304172728433062923762076470246988893098901391900547118548,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1580),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    11377070488770263259987342577173204149358055510182982082489928583535951905289,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x15a0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    10511172383069011962259063168084070939190308890233052261208275603039856590328,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x15c0),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    4443263508319656594054352481848447997537391617204595126809744742387004492585,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x15e0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    17444979363519618628192053263408827091010972783211439216888459444188804003032,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1600),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    19985282492189863552708916346580412311177862193769287858714131049050994424713,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1620),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    1902960379649411669537489398676862777370502206646746484984073137524814070904,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1640),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    14097108278147741990520379122266872928869658252366071399515986875510798690086,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1660),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    7791134593691533231726026622990402159678706148049962944182217311065009805531,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1680),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    6627785884599252700762253281725354514166862545029838477137108799418301075772,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x16a0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    15260456987240022521484152463531920574381501855386195866561095387157507419845,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x16c0),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    17903030951520571210920333716852671101035531163558200326249599288512346109298,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x16e0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    3985211920318704011326072028404603987512833236857834017448604898063462386319,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1700),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    11035518299930001136359438931464797296692550928390518034154929456101747640464,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1720),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    10852724571909274085886966813792477791855813472025516309543274730474060855153,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1740),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    18688952208745222403383340988737175223354233319065239587068249291731518085091,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1760),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    3199290663094052818863064756520099865194131081350794756629954894844290410526,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1780),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    8090920612475884933082466243206416300093207106708869460568715124120849083471,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x17a0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    13797322259363390289163939502050858788455157293707164883129489062454959412146,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x17c0),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    12491230264321380165669116208790466830459716800431293091713220204712467607643,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x17e0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    9397012607517895056577289536466808258088647599984741251984983981863340887974,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1800),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    14687965552285838243290987533880488643745654567024204451720932257436576359630,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1820),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    7200277319553436978955418211376786444802709833391829891977271929139232135987,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1840),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    10782482590221345366894477779143691555941079397976808158583337170923876671981,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1860),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    11105760281617929855351927966113583532607285002439226185114867015651931823636,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1880),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    1452540440676902820341293582407938150865945383684436373266313854321654075600,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x18a0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    20435702431162372401905112162849336937682419016731597970431890332254154420017,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x18c0),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    13634252820192586424999035792358765796924408729195911337098964638191944583761,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x18e0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    8253990051646688797247369952898509291623955671220123006599239548383863911856,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1900),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    3358079685698890421105181125304567925649305773352495778456565263339712823690,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1920),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    18530163186140384801141224619952707162899058627063538565241638923236095671927,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1940),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    3628700364396504631491042807121099764524754378892978335944181818035417230606,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1960),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    18259542507442770590755362938136175324023610021523056007754022368540391265011,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1980),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    5350958374163400325432855009358668006196165884258454958241166518346196236341,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x19a0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    16537284497675874896813550735898607082352198516157579385457037668229612259276,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x19c0),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    19671853614403325433334785013442879012032153960035114761748042217991436932142,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x19e0),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    2216389257435949788911620731814396076516210440380919581950161968584371563475,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a00),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    11142295966249215492317669079015724767621612808891027770613254683268538304057,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a20),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    10745946905590059729928736666241550320926751591525006573084949503307270191560,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a40),
                mulmod(
                    mload(add(transcript, 0xfe0)),
                    20717288395367212412705396942265759123865597725953187302178122836355445772327,
                    f_q
                )
            )
            mstore(
                add(transcript, 0x1a60),
                addmod(
                    mload(add(transcript, 0x8a0)),
                    1170954476472062809541008802991515964682766674462847041520081350220362723290,
                    f_q
                )
            )
            {
                let prod := mload(add(transcript, 0x1020))
                prod := mulmod(mload(add(transcript, 0x1060)), prod, f_q)
                mstore(add(transcript, 0x1a80), prod)
                prod := mulmod(mload(add(transcript, 0x10a0)), prod, f_q)
                mstore(add(transcript, 0x1aa0), prod)
                prod := mulmod(mload(add(transcript, 0x10e0)), prod, f_q)
                mstore(add(transcript, 0x1ac0), prod)
                prod := mulmod(mload(add(transcript, 0x1120)), prod, f_q)
                mstore(add(transcript, 0x1ae0), prod)
                prod := mulmod(mload(add(transcript, 0x1160)), prod, f_q)
                mstore(add(transcript, 0x1b00), prod)
                prod := mulmod(mload(add(transcript, 0x11a0)), prod, f_q)
                mstore(add(transcript, 0x1b20), prod)
                prod := mulmod(mload(add(transcript, 0x11e0)), prod, f_q)
                mstore(add(transcript, 0x1b40), prod)
                prod := mulmod(mload(add(transcript, 0x1220)), prod, f_q)
                mstore(add(transcript, 0x1b60), prod)
                prod := mulmod(mload(add(transcript, 0x1260)), prod, f_q)
                mstore(add(transcript, 0x1b80), prod)
                prod := mulmod(mload(add(transcript, 0x12a0)), prod, f_q)
                mstore(add(transcript, 0x1ba0), prod)
                prod := mulmod(mload(add(transcript, 0x12e0)), prod, f_q)
                mstore(add(transcript, 0x1bc0), prod)
                prod := mulmod(mload(add(transcript, 0x1320)), prod, f_q)
                mstore(add(transcript, 0x1be0), prod)
                prod := mulmod(mload(add(transcript, 0x1360)), prod, f_q)
                mstore(add(transcript, 0x1c00), prod)
                prod := mulmod(mload(add(transcript, 0x13a0)), prod, f_q)
                mstore(add(transcript, 0x1c20), prod)
                prod := mulmod(mload(add(transcript, 0x13e0)), prod, f_q)
                mstore(add(transcript, 0x1c40), prod)
                prod := mulmod(mload(add(transcript, 0x1420)), prod, f_q)
                mstore(add(transcript, 0x1c60), prod)
                prod := mulmod(mload(add(transcript, 0x1460)), prod, f_q)
                mstore(add(transcript, 0x1c80), prod)
                prod := mulmod(mload(add(transcript, 0x14a0)), prod, f_q)
                mstore(add(transcript, 0x1ca0), prod)
                prod := mulmod(mload(add(transcript, 0x14e0)), prod, f_q)
                mstore(add(transcript, 0x1cc0), prod)
                prod := mulmod(mload(add(transcript, 0x1520)), prod, f_q)
                mstore(add(transcript, 0x1ce0), prod)
                prod := mulmod(mload(add(transcript, 0x1560)), prod, f_q)
                mstore(add(transcript, 0x1d00), prod)
                prod := mulmod(mload(add(transcript, 0x15a0)), prod, f_q)
                mstore(add(transcript, 0x1d20), prod)
                prod := mulmod(mload(add(transcript, 0x15e0)), prod, f_q)
                mstore(add(transcript, 0x1d40), prod)
                prod := mulmod(mload(add(transcript, 0x1620)), prod, f_q)
                mstore(add(transcript, 0x1d60), prod)
                prod := mulmod(mload(add(transcript, 0x1660)), prod, f_q)
                mstore(add(transcript, 0x1d80), prod)
                prod := mulmod(mload(add(transcript, 0x16a0)), prod, f_q)
                mstore(add(transcript, 0x1da0), prod)
                prod := mulmod(mload(add(transcript, 0x16e0)), prod, f_q)
                mstore(add(transcript, 0x1dc0), prod)
                prod := mulmod(mload(add(transcript, 0x1720)), prod, f_q)
                mstore(add(transcript, 0x1de0), prod)
                prod := mulmod(mload(add(transcript, 0x1760)), prod, f_q)
                mstore(add(transcript, 0x1e00), prod)
                prod := mulmod(mload(add(transcript, 0x17a0)), prod, f_q)
                mstore(add(transcript, 0x1e20), prod)
                prod := mulmod(mload(add(transcript, 0x17e0)), prod, f_q)
                mstore(add(transcript, 0x1e40), prod)
                prod := mulmod(mload(add(transcript, 0x1820)), prod, f_q)
                mstore(add(transcript, 0x1e60), prod)
                prod := mulmod(mload(add(transcript, 0x1860)), prod, f_q)
                mstore(add(transcript, 0x1e80), prod)
                prod := mulmod(mload(add(transcript, 0x18a0)), prod, f_q)
                mstore(add(transcript, 0x1ea0), prod)
                prod := mulmod(mload(add(transcript, 0x18e0)), prod, f_q)
                mstore(add(transcript, 0x1ec0), prod)
                prod := mulmod(mload(add(transcript, 0x1920)), prod, f_q)
                mstore(add(transcript, 0x1ee0), prod)
                prod := mulmod(mload(add(transcript, 0x1960)), prod, f_q)
                mstore(add(transcript, 0x1f00), prod)
                prod := mulmod(mload(add(transcript, 0x19a0)), prod, f_q)
                mstore(add(transcript, 0x1f20), prod)
                prod := mulmod(mload(add(transcript, 0x19e0)), prod, f_q)
                mstore(add(transcript, 0x1f40), prod)
                prod := mulmod(mload(add(transcript, 0x1a20)), prod, f_q)
                mstore(add(transcript, 0x1f60), prod)
                prod := mulmod(mload(add(transcript, 0x1a60)), prod, f_q)
                mstore(add(transcript, 0x1f80), prod)
                prod := mulmod(mload(add(transcript, 0xfc0)), prod, f_q)
                mstore(add(transcript, 0x1fa0), prod)
            }
            mstore(add(transcript, 0x1fe0), 32)
            mstore(add(transcript, 0x2000), 32)
            mstore(add(transcript, 0x2020), 32)
            mstore(add(transcript, 0x2040), mload(add(transcript, 0x1fa0)))
            mstore(
                add(transcript, 0x2060),
                21888242871839275222246405745257275088548364400416034343698204186575808495615
            )
            mstore(
                add(transcript, 0x2080),
                21888242871839275222246405745257275088548364400416034343698204186575808495617
            )
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x5,
                        add(transcript, 0x1fe0),
                        0xc0,
                        add(transcript, 0x1fc0),
                        0x20
                    ),
                    1
                ),
                success
            )
            {
                let inv := mload(add(transcript, 0x1fc0))
                let v
                v := mload(add(transcript, 0xfc0))
                mstore(
                    add(transcript, 0xfc0),
                    mulmod(mload(add(transcript, 0x1f80)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1a60))
                mstore(
                    add(transcript, 0x1a60),
                    mulmod(mload(add(transcript, 0x1f60)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1a20))
                mstore(
                    add(transcript, 0x1a20),
                    mulmod(mload(add(transcript, 0x1f40)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x19e0))
                mstore(
                    add(transcript, 0x19e0),
                    mulmod(mload(add(transcript, 0x1f20)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x19a0))
                mstore(
                    add(transcript, 0x19a0),
                    mulmod(mload(add(transcript, 0x1f00)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1960))
                mstore(
                    add(transcript, 0x1960),
                    mulmod(mload(add(transcript, 0x1ee0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1920))
                mstore(
                    add(transcript, 0x1920),
                    mulmod(mload(add(transcript, 0x1ec0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x18e0))
                mstore(
                    add(transcript, 0x18e0),
                    mulmod(mload(add(transcript, 0x1ea0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x18a0))
                mstore(
                    add(transcript, 0x18a0),
                    mulmod(mload(add(transcript, 0x1e80)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1860))
                mstore(
                    add(transcript, 0x1860),
                    mulmod(mload(add(transcript, 0x1e60)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1820))
                mstore(
                    add(transcript, 0x1820),
                    mulmod(mload(add(transcript, 0x1e40)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x17e0))
                mstore(
                    add(transcript, 0x17e0),
                    mulmod(mload(add(transcript, 0x1e20)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x17a0))
                mstore(
                    add(transcript, 0x17a0),
                    mulmod(mload(add(transcript, 0x1e00)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1760))
                mstore(
                    add(transcript, 0x1760),
                    mulmod(mload(add(transcript, 0x1de0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1720))
                mstore(
                    add(transcript, 0x1720),
                    mulmod(mload(add(transcript, 0x1dc0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x16e0))
                mstore(
                    add(transcript, 0x16e0),
                    mulmod(mload(add(transcript, 0x1da0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x16a0))
                mstore(
                    add(transcript, 0x16a0),
                    mulmod(mload(add(transcript, 0x1d80)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1660))
                mstore(
                    add(transcript, 0x1660),
                    mulmod(mload(add(transcript, 0x1d60)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1620))
                mstore(
                    add(transcript, 0x1620),
                    mulmod(mload(add(transcript, 0x1d40)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x15e0))
                mstore(
                    add(transcript, 0x15e0),
                    mulmod(mload(add(transcript, 0x1d20)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x15a0))
                mstore(
                    add(transcript, 0x15a0),
                    mulmod(mload(add(transcript, 0x1d00)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1560))
                mstore(
                    add(transcript, 0x1560),
                    mulmod(mload(add(transcript, 0x1ce0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1520))
                mstore(
                    add(transcript, 0x1520),
                    mulmod(mload(add(transcript, 0x1cc0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x14e0))
                mstore(
                    add(transcript, 0x14e0),
                    mulmod(mload(add(transcript, 0x1ca0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x14a0))
                mstore(
                    add(transcript, 0x14a0),
                    mulmod(mload(add(transcript, 0x1c80)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1460))
                mstore(
                    add(transcript, 0x1460),
                    mulmod(mload(add(transcript, 0x1c60)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1420))
                mstore(
                    add(transcript, 0x1420),
                    mulmod(mload(add(transcript, 0x1c40)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x13e0))
                mstore(
                    add(transcript, 0x13e0),
                    mulmod(mload(add(transcript, 0x1c20)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x13a0))
                mstore(
                    add(transcript, 0x13a0),
                    mulmod(mload(add(transcript, 0x1c00)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1360))
                mstore(
                    add(transcript, 0x1360),
                    mulmod(mload(add(transcript, 0x1be0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1320))
                mstore(
                    add(transcript, 0x1320),
                    mulmod(mload(add(transcript, 0x1bc0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x12e0))
                mstore(
                    add(transcript, 0x12e0),
                    mulmod(mload(add(transcript, 0x1ba0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x12a0))
                mstore(
                    add(transcript, 0x12a0),
                    mulmod(mload(add(transcript, 0x1b80)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1260))
                mstore(
                    add(transcript, 0x1260),
                    mulmod(mload(add(transcript, 0x1b60)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1220))
                mstore(
                    add(transcript, 0x1220),
                    mulmod(mload(add(transcript, 0x1b40)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x11e0))
                mstore(
                    add(transcript, 0x11e0),
                    mulmod(mload(add(transcript, 0x1b20)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x11a0))
                mstore(
                    add(transcript, 0x11a0),
                    mulmod(mload(add(transcript, 0x1b00)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1160))
                mstore(
                    add(transcript, 0x1160),
                    mulmod(mload(add(transcript, 0x1ae0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1120))
                mstore(
                    add(transcript, 0x1120),
                    mulmod(mload(add(transcript, 0x1ac0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x10e0))
                mstore(
                    add(transcript, 0x10e0),
                    mulmod(mload(add(transcript, 0x1aa0)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x10a0))
                mstore(
                    add(transcript, 0x10a0),
                    mulmod(mload(add(transcript, 0x1a80)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                v := mload(add(transcript, 0x1060))
                mstore(
                    add(transcript, 0x1060),
                    mulmod(mload(add(transcript, 0x1020)), inv, f_q)
                )
                inv := mulmod(v, inv, f_q)
                mstore(add(transcript, 0x1020), inv)
            }
            mstore(
                add(transcript, 0x20a0),
                mulmod(
                    mload(add(transcript, 0x1000)),
                    mload(add(transcript, 0x1020)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x20c0),
                mulmod(
                    mload(add(transcript, 0x1040)),
                    mload(add(transcript, 0x1060)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x20e0),
                mulmod(
                    mload(add(transcript, 0x1080)),
                    mload(add(transcript, 0x10a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2100),
                mulmod(
                    mload(add(transcript, 0x10c0)),
                    mload(add(transcript, 0x10e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2120),
                mulmod(
                    mload(add(transcript, 0x1100)),
                    mload(add(transcript, 0x1120)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2140),
                mulmod(
                    mload(add(transcript, 0x1140)),
                    mload(add(transcript, 0x1160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2160),
                mulmod(
                    mload(add(transcript, 0x1180)),
                    mload(add(transcript, 0x11a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2180),
                mulmod(
                    mload(add(transcript, 0x11c0)),
                    mload(add(transcript, 0x11e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x21a0),
                mulmod(
                    mload(add(transcript, 0x1200)),
                    mload(add(transcript, 0x1220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x21c0),
                mulmod(
                    mload(add(transcript, 0x1240)),
                    mload(add(transcript, 0x1260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x21e0),
                mulmod(
                    mload(add(transcript, 0x1280)),
                    mload(add(transcript, 0x12a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2200),
                mulmod(
                    mload(add(transcript, 0x12c0)),
                    mload(add(transcript, 0x12e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2220),
                mulmod(
                    mload(add(transcript, 0x1300)),
                    mload(add(transcript, 0x1320)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2240),
                mulmod(
                    mload(add(transcript, 0x1340)),
                    mload(add(transcript, 0x1360)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2260),
                mulmod(
                    mload(add(transcript, 0x1380)),
                    mload(add(transcript, 0x13a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2280),
                mulmod(
                    mload(add(transcript, 0x13c0)),
                    mload(add(transcript, 0x13e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x22a0),
                mulmod(
                    mload(add(transcript, 0x1400)),
                    mload(add(transcript, 0x1420)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x22c0),
                mulmod(
                    mload(add(transcript, 0x1440)),
                    mload(add(transcript, 0x1460)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x22e0),
                mulmod(
                    mload(add(transcript, 0x1480)),
                    mload(add(transcript, 0x14a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2300),
                mulmod(
                    mload(add(transcript, 0x14c0)),
                    mload(add(transcript, 0x14e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2320),
                mulmod(
                    mload(add(transcript, 0x1500)),
                    mload(add(transcript, 0x1520)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2340),
                mulmod(
                    mload(add(transcript, 0x1540)),
                    mload(add(transcript, 0x1560)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2360),
                mulmod(
                    mload(add(transcript, 0x1580)),
                    mload(add(transcript, 0x15a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2380),
                mulmod(
                    mload(add(transcript, 0x15c0)),
                    mload(add(transcript, 0x15e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x23a0),
                mulmod(
                    mload(add(transcript, 0x1600)),
                    mload(add(transcript, 0x1620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x23c0),
                mulmod(
                    mload(add(transcript, 0x1640)),
                    mload(add(transcript, 0x1660)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x23e0),
                mulmod(
                    mload(add(transcript, 0x1680)),
                    mload(add(transcript, 0x16a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2400),
                mulmod(
                    mload(add(transcript, 0x16c0)),
                    mload(add(transcript, 0x16e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2420),
                mulmod(
                    mload(add(transcript, 0x1700)),
                    mload(add(transcript, 0x1720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2440),
                mulmod(
                    mload(add(transcript, 0x1740)),
                    mload(add(transcript, 0x1760)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2460),
                mulmod(
                    mload(add(transcript, 0x1780)),
                    mload(add(transcript, 0x17a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2480),
                mulmod(
                    mload(add(transcript, 0x17c0)),
                    mload(add(transcript, 0x17e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x24a0),
                mulmod(
                    mload(add(transcript, 0x1800)),
                    mload(add(transcript, 0x1820)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x24c0),
                mulmod(
                    mload(add(transcript, 0x1840)),
                    mload(add(transcript, 0x1860)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x24e0),
                mulmod(
                    mload(add(transcript, 0x1880)),
                    mload(add(transcript, 0x18a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2500),
                mulmod(
                    mload(add(transcript, 0x18c0)),
                    mload(add(transcript, 0x18e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2520),
                mulmod(
                    mload(add(transcript, 0x1900)),
                    mload(add(transcript, 0x1920)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2540),
                mulmod(
                    mload(add(transcript, 0x1940)),
                    mload(add(transcript, 0x1960)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2560),
                mulmod(
                    mload(add(transcript, 0x1980)),
                    mload(add(transcript, 0x19a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2580),
                mulmod(
                    mload(add(transcript, 0x19c0)),
                    mload(add(transcript, 0x19e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x25a0),
                mulmod(
                    mload(add(transcript, 0x1a00)),
                    mload(add(transcript, 0x1a20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x25c0),
                mulmod(
                    mload(add(transcript, 0x1a40)),
                    mload(add(transcript, 0x1a60)),
                    f_q
                )
            )
            {
                let result := mulmod(
                    mload(add(transcript, 0x2180)),
                    mload(add(transcript, 0x20)),
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x21a0)),
                        mload(add(transcript, 0x40)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x21c0)),
                        mload(add(transcript, 0x60)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x21e0)),
                        mload(add(transcript, 0x80)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2200)),
                        mload(add(transcript, 0xa0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2220)),
                        mload(add(transcript, 0xc0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2240)),
                        mload(add(transcript, 0xe0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2260)),
                        mload(add(transcript, 0x100)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2280)),
                        mload(add(transcript, 0x120)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x22a0)),
                        mload(add(transcript, 0x140)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x22c0)),
                        mload(add(transcript, 0x160)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x22e0)),
                        mload(add(transcript, 0x180)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2300)),
                        mload(add(transcript, 0x1a0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2320)),
                        mload(add(transcript, 0x1c0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2340)),
                        mload(add(transcript, 0x1e0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2360)),
                        mload(add(transcript, 0x200)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2380)),
                        mload(add(transcript, 0x220)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x23a0)),
                        mload(add(transcript, 0x240)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x23c0)),
                        mload(add(transcript, 0x260)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x23e0)),
                        mload(add(transcript, 0x280)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2400)),
                        mload(add(transcript, 0x2a0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2420)),
                        mload(add(transcript, 0x2c0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2440)),
                        mload(add(transcript, 0x2e0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2460)),
                        mload(add(transcript, 0x300)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2480)),
                        mload(add(transcript, 0x320)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x24a0)),
                        mload(add(transcript, 0x340)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x24c0)),
                        mload(add(transcript, 0x360)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x24e0)),
                        mload(add(transcript, 0x380)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2500)),
                        mload(add(transcript, 0x3a0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2520)),
                        mload(add(transcript, 0x3c0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2540)),
                        mload(add(transcript, 0x3e0)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2560)),
                        mload(add(transcript, 0x400)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x2580)),
                        mload(add(transcript, 0x420)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x25a0)),
                        mload(add(transcript, 0x440)),
                        f_q
                    ),
                    result,
                    f_q
                )
                result := addmod(
                    mulmod(
                        mload(add(transcript, 0x25c0)),
                        mload(add(transcript, 0x460)),
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(add(transcript, 0x25e0), result)
            }
            mstore(
                add(transcript, 0x2600),
                mulmod(
                    mload(add(transcript, 0x920)),
                    mload(add(transcript, 0x900)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2620),
                addmod(
                    mload(add(transcript, 0x8e0)),
                    mload(add(transcript, 0x2600)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2640),
                addmod(
                    mload(add(transcript, 0x2620)),
                    sub(f_q, mload(add(transcript, 0x940))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2660),
                mulmod(
                    mload(add(transcript, 0x2640)),
                    mload(add(transcript, 0x9c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2680),
                mulmod(
                    mload(add(transcript, 0x740)),
                    mload(add(transcript, 0x2660)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x26a0),
                addmod(1, sub(f_q, mload(add(transcript, 0xa60))), f_q)
            )
            mstore(
                add(transcript, 0x26c0),
                mulmod(
                    mload(add(transcript, 0x26a0)),
                    mload(add(transcript, 0x2180)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x26e0),
                addmod(
                    mload(add(transcript, 0x2680)),
                    mload(add(transcript, 0x26c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2700),
                mulmod(
                    mload(add(transcript, 0x740)),
                    mload(add(transcript, 0x26e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2720),
                mulmod(
                    mload(add(transcript, 0xa60)),
                    mload(add(transcript, 0xa60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2740),
                addmod(
                    mload(add(transcript, 0x2720)),
                    sub(f_q, mload(add(transcript, 0xa60))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2760),
                mulmod(
                    mload(add(transcript, 0x2740)),
                    mload(add(transcript, 0x20a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2780),
                addmod(
                    mload(add(transcript, 0x2700)),
                    mload(add(transcript, 0x2760)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x27a0),
                mulmod(
                    mload(add(transcript, 0x740)),
                    mload(add(transcript, 0x2780)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x27c0),
                addmod(1, sub(f_q, mload(add(transcript, 0x20a0))), f_q)
            )
            mstore(
                add(transcript, 0x27e0),
                addmod(
                    mload(add(transcript, 0x20c0)),
                    mload(add(transcript, 0x20e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2800),
                addmod(
                    mload(add(transcript, 0x27e0)),
                    mload(add(transcript, 0x2100)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2820),
                addmod(
                    mload(add(transcript, 0x2800)),
                    mload(add(transcript, 0x2120)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2840),
                addmod(
                    mload(add(transcript, 0x2820)),
                    mload(add(transcript, 0x2140)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2860),
                addmod(
                    mload(add(transcript, 0x2840)),
                    mload(add(transcript, 0x2160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2880),
                addmod(
                    mload(add(transcript, 0x27c0)),
                    sub(f_q, mload(add(transcript, 0x2860))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x28a0),
                mulmod(
                    mload(add(transcript, 0xa00)),
                    mload(add(transcript, 0x5c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x28c0),
                addmod(
                    mload(add(transcript, 0x960)),
                    mload(add(transcript, 0x28a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x28e0),
                addmod(
                    mload(add(transcript, 0x28c0)),
                    mload(add(transcript, 0x620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2900),
                mulmod(
                    mload(add(transcript, 0xa20)),
                    mload(add(transcript, 0x5c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2920),
                addmod(
                    mload(add(transcript, 0x8e0)),
                    mload(add(transcript, 0x2900)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2940),
                addmod(
                    mload(add(transcript, 0x2920)),
                    mload(add(transcript, 0x620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2960),
                mulmod(
                    mload(add(transcript, 0x2940)),
                    mload(add(transcript, 0x28e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2980),
                mulmod(
                    mload(add(transcript, 0xa40)),
                    mload(add(transcript, 0x5c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29a0),
                addmod(
                    mload(add(transcript, 0x25e0)),
                    mload(add(transcript, 0x2980)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29c0),
                addmod(
                    mload(add(transcript, 0x29a0)),
                    mload(add(transcript, 0x620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x29e0),
                mulmod(
                    mload(add(transcript, 0x29c0)),
                    mload(add(transcript, 0x2960)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a00),
                mulmod(
                    mload(add(transcript, 0x29e0)),
                    mload(add(transcript, 0xa80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a20),
                mulmod(1, mload(add(transcript, 0x5c0)), f_q)
            )
            mstore(
                add(transcript, 0x2a40),
                mulmod(
                    mload(add(transcript, 0x8a0)),
                    mload(add(transcript, 0x2a20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a60),
                addmod(
                    mload(add(transcript, 0x960)),
                    mload(add(transcript, 0x2a40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2a80),
                addmod(
                    mload(add(transcript, 0x2a60)),
                    mload(add(transcript, 0x620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2aa0),
                mulmod(
                    4131629893567559867359510883348571134090853742863529169391034518566172092834,
                    mload(add(transcript, 0x5c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ac0),
                mulmod(
                    mload(add(transcript, 0x8a0)),
                    mload(add(transcript, 0x2aa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ae0),
                addmod(
                    mload(add(transcript, 0x8e0)),
                    mload(add(transcript, 0x2ac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b00),
                addmod(
                    mload(add(transcript, 0x2ae0)),
                    mload(add(transcript, 0x620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b20),
                mulmod(
                    mload(add(transcript, 0x2b00)),
                    mload(add(transcript, 0x2a80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b40),
                mulmod(
                    8910878055287538404433155982483128285667088683464058436815641868457422632747,
                    mload(add(transcript, 0x5c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b60),
                mulmod(
                    mload(add(transcript, 0x8a0)),
                    mload(add(transcript, 0x2b40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2b80),
                addmod(
                    mload(add(transcript, 0x25e0)),
                    mload(add(transcript, 0x2b60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ba0),
                addmod(
                    mload(add(transcript, 0x2b80)),
                    mload(add(transcript, 0x620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2bc0),
                mulmod(
                    mload(add(transcript, 0x2ba0)),
                    mload(add(transcript, 0x2b20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2be0),
                mulmod(
                    mload(add(transcript, 0x2bc0)),
                    mload(add(transcript, 0xa60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c00),
                addmod(
                    mload(add(transcript, 0x2a00)),
                    sub(f_q, mload(add(transcript, 0x2be0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c20),
                mulmod(
                    mload(add(transcript, 0x2c00)),
                    mload(add(transcript, 0x2880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c40),
                addmod(
                    mload(add(transcript, 0x27a0)),
                    mload(add(transcript, 0x2c20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c60),
                mulmod(
                    mload(add(transcript, 0x740)),
                    mload(add(transcript, 0x2c40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2c80),
                addmod(1, sub(f_q, mload(add(transcript, 0xaa0))), f_q)
            )
            mstore(
                add(transcript, 0x2ca0),
                mulmod(
                    mload(add(transcript, 0x2c80)),
                    mload(add(transcript, 0x2180)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2cc0),
                addmod(
                    mload(add(transcript, 0x2c60)),
                    mload(add(transcript, 0x2ca0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ce0),
                mulmod(
                    mload(add(transcript, 0x740)),
                    mload(add(transcript, 0x2cc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d00),
                mulmod(
                    mload(add(transcript, 0xaa0)),
                    mload(add(transcript, 0xaa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d20),
                addmod(
                    mload(add(transcript, 0x2d00)),
                    sub(f_q, mload(add(transcript, 0xaa0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d40),
                mulmod(
                    mload(add(transcript, 0x2d20)),
                    mload(add(transcript, 0x20a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d60),
                addmod(
                    mload(add(transcript, 0x2ce0)),
                    mload(add(transcript, 0x2d40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2d80),
                mulmod(
                    mload(add(transcript, 0x740)),
                    mload(add(transcript, 0x2d60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2da0),
                addmod(
                    mload(add(transcript, 0xae0)),
                    mload(add(transcript, 0x5c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2dc0),
                mulmod(
                    mload(add(transcript, 0x2da0)),
                    mload(add(transcript, 0xac0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2de0),
                addmod(
                    mload(add(transcript, 0xb20)),
                    mload(add(transcript, 0x620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e00),
                mulmod(
                    mload(add(transcript, 0x2de0)),
                    mload(add(transcript, 0x2dc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e20),
                mulmod(
                    mload(add(transcript, 0x8e0)),
                    mload(add(transcript, 0x9a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e40),
                addmod(
                    mload(add(transcript, 0x2e20)),
                    mload(add(transcript, 0x5c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e60),
                mulmod(
                    mload(add(transcript, 0x2e40)),
                    mload(add(transcript, 0xaa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2e80),
                addmod(
                    mload(add(transcript, 0x980)),
                    mload(add(transcript, 0x620)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ea0),
                mulmod(
                    mload(add(transcript, 0x2e80)),
                    mload(add(transcript, 0x2e60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ec0),
                addmod(
                    mload(add(transcript, 0x2e00)),
                    sub(f_q, mload(add(transcript, 0x2ea0))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2ee0),
                mulmod(
                    mload(add(transcript, 0x2ec0)),
                    mload(add(transcript, 0x2880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f00),
                addmod(
                    mload(add(transcript, 0x2d80)),
                    mload(add(transcript, 0x2ee0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f20),
                mulmod(
                    mload(add(transcript, 0x740)),
                    mload(add(transcript, 0x2f00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f40),
                addmod(
                    mload(add(transcript, 0xae0)),
                    sub(f_q, mload(add(transcript, 0xb20))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f60),
                mulmod(
                    mload(add(transcript, 0x2f40)),
                    mload(add(transcript, 0x2180)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2f80),
                addmod(
                    mload(add(transcript, 0x2f20)),
                    mload(add(transcript, 0x2f60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2fa0),
                mulmod(
                    mload(add(transcript, 0x740)),
                    mload(add(transcript, 0x2f80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2fc0),
                mulmod(
                    mload(add(transcript, 0x2f40)),
                    mload(add(transcript, 0x2880)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x2fe0),
                addmod(
                    mload(add(transcript, 0xae0)),
                    sub(f_q, mload(add(transcript, 0xb00))),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3000),
                mulmod(
                    mload(add(transcript, 0x2fe0)),
                    mload(add(transcript, 0x2fc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3020),
                addmod(
                    mload(add(transcript, 0x2fa0)),
                    mload(add(transcript, 0x3000)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3040),
                mulmod(
                    mload(add(transcript, 0xfa0)),
                    mload(add(transcript, 0xfa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3060),
                mulmod(
                    mload(add(transcript, 0x3040)),
                    mload(add(transcript, 0xfa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3080),
                mulmod(
                    mload(add(transcript, 0x3060)),
                    mload(add(transcript, 0xfa0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x30a0),
                mulmod(1, mload(add(transcript, 0xfa0)), f_q)
            )
            mstore(
                add(transcript, 0x30c0),
                mulmod(1, mload(add(transcript, 0x3040)), f_q)
            )
            mstore(
                add(transcript, 0x30e0),
                mulmod(1, mload(add(transcript, 0x3060)), f_q)
            )
            mstore(
                add(transcript, 0x3100),
                mulmod(
                    mload(add(transcript, 0x3020)),
                    mload(add(transcript, 0xfc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3120),
                mulmod(
                    mload(add(transcript, 0xd00)),
                    mload(add(transcript, 0xd00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3140),
                mulmod(
                    mload(add(transcript, 0x3120)),
                    mload(add(transcript, 0xd00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3160),
                mulmod(
                    mload(add(transcript, 0x3140)),
                    mload(add(transcript, 0xd00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3180),
                mulmod(
                    mload(add(transcript, 0x3160)),
                    mload(add(transcript, 0xd00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x31a0),
                mulmod(
                    mload(add(transcript, 0xb60)),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x31c0),
                mulmod(
                    mload(add(transcript, 0x31a0)),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x31e0),
                mulmod(
                    mload(add(transcript, 0x31c0)),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3200),
                mulmod(
                    mload(add(transcript, 0x31e0)),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3220),
                mulmod(
                    mload(add(transcript, 0x3200)),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3240),
                mulmod(
                    mload(add(transcript, 0x3220)),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3260),
                mulmod(
                    mload(add(transcript, 0x3240)),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3280),
                mulmod(
                    mload(add(transcript, 0x3260)),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x32a0),
                mulmod(
                    mload(add(transcript, 0x3280)),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x32c0),
                mulmod(
                    mload(add(transcript, 0x32a0)),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x32e0),
                mulmod(
                    mload(add(transcript, 0x32c0)),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3300),
                mulmod(
                    mload(add(transcript, 0x32e0)),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3320),
                mulmod(
                    mload(add(transcript, 0x3300)),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3340),
                mulmod(sub(f_q, mload(add(transcript, 0x8e0))), 1, f_q)
            )
            mstore(
                add(transcript, 0x3360),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xa60))),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3380),
                mulmod(1, mload(add(transcript, 0xb60)), f_q)
            )
            mstore(
                add(transcript, 0x33a0),
                addmod(
                    mload(add(transcript, 0x3340)),
                    mload(add(transcript, 0x3360)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x33c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xaa0))),
                    mload(add(transcript, 0x31a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x33e0),
                mulmod(1, mload(add(transcript, 0x31a0)), f_q)
            )
            mstore(
                add(transcript, 0x3400),
                addmod(
                    mload(add(transcript, 0x33a0)),
                    mload(add(transcript, 0x33c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3420),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xae0))),
                    mload(add(transcript, 0x31c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3440),
                mulmod(1, mload(add(transcript, 0x31c0)), f_q)
            )
            mstore(
                add(transcript, 0x3460),
                addmod(
                    mload(add(transcript, 0x3400)),
                    mload(add(transcript, 0x3420)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3480),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xb20))),
                    mload(add(transcript, 0x31e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x34a0),
                mulmod(1, mload(add(transcript, 0x31e0)), f_q)
            )
            mstore(
                add(transcript, 0x34c0),
                addmod(
                    mload(add(transcript, 0x3460)),
                    mload(add(transcript, 0x3480)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x34e0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x960))),
                    mload(add(transcript, 0x3200)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3500),
                mulmod(1, mload(add(transcript, 0x3200)), f_q)
            )
            mstore(
                add(transcript, 0x3520),
                addmod(
                    mload(add(transcript, 0x34c0)),
                    mload(add(transcript, 0x34e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3540),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x980))),
                    mload(add(transcript, 0x3220)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3560),
                mulmod(1, mload(add(transcript, 0x3220)), f_q)
            )
            mstore(
                add(transcript, 0x3580),
                addmod(
                    mload(add(transcript, 0x3520)),
                    mload(add(transcript, 0x3540)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x35a0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x9a0))),
                    mload(add(transcript, 0x3240)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x35c0),
                mulmod(1, mload(add(transcript, 0x3240)), f_q)
            )
            mstore(
                add(transcript, 0x35e0),
                addmod(
                    mload(add(transcript, 0x3580)),
                    mload(add(transcript, 0x35a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3600),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x9c0))),
                    mload(add(transcript, 0x3260)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3620),
                mulmod(1, mload(add(transcript, 0x3260)), f_q)
            )
            mstore(
                add(transcript, 0x3640),
                addmod(
                    mload(add(transcript, 0x35e0)),
                    mload(add(transcript, 0x3600)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3660),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xa00))),
                    mload(add(transcript, 0x3280)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3680),
                mulmod(1, mload(add(transcript, 0x3280)), f_q)
            )
            mstore(
                add(transcript, 0x36a0),
                addmod(
                    mload(add(transcript, 0x3640)),
                    mload(add(transcript, 0x3660)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x36c0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xa20))),
                    mload(add(transcript, 0x32a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x36e0),
                mulmod(1, mload(add(transcript, 0x32a0)), f_q)
            )
            mstore(
                add(transcript, 0x3700),
                addmod(
                    mload(add(transcript, 0x36a0)),
                    mload(add(transcript, 0x36c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3720),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xa40))),
                    mload(add(transcript, 0x32c0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3740),
                mulmod(1, mload(add(transcript, 0x32c0)), f_q)
            )
            mstore(
                add(transcript, 0x3760),
                addmod(
                    mload(add(transcript, 0x3700)),
                    mload(add(transcript, 0x3720)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3780),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x3100))),
                    mload(add(transcript, 0x32e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x37a0),
                mulmod(1, mload(add(transcript, 0x32e0)), f_q)
            )
            mstore(
                add(transcript, 0x37c0),
                mulmod(
                    mload(add(transcript, 0x30a0)),
                    mload(add(transcript, 0x32e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x37e0),
                mulmod(
                    mload(add(transcript, 0x30c0)),
                    mload(add(transcript, 0x32e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3800),
                mulmod(
                    mload(add(transcript, 0x30e0)),
                    mload(add(transcript, 0x32e0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3820),
                addmod(
                    mload(add(transcript, 0x3760)),
                    mload(add(transcript, 0x3780)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3840),
                mulmod(
                    sub(f_q, mload(add(transcript, 0x9e0))),
                    mload(add(transcript, 0x3300)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3860),
                mulmod(1, mload(add(transcript, 0x3300)), f_q)
            )
            mstore(
                add(transcript, 0x3880),
                addmod(
                    mload(add(transcript, 0x3820)),
                    mload(add(transcript, 0x3840)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x38a0),
                mulmod(mload(add(transcript, 0x3880)), 1, f_q)
            )
            mstore(
                add(transcript, 0x38c0),
                mulmod(mload(add(transcript, 0x3380)), 1, f_q)
            )
            mstore(
                add(transcript, 0x38e0),
                mulmod(mload(add(transcript, 0x33e0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3900),
                mulmod(mload(add(transcript, 0x3440)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3920),
                mulmod(mload(add(transcript, 0x34a0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3940),
                mulmod(mload(add(transcript, 0x3500)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3960),
                mulmod(mload(add(transcript, 0x3560)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3980),
                mulmod(mload(add(transcript, 0x35c0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x39a0),
                mulmod(mload(add(transcript, 0x3620)), 1, f_q)
            )
            mstore(
                add(transcript, 0x39c0),
                mulmod(mload(add(transcript, 0x3680)), 1, f_q)
            )
            mstore(
                add(transcript, 0x39e0),
                mulmod(mload(add(transcript, 0x36e0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3a00),
                mulmod(mload(add(transcript, 0x3740)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3a20),
                mulmod(mload(add(transcript, 0x37a0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3a40),
                mulmod(mload(add(transcript, 0x37c0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3a60),
                mulmod(mload(add(transcript, 0x37e0)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3a80),
                mulmod(mload(add(transcript, 0x3800)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3aa0),
                mulmod(mload(add(transcript, 0x3860)), 1, f_q)
            )
            mstore(
                add(transcript, 0x3ac0),
                mulmod(sub(f_q, mload(add(transcript, 0x900))), 1, f_q)
            )
            mstore(
                add(transcript, 0x3ae0),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xa80))),
                    mload(add(transcript, 0xb60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b00),
                addmod(
                    mload(add(transcript, 0x3ac0)),
                    mload(add(transcript, 0x3ae0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b20),
                mulmod(
                    sub(f_q, mload(add(transcript, 0xac0))),
                    mload(add(transcript, 0x31a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b40),
                addmod(
                    mload(add(transcript, 0x3b00)),
                    mload(add(transcript, 0x3b20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b60),
                mulmod(
                    mload(add(transcript, 0x3b40)),
                    mload(add(transcript, 0xd00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3b80),
                mulmod(1, mload(add(transcript, 0xd00)), f_q)
            )
            mstore(
                add(transcript, 0x3ba0),
                mulmod(
                    mload(add(transcript, 0x3380)),
                    mload(add(transcript, 0xd00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3bc0),
                mulmod(
                    mload(add(transcript, 0x33e0)),
                    mload(add(transcript, 0xd00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3be0),
                addmod(
                    mload(add(transcript, 0x38a0)),
                    mload(add(transcript, 0x3b60)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c00),
                addmod(1, mload(add(transcript, 0x3b80)), f_q)
            )
            mstore(
                add(transcript, 0x3c20),
                addmod(
                    mload(add(transcript, 0x38c0)),
                    mload(add(transcript, 0x3ba0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c40),
                addmod(
                    mload(add(transcript, 0x38e0)),
                    mload(add(transcript, 0x3bc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3c60),
                mulmod(sub(f_q, mload(add(transcript, 0x920))), 1, f_q)
            )
            mstore(
                add(transcript, 0x3c80),
                mulmod(
                    mload(add(transcript, 0x3c60)),
                    mload(add(transcript, 0x3120)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ca0),
                mulmod(1, mload(add(transcript, 0x3120)), f_q)
            )
            mstore(
                add(transcript, 0x3cc0),
                addmod(
                    mload(add(transcript, 0x3be0)),
                    mload(add(transcript, 0x3c80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ce0),
                addmod(
                    mload(add(transcript, 0x3c00)),
                    mload(add(transcript, 0x3ca0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d00),
                mulmod(sub(f_q, mload(add(transcript, 0x940))), 1, f_q)
            )
            mstore(
                add(transcript, 0x3d20),
                mulmod(
                    mload(add(transcript, 0x3d00)),
                    mload(add(transcript, 0x3140)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d40),
                mulmod(1, mload(add(transcript, 0x3140)), f_q)
            )
            mstore(
                add(transcript, 0x3d60),
                addmod(
                    mload(add(transcript, 0x3cc0)),
                    mload(add(transcript, 0x3d20)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3d80),
                addmod(
                    mload(add(transcript, 0x3ce0)),
                    mload(add(transcript, 0x3d40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3da0),
                mulmod(sub(f_q, mload(add(transcript, 0xb00))), 1, f_q)
            )
            mstore(
                add(transcript, 0x3dc0),
                mulmod(
                    mload(add(transcript, 0x3da0)),
                    mload(add(transcript, 0x3160)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3de0),
                mulmod(1, mload(add(transcript, 0x3160)), f_q)
            )
            mstore(
                add(transcript, 0x3e00),
                addmod(
                    mload(add(transcript, 0x3d60)),
                    mload(add(transcript, 0x3dc0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e20),
                addmod(
                    mload(add(transcript, 0x3900)),
                    mload(add(transcript, 0x3de0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3e40),
                mulmod(1, mload(add(transcript, 0x8a0)), f_q)
            )
            mstore(
                add(transcript, 0x3e60),
                mulmod(1, mload(add(transcript, 0x3e40)), f_q)
            )
            mstore(
                add(transcript, 0x3e80),
                mulmod(
                    19032961837237948602743626455740240236231119053033140765040043513661803148152,
                    mload(add(transcript, 0x8a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ea0),
                mulmod(
                    mload(add(transcript, 0x3b80)),
                    mload(add(transcript, 0x3e80)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ec0),
                mulmod(
                    5854133144571823792863860130267644613802765696134002830362054821530146160770,
                    mload(add(transcript, 0x8a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3ee0),
                mulmod(
                    mload(add(transcript, 0x3ca0)),
                    mload(add(transcript, 0x3ec0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f00),
                mulmod(
                    9697063347556872083384215826199993067635178715531258559890418744774301211662,
                    mload(add(transcript, 0x8a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f20),
                mulmod(
                    mload(add(transcript, 0x3d40)),
                    mload(add(transcript, 0x3f00)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f40),
                mulmod(
                    15402826414547299628414612080036060696555554914079673875872749760617770134879,
                    mload(add(transcript, 0x8a0)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f60),
                mulmod(
                    mload(add(transcript, 0x3de0)),
                    mload(add(transcript, 0x3f40)),
                    f_q
                )
            )
            mstore(
                add(transcript, 0x3f80),
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            mstore(
                add(transcript, 0x3fa0),
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            mstore(add(transcript, 0x3fc0), mload(add(transcript, 0x3e00)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x3f80),
                        0x60,
                        add(transcript, 0x3f80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x3fe0), mload(add(transcript, 0x480)))
            mstore(add(transcript, 0x4000), mload(add(transcript, 0x4a0)))
            mstore(add(transcript, 0x4020), mload(add(transcript, 0x3d80)))
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
            mstore(add(transcript, 0x4040), mload(add(transcript, 0x3f80)))
            mstore(add(transcript, 0x4060), mload(add(transcript, 0x3fa0)))
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
            mstore(add(transcript, 0x40c0), mload(add(transcript, 0x660)))
            mstore(add(transcript, 0x40e0), mload(add(transcript, 0x680)))
            mstore(add(transcript, 0x4100), mload(add(transcript, 0x3c20)))
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
            mstore(add(transcript, 0x41a0), mload(add(transcript, 0x6a0)))
            mstore(add(transcript, 0x41c0), mload(add(transcript, 0x6c0)))
            mstore(add(transcript, 0x41e0), mload(add(transcript, 0x3c40)))
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
            mstore(add(transcript, 0x4200), mload(add(transcript, 0x4120)))
            mstore(add(transcript, 0x4220), mload(add(transcript, 0x4140)))
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
            mstore(add(transcript, 0x4280), mload(add(transcript, 0x520)))
            mstore(add(transcript, 0x42a0), mload(add(transcript, 0x540)))
            mstore(add(transcript, 0x42c0), mload(add(transcript, 0x3e20)))
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
            mstore(add(transcript, 0x4360), mload(add(transcript, 0x560)))
            mstore(add(transcript, 0x4380), mload(add(transcript, 0x580)))
            mstore(add(transcript, 0x43a0), mload(add(transcript, 0x3920)))
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
            mstore(
                add(transcript, 0x4440),
                0x00d579414e5933c3161a00702dffe71389ccff19e0cd9971658a960d7dfe8dff
            )
            mstore(
                add(transcript, 0x4460),
                0x1e8fb4d88fcdf88427836b8613479e713a4cf03baef5c218e0951a507108d29d
            )
            mstore(add(transcript, 0x4480), mload(add(transcript, 0x3940)))
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
            mstore(
                add(transcript, 0x4520),
                0x07f70134a46bee8e3af2e041b227b82910d50e5d1e5201a7ad5c117aa140c47b
            )
            mstore(
                add(transcript, 0x4540),
                0x15a2a99b119d10c38cd3e59076e6229b229849700bbbbefc0ba78b5b40e22439
            )
            mstore(add(transcript, 0x4560), mload(add(transcript, 0x3960)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4520),
                        0x60,
                        add(transcript, 0x4520),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4580), mload(add(transcript, 0x44a0)))
            mstore(add(transcript, 0x45a0), mload(add(transcript, 0x44c0)))
            mstore(add(transcript, 0x45c0), mload(add(transcript, 0x4520)))
            mstore(add(transcript, 0x45e0), mload(add(transcript, 0x4540)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4580),
                        0x80,
                        add(transcript, 0x4580),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x4600),
                0x13eaa429a93802360d3caacadbfef206f830f6d99d1711ff0f7b9bfd57a2a59a
            )
            mstore(
                add(transcript, 0x4620),
                0x006b98dc9d8030d70a88db44b0577c46ae29021db5b61a224fd287b4f32bc29d
            )
            mstore(add(transcript, 0x4640), mload(add(transcript, 0x3980)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4600),
                        0x60,
                        add(transcript, 0x4600),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4660), mload(add(transcript, 0x4580)))
            mstore(add(transcript, 0x4680), mload(add(transcript, 0x45a0)))
            mstore(add(transcript, 0x46a0), mload(add(transcript, 0x4600)))
            mstore(add(transcript, 0x46c0), mload(add(transcript, 0x4620)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4660),
                        0x80,
                        add(transcript, 0x4660),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x46e0),
                0x1183c7880b28c1a25b4f2aae8725a2b0d5d7009bbc28bb0cf68e1c2651ef2b6a
            )
            mstore(
                add(transcript, 0x4700),
                0x0b7b9c652d4b54f3e4c4e01b7165129a57af16d7a79e26f3a24f41224c4b21c7
            )
            mstore(add(transcript, 0x4720), mload(add(transcript, 0x39a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x46e0),
                        0x60,
                        add(transcript, 0x46e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4740), mload(add(transcript, 0x4660)))
            mstore(add(transcript, 0x4760), mload(add(transcript, 0x4680)))
            mstore(add(transcript, 0x4780), mload(add(transcript, 0x46e0)))
            mstore(add(transcript, 0x47a0), mload(add(transcript, 0x4700)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4740),
                        0x80,
                        add(transcript, 0x4740),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x47c0),
                0x2a89e4d6e5af2f41c9c57fc4c467484e8a6bfc04f3e17677b952feae27250a0f
            )
            mstore(
                add(transcript, 0x47e0),
                0x0aaa79875b21be9dd38b97c01e265d4fcb521974cc4c1184a26e491f020a5369
            )
            mstore(add(transcript, 0x4800), mload(add(transcript, 0x39c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x47c0),
                        0x60,
                        add(transcript, 0x47c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4820), mload(add(transcript, 0x4740)))
            mstore(add(transcript, 0x4840), mload(add(transcript, 0x4760)))
            mstore(add(transcript, 0x4860), mload(add(transcript, 0x47c0)))
            mstore(add(transcript, 0x4880), mload(add(transcript, 0x47e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4820),
                        0x80,
                        add(transcript, 0x4820),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x48a0),
                0x086553a86cb1e4228841afe7e79e5813bd00a7cfd300090303c6dd47614ddce5
            )
            mstore(
                add(transcript, 0x48c0),
                0x111d37f701e1a115e036da7ad0da901b284cd58d69737945dbb9f7d76af097f1
            )
            mstore(add(transcript, 0x48e0), mload(add(transcript, 0x39e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x48a0),
                        0x60,
                        add(transcript, 0x48a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4900), mload(add(transcript, 0x4820)))
            mstore(add(transcript, 0x4920), mload(add(transcript, 0x4840)))
            mstore(add(transcript, 0x4940), mload(add(transcript, 0x48a0)))
            mstore(add(transcript, 0x4960), mload(add(transcript, 0x48c0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4900),
                        0x80,
                        add(transcript, 0x4900),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(
                add(transcript, 0x4980),
                0x07f4ea115ede11825e6619c37f65559567ecf82ac913bea7f24dc9d4be8bf6c8
            )
            mstore(
                add(transcript, 0x49a0),
                0x0fce343bf1b5c37d39b35bb8378ed672e2b8e70df7bfa362d63ebda9593eec33
            )
            mstore(add(transcript, 0x49c0), mload(add(transcript, 0x3a00)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4980),
                        0x60,
                        add(transcript, 0x4980),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x49e0), mload(add(transcript, 0x4900)))
            mstore(add(transcript, 0x4a00), mload(add(transcript, 0x4920)))
            mstore(add(transcript, 0x4a20), mload(add(transcript, 0x4980)))
            mstore(add(transcript, 0x4a40), mload(add(transcript, 0x49a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x49e0),
                        0x80,
                        add(transcript, 0x49e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4a60), mload(add(transcript, 0x780)))
            mstore(add(transcript, 0x4a80), mload(add(transcript, 0x7a0)))
            mstore(add(transcript, 0x4aa0), mload(add(transcript, 0x3a20)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4a60),
                        0x60,
                        add(transcript, 0x4a60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4ac0), mload(add(transcript, 0x49e0)))
            mstore(add(transcript, 0x4ae0), mload(add(transcript, 0x4a00)))
            mstore(add(transcript, 0x4b00), mload(add(transcript, 0x4a60)))
            mstore(add(transcript, 0x4b20), mload(add(transcript, 0x4a80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4ac0),
                        0x80,
                        add(transcript, 0x4ac0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4b40), mload(add(transcript, 0x7c0)))
            mstore(add(transcript, 0x4b60), mload(add(transcript, 0x7e0)))
            mstore(add(transcript, 0x4b80), mload(add(transcript, 0x3a40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4b40),
                        0x60,
                        add(transcript, 0x4b40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4ba0), mload(add(transcript, 0x4ac0)))
            mstore(add(transcript, 0x4bc0), mload(add(transcript, 0x4ae0)))
            mstore(add(transcript, 0x4be0), mload(add(transcript, 0x4b40)))
            mstore(add(transcript, 0x4c00), mload(add(transcript, 0x4b60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4ba0),
                        0x80,
                        add(transcript, 0x4ba0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4c20), mload(add(transcript, 0x800)))
            mstore(add(transcript, 0x4c40), mload(add(transcript, 0x820)))
            mstore(add(transcript, 0x4c60), mload(add(transcript, 0x3a60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4c20),
                        0x60,
                        add(transcript, 0x4c20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4c80), mload(add(transcript, 0x4ba0)))
            mstore(add(transcript, 0x4ca0), mload(add(transcript, 0x4bc0)))
            mstore(add(transcript, 0x4cc0), mload(add(transcript, 0x4c20)))
            mstore(add(transcript, 0x4ce0), mload(add(transcript, 0x4c40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4c80),
                        0x80,
                        add(transcript, 0x4c80),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4d00), mload(add(transcript, 0x840)))
            mstore(add(transcript, 0x4d20), mload(add(transcript, 0x860)))
            mstore(add(transcript, 0x4d40), mload(add(transcript, 0x3a80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4d00),
                        0x60,
                        add(transcript, 0x4d00),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4d60), mload(add(transcript, 0x4c80)))
            mstore(add(transcript, 0x4d80), mload(add(transcript, 0x4ca0)))
            mstore(add(transcript, 0x4da0), mload(add(transcript, 0x4d00)))
            mstore(add(transcript, 0x4dc0), mload(add(transcript, 0x4d20)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4d60),
                        0x80,
                        add(transcript, 0x4d60),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4de0), mload(add(transcript, 0x6e0)))
            mstore(add(transcript, 0x4e00), mload(add(transcript, 0x700)))
            mstore(add(transcript, 0x4e20), mload(add(transcript, 0x3aa0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4de0),
                        0x60,
                        add(transcript, 0x4de0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4e40), mload(add(transcript, 0x4d60)))
            mstore(add(transcript, 0x4e60), mload(add(transcript, 0x4d80)))
            mstore(add(transcript, 0x4e80), mload(add(transcript, 0x4de0)))
            mstore(add(transcript, 0x4ea0), mload(add(transcript, 0x4e00)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4e40),
                        0x80,
                        add(transcript, 0x4e40),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4ec0), mload(add(transcript, 0xba0)))
            mstore(add(transcript, 0x4ee0), mload(add(transcript, 0xbc0)))
            mstore(add(transcript, 0x4f00), mload(add(transcript, 0x3e60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4ec0),
                        0x60,
                        add(transcript, 0x4ec0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4f20), mload(add(transcript, 0x4e40)))
            mstore(add(transcript, 0x4f40), mload(add(transcript, 0x4e60)))
            mstore(add(transcript, 0x4f60), mload(add(transcript, 0x4ec0)))
            mstore(add(transcript, 0x4f80), mload(add(transcript, 0x4ee0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x4f20),
                        0x80,
                        add(transcript, 0x4f20),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x4fa0), mload(add(transcript, 0xbe0)))
            mstore(add(transcript, 0x4fc0), mload(add(transcript, 0xc00)))
            mstore(add(transcript, 0x4fe0), mload(add(transcript, 0x3ea0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x4fa0),
                        0x60,
                        add(transcript, 0x4fa0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5000), mload(add(transcript, 0x4f20)))
            mstore(add(transcript, 0x5020), mload(add(transcript, 0x4f40)))
            mstore(add(transcript, 0x5040), mload(add(transcript, 0x4fa0)))
            mstore(add(transcript, 0x5060), mload(add(transcript, 0x4fc0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5000),
                        0x80,
                        add(transcript, 0x5000),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5080), mload(add(transcript, 0xc20)))
            mstore(add(transcript, 0x50a0), mload(add(transcript, 0xc40)))
            mstore(add(transcript, 0x50c0), mload(add(transcript, 0x3ee0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5080),
                        0x60,
                        add(transcript, 0x5080),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x50e0), mload(add(transcript, 0x5000)))
            mstore(add(transcript, 0x5100), mload(add(transcript, 0x5020)))
            mstore(add(transcript, 0x5120), mload(add(transcript, 0x5080)))
            mstore(add(transcript, 0x5140), mload(add(transcript, 0x50a0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x50e0),
                        0x80,
                        add(transcript, 0x50e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5160), mload(add(transcript, 0xc60)))
            mstore(add(transcript, 0x5180), mload(add(transcript, 0xc80)))
            mstore(add(transcript, 0x51a0), mload(add(transcript, 0x3f20)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5160),
                        0x60,
                        add(transcript, 0x5160),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x51c0), mload(add(transcript, 0x50e0)))
            mstore(add(transcript, 0x51e0), mload(add(transcript, 0x5100)))
            mstore(add(transcript, 0x5200), mload(add(transcript, 0x5160)))
            mstore(add(transcript, 0x5220), mload(add(transcript, 0x5180)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x51c0),
                        0x80,
                        add(transcript, 0x51c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5240), mload(add(transcript, 0xca0)))
            mstore(add(transcript, 0x5260), mload(add(transcript, 0xcc0)))
            mstore(add(transcript, 0x5280), mload(add(transcript, 0x3f60)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5240),
                        0x60,
                        add(transcript, 0x5240),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x52a0), mload(add(transcript, 0x51c0)))
            mstore(add(transcript, 0x52c0), mload(add(transcript, 0x51e0)))
            mstore(add(transcript, 0x52e0), mload(add(transcript, 0x5240)))
            mstore(add(transcript, 0x5300), mload(add(transcript, 0x5260)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x52a0),
                        0x80,
                        add(transcript, 0x52a0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5320), mload(add(transcript, 0xbe0)))
            mstore(add(transcript, 0x5340), mload(add(transcript, 0xc00)))
            mstore(add(transcript, 0x5360), mload(add(transcript, 0x3b80)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5320),
                        0x60,
                        add(transcript, 0x5320),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5380), mload(add(transcript, 0xba0)))
            mstore(add(transcript, 0x53a0), mload(add(transcript, 0xbc0)))
            mstore(add(transcript, 0x53c0), mload(add(transcript, 0x5320)))
            mstore(add(transcript, 0x53e0), mload(add(transcript, 0x5340)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5380),
                        0x80,
                        add(transcript, 0x5380),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5400), mload(add(transcript, 0xc20)))
            mstore(add(transcript, 0x5420), mload(add(transcript, 0xc40)))
            mstore(add(transcript, 0x5440), mload(add(transcript, 0x3ca0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x5400),
                        0x60,
                        add(transcript, 0x5400),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5460), mload(add(transcript, 0x5380)))
            mstore(add(transcript, 0x5480), mload(add(transcript, 0x53a0)))
            mstore(add(transcript, 0x54a0), mload(add(transcript, 0x5400)))
            mstore(add(transcript, 0x54c0), mload(add(transcript, 0x5420)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5460),
                        0x80,
                        add(transcript, 0x5460),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x54e0), mload(add(transcript, 0xc60)))
            mstore(add(transcript, 0x5500), mload(add(transcript, 0xc80)))
            mstore(add(transcript, 0x5520), mload(add(transcript, 0x3d40)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x54e0),
                        0x60,
                        add(transcript, 0x54e0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5540), mload(add(transcript, 0x5460)))
            mstore(add(transcript, 0x5560), mload(add(transcript, 0x5480)))
            mstore(add(transcript, 0x5580), mload(add(transcript, 0x54e0)))
            mstore(add(transcript, 0x55a0), mload(add(transcript, 0x5500)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5540),
                        0x80,
                        add(transcript, 0x5540),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x55c0), mload(add(transcript, 0xca0)))
            mstore(add(transcript, 0x55e0), mload(add(transcript, 0xcc0)))
            mstore(add(transcript, 0x5600), mload(add(transcript, 0x3de0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x7,
                        add(transcript, 0x55c0),
                        0x60,
                        add(transcript, 0x55c0),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x5620), mload(add(transcript, 0x5540)))
            mstore(add(transcript, 0x5640), mload(add(transcript, 0x5560)))
            mstore(add(transcript, 0x5660), mload(add(transcript, 0x55c0)))
            mstore(add(transcript, 0x5680), mload(add(transcript, 0x55e0)))
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x6,
                        add(transcript, 0x5620),
                        0x80,
                        add(transcript, 0x5620),
                        0x40
                    ),
                    1
                ),
                success
            )
            mstore(add(transcript, 0x56a0), mload(add(transcript, 0x52a0)))
            mstore(add(transcript, 0x56c0), mload(add(transcript, 0x52c0)))
            mstore(
                add(transcript, 0x56e0),
                0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
            )
            mstore(
                add(transcript, 0x5700),
                0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
            )
            mstore(
                add(transcript, 0x5720),
                0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
            )
            mstore(
                add(transcript, 0x5740),
                0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
            )
            mstore(add(transcript, 0x5760), mload(add(transcript, 0x5620)))
            mstore(add(transcript, 0x5780), mload(add(transcript, 0x5640)))
            mstore(
                add(transcript, 0x57a0),
                0x1a841de4ef28295bb0f595db8ba843466c05ba433095a9bf6603d334a58fa4a0
            )
            mstore(
                add(transcript, 0x57c0),
                0x0ed2763108f401e9a91572f9a492ffff2c1c48e8230c2f39297a278ed1316bd5
            )
            mstore(
                add(transcript, 0x57e0),
                0x24b642f23220c156d35570de68511f3a2540741cd5cd485ffc3e1ff3599c00f2
            )
            mstore(
                add(transcript, 0x5800),
                0x25cdb46289be9daf2bd56f895e4f15101e47481acaf36c393c08bd0de206ca05
            )
            success := and(
                eq(
                    staticcall(
                        gas(),
                        0x8,
                        add(transcript, 0x56a0),
                        0x180,
                        add(transcript, 0x56a0),
                        0x20
                    ),
                    1
                ),
                success
            )
            success := and(eq(mload(add(transcript, 0x56a0)), 1), success)
        }
        return success;
    }
}
