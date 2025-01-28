from web3client.contracts.token import TokenInterface

def test_token_decimals():
    assert TokenInterface.decimals == 9

def test_float_to_atomic():
    assert TokenInterface.to_atomic(0) ==                       0
    assert TokenInterface.to_atomic(0.0) ==                     0

    assert TokenInterface.to_atomic(1) ==             1_000000000
    assert TokenInterface.to_atomic(1.0) ==           1_000000000

    assert TokenInterface.to_atomic(10) ==           10_000000000
    assert TokenInterface.to_atomic(10.0) ==         10_000000000

    assert TokenInterface.to_atomic(999) ==         999_000000000
    assert TokenInterface.to_atomic(999.0) ==       999_000000000

    assert TokenInterface.to_atomic(0.1) ==             100000000
    assert TokenInterface.to_atomic(0.000000001) ==             1
    assert TokenInterface.to_atomic(0.9) ==             900000000
    assert TokenInterface.to_atomic(0.99999) ==         999990000
    assert TokenInterface.to_atomic(1.99999) ==       1_999990000
    assert TokenInterface.to_atomic(0.999999999) ==     999999999
    assert TokenInterface.to_atomic(1.999999999) ==   1_999999999
    assert TokenInterface.to_atomic(0.333333333) ==     333333333
    assert TokenInterface.to_atomic(1.333333333) ==   1_333333333
    assert TokenInterface.to_atomic(1.000000001) ==   1_000000001

    assert TokenInterface.to_atomic(99.99) ==        99_990000000
    assert TokenInterface.to_atomic(99.98) ==        99_980000000
    assert TokenInterface.to_atomic(100) ==         100_000000000
    assert TokenInterface.to_atomic(101) ==         101_000000000
    assert TokenInterface.to_atomic(1000) ==       1000_000000000
    assert TokenInterface.to_atomic(10.22) ==        10_220000000
    assert TokenInterface.to_atomic(45.42) ==        45_420000000


def test_float_from_atomic():
    assert TokenInterface.from_atomic(0) == 0

    assert TokenInterface.from_atomic(1_000000000) ==         1
    assert TokenInterface.from_atomic(10_000000000) ==       10
    assert TokenInterface.from_atomic(999_000000000) ==     999

    assert TokenInterface.from_atomic(100000000) ==           0.1
    assert TokenInterface.from_atomic(1) ==                   0.000000001
    assert TokenInterface.from_atomic(900000000) ==           0.9
    assert TokenInterface.from_atomic(999990000) ==           0.99999
    assert TokenInterface.from_atomic(1_999990000) ==         1.99999
    assert TokenInterface.from_atomic(999999999) ==           0.999999999
    assert TokenInterface.from_atomic(1_999999999) ==         1.999999999
    assert TokenInterface.from_atomic(333333333) ==           0.333333333
    assert TokenInterface.from_atomic(1_333333333) ==         1.333333333
    assert TokenInterface.from_atomic(1_000000001) ==         1.000000001

    assert TokenInterface.from_atomic(99_990000000) ==        99.99
    assert TokenInterface.from_atomic(99_980000000) ==        99.98
    assert TokenInterface.from_atomic(100_000000000) ==      100
    assert TokenInterface.from_atomic(101_000000000) ==      101
    assert TokenInterface.from_atomic(1000_000000000) ==    1000
    assert TokenInterface.from_atomic(10_220000000) ==        10.22
    assert TokenInterface.from_atomic(45_420000000) ==        45.42


