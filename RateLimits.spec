// RateLimits.spec

methods {
    // constants
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function CONTROLLER() external returns (bytes32) envfree;
    // getters
    function hasRole(bytes32,address) external returns (bool) envfree;
    function getRoleAdmin(bytes32) external returns (bytes32) envfree;
    function getRateLimitData(bytes32) external returns (IRateLimits.RateLimitData) envfree;
    //
}

definition defMin(mathint a, mathint b) returns mathint = a < b ? a : b;
definition defGetCurrentRateLimit(env e, bytes32 key) returns mathint =
    currentContract._data[key].maxAmount == max_uint256
        ? max_uint256
        : defMin(
            currentContract._data[key].slope * (e.block.timestamp - currentContract._data[key].lastUpdated) + currentContract._data[key].lastAmount,
            currentContract._data[key].maxAmount
        );

// Verify no more entry points exist
rule entryPoints(method f) filtered { f -> !f.isView } {
    env e;

    calldataarg args;
    f(e, args);

    assert f.selector == sig:grantRole(bytes32,address).selector ||
           f.selector == sig:revokeRole(bytes32,address).selector ||
           f.selector == sig:renounceRole(bytes32,address).selector ||
           f.selector == sig:setRateLimitData(bytes32,uint256,uint256,uint256,uint256).selector ||
           f.selector == sig:setRateLimitData(bytes32,uint256,uint256).selector ||
           f.selector == sig:setUnlimitedRateLimitData(bytes32).selector ||
           f.selector == sig:triggerRateLimitDecrease(bytes32,uint256).selector ||
           f.selector == sig:triggerRateLimitIncrease(bytes32,uint256).selector;
}

// Verify that each storage layout is only modified in the corresponding functions
rule storageAffected(method f) {
    env e;

    bytes32 anyBytes32;
    address anyAddr;

    bool hasRoleBefore = hasRole(anyBytes32, anyAddr);
    bytes32 roleAdminBefore = getRoleAdmin(anyBytes32);
    IRateLimits.RateLimitData dataBefore = getRateLimitData(anyBytes32);

    calldataarg args;
    f(e, args);

    bool hasRoleAfter = hasRole(anyBytes32, anyAddr);
    bytes32 roleAdminAfter = getRoleAdmin(anyBytes32);
    IRateLimits.RateLimitData dataAfter = getRateLimitData(anyBytes32);

    assert hasRoleAfter != hasRoleBefore =>
        f.selector == sig:grantRole(bytes32,address).selector ||
        f.selector == sig:revokeRole(bytes32,address).selector ||
        f.selector == sig:renounceRole(bytes32,address).selector, "Assert 1";
    assert roleAdminAfter == roleAdminBefore, "Assert 2";
    assert dataAfter.maxAmount != dataBefore.maxAmount =>
        f.selector == sig:setRateLimitData(bytes32,uint256,uint256,uint256,uint256).selector ||
        f.selector == sig:setRateLimitData(bytes32,uint256,uint256).selector ||
        f.selector == sig:setUnlimitedRateLimitData(bytes32).selector, "Assert 3";
    assert dataAfter.slope != dataBefore.slope =>
        f.selector == sig:setRateLimitData(bytes32,uint256,uint256,uint256,uint256).selector ||
        f.selector == sig:setRateLimitData(bytes32,uint256,uint256).selector ||
        f.selector == sig:setUnlimitedRateLimitData(bytes32).selector, "Assert 4";
    assert dataAfter.lastAmount != dataBefore.lastAmount =>
        f.selector == sig:setRateLimitData(bytes32,uint256,uint256,uint256,uint256).selector ||
        f.selector == sig:setRateLimitData(bytes32,uint256,uint256).selector ||
        f.selector == sig:setUnlimitedRateLimitData(bytes32).selector ||
        f.selector == sig:triggerRateLimitDecrease(bytes32,uint256).selector ||
        f.selector == sig:triggerRateLimitIncrease(bytes32,uint256).selector, "Assert 5";
    assert dataAfter.lastUpdated != dataBefore.lastUpdated =>
        f.selector == sig:setRateLimitData(bytes32,uint256,uint256,uint256,uint256).selector ||
        f.selector == sig:setRateLimitData(bytes32,uint256,uint256).selector ||
        f.selector == sig:setUnlimitedRateLimitData(bytes32).selector ||
        f.selector == sig:triggerRateLimitDecrease(bytes32,uint256).selector ||
        f.selector == sig:triggerRateLimitIncrease(bytes32,uint256).selector, "Assert 6";
}

// Verify correct storage changes for non reverting grantRole
rule grantRole(bytes32 role, address account) {
    env e;

    bytes32 otherRole;
    address otherAccount;
    require otherRole != role || otherAccount != account;

    bool hasOtherBefore = hasRole(otherRole, otherAccount);

    grantRole(e, role, account);

    bool hasRoleAfter = hasRole(role, account);
    bool hasOtherAfter = hasRole(otherRole, otherAccount);

    assert hasRoleAfter, "Assert 1";
    assert hasOtherAfter == hasOtherBefore, "Assert 2";
}

// Verify revert rules on grantRole
rule grantRole_revert(bytes32 role, address account) {
    env e;

    bool hasRoleAdminSender = hasRole(getRoleAdmin(role), e.msg.sender);

    grantRole@withrevert(e, role, account);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleAdminSender;

    assert lastReverted <=> revert1 || revert2, "Revert rules failed";
}

// Verify correct storage changes for non reverting revokeRole
rule revokeRole(bytes32 role, address account) {
    env e;

    bytes32 otherRole;
    address otherAccount;
    require otherRole != role || otherAccount != account;

    bool hasOtherBefore = hasRole(otherRole, otherAccount);

    revokeRole(e, role, account);

    bool hasRoleAfter = hasRole(role, account);
    bool hasOtherAfter = hasRole(otherRole, otherAccount);

    assert !hasRoleAfter, "Assert 1";
    assert hasOtherAfter == hasOtherBefore, "Assert 2";
}

// Verify revert rules on revokeRole
rule revokeRole_revert(bytes32 role, address account) {
    env e;

    bool hasRoleAdminSender = hasRole(getRoleAdmin(role), e.msg.sender);

    revokeRole@withrevert(e, role, account);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleAdminSender;

    assert lastReverted <=> revert1 || revert2, "Revert rules failed";
}

// Verify correct storage changes for non reverting renounceRole
rule renounceRole(bytes32 role, address account) {
    env e;

    bytes32 otherRole;
    address otherAccount;
    require otherRole != role || otherAccount != account;

    bool hasOtherBefore = hasRole(otherRole, otherAccount);

    renounceRole(e, role, account);

    bool hasRoleAfter = hasRole(role, account);
    bool hasOtherAfter = hasRole(otherRole, otherAccount);

    assert !hasRoleAfter, "Assert 1";
    assert hasOtherAfter == hasOtherBefore, "Assert 2";
}

// Verify revert rules on renounceRole
rule renounceRole_revert(bytes32 role, address account) {
    env e;

    renounceRole@withrevert(e, role, account);

    bool revert1 = e.msg.value > 0;
    bool revert2 = account != e.msg.sender;

    assert lastReverted <=> revert1 || revert2, "Revert rules failed";
}

// Verify correct storage changes for non reverting setRateLimitData
rule setRateLimitData(bytes32 key, uint256 maxAmount, uint256 slope, uint256 lastAmount, uint256 lastUpdated) {
    env e;

    setRateLimitData(e, key, maxAmount, slope, lastAmount, lastUpdated);

    IRateLimits.RateLimitData dataAfter = getRateLimitData(key);

    assert dataAfter.maxAmount == maxAmount, "Assert 1";
    assert dataAfter.slope == slope, "Assert 2";
    assert dataAfter.lastAmount == lastAmount, "Assert 3";
    assert dataAfter.lastUpdated == lastUpdated, "Assert 4";
}

// Verify revert rules on setRateLimitData
rule setRateLimitData_revert(bytes32 key, uint256 maxAmount, uint256 slope, uint256 lastAmount, uint256 lastUpdated) {
    env e;

    bool hasRoleAdminSender = hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    setRateLimitData@withrevert(e, key, maxAmount, slope, lastAmount, lastUpdated);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleAdminSender;
    bool revert3 = lastAmount > maxAmount;
    bool revert4 = lastUpdated > e.block.timestamp;

    assert lastReverted <=> revert1 || revert2 || revert3 ||
                            revert4, "Revert rules failed";
}

// Verify correct storage changes for non reverting setRateLimitData
rule setRateLimitData2(bytes32 key, uint256 maxAmount, uint256 slope) {
    env e;

    setRateLimitData(e, key, maxAmount, slope);

    IRateLimits.RateLimitData dataAfter = getRateLimitData(key);

    assert dataAfter.maxAmount == maxAmount, "Assert 1";
    assert dataAfter.slope == slope, "Assert 2";
    assert dataAfter.lastAmount == maxAmount, "Assert 3";
    assert dataAfter.lastUpdated == e.block.timestamp, "Assert 4";
}

// Verify revert rules on setRateLimitData
rule setRateLimitData2_revert(bytes32 key, uint256 maxAmount, uint256 slope) {
    env e;

    bool hasRoleAdminSender = hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    setRateLimitData@withrevert(e, key, maxAmount, slope);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleAdminSender;

    assert lastReverted <=> revert1 || revert2, "Revert rules failed";
}

// Verify correct storage changes for non reverting setUnlimitedRateLimitData
rule setUnlimitedRateLimitData(bytes32 key) {
    env e;

    setUnlimitedRateLimitData(e, key);

    IRateLimits.RateLimitData dataAfter = getRateLimitData(key);

    assert dataAfter.maxAmount == max_uint256, "Assert 1";
    assert dataAfter.slope == 0, "Assert 2";
    assert dataAfter.lastAmount == max_uint256, "Assert 3";
    assert dataAfter.lastUpdated == e.block.timestamp, "Assert 4";
}

// Verify revert rules on setUnlimitedRateLimitData
rule setUnlimitedRateLimitData_revert(bytes32 key) {
    env e;

    bool hasRoleAdminSender = hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    setUnlimitedRateLimitData@withrevert(e, key);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleAdminSender;

    assert lastReverted <=> revert1 || revert2, "Revert rules failed";
}

// Verify correct behaviour for getRateLimitData getter
rule getRateLimitData(bytes32 key) {
    env e;

    IRateLimits.RateLimitData data = getRateLimitData(key);

    assert data.maxAmount == currentContract._data[key].maxAmount, "Assert 1";
    assert data.slope == currentContract._data[key].slope, "Assert 2";
    assert data.lastAmount == currentContract._data[key].lastAmount, "Assert 3";
    assert data.lastUpdated == currentContract._data[key].lastUpdated, "Assert 4";
}

// Verify correct behaviour for getCurrentRateLimit getter
rule getCurrentRateLimit(bytes32 key) {
    env e;

    mathint limit = defGetCurrentRateLimit(e, key);

    mathint limitRet = getCurrentRateLimit(e, key);

    assert limitRet == limit, "Assert 1";
}

// // Verify correct storage changes for non reverting triggerRateLimitDecrease
// rule triggerRateLimitDecrease(bytes32 key, uint256 amountToDecrease) {
//     env e;

//     triggerRateLimitDecrease(e, key, amountToDecrease);

//     IRateLimits.RateLimitData dataAfter = getRateLimitData(key);

//     assert dataAfter.maxAmount == max_uint256, "Assert 1";
//     assert dataAfter.slope == 0, "Assert 2";
//     assert dataAfter.lastAmount == max_uint256, "Assert 3";
//     assert dataAfter.lastUpdated == e.block.timestamp, "Assert 4";
// }
