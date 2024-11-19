// ALMProxy.spec

methods {
    // constants
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function CONTROLLER() external returns (bytes32) envfree;
    // getters
    function hasRole(bytes32,address) external returns (bool) envfree;
    function getRoleAdmin(bytes32) external returns (bytes32) envfree;
    //
}

persistent ghost bool callSuccess;
persistent ghost mathint callRetLength;
hook CALL(uint256 g, address addr, uint256 value, uint256 argsOffset, uint256 argsLength, uint256 retOffset, uint256 retLength) uint256 rc {
    callSuccess = rc != 0;
    callRetLength = retLength;
}

persistent ghost bool delegateCallSuccess;
persistent ghost mathint delegateCallRetLength;
hook DELEGATECALL(uint256 g, address addr, uint256 argsOffset, uint256 argsLength, uint256 retOffset, uint256 retLength) uint256 rc {
    delegateCallSuccess = rc != 0;
    delegateCallRetLength = retLength;
}

// Verify no more entry points exist
rule entryPoints(method f) filtered { f -> !f.isView } {
    env e;

    calldataarg args;
    f(e, args);

    assert f.selector == sig:grantRole(bytes32,address).selector ||
           f.selector == sig:revokeRole(bytes32,address).selector ||
           f.selector == sig:renounceRole(bytes32,address).selector ||
           f.selector == sig:doCall(address,bytes).selector ||
           f.selector == sig:doCallWithValue(address,bytes,uint256).selector ||
           f.selector == sig:doDelegateCall(address,bytes).selector ||
           f.isFallback;
}

// Verify that each storage layout is only modified in the corresponding functions
rule storageAffected(method f) filtered { f -> f.selector != sig:doDelegateCall(address,bytes).selector } {
    env e;

    bytes32 anyBytes32;
    address anyAddr;

    bool hasRoleBefore = hasRole(anyBytes32, anyAddr);
    bytes32 roleAdminBefore = getRoleAdmin(anyBytes32);

    calldataarg args;
    f(e, args);

    bool hasRoleAfter = hasRole(anyBytes32, anyAddr);
    bytes32 roleAdminAfter = getRoleAdmin(anyBytes32);

    assert hasRoleAfter != hasRoleBefore =>
        f.selector == sig:grantRole(bytes32,address).selector ||
        f.selector == sig:revokeRole(bytes32,address).selector ||
        f.selector == sig:renounceRole(bytes32,address).selector, "Assert 1";
    assert roleAdminAfter == roleAdminBefore, "Assert 2";
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

// Verify revert rules on doCall
rule doCall_revert(address target, bytes data) {
    env e;

    mathint targetCodeSize = nativeCodesize[target];
    bool hasRoleControllerSender = hasRole(CONTROLLER(), e.msg.sender);

    doCall@withrevert(e, target, data);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleControllerSender;
    bool revert3 = !callSuccess;
    bool revert4 = callSuccess && callRetLength == 0 && targetCodeSize == 0;

    assert lastReverted <=> revert1 || revert2 || revert3 ||
                            revert4, "Revert rules failed";
}

// Verify revert rules on doCallWithValue
rule doCallWithValue_revert(address target, bytes data, uint256 value) {
    env e;

    mathint balance = nativeBalances[currentContract] + e.msg.value;
    mathint targetCodeSize = nativeCodesize[target];
    require nativeBalances[currentContract] >= 0 && targetCodeSize >= 0;
    bool hasRoleControllerSender = hasRole(CONTROLLER(), e.msg.sender);

    doCallWithValue@withrevert(e, target, data, value);

    bool revert1 = !hasRoleControllerSender;
    bool revert2 = value > balance;
    bool revert3 = !callSuccess;
    bool revert4 = callSuccess && callRetLength == 0 && targetCodeSize == 0;

    assert lastReverted <=> revert1 || revert2 || revert3 ||
                            revert4, "Revert rules failed";
}

// Verify revert rules on doDelegateCall
rule doDelegateCall_revert(address target, bytes data) {
    env e;

    mathint balance = nativeBalances[currentContract] + e.msg.value;
    mathint targetCodeSize = nativeCodesize[target];
    bool hasRoleControllerSender = hasRole(CONTROLLER(), e.msg.sender);

    doDelegateCall@withrevert(e, target, data);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleControllerSender;
    bool revert3 = !delegateCallSuccess;
    bool revert4 = delegateCallSuccess && delegateCallRetLength == 0 && targetCodeSize == 0;

    assert lastReverted <=> revert1 || revert2 || revert3 ||
                            revert4, "Revert rules failed";
}
