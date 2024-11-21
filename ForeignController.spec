// ForeignController.spec

using ALMProxy as proxy;
using CctpMock as cctp;
using Psm3Mock as psm;
using RateLimits as rateLimits;
using UsdcMock as usdc;
using UsdsMock as usds;
using SUsdsMock as sUsds;
using Auxiliar as aux;

methods {
    // storage variables
    function active() external returns (bool) envfree;
    function mintRecipients(uint32) external returns (bytes32) envfree;
    // constants
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function FREEZER() external returns (bytes32) envfree;
    function RELAYER() external returns (bytes32) envfree;
    function LIMIT_PSM_DEPOSIT() external returns (bytes32) envfree;
    function LIMIT_PSM_WITHDRAW() external returns (bytes32) envfree;
    function LIMIT_USDC_TO_CCTP() external returns (bytes32) envfree;
    function LIMIT_USDC_TO_DOMAIN() external returns (bytes32) envfree;
    // getters
    function hasRole(bytes32,address) external returns (bool) envfree;
    function getRoleAdmin(bytes32) external returns (bytes32) envfree;
    //
    function proxy.CONTROLLER() external returns (bytes32) envfree;
    function proxy.hasRole(bytes32,address) external returns (bool) envfree;
    function rateLimits.CONTROLLER() external returns (bytes32) envfree;
    function rateLimits.hasRole(bytes32,address) external returns (bool) envfree;
    function rateLimits.getRateLimitData(bytes32) external returns (IRateLimits.RateLimitData) envfree;
    function cctp.lastSender() external returns (address) envfree;
    function cctp.lastSig() external returns (bytes4) envfree;
    function cctp.times() external returns (uint256) envfree;
    function psm.lastSender() external returns (address) envfree;
    function psm.lastSig() external returns (bytes4) envfree;
    function psm.retValue() external returns (uint256) envfree;
    function usdc.lastSender() external returns (address) envfree;
    function usdc.lastSig() external returns (bytes4) envfree;
    function aux.makeAssetKey(bytes32,address) external returns (bytes32) envfree;
    function aux.makeDomainKey(bytes32,uint32) external returns (bytes32) envfree;
    //
    unresolved external in proxy.doCall(address,bytes) => DISPATCH [
        _.approve(address,uint256),
        psm.deposit(address,address,uint256),
        psm.withdraw(address,address,uint256),
        cctp.depositForBurn(uint256,uint32,bytes32,address)
    ] default HAVOC_ALL;
    function _.burnLimitsPerMessage(address token) external => burnLimitsPerMessageSummary() expect uint256;
}

persistent ghost bool callProxySuccess;
hook CALL(uint256 g, address addr, uint256 value, uint256 argsOffset, uint256 argsLength, uint256 retOffset, uint256 retLength) uint256 rc {
    if (addr == proxy) {
        callProxySuccess = rc != 0;
    }
}

ghost uint256 cctpBurnLimit;
function burnLimitsPerMessageSummary() returns uint256 {
    return cctpBurnLimit;
}

definition defDivUp(mathint a, mathint b) returns mathint = a == 0 ? 0 : (a - 1) / b + 1;

// Verify no more entry points exist
rule entryPoints(method f) filtered { f -> !f.isView } {
    env e;

    calldataarg args;
    f(e, args);

    assert f.selector == sig:grantRole(bytes32,address).selector ||
           f.selector == sig:revokeRole(bytes32,address).selector ||
           f.selector == sig:renounceRole(bytes32,address).selector ||
           f.selector == sig:setMintRecipient(uint32,bytes32).selector ||
           f.selector == sig:freeze().selector ||
           f.selector == sig:reactivate().selector ||
           f.selector == sig:depositPSM(address,uint256).selector ||
           f.selector == sig:withdrawPSM(address,uint256).selector ||
           f.selector == sig:transferUSDCToCCTP(uint256,uint32).selector;
}

// Verify that each storage layout is only modified in the corresponding functions
rule storageAffected(method f) {
    env e;

    bytes32 anyBytes32;
    address anyAddr;
    uint32 anyUint32;

    bool hasRoleBefore = hasRole(anyBytes32, anyAddr);
    bytes32 roleAdminBefore = getRoleAdmin(anyBytes32);
    bool activeBefore = active();
    bytes32 mintRecipientsBefore = mintRecipients(anyUint32);

    if (f.selector != sig:depositPSM(address,uint256).selector) {
        calldataarg args;
        f(e, args);
    } else {
        address asset; uint256 amount;
        require asset == usdc || asset == usds || asset == sUsds;
        depositPSM(e, asset, amount);
    }

    bool hasRoleAfter = hasRole(anyBytes32, anyAddr);
    bytes32 roleAdminAfter = getRoleAdmin(anyBytes32);
    bool activeAfter = active();
    bytes32 mintRecipientsAfter = mintRecipients(anyUint32);

    assert hasRoleAfter != hasRoleBefore =>
        f.selector == sig:grantRole(bytes32,address).selector ||
        f.selector == sig:revokeRole(bytes32,address).selector ||
        f.selector == sig:renounceRole(bytes32,address).selector, "Assert 1";
    assert roleAdminAfter == roleAdminBefore, "Assert 2";
    assert activeAfter != activeBefore =>
        f.selector == sig:freeze().selector ||
        f.selector == sig:reactivate().selector, "Assert 3";
    assert mintRecipientsAfter != mintRecipientsBefore =>
        f.selector == sig:setMintRecipient(uint32,bytes32).selector, "Assert 4";
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

// Verify correct storage changes for non reverting setMintRecipient
rule setMintRecipient(uint32 destinationDomain, bytes32 mintRecipient) {
    env e;

    uint32 otherUint32;
    require otherUint32 != destinationDomain;

    bytes32 mintRecipientsOtherBefore = mintRecipients(otherUint32);

    setMintRecipient(e, destinationDomain, mintRecipient);

    bytes32 mintRecipientsDestinationDomainAfter = mintRecipients(destinationDomain);
    bytes32 mintRecipientsOtherAfter = mintRecipients(otherUint32);

    assert mintRecipientsDestinationDomainAfter == mintRecipient, "Assert 1";
    assert mintRecipientsOtherAfter == mintRecipientsOtherBefore, "Assert 1";
}

// Verify revert rules on setMintRecipient
rule setMintRecipient_revert(uint32 destinationDomain, bytes32 mintRecipient) {
    env e;

    bool hasRoleAdminSender = hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    setMintRecipient@withrevert(e, destinationDomain, mintRecipient);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleAdminSender;

    assert lastReverted <=> revert1 || revert2, "Revert rules failed";
}

// Verify correct storage changes for non reverting freeze
rule freeze() {
    env e;

    freeze(e);

    bool activeAfter = active();

    assert !activeAfter, "Assert 1";
}

// Verify revert rules on freeze
rule freeze_revert() {
    env e;

    bool hasRoleFreezerSender = hasRole(FREEZER(), e.msg.sender);

    freeze@withrevert(e);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleFreezerSender;

    assert lastReverted <=> revert1 || revert2, "Revert rules failed";
}

// Verify correct storage changes for non reverting reactivate
rule reactivate() {
    env e;

    reactivate(e);

    bool activeAfter = active();

    assert activeAfter, "Assert 1";
}

// Verify revert rules on reactivate
rule reactivate_revert() {
    env e;

    bool hasRoleAdminSender = hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    reactivate@withrevert(e);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleAdminSender;

    assert lastReverted <=> revert1 || revert2, "Revert rules failed";
}

// Verify correct storage changes for non reverting depositPSM
rule depositPSM(address asset, uint256 amount) {
    env e;

    require asset == usdc || asset == usds || asset == sUsds;

    bytes32 key = aux.makeAssetKey(LIMIT_PSM_DEPOSIT(), asset);
    IRateLimits.RateLimitData rateLimitsPsmDepositData = rateLimits.getRateLimitData(key);
    mathint currentRateLimitBefore = rateLimits.getCurrentRateLimit(e, key);

    depositPSM(e, asset, amount);

    mathint currentRateLimitAfter = rateLimits.getCurrentRateLimit(e, key);
    address assetLastSenderAfter = asset.lastSender(e);
    bytes4  assetLastSigAfter = asset.lastSig(e);
    address psmLastSenderAfter = psm.lastSender();
    bytes4  psmLastSigAfter = psm.lastSig();

    assert currentRateLimitBefore == max_uint256 => currentRateLimitAfter == max_uint256, "Assert ";
    assert currentRateLimitBefore < max_uint256 => currentRateLimitAfter == currentRateLimitBefore - amount, "Assert ";
    assert assetLastSenderAfter == proxy, "Assert ";
    assert assetLastSigAfter == to_bytes4(0x095ea7b3), "Assert ";
    assert psmLastSenderAfter == proxy, "Assert ";
    assert psmLastSigAfter == to_bytes4(0x8340f549), "Assert ";
}

// Verify revert rules on depositPSM
rule depositPSM_revert(address asset, uint256 amount) {
    env e;

    require asset == usdc || asset == usds || asset == sUsds;

    bool hasRoleRelayerSender = hasRole(RELAYER(), e.msg.sender);
    bool active = active();

    bytes32 key = aux.makeAssetKey(LIMIT_PSM_DEPOSIT(), asset);
    IRateLimits.RateLimitData rateLimitsPsmDepositData = rateLimits.getRateLimitData(key);
    mathint currentRateLimit = rateLimits.getCurrentRateLimit(e, key);

    // Setup assumptions
    require proxy.hasRole(proxy.CONTROLLER(), currentContract);
    require rateLimits.hasRole(rateLimits.CONTROLLER(), currentContract);
    // Practical assumptions
    require e.block.timestamp >= rateLimitsPsmDepositData.lastUpdated;
    require rateLimitsPsmDepositData.slope * (e.block.timestamp - rateLimitsPsmDepositData.lastUpdated) + rateLimitsPsmDepositData.lastAmount <= max_uint256;

    depositPSM@withrevert(e, asset, amount);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleRelayerSender;
    bool revert3 = !active;
    bool revert4 = rateLimitsPsmDepositData.maxAmount == 0;
    bool revert5 = amount > currentRateLimit;
    bool revert6 = !callProxySuccess;

    assert lastReverted <=> revert1 || revert2 || revert3 ||
                            revert4 || revert5 || revert6, "Revert rules failed";
}

// Verify correct storage changes for non reverting withdrawPSM
rule withdrawPSM(address asset, uint256 amount) {
    env e;

    bytes32 key = aux.makeAssetKey(LIMIT_PSM_WITHDRAW(), asset);
    IRateLimits.RateLimitData rateLimitsPsmWithdrawData = rateLimits.getRateLimitData(key);
    mathint currentRateLimitBefore = rateLimits.getCurrentRateLimit(e, key);

    mathint assetsWithdrawn = psm.retValue();

    withdrawPSM(e, asset, amount);

    mathint currentRateLimitAfter = rateLimits.getCurrentRateLimit(e, key);
    address psmLastSenderAfter = psm.lastSender();
    bytes4  psmLastSigAfter = psm.lastSig();

    assert currentRateLimitBefore == max_uint256 => currentRateLimitAfter == max_uint256, "Assert ";
    assert currentRateLimitBefore < max_uint256 => currentRateLimitAfter == currentRateLimitBefore - assetsWithdrawn, "Assert ";
    assert psmLastSenderAfter == proxy, "Assert ";
    assert psmLastSigAfter == to_bytes4(0xd9caed12), "Assert ";
}

// Verify revert rules on withdrawPSM
rule withdrawPSM_revert(address asset, uint256 amount) {
    env e;

    bool hasRoleRelayerSender = hasRole(RELAYER(), e.msg.sender);
    bool active = active();

    bytes32 key = aux.makeAssetKey(LIMIT_PSM_WITHDRAW(), asset);
    IRateLimits.RateLimitData rateLimitsPsmWithdrawData = rateLimits.getRateLimitData(key);
    mathint currentRateLimit = rateLimits.getCurrentRateLimit(e, key);

    // Setup assumptions
    require proxy.hasRole(proxy.CONTROLLER(), currentContract);
    require rateLimits.hasRole(rateLimits.CONTROLLER(), currentContract);
    // Practical assumptions
    require e.block.timestamp >= rateLimitsPsmWithdrawData.lastUpdated;
    require rateLimitsPsmWithdrawData.slope * (e.block.timestamp - rateLimitsPsmWithdrawData.lastUpdated) + rateLimitsPsmWithdrawData.lastAmount <= max_uint256;

    mathint assetsWithdrawn = psm.retValue();

    withdrawPSM@withrevert(e, asset, amount);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleRelayerSender;
    bool revert3 = !active;
    bool revert4 = rateLimitsPsmWithdrawData.maxAmount == 0;
    bool revert5 = assetsWithdrawn > currentRateLimit;
    bool revert6 = !callProxySuccess;

    assert lastReverted <=> revert1 || revert2 || revert3 ||
                            revert4 || revert5 || revert6, "Revert rules failed";
}

// Verify correct storage changes for non reverting transferUSDCToCCTP
rule transferUSDCToCCTP(uint256 usdcAmount, uint32 destinationDomain) {
    env e;

    require cctp.times() == 0;

    bytes32 LIMIT_USDC_TO_CCTP = LIMIT_USDC_TO_CCTP();
    IRateLimits.RateLimitData rateLimitsUsdcToCctpData = rateLimits.getRateLimitData(LIMIT_USDC_TO_CCTP);
    mathint currentRateLimitUsdcToCctpBefore = rateLimits.getCurrentRateLimit(e, LIMIT_USDC_TO_CCTP);
    bytes32 keyDomain = aux.makeDomainKey(LIMIT_USDC_TO_DOMAIN(), destinationDomain);
    IRateLimits.RateLimitData rateLimitsUsdcToDomainData = rateLimits.getRateLimitData(keyDomain);
    mathint currentRateLimitUsdcToDomainBefore = rateLimits.getCurrentRateLimit(e, keyDomain);

    mathint burnLimit = cctpBurnLimit;

    mathint calcTimes = burnLimit > 0 ? defDivUp(usdcAmount, burnLimit) : 0;

    transferUSDCToCCTP(e, usdcAmount, destinationDomain);

    mathint currentRateLimitUsdcToCctpAfter = rateLimits.getCurrentRateLimit(e, LIMIT_USDC_TO_CCTP);
    mathint currentRateLimitUsdcToDomainAfter = rateLimits.getCurrentRateLimit(e, keyDomain);
    address usdcLastSenderAfter = usdc.lastSender();
    bytes4  usdcLastSigAfter = usdc.lastSig();
    address cctpLastSenderAfter = cctp.lastSender();
    bytes4  cctpLastSigAfter = cctp.lastSig();
    mathint cctpTimesAfter = cctp.times();

    assert currentRateLimitUsdcToCctpBefore == max_uint256 => currentRateLimitUsdcToCctpAfter == max_uint256, "Assert ";
    assert currentRateLimitUsdcToCctpBefore < max_uint256 => currentRateLimitUsdcToCctpAfter == currentRateLimitUsdcToCctpBefore - usdcAmount, "Assert ";
    assert currentRateLimitUsdcToDomainBefore == max_uint256 => currentRateLimitUsdcToDomainAfter == max_uint256, "Assert ";
    assert currentRateLimitUsdcToDomainBefore < max_uint256 => currentRateLimitUsdcToDomainAfter == currentRateLimitUsdcToDomainBefore - usdcAmount, "Assert ";
    assert usdcLastSenderAfter == proxy, "Assert ";
    assert usdcLastSigAfter == to_bytes4(0x095ea7b3), "Assert ";
    assert calcTimes > 0 => cctpLastSenderAfter == proxy, "Assert ";
    assert calcTimes > 0 => cctpLastSigAfter == to_bytes4(0x6fd3504e), "Assert ";
    assert cctpTimesAfter == calcTimes, "Assert ";
}

// Verify revert rules on transferUSDCToCCTP
rule transferUSDCToCCTP_revert(uint256 usdcAmount, uint32 destinationDomain) {
    env e;

    bool hasRoleRelayerSender = hasRole(RELAYER(), e.msg.sender);
    bool active = active();

    bytes32 LIMIT_USDC_TO_CCTP = LIMIT_USDC_TO_CCTP();
    IRateLimits.RateLimitData rateLimitsUsdcToCctpData = rateLimits.getRateLimitData(LIMIT_USDC_TO_CCTP);
    mathint currentRateLimitUsdcToCctp = rateLimits.getCurrentRateLimit(e, LIMIT_USDC_TO_CCTP);
    bytes32 keyDomain = aux.makeDomainKey(LIMIT_USDC_TO_DOMAIN(), destinationDomain);
    IRateLimits.RateLimitData rateLimitsUsdcToDomainData = rateLimits.getRateLimitData(keyDomain);
    mathint currentRateLimitUsdcToDomain = rateLimits.getCurrentRateLimit(e, keyDomain);

    bytes32 mintRecipient = mintRecipients(destinationDomain);

    // Setup assumptions
    require proxy.hasRole(proxy.CONTROLLER(), currentContract);
    require rateLimits.hasRole(rateLimits.CONTROLLER(), currentContract);
    // Practical assumptions
    require e.block.timestamp >= rateLimitsUsdcToCctpData.lastUpdated;
    require rateLimitsUsdcToCctpData.slope * (e.block.timestamp - rateLimitsUsdcToCctpData.lastUpdated) + rateLimitsUsdcToCctpData.lastAmount <= max_uint256;
    require e.block.timestamp >= rateLimitsUsdcToDomainData.lastUpdated;
    require rateLimitsUsdcToDomainData.slope * (e.block.timestamp - rateLimitsUsdcToDomainData.lastUpdated) + rateLimitsUsdcToDomainData.lastAmount <= max_uint256;

    transferUSDCToCCTP@withrevert(e, usdcAmount, destinationDomain);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleRelayerSender;
    bool revert3 = !active;
    bool revert4 = rateLimitsUsdcToCctpData.maxAmount == 0;
    bool revert5 = usdcAmount > currentRateLimitUsdcToCctp;
    bool revert6 = rateLimitsUsdcToDomainData.maxAmount == 0;
    bool revert7 = usdcAmount > currentRateLimitUsdcToDomain;
    bool revert8 = mintRecipient == to_bytes32(0x0);
    bool revert9 = !callProxySuccess;

    assert lastReverted <=> revert1 || revert2 || revert3 ||
                            revert4 || revert5 || revert6 ||
                            revert7 || revert8 || revert9, "Revert rules failed";
}
