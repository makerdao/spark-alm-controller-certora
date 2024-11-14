// MainnetController.spec

using ALMProxy as proxy;
using RateLimits as rateLimits;
using CctpMock as cctp;
using DaiUsdsMock as daiUsds;
using PsmMock as psm;
using AllocatorVaultMock as vault;
using DaiMock as dai;
using UsdsMock as usds;
using UsdcMock as usdc;
using SUsdsMock as sUsds;
using Auxiliar as aux;

methods {
    // storage variables
    function active() external returns (bool) envfree;
    function mintRecipients(uint32) external returns (bytes32) envfree;
    // immutables
    function buffer() external returns (address) envfree;
    function psmTo18ConversionFactor() external returns (uint256) envfree;
    // constants
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function FREEZER() external returns (bytes32) envfree;
    function RELAYER() external returns (bytes32) envfree;
    function LIMIT_USDC_TO_CCTP() external returns (bytes32) envfree;
    function LIMIT_USDC_TO_DOMAIN() external returns (bytes32) envfree;
    function LIMIT_USDS_MINT() external returns (bytes32) envfree;
    function LIMIT_USDS_TO_USDC() external returns (bytes32) envfree;
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
    function daiUsds.lastSender() external returns (address) envfree;
    function daiUsds.lastSig() external returns (bytes4) envfree;
    function psm.lastSender() external returns (address) envfree;
    function psm.lastSig() external returns (bytes4) envfree;
    function vault.lastAmount() external returns (uint256) envfree;
    function vault.lastSender() external returns (address) envfree;
    function vault.lastSig() external returns (bytes4) envfree;
    function dai.lastSender() external returns (address) envfree;
    function dai.lastSig() external returns (bytes4) envfree;
    function usds.lastFrom() external returns (address) envfree;
    function usds.lastTo() external returns (address) envfree;
    function usds.lastAmount() external returns (uint256) envfree;
    function usds.lastSender() external returns (address) envfree;
    function usds.lastSig() external returns (bytes4) envfree;
    function usdc.lastSender() external returns (address) envfree;
    function usdc.lastSig() external returns (bytes4) envfree;
    function sUsds.lastSender() external returns (address) envfree;
    function sUsds.lastSig() external returns (bytes4) envfree;
    function aux.makeDomainKey(bytes32,uint32) external returns (bytes32) envfree;
    //
    function _._ => DISPATCH [
        _.approve(address,uint256),
        _.transfer(address,uint256),
        _.transferFrom(address,address,uint256),
        _.depositForBurn(uint256,uint32,bytes32,address),
        _.usdsToDai(address,uint256),
        _.daiToUsds(address,uint256),
        _.usdsToDai(address,uint256),
        _.buyGemNoFee(address,uint256),
        _.sellGemNoFee(address,uint256),
        _.draw(uint256),
        _.wipe(uint256),
        _.deposit(uint256,address),
        _.withdraw(uint256,address,address),
        _.redeem(uint256,address,address)
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
definition defMin(mathint a, mathint b) returns mathint = a < b ? a : b;

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
           f.selector == sig:mintUSDS(uint256).selector ||
           f.selector == sig:burnUSDS(uint256).selector ||
           f.selector == sig:depositToSUSDS(uint256).selector ||
           f.selector == sig:withdrawFromSUSDS(uint256).selector ||
           f.selector == sig:redeemFromSUSDS(uint256).selector ||
           f.selector == sig:swapUSDSToUSDC(uint256).selector ||
           f.selector == sig:swapUSDCToUSDS(uint256).selector ||
           f.selector == sig:transferUSDCToCCTP(uint256,uint32).selector ||
           f.selector == sig:swapUSDSToUSDC(uint256).selector;
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

    calldataarg args;
    f(e, args);

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

// Verify correct storage changes for non reverting mintUSDS
rule mintUSDS(uint256 usdsAmount) {
    env e;

    mintUSDS(e, usdsAmount);

    uint256 vaultLastAmountAfter = vault.lastAmount();
    address vaultLastSenderAfter = vault.lastSender();
    bytes4  vaultLastSigAfter = vault.lastSig();
    address usdsLastFromAfter = usds.lastFrom();
    address usdsLastToAfter = usds.lastTo();
    uint256 usdsLastAmountAfter = usds.lastAmount();
    address usdsLastSenderAfter = usds.lastSender();
    bytes4  usdsLastSigAfter = usds.lastSig();

    // assert vaultLastAmountAfter == usdsAmount, "Assert 1";
    assert vaultLastSenderAfter == proxy, "Assert 2";
    assert vaultLastSigAfter == to_bytes4(0x3b304147), "Assert 3";
    // assert usdsLastFromAfter == buffer(), "Assert 4";
    // assert usdsLastToAfter == proxy, "Assert 5";
    // assert usdsLastAmountAfter == usdsAmount, "Assert 6";
    assert usdsLastSenderAfter == proxy, "Assert 7";
    assert usdsLastSigAfter == to_bytes4(0x23b872dd), "Assert 8";
}

// Verify revert rules on mintUSDS
rule mintUSDS_revert(uint256 usdsAmount) {
    env e;

    bool hasRoleRelayerSender = hasRole(RELAYER(), e.msg.sender);
    bool active = active();

    bytes32 LIMIT_USDS_MINT = LIMIT_USDS_MINT();
    IRateLimits.RateLimitData rateLimitsUsdsMintData = rateLimits.getRateLimitData(LIMIT_USDS_MINT);
    mathint currentRateLimit = rateLimits.getCurrentRateLimit(e, LIMIT_USDS_MINT);

    // Setup assumptions
    require proxy.hasRole(proxy.CONTROLLER(), currentContract);
    require rateLimits.hasRole(rateLimits.CONTROLLER(), currentContract);
    // Practical assumptions
    require e.block.timestamp >= rateLimitsUsdsMintData.lastUpdated;
    require rateLimitsUsdsMintData.slope * (e.block.timestamp - rateLimitsUsdsMintData.lastUpdated) + rateLimitsUsdsMintData.lastAmount <= max_uint256;

    mintUSDS@withrevert(e, usdsAmount);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleRelayerSender;
    bool revert3 = !active;
    bool revert4 = rateLimitsUsdsMintData.maxAmount == 0;
    bool revert5 = usdsAmount > currentRateLimit;
    bool revert6 = !callProxySuccess;

    assert lastReverted <=> revert1 || revert2 || revert3 ||
                            revert4 || revert5 || revert6, "Revert rules failed";
}

// Verify correct storage changes for non reverting burnUSDS
rule burnUSDS(uint256 usdsAmount) {
    env e;

    burnUSDS(e, usdsAmount);

    uint256 vaultLastAmountAfter = vault.lastAmount();
    address vaultLastSenderAfter = vault.lastSender();
    bytes4  vaultLastSigAfter = vault.lastSig();
    address usdsLastFromAfter = usds.lastFrom();
    address usdsLastToAfter = usds.lastTo();
    uint256 usdsLastAmountAfter = usds.lastAmount();
    address usdsLastSenderAfter = usds.lastSender();
    bytes4  usdsLastSigAfter = usds.lastSig();

    // assert vaultLastAmountAfter == usdsAmount, "Assert 1";
    assert vaultLastSenderAfter == proxy, "Assert 2";
    assert vaultLastSigAfter == to_bytes4(0xb38a1620), "Assert 3";
    // assert usdsLastFromAfter == proxy, "Assert 4";
    // assert usdsLastToAfter == proxy, "Assert 5";
    // assert usdsLastAmountAfter == usdsAmount, "Assert 6";
    assert usdsLastSenderAfter == proxy, "Assert 7";
    assert usdsLastSigAfter == to_bytes4(0xa9059cbb), "Assert 8";
}

// Verify revert rules on burnUSDS
rule burnUSDS_revert(uint256 usdsAmount) {
    env e;

    bool hasRoleRelayerSender = hasRole(RELAYER(), e.msg.sender);
    bool active = active();

    bytes32 LIMIT_USDS_MINT = LIMIT_USDS_MINT();
    IRateLimits.RateLimitData rateLimitsUsdsMintData = rateLimits.getRateLimitData(LIMIT_USDS_MINT);
    mathint currentRateLimit = rateLimits.getCurrentRateLimit(e, LIMIT_USDS_MINT);

    // Setup assumptions
    require proxy.hasRole(proxy.CONTROLLER(), currentContract);
    require rateLimits.hasRole(rateLimits.CONTROLLER(), currentContract);
    // Practical assumptions
    require e.block.timestamp >= rateLimitsUsdsMintData.lastUpdated;
    require rateLimitsUsdsMintData.slope * (e.block.timestamp - rateLimitsUsdsMintData.lastUpdated) + rateLimitsUsdsMintData.lastAmount <= max_uint256;

    burnUSDS@withrevert(e, usdsAmount);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleRelayerSender;
    bool revert3 = !active;
    bool revert4 = rateLimitsUsdsMintData.maxAmount == 0;
    bool revert5 = rateLimitsUsdsMintData.maxAmount < max_uint256 && currentRateLimit + usdsAmount > max_uint256;
    bool revert6 = !callProxySuccess;

    assert lastReverted <=> revert1 || revert2 || revert3 ||
                            revert4 || revert5 || revert6, "Revert rules failed";
}

// Verify correct storage changes for non reverting depositToSUSDS
rule depositToSUSDS(uint256 usdsAmount) {
    env e;

    depositToSUSDS(e, usdsAmount);

    address usdsLastSenderAfter = usds.lastSender();
    bytes4  usdsLastSigAfter = usds.lastSig();
    address sUsdsLastSenderAfter = sUsds.lastSender();
    bytes4  sUsdsLastSigAfter = sUsds.lastSig();

    assert usdsLastSenderAfter == proxy, "Assert ";
    assert usdsLastSigAfter == to_bytes4(0x095ea7b3), "Assert ";
    assert sUsdsLastSenderAfter == proxy, "Assert ";
    assert sUsdsLastSigAfter == to_bytes4(0x6e553f65), "Assert ";
}

// Verify revert rules on depositToSUSDS
rule depositToSUSDS_revert(uint256 usdsAmount) {
    env e;

    bool hasRoleRelayerSender = hasRole(RELAYER(), e.msg.sender);
    bool active = active();

    // Setup assumptions
    require proxy.hasRole(proxy.CONTROLLER(), currentContract);
    require rateLimits.hasRole(rateLimits.CONTROLLER(), currentContract);

    depositToSUSDS@withrevert(e, usdsAmount);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleRelayerSender;
    bool revert3 = !active;
    bool revert4 = !callProxySuccess;

    assert lastReverted <=> revert1 || revert2 || revert3 ||
                            revert4, "Revert rules failed";
}

// Verify correct storage changes for non reverting withdrawFromSUSDS
rule withdrawFromSUSDS(uint256 usdsAmount) {
    env e;

    withdrawFromSUSDS(e, usdsAmount);

    address sUsdsLastSenderAfter = sUsds.lastSender();
    bytes4  sUsdsLastSigAfter = sUsds.lastSig();

    assert sUsdsLastSenderAfter == proxy, "Assert ";
    assert sUsdsLastSigAfter == to_bytes4(0xb460af94), "Assert ";
}

// Verify revert rules on withdrawFromSUSDS
rule withdrawFromSUSDS_revert(uint256 usdsAmount) {
    env e;

    bool hasRoleRelayerSender = hasRole(RELAYER(), e.msg.sender);
    bool active = active();

    // Setup assumptions
    require proxy.hasRole(proxy.CONTROLLER(), currentContract);
    require rateLimits.hasRole(rateLimits.CONTROLLER(), currentContract);

    withdrawFromSUSDS@withrevert(e, usdsAmount);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleRelayerSender;
    bool revert3 = !active;
    bool revert4 = !callProxySuccess;

    assert lastReverted <=> revert1 || revert2 || revert3 ||
                            revert4, "Revert rules failed";
}

// Verify correct storage changes for non reverting redeemFromSUSDS
rule redeemFromSUSDS(uint256 sUsdsSharesAmount) {
    env e;

    redeemFromSUSDS(e, sUsdsSharesAmount);

    address sUsdsLastSenderAfter = sUsds.lastSender();
    bytes4  sUsdsLastSigAfter = sUsds.lastSig();

    assert sUsdsLastSenderAfter == proxy, "Assert ";
    assert sUsdsLastSigAfter == to_bytes4(0xba087652), "Assert ";
}

// Verify revert rules on redeemFromSUSDS
rule redeemFromSUSDS_revert(uint256 sUsdsSharesAmount) {
    env e;

    bool hasRoleRelayerSender = hasRole(RELAYER(), e.msg.sender);
    bool active = active();

    // Setup assumptions
    require proxy.hasRole(proxy.CONTROLLER(), currentContract);
    require rateLimits.hasRole(rateLimits.CONTROLLER(), currentContract);

    redeemFromSUSDS@withrevert(e, sUsdsSharesAmount);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleRelayerSender;
    bool revert3 = !active;
    bool revert4 = !callProxySuccess;

    assert lastReverted <=> revert1 || revert2 || revert3 ||
                            revert4, "Revert rules failed";
}

// Verify correct storage changes for non reverting swapUSDSToUSDC
rule swapUSDSToUSDC(uint256 usdcAmount) {
    env e;

    swapUSDSToUSDC(e, usdcAmount);

    address usdsLastSenderAfter = usds.lastSender();
    bytes4  usdsLastSigAfter = usds.lastSig();
    address daiUsdsLastSenderAfter = daiUsds.lastSender();
    bytes4  daiUsdsLastSigAfter = daiUsds.lastSig();
    address daiLastSenderAfter = dai.lastSender();
    bytes4  daiLastSigAfter = dai.lastSig();
    address psmLastSenderAfter = psm.lastSender();
    bytes4  psmLastSigAfter = psm.lastSig();

    assert usdsLastSenderAfter == proxy, "Assert ";
    assert usdsLastSigAfter == to_bytes4(0x095ea7b3), "Assert ";
    assert daiUsdsLastSenderAfter == proxy, "Assert ";
    assert daiUsdsLastSigAfter == to_bytes4(0x68f30150), "Assert ";
    assert daiLastSenderAfter == proxy, "Assert ";
    assert daiLastSigAfter == to_bytes4(0x095ea7b3), "Assert ";
    assert psmLastSenderAfter == proxy, "Assert ";
    assert psmLastSigAfter == to_bytes4(0x067d9274), "Assert ";
}

// Verify revert rules on swapUSDSToUSDC
rule swapUSDSToUSDC_revert(uint256 usdcAmount) {
    env e;

    bool hasRoleRelayerSender = hasRole(RELAYER(), e.msg.sender);
    bool active = active();

    bytes32 LIMIT_USDS_TO_USDC = LIMIT_USDS_TO_USDC();
    IRateLimits.RateLimitData rateLimitsUsdsToUsdcData = rateLimits.getRateLimitData(LIMIT_USDS_TO_USDC);
    mathint currentRateLimit = rateLimits.getCurrentRateLimit(e, LIMIT_USDS_TO_USDC);

    mathint psmTo18ConversionFactor = psmTo18ConversionFactor();

    // Setup assumptions
    require proxy.hasRole(proxy.CONTROLLER(), currentContract);
    require rateLimits.hasRole(rateLimits.CONTROLLER(), currentContract);
    // Practical assumptions
    require e.block.timestamp >= rateLimitsUsdsToUsdcData.lastUpdated;
    require rateLimitsUsdsToUsdcData.slope * (e.block.timestamp - rateLimitsUsdsToUsdcData.lastUpdated) + rateLimitsUsdsToUsdcData.lastAmount <= max_uint256;

    swapUSDSToUSDC@withrevert(e, usdcAmount);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleRelayerSender;
    bool revert3 = !active;
    bool revert4 = rateLimitsUsdsToUsdcData.maxAmount == 0;
    bool revert5 = usdcAmount > currentRateLimit;
    bool revert6 = !callProxySuccess;
    bool revert7 = usdcAmount * psmTo18ConversionFactor > max_uint256;

    assert lastReverted <=> revert1 || revert2 || revert3 ||
                            revert4 || revert5 || revert6 ||
                            revert7, "Revert rules failed";
}

// Verify correct storage changes for non reverting swapUSDCToUSDS
rule swapUSDCToUSDS(uint256 usdcAmount) {
    env e;

    swapUSDCToUSDS(e, usdcAmount);

    address usdcLastSenderAfter = usdc.lastSender();
    bytes4  usdcLastSigAfter = usdc.lastSig();
    address psmLastSenderAfter = psm.lastSender();
    bytes4  psmLastSigAfter = psm.lastSig();
    address daiLastSenderAfter = dai.lastSender();
    bytes4  daiLastSigAfter = dai.lastSig();
    address daiUsdsLastSenderAfter = daiUsds.lastSender();
    bytes4  daiUsdsLastSigAfter = daiUsds.lastSig();

    assert usdcLastSenderAfter == proxy, "Assert ";
    assert usdcLastSigAfter == to_bytes4(0x095ea7b3), "Assert ";
    assert psmLastSenderAfter == proxy, "Assert ";
    assert psmLastSigAfter == to_bytes4(0x86c34f42), "Assert ";
    assert daiLastSenderAfter == proxy, "Assert ";
    assert daiLastSigAfter == to_bytes4(0x095ea7b3), "Assert ";
    assert daiUsdsLastSenderAfter == proxy, "Assert ";
    assert daiUsdsLastSigAfter == to_bytes4(0xf2c07aae), "Assert ";
}

// Verify revert rules on swapUSDCToUSDS
rule swapUSDCToUSDS_revert(uint256 usdcAmount) {
    env e;

    bool hasRoleRelayerSender = hasRole(RELAYER(), e.msg.sender);
    bool active = active();

    bytes32 LIMIT_USDS_TO_USDC = LIMIT_USDS_TO_USDC();
    IRateLimits.RateLimitData rateLimitsUsdsToUsdcData = rateLimits.getRateLimitData(LIMIT_USDS_TO_USDC);
    mathint currentRateLimit = rateLimits.getCurrentRateLimit(e, LIMIT_USDS_TO_USDC);

    mathint psmTo18ConversionFactor = psmTo18ConversionFactor();

    // Setup assumptions
    require proxy.hasRole(proxy.CONTROLLER(), currentContract);
    require rateLimits.hasRole(rateLimits.CONTROLLER(), currentContract);
    // Practical assumptions
    require e.block.timestamp >= rateLimitsUsdsToUsdcData.lastUpdated;
    require rateLimitsUsdsToUsdcData.slope * (e.block.timestamp - rateLimitsUsdsToUsdcData.lastUpdated) + rateLimitsUsdsToUsdcData.lastAmount <= max_uint256;

    swapUSDCToUSDS@withrevert(e, usdcAmount);

    bool revert1 = e.msg.value > 0;
    bool revert2 = !hasRoleRelayerSender;
    bool revert3 = !active;
    bool revert4 = rateLimitsUsdsToUsdcData.maxAmount == 0;
    bool revert5 = rateLimitsUsdsToUsdcData.maxAmount < max_uint256 && currentRateLimit + usdcAmount > max_uint256;
    bool revert6 = !callProxySuccess;
    bool revert7 = psmTo18ConversionFactor == 0;
    bool revert8 = usdcAmount * psmTo18ConversionFactor > max_uint256;

    assert lastReverted <=> revert1 || revert2 || revert3 ||
                            revert4 || revert5 || revert6 ||
                            revert7 || revert8, "Revert rules failed";
}

// Verify correct storage changes for non reverting transferUSDCToCCTP
rule transferUSDCToCCTP(uint256 usdcAmount, uint32 destinationDomain) {
    env e;

    require cctp.times() == 0;

    mathint burnLimit = cctpBurnLimit;

    mathint calcTimes = burnLimit > 0 ? defDivUp(usdcAmount, burnLimit) : 0;

    transferUSDCToCCTP(e, usdcAmount, destinationDomain);

    address usdcLastSenderAfter = usdc.lastSender();
    bytes4  usdcLastSigAfter = usdc.lastSig();
    address cctpLastSenderAfter = cctp.lastSender();
    bytes4  cctpLastSigAfter = cctp.lastSig();
    mathint cctpTimesAfter = cctp.times();

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
