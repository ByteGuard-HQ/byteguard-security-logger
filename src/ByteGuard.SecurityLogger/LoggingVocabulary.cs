namespace ByteGuard.SecurityLogger;

internal static class LoggingVocabulary
{
    internal const string AuthnLoginSuccess = "authn_login_success";
    internal const string AuthnLoginSuccessAfterFail = "authn_login_successafterfail";
    internal const string AuthnLoginFail = "authn_login_fail";
    internal const string AuthnLoginFailMax = "authn_login_fail_max";
    internal const string AuthnLoginLock = "authn_login_lock";
    internal const string AuthnPasswordChange = "authn_password_change";
    internal const string AuthnPasswordChangeFail = "authn_password_change_fail";
    internal const string AuthnImpossibleTravel = "authn_impossible_travel";
    internal const string AuthnTokenCreated = "authn_token_created";
    internal const string AuthnTokenRevoked = "authn_token_revoked";
    internal const string AuthnTokenReuse = "authn_token_reuse";
    internal const string AuthnTokenDelete = "authn_token_delete";

    internal const string AuthzFail = "authz_fail";
    internal const string AuthzChange = "authz_change";
    internal const string AuthzAdmin = "authz_admin";

    internal const string CryptDecryptFail = "crypt_decrypt_fail";
    internal const string CryptEncryptFail = "crypt_encrypt_fail";

    internal const string ExcessRateLimitExceeded = "excess_rate_limit_exceeded";

    internal const string UploadComplete = "upload_complete";
    internal const string UploadStored = "upload_stored";
    internal const string UploadValidation = "upload_validation";
    internal const string UploadDelete = "upload_delete";

    internal const string InputValidationFailed = "input_validation_failed";
    internal const string InputValidationDiscreteFail = "input_validation_discrete_fail";

    internal const string MaliciousExcess404 = "malicious_excess_404";
    internal const string MaliciousExtraneous = "malicious_extraneous";
    internal const string MaliciousAttackTool = "malicious_attack_tool";
    internal const string MaliciousCors = "malicious_cors";
    internal const string MaliciousDirectReference = "malicious_direct_reference";

    internal const string PrivilegePermissionsChanged = "privilege_permissions_changed";

    internal const string SensitiveCreate = "sensitive_create";
    internal const string SensitiveRead = "sensitive_read";
    internal const string SensitiveUpdate = "sensitive_update";
    internal const string SensitiveDelete = "sensitive_delete";

    internal const string SequenceFail = "sequence_fail";

    internal const string SessionCreated = "session_created";
    internal const string SessionRenewed = "session_renewed";
    internal const string SessionExpired = "session_expired";
    internal const string SessionUseAfterExpire = "session_use_after_expire";

    internal const string SystemStartup = "sys_startup";
    internal const string SystemShutdown = "sys_shutdown";
    internal const string SystemRestart = "sys_restart";
    internal const string SystemCrash = "sys_crash";
    internal const string SystemMonitorDisabled = "sys_monitor_disabled";
    internal const string SystemMonitorEnabled = "sys_monitor_enabled";

    internal const string UserCreated = "user_created";
    internal const string UserUpdated = "user_updated";
    internal const string UserArchived = "user_archived";
    internal const string UserDeleted = "user_deleted";
}
