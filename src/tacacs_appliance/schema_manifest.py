"""Packaged schema compatibility manifest; hashes use universal newlines."""

EXPECTED_MIGRATIONS = {
    "001_initial.sql": "fd26105f4571d2c46f47e42d7e178adbf81754d89bf664d9e84f2a7b6dcaed7d",
    "002_accounting.sql": "042d9c2a773929f89f6577b30228234fe05259d4f2a273d67eeb42bc9066a86f",
    "003_groups.sql": "7137074a6959e717654c95fba0d6f08a33080b0be99bc1d3ce6f9762fb95332f",
    "004_audit_sequence.sql": "de5803c9a6b7024a151beac9cd9e6a57b8fb2cd91825f58cd1c57f4b0239ace3",
    "005_mfa.sql": "84e75c3d42dea9ccdc85758da4a775ca34eac6165b2c90c8e655cd73fc4d8647",
    "006_admin_sessions.sql": "3add29b55f31169426e1fd006324dd22988a7333571a650f4002d95d9a4c251e",
    "007_admin_grants.sql": "46a3924bcdffd96f180d358e8518f1d932028aff20a2d5cae805d7bd740f9dc5",
    "008_policy_tenant_integrity.sql": "38ba8f3120ad9cc3bbbc6a1f15e6873a71cf0c223e0b316933524eebd8b601fd",
    "009_policy_immutability.sql": "aa11997226f6beb892da6be83922ac33a267a7100cfa7245d074813648aa23b1",
    "010_policy_test_reports.sql": "5539cf69ea48228795a970185d2d4f9e5bcccdb213389fcbc81b5728d3d053ec",
    "011_policy_test_evidence.sql": "f79620810024a2d6b571752b859e812d35afe83bc5e34ef96b2cb9120d6cc2df",
    "012_audit_append_only.sql": "c0653b00e087ae0a13d25f5f3fdcefb4554c2994c64499d8bebb3321b34c7fb4",
    "013_mfa_attempt_limits.sql": "9bd469d1706fbd0c2e0691d5f8724087f7150da89294a92ffd52310df754abab",
    "014_admin_session_invalidation.sql": "3376306ccff05af11197195be3aabf0c3a233a0cfe43816ded1cc77adfc1feb3",
    "015_session_trigger_search_path.sql": "2a33a7a2e0d7cdef163b70491b6b1b8063de8e95a06621a6d9f4e6d2858afe18",
    "016_simulation_evidence.sql": "0ff07e0c21d64c5df520aa58660a97dcadbbf2a6bb8e49a824af0cce3f034d96",
    "017_network_devices.sql": "f27aae213e6610ce7816f0227614674420c6de48081ccdd3e12ba9c00bef1e85",
    "018_accounting_query_indexes.sql": "92ba54074c9cd700a6a2c282d298edec3408c3dbb169ceac73a61a608d712b62",
    "019_device_runtime_observations.sql": "340cf10e206e48fd8ae5d8873c9b11243643010329aca89f505f8db0538a7e28",
    "020_network_device_groups.sql": "dbe19d810a764a44f50e899b3dc0fabd80692e6f0913747b92a70d3d737d4c4c",
    "021_device_access_mappings.sql": "535875968e57fad95a949b3a2080f27888c9307b4dc6a6d8f7b5c112eb81bf5e",
    "022_policy_retirements.sql": "15794e94594449cc2ae42562d69b15c7b6b9bd37359087513078e9c92fb7332a",
    "023_device_removal.sql": "1c00855a3946ae978384aa1ec8d93b2b388c828d302726e9029ef915babb0529",
    "024_identity_removal.sql": "c824cff1faca690949cf65e7eccf7fc876401a8e87f9db2dff6e523db3646826",
    "025_default_identity_groups.sql": "9319721c2ebf3c14d741ac6834a3f98a1cd6f62f2ab7634bc98b7c663cd46c47",
    "026_shared_listener_device_addresses.sql": "f1d05ce9ab4130304ea5dae8caed77794b714039ce83bd1257987b6c78238016",
    "027_global_audit_grant.sql": "072a723f913bc1ecd93adb49eb836e44f7ab727f56eaf2940d94461b9f19b6e1",
    "028_tenant_creation_grant.sql": "a218ef7a6b3d7b6d32561339a3da8734c2a8a58c10bc213d0bd66bffc1dd2783",
    "029_global_device_grant.sql": "e66c377fd4085eb2d673668a77eec293ce5e5e3f7a493b5488c74ce6e0debe2f",
    "030_global_identity_grant.sql": "f9cec2b289df58b35ba322675daadceefcb43ea209faa5f161f9bad8e40bdfeb",
    "031_global_policy_read.sql": "f4411bcf2132f1ec798364dac947eb087922abd12ff8dd7fd6043a5e304b1203",
    "032_policy_actor_tenants.sql": "73c2c7c0c2e18ef1b4387e9cc1164ae4ae1839977b3f319f68488afc202e80af",
    "033_device_console_access.sql": "1a0539b736c83ff0c96baa9e17002daa7bbcd41eb0efbf5a6f2fbb446a15ca5b",
    "034_device_console_scopes.sql": "f24810597b5f316be614a942a3367326c2190d603bfd3b912a45d2ac95ecdef9",
    "035_device_creation_addresses.sql": "d93888ec2b36835e0bda1c5e767fb7194e1f230de8cd9f127805c3d9a7ecafcc",
    "036_release_deleted_usernames.sql": "5ed36ca5ea4648f0f2b46a91b7df5e59456c632e7dd737be4ad1c3987197abbd",
    "037_scoped_aaa_logs.sql": "2dc93a34e5ae081f8d2c9acba6685249f65069c981e45d2a72cf965a75f18404",
}


def validate_schema(connection):
    rows = connection.execute("SELECT name,checksum FROM schema_migrations").fetchall()
    applied = dict(rows)
    if applied != EXPECTED_MIGRATIONS:
        raise ValueError("database migration manifest mismatch")
