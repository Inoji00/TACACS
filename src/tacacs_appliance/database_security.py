"""Fail closed when an AAA runtime role can bypass database protections."""


def validate_unprivileged_role(connection) -> None:
    privileged = connection.execute(
        "SELECT EXISTS (SELECT 1 FROM pg_roles r WHERE pg_has_role(current_user,r.oid,'MEMBER') "
        "AND (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls))"
    ).fetchone()
    if privileged is None or privileged[0]:
        raise ValueError("privileged runtime database role forbidden")
    owned = connection.execute(
        "SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=current_schema() AND pg_has_role(current_user,c.relowner,'MEMBER')) "
        "OR EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspname=current_schema() "
        "AND pg_has_role(current_user,n.nspowner,'MEMBER')) "
        "OR EXISTS (SELECT 1 FROM pg_database d WHERE d.datname=current_database() "
        "AND pg_has_role(current_user,d.datdba,'MEMBER')) "
        "OR has_schema_privilege(current_user,current_schema(),'CREATE')"
    ).fetchone()
    if owned is None or owned[0]:
        raise ValueError("runtime database ownership or schema CREATE forbidden")


def validate_runtime_role(connection) -> None:
    validate_unprivileged_role(connection)
    unsafe = connection.execute(
        "SELECT has_table_privilege(current_user,'audit_events','UPDATE') "
        "OR has_any_column_privilege(current_user,'audit_events','UPDATE') "
        "OR has_table_privilege(current_user,'audit_events','DELETE') "
        "OR has_table_privilege(current_user,'audit_events','TRUNCATE') "
        "OR has_table_privilege(current_user,'policy_versions','INSERT') "
        "OR has_any_column_privilege(current_user,'policy_versions','INSERT') "
        "OR has_table_privilege(current_user,'policy_versions','UPDATE') "
        "OR has_any_column_privilege(current_user,'policy_versions','UPDATE') "
        "OR has_table_privilege(current_user,'policy_versions','DELETE') "
        "OR has_any_column_privilege(current_user,'policy_simulation_reports','INSERT') "
        "OR has_any_column_privilege(current_user,'policy_simulation_reports','UPDATE') "
        "OR has_table_privilege(current_user,'policy_simulation_reports','DELETE') "
        "OR has_table_privilege(current_user,'policy_simulation_reports','TRUNCATE') "
        "OR has_any_column_privilege(current_user,'network_devices','INSERT') "
        "OR has_any_column_privilege(current_user,'network_devices','UPDATE') "
        "OR has_table_privilege(current_user,'network_devices','DELETE') "
        "OR has_table_privilege(current_user,'network_devices','TRUNCATE') "
        "OR has_any_column_privilege(current_user,'network_device_groups','INSERT') "
        "OR has_any_column_privilege(current_user,'network_device_groups','UPDATE') "
        "OR has_table_privilege(current_user,'network_device_groups','DELETE') "
        "OR has_any_column_privilege(current_user,'policy_retirements','INSERT') "
        "OR has_any_column_privilege(current_user,'identity_groups','UPDATE') "
        "OR has_table_privilege(current_user,'identity_groups','DELETE')"
    ).fetchone()
    if unsafe is None or unsafe[0]:
        raise ValueError("AAA role has forbidden audit or policy mutation privileges")


def validate_admin_role(connection) -> None:
    validate_unprivileged_role(connection)
    immutable = (
        "audit_events",
        "policy_test_reports",
        "policy_simulation_reports",
        "schema_migrations",
        "device_runtime_observations",
        "policy_retirements",
    )
    for table in immutable:
        privileges = ("UPDATE", "DELETE", "TRUNCATE") + (
            ("INSERT",)
            if table in ("schema_migrations", "device_runtime_observations")
            else ()
        )
        for privilege in privileges:
            function = (
                "has_any_column_privilege"
                if privilege in ("UPDATE", "INSERT")
                else "has_table_privilege"
            )
            # has_any_column_privilege includes whole-table grants as well as
            # grants on a single column; DELETE/TRUNCATE are table-only.
            row = connection.execute(
                "SELECT " + function + "(current_user,%s,%s)", (table, privilege)
            ).fetchone()
            if row is None or row[0]:
                raise ValueError(
                    "administrator role has forbidden evidence mutation privileges"
                )
    for privilege in ("DELETE", "TRUNCATE"):
        row = connection.execute(
            "SELECT has_table_privilege(current_user,'policy_versions',%s)",
            (privilege,),
        ).fetchone()
        if row is None or row[0]:
            raise ValueError(
                "administrator role has forbidden policy history deletion privileges"
            )
