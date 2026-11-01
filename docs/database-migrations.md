# Database migrations

## Ownership and startup

Flyway owns DDL. Hibernate uses `ddl-auto: validate` and does not create or update
application tables. On an empty PostgreSQL schema, startup applies
`V1__create_auth_tables.sql`, then Hibernate checks the mapped column types.
Flyway records versions and checksums in `flyway_schema_history`. A subsequent
startup validates migration history and only applies new versions.

Keep applied migration files immutable. Put future changes in `V2__...sql`,
`V3__...sql`, etc. Do not use `repair` to hide an unexplained checksum mismatch.
`clean` is disabled and automatic baseline is disabled.

V1 preserves current Hibernate-model column types, nullability and indexes. It
adds no user foreign keys, seeds, database UUID generators, or timestamp defaults.
UUIDs/timestamps continue to be assigned by Java. Audit events intentionally have
no user FK because they may be recorded independently of authentication transactions.
Hibernate validation does not verify every index, unique constraint or nullability
rule, so it is not a complete schema-diff tool.

## New empty database

Use the normal application configuration and start the app. No separate migration
command is required. The database user needs DDL privileges for migrations; splitting
migration credentials from runtime credentials can be introduced for deployment.
The Docker/PostgreSQL development credentials are not a deployment access policy.

## Existing database created by Hibernate

Do not set `baseline-on-migrate=true` globally. Flyway intentionally refuses a
nonempty schema without migration history. This prevents silently adopting an
unverified database. Baseline only records history; it does not reconcile schemas.

1. Stop application writers and back up the database. Test the following process
   on a restored copy before applying it to a database whose data must be retained.
2. Export the existing schema and compare **all three tables** against V1: columns,
   UUID and `timestamp(6) with time zone` types, lengths, nullability, primary keys,
   unique email enforcement, and all five declared indexes. Existing Hibernate-generated
   constraint names may differ; compare their definitions, not only their names.
   Check for extra application tables, triggers and defaults as well.
3. Reconcile discrepancies explicitly with reviewed SQL. Do not baseline an empty,
   partial or mismatched schema at version 1: V1 will be skipped afterward.
4. With the Flyway CLI installed and `FLYWAY_URL`, `FLYWAY_USER`, and `FLYWAY_PASSWORD`
   set securely for the **verified target database**, explicitly baseline version 1:

   ```bash
   flyway -schemas=public -baselineVersion=1 -baselineDescription="Verified Hibernate schema" baseline
   ```

   This project's default schema is PostgreSQL `public`. If you use a different
   schema, align CLI and application Flyway/default schema settings before proceeding.
   Confirm the CLI points to the expected database and schema. Do not store secrets
   in shell history or commit them to the repository.
5. Start this version of the application. Hibernate must validate successfully.
   Check history for the version 1 baseline entry, verify existing data is retained,
   and exercise login and refresh. Future V2+ migrations will run normally.

This PR does not run baseline or migration against any existing external database.
For disposable development databases, using a separately created empty database is
an alternative. No automatic database reset is performed.

## Validation

`mvn clean verify` requires Docker and runs PostgreSQL/Redis Testcontainers.
Authentication tests use the production Flyway + Hibernate validation settings.
Migration-specific tests check creation of all tables/indexes, data-preserving repeat
startup, refusal of unmanaged nonempty schemas, and checksum mismatch rejection.
A further application test verifies V1 history after successful JPA startup.

Flyway is a forward migration tool here. Transactional PostgreSQL DDL protects a
failed migration where supported; it is not an application/data rollback plan.
