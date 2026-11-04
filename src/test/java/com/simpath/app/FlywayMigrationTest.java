package com.simpath.app;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.FlywayException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.UUID;
import static org.assertj.core.api.Assertions.*;

@Testcontainers
class FlywayMigrationTest {
    @Container
    static final PostgreSQLContainer DB = new PostgreSQLContainer("postgres:16-alpine");
    private String schema;
    private Flyway flyway;

    @BeforeEach void configure() {
        schema = "test_" + UUID.randomUUID().toString().replace("-", "");
        flyway = Flyway.configure().dataSource(DB.getJdbcUrl(), DB.getUsername(), DB.getPassword())
                .locations("classpath:db/migration").schemas(schema).defaultSchema(schema)
                .baselineOnMigrate(false).cleanDisabled(true).validateOnMigrate(true).load();
    }

    private Connection connect() throws Exception {
        Connection connection = DriverManager.getConnection(DB.getJdbcUrl(), DB.getUsername(), DB.getPassword());
        connection.setSchema(schema);
        return connection;
    }

    @Test void emptyDatabaseGetsAllTablesAndIndexes() throws Exception {
        assertThat(flyway.migrate().migrationsExecuted).isEqualTo(5);
        try (Connection connection = connect(); Statement sql = connection.createStatement()) {
            try (ResultSet result = sql.executeQuery("select count(*) from information_schema.tables where table_schema = current_schema() and table_name in ('users','refresh_tokens','audit_events','auth_sessions','email_verification_tokens','mail_outbox')")) {
                assertThat(result.next()).isTrue();
                assertThat(result.getInt(1)).isEqualTo(6);
            }
            try (ResultSet result = sql.executeQuery("select count(*) from pg_indexes where schemaname = current_schema() and indexname in ('idx_users_email','idx_refresh_user','idx_refresh_family','idx_audit_user','idx_audit_type','idx_session_user_active','idx_session_expiry')")) {
                assertThat(result.next()).isTrue();
                assertThat(result.getInt(1)).isEqualTo(7);
            }
        }
        assertThat(flyway.validateWithResult().validationSuccessful).isTrue();
    }

    @Test void restartDoesNotReapplyMigrationOrDeleteExistingData() throws Exception {
        flyway.migrate();
        UUID userId = UUID.randomUUID();
        try (Connection connection = connect(); Statement sql = connection.createStatement()) {
            sql.executeUpdate("insert into users(id,email,password_hash,enabled,created_at) values ('" + userId + "','preserved@example.com','test-hash',true,current_timestamp)");
        }
        assertThat(flyway.migrate().migrationsExecuted).isZero();
        try (Connection connection = connect(); Statement sql = connection.createStatement();
             ResultSet result = sql.executeQuery("select email from users")) {
            assertThat(result.next()).isTrue();
            assertThat(result.getString(1)).isEqualTo("preserved@example.com");
        }
    }

    @Test void nonemptyUnmanagedSchemaIsRejectedWithoutAutomaticBaseline() throws Exception {
        try (Connection connection = DriverManager.getConnection(DB.getJdbcUrl(), DB.getUsername(), DB.getPassword());
             Statement sql = connection.createStatement()) {
            sql.execute("create schema " + schema);
            sql.execute("create table " + schema + ".legacy_data(id integer primary key)");
            sql.execute("insert into " + schema + ".legacy_data values (42)");
        }
        assertThatThrownBy(() -> flyway.migrate()).isInstanceOf(FlywayException.class);
        try (Connection connection = connect(); Statement sql = connection.createStatement();
             ResultSet result = sql.executeQuery("select id from legacy_data")) {
            assertThat(result.next()).isTrue();
            assertThat(result.getInt(1)).isEqualTo(42);
        }
    }

    @Test void checksumMismatchStopsMigration() throws Exception {
        flyway.migrate();
        try (Connection connection = connect(); Statement sql = connection.createStatement()) {
            sql.executeUpdate("update flyway_schema_history set checksum = checksum + 1 where version = '1'");
        }
        assertThat(flyway.validateWithResult().validationSuccessful).isFalse();
        assertThatThrownBy(() -> flyway.migrate()).isInstanceOf(FlywayException.class);
    }

    @Test void upgradeFromVersionOnePreservesTokensAndAddsUniqueHashIndex() throws Exception {
        Flyway versionOne = Flyway.configure().dataSource(DB.getJdbcUrl(), DB.getUsername(), DB.getPassword())
                .locations("classpath:db/migration").schemas(schema).defaultSchema(schema).target("1").load();
        versionOne.migrate();
        try (Connection connection = connect(); Statement sql = connection.createStatement()) {
            sql.executeUpdate("insert into refresh_tokens(id,user_id,token_hash,family_id) values ('" + UUID.randomUUID()
                    + "','" + UUID.randomUUID() + "','preserved-token','" + UUID.randomUUID() + "')");
        }
        assertThat(flyway.migrate().migrationsExecuted).isEqualTo(4);
        try (Connection connection = connect(); Statement sql = connection.createStatement();
             ResultSet result = sql.executeQuery("select count(*) from refresh_tokens where token_hash='preserved-token'")) {
            assertThat(result.next()).isTrue(); assertThat(result.getInt(1)).isEqualTo(1);
        }
        try (Connection connection = connect(); Statement sql = connection.createStatement()) {
            assertThatThrownBy(() -> sql.executeUpdate("insert into refresh_tokens(id,user_id,token_hash,family_id) values ('"
                    + UUID.randomUUID() + "','" + UUID.randomUUID() + "','preserved-token','" + UUID.randomUUID() + "')"))
                    .isInstanceOf(java.sql.SQLException.class);
        }
    }

    @Test void canonicalEmailCutoverRejectsLegacyRowsWithoutChangingIdentities() throws Exception {
        Flyway versionTwo = Flyway.configure().dataSource(DB.getJdbcUrl(), DB.getUsername(), DB.getPassword())
                .locations("classpath:db/migration").schemas(schema).defaultSchema(schema).target("2").load();
        versionTwo.migrate();
        try (Connection connection = connect(); Statement sql = connection.createStatement()) {
            sql.executeUpdate("insert into users(id,email,password_hash,enabled,created_at) values ('"
                    + UUID.randomUUID() + "','LEGACY@example.com','test-hash',true,current_timestamp)");
        }
        assertThatThrownBy(() -> flyway.migrate()).isInstanceOf(FlywayException.class);
        try (Connection connection = connect(); Statement sql = connection.createStatement();
             ResultSet result = sql.executeQuery("select email from users")) {
            assertThat(result.next()).isTrue();
            assertThat(result.getString(1)).isEqualTo("LEGACY@example.com");
        }
    }
    @Test void sessionCutoverRevokesLegacyRefreshTokensWithoutDeletingHistory() throws Exception {
        Flyway previous = Flyway.configure().dataSource(DB.getJdbcUrl(), DB.getUsername(), DB.getPassword())
                .locations("classpath:db/migration").schemas(schema).defaultSchema(schema).target("3").load();
        previous.migrate();
        try (Connection connection = connect(); Statement sql = connection.createStatement()) {
            sql.executeUpdate("insert into refresh_tokens(id,user_id,token_hash,family_id) values ('" + UUID.randomUUID()
                    + "','" + UUID.randomUUID() + "','legacy-session-cutover','" + UUID.randomUUID() + "')");
        }
        assertThat(flyway.migrate().migrationsExecuted).isEqualTo(2);
        try (Connection connection = connect(); Statement sql = connection.createStatement();
             ResultSet result = sql.executeQuery("select revoked_at from refresh_tokens where token_hash='legacy-session-cutover'")) {
            assertThat(result.next()).isTrue();
            assertThat(result.getTimestamp(1)).isNotNull();
        }
    }

    @Test void emailCutoverRequiresExistingUsersToVerifyAndRevokesTheirSessions() throws Exception {
        Flyway previous = Flyway.configure().dataSource(DB.getJdbcUrl(), DB.getUsername(), DB.getPassword())
                .locations("classpath:db/migration").schemas(schema).defaultSchema(schema).target("4").load();
        previous.migrate(); UUID uid = UUID.randomUUID(); UUID sid = UUID.randomUUID();
        try (Connection connection = connect(); Statement sql = connection.createStatement()) {
            sql.executeUpdate("insert into users(id,email,password_hash,enabled,created_at) values ('" + uid + "','legacy@example.com','hash',true,current_timestamp)");
            sql.executeUpdate("insert into auth_sessions(id,user_id,created_at,last_seen_at,expires_at) values ('" + sid + "','" + uid + "',current_timestamp,current_timestamp,current_timestamp + interval '1 day')");
            sql.executeUpdate("insert into refresh_tokens(id,user_id,token_hash,family_id) values ('" + UUID.randomUUID() + "','" + uid + "','email-cutover','" + sid + "')");
        }
        assertThat(flyway.migrate().migrationsExecuted).isEqualTo(1);
        try (Connection connection = connect(); Statement sql = connection.createStatement();
             ResultSet result = sql.executeQuery("select u.email_verified, s.revoked_at, t.revoked_at from users u join auth_sessions s on s.user_id=u.id join refresh_tokens t on t.user_id=u.id")) {
            assertThat(result.next()).isTrue(); assertThat(result.getBoolean(1)).isFalse();
            assertThat(result.getTimestamp(2)).isNotNull(); assertThat(result.getTimestamp(3)).isNotNull();
        }
    }

}



