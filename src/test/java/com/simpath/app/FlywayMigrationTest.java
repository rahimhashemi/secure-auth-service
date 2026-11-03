package com.simpath.app;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.FlywayException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
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
    static final PostgreSQLContainer<?> DB = new PostgreSQLContainer<>("postgres:16-alpine");
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
        assertThat(flyway.migrate().migrationsExecuted).isEqualTo(1);
        try (Connection connection = connect(); Statement sql = connection.createStatement()) {
            try (ResultSet result = sql.executeQuery("select count(*) from information_schema.tables where table_schema = current_schema() and table_name in ('users','refresh_tokens','audit_events')")) {
                assertThat(result.next()).isTrue();
                assertThat(result.getInt(1)).isEqualTo(3);
            }
            try (ResultSet result = sql.executeQuery("select count(*) from pg_indexes where schemaname = current_schema() and indexname in ('idx_users_email','idx_refresh_user','idx_refresh_family','idx_audit_user','idx_audit_type')")) {
                assertThat(result.next()).isTrue();
                assertThat(result.getInt(1)).isEqualTo(5);
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
}
