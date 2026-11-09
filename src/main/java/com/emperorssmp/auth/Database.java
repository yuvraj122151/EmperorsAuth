package com.emperorssmp.auth;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Locale;

/** SQLite storage (the driver ships with Paper). All calls are synchronized; call them off the main thread. */
public final class Database {

    public record Account(String name, String realName, String uuid, String hash,
                          String regIp, String lastIp, long regDate, long lastLogin, int loginCount) {}

    private final EmperorsAuth plugin;
    private Connection conn;

    public Database(EmperorsAuth plugin) {
        this.plugin = plugin;
    }

    public void init() throws Exception {
        Class.forName("org.sqlite.JDBC");
        plugin.getDataFolder().mkdirs();
        File f = new File(plugin.getDataFolder(), "accounts.db");
        conn = DriverManager.getConnection("jdbc:sqlite:" + f.getAbsolutePath());
        try (Statement s = conn.createStatement()) {
            s.executeUpdate("CREATE TABLE IF NOT EXISTS accounts ("
                    + "name TEXT PRIMARY KEY, real_name TEXT NOT NULL, uuid TEXT, password TEXT NOT NULL,"
                    + "reg_ip TEXT, last_ip TEXT, reg_date INTEGER, last_login INTEGER, login_count INTEGER DEFAULT 0)");
            s.executeUpdate("CREATE INDEX IF NOT EXISTS idx_reg_ip ON accounts(reg_ip)");
        }
    }

    private static String k(String name) {
        return name.toLowerCase(Locale.ROOT);
    }

    public synchronized Account get(String name) {
        try (PreparedStatement ps = conn.prepareStatement("SELECT * FROM accounts WHERE name=?")) {
            ps.setString(1, k(name));
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                return new Account(rs.getString("name"), rs.getString("real_name"), rs.getString("uuid"),
                        rs.getString("password"), rs.getString("reg_ip"), rs.getString("last_ip"),
                        rs.getLong("reg_date"), rs.getLong("last_login"), rs.getInt("login_count"));
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    public synchronized void create(Account a) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO accounts (name, real_name, uuid, password, reg_ip, last_ip, reg_date, last_login, login_count) VALUES (?,?,?,?,?,?,?,?,?)")) {
            ps.setString(1, k(a.name()));
            ps.setString(2, a.realName());
            ps.setString(3, a.uuid());
            ps.setString(4, a.hash());
            ps.setString(5, a.regIp());
            ps.setString(6, a.lastIp());
            ps.setLong(7, a.regDate());
            ps.setLong(8, a.lastLogin());
            ps.setInt(9, a.loginCount());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    public synchronized void setPassword(String name, String hash) {
        exec("UPDATE accounts SET password=? WHERE name=?", hash, k(name));
    }

    public synchronized void touchLogin(String name, String ip, long time) {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE accounts SET last_ip=?, last_login=?, login_count=login_count+1 WHERE name=?")) {
            ps.setString(1, ip);
            ps.setLong(2, time);
            ps.setString(3, k(name));
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    public synchronized void delete(String name) {
        exec("DELETE FROM accounts WHERE name=?", k(name));
    }

    public synchronized int countByIp(String ip) {
        try (PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM accounts WHERE reg_ip=?")) {
            ps.setString(1, ip);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    private void exec(String sql, String... args) {
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            for (int i = 0; i < args.length; i++) ps.setString(i + 1, args[i]);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    public synchronized void close() {
        try {
            if (conn != null) conn.close();
        } catch (SQLException ignored) {
        }
    }
}
