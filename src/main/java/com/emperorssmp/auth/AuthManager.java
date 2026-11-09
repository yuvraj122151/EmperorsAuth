package com.emperorssmp.auth;

import net.kyori.adventure.bossbar.BossBar;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import net.kyori.adventure.title.Title;
import org.bukkit.Bukkit;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;
import org.bukkit.scheduler.BukkitTask;

import java.time.Duration;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class AuthManager {

    private record Session(String ip, long expires) {}

    private static final class Pending {
        BukkitTask task;
        BukkitTask shimmer;
        BossBar bar;
        int remaining;
        int total;
    }

    private static final DateTimeFormatter DATE =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault());

    private final EmperorsAuth plugin;
    private final Database db;
    private final Messages msg;
    private final DiscordWebhook webhook;

    private final Set<UUID> authed = ConcurrentHashMap.newKeySet();
    private final Set<UUID> announced = ConcurrentHashMap.newKeySet();
    private final Set<UUID> busy = ConcurrentHashMap.newKeySet();
    private final Map<String, Database.Account> preloaded = new ConcurrentHashMap<>();
    private final Map<UUID, Integer> attempts = new ConcurrentHashMap<>();
    private final Map<String, Long> ipLocks = new ConcurrentHashMap<>();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final Map<UUID, Pending> pending = new ConcurrentHashMap<>();

    public AuthManager(EmperorsAuth plugin, Database db, Messages msg) {
        this.plugin = plugin;
        this.db = db;
        this.msg = msg;
        this.webhook = new DiscordWebhook(plugin);
    }

    // ------------------------------------------------------------ helpers

    private FileConfiguration cfg() {
        return plugin.getConfig();
    }

    private static String key(String name) {
        return name.toLowerCase(Locale.ROOT);
    }

    private static String ip(Player p) {
        var a = p.getAddress();
        return a == null ? "unknown" : a.getAddress().getHostAddress();
    }

    private void async(Runnable r) {
        Bukkit.getScheduler().runTaskAsynchronously(plugin, r);
    }

    private void sync(Runnable r) {
        Bukkit.getScheduler().runTask(plugin, r);
    }

    private long sessionMillis() {
        return cfg().getLong("session.minutes", 30) * 60_000L;
    }

    public boolean isAuthenticated(Player p) {
        return authed.contains(p.getUniqueId());
    }

    /** Returns a validation message key or null when the password is fine. */
    private String validatePassword(String name, String pw) {
        int min = cfg().getInt("password.min-length", 6);
        int max = cfg().getInt("password.max-length", 64);
        if (pw.length() < min) return "password-too-short";
        if (pw.length() > max) return "password-too-long";
        if (pw.equalsIgnoreCase(name)) return "password-is-name";
        for (String bad : cfg().getStringList("password.blocked")) {
            if (bad.equalsIgnoreCase(pw)) return "password-weak";
        }
        if (cfg().getBoolean("password.require-digit", false) && pw.chars().noneMatch(Character::isDigit)) {
            return "password-no-digit";
        }
        return null;
    }

    private void sendPasswordError(CommandSender to, String key) {
        msg.send(to, key,
                Placeholder.unparsed("min", String.valueOf(cfg().getInt("password.min-length", 6))),
                Placeholder.unparsed("max", String.valueOf(cfg().getInt("password.max-length", 64))));
    }

    // ------------------------------------------------------------ join / quit

    /** Runs on the async pre-login thread. Returns a kick message or null. */
    public Component preLogin(String name, String ip) {
        if (!name.matches(cfg().getString("username-regex", "^[A-Za-z0-9_]{3,16}$"))) {
            return msg.get("kick-invalid-name");
        }
        Long until = ipLocks.get(ip);
        if (until != null) {
            long left = until - System.currentTimeMillis();
            if (left > 0) {
                return msg.get("kick-locked", Placeholder.unparsed("minutes", String.valueOf(Math.max(1, left / 60_000))));
            }
            ipLocks.remove(ip);
        }
        try {
            Database.Account acc = db.get(name);
            if (acc != null) {
                if (!acc.realName().equals(name)) {
                    return msg.get("kick-name-case", Placeholder.unparsed("name", acc.realName()));
                }
                preloaded.put(key(name), acc);
            }
        } catch (Exception e) {
            plugin.getLogger().severe("Database error during pre-login: " + e.getMessage());
            return msg.get("kick-error");
        }
        return null;
    }

    public void handleJoin(Player p) {
        if (p.hasPermission("emperorsauth.bypass")) {
            authenticate(p, null, false);
            return;
        }
        Database.Account acc = preloaded.remove(key(p.getName()));
        boolean registered = acc != null;
        if (registered && cfg().getBoolean("session.enabled", true)) {
            Session s = sessions.get(key(p.getName()));
            if (s != null && s.expires() > System.currentTimeMillis() && s.ip().equals(ip(p))) {
                authenticate(p, "session-resumed", false);
                return;
            }
        }
        lock(p, registered);
    }

    /** @return true if the player was authenticated when they left. */
    public boolean handleQuit(Player p) {
        UUID id = p.getUniqueId();
        boolean was = authed.remove(id);
        clearPending(p);
        attempts.remove(id);
        busy.remove(id);
        announced.remove(id);
        if (was && cfg().getBoolean("session.enabled", true)) {
            sessions.put(key(p.getName()), new Session(ip(p), System.currentTimeMillis() + sessionMillis()));
        }
        return was;
    }

    public void shutdown() {
        for (Player p : Bukkit.getOnlinePlayers()) clearPending(p);
    }

    // ------------------------------------------------------------ lock / unlock

    private void lock(Player p, boolean registered) {
        UUID id = p.getUniqueId();
        authed.remove(id);

        if (cfg().getBoolean("restrictions.blind-until-login", true)) {
            p.addPotionEffect(new PotionEffect(PotionEffectType.BLINDNESS, Integer.MAX_VALUE, 1, false, false, false));
        }

        Pending pd = new Pending();
        pd.total = Math.max(5, cfg().getInt("login-timeout-seconds", 60));
        pd.remaining = pd.total;
        pd.bar = BossBar.bossBar(msg.get("bossbar", Placeholder.unparsed("seconds", String.valueOf(pd.total))),
                1f, BossBar.Color.RED, BossBar.Overlay.PROGRESS);

        Pending old = pending.put(id, pd);
        if (old != null) {
            if (old.task != null) old.task.cancel();
            if (old.shimmer != null) old.shimmer.cancel();
            p.hideBossBar(old.bar);
        }
        p.showBossBar(pd.bar);
        final Component subtitle = msg.get(registered ? "subtitle-login" : "subtitle-register");
        if (cfg().getBoolean("animated-title.enabled", true)) {
            final MiniMessage mini = MiniMessage.miniMessage();
            final String text = mini.escapeTags(cfg().getString("animated-title.text", "EMPERORS SMP"));
            final int[] tick = {0};
            pd.shimmer = Bukkit.getScheduler().runTaskTimer(plugin, () -> {
                if (!p.isOnline() || isAuthenticated(p)) return;
                double phase = ((tick[0]++ % 40) / 20.0) - 1.0;
                Component title = mini.deserialize("<bold><gradient:" + phase
                        + ":#8a5a00:#ffd54a:#fff6c2:#ffd54a:#8a5a00>" + text + "</gradient></bold>");
                p.showTitle(Title.title(title, subtitle,
                        Title.Times.times(Duration.ZERO, Duration.ofMillis(1500), Duration.ZERO)));
            }, 0L, 2L);
        } else {
            p.showTitle(Title.title(
                    msg.get(registered ? "title-login" : "title-register"), subtitle,
                    Title.Times.times(Duration.ofMillis(300), Duration.ofSeconds(4), Duration.ofMillis(500))));
        }
        msg.send(p, registered ? "prompt-login" : "prompt-register");

        final int interval = Math.max(1, cfg().getInt("reminder-interval-seconds", 10));
        pd.task = Bukkit.getScheduler().runTaskTimer(plugin, () -> {
            if (!p.isOnline() || isAuthenticated(p)) {
                clearPending(p);
                return;
            }
            pd.remaining--;
            if (pd.remaining <= 0) {
                p.kick(msg.get("kick-timeout"));
                return;
            }
            pd.bar.progress(Math.max(0f, Math.min(1f, (float) pd.remaining / pd.total)));
            pd.bar.name(msg.get("bossbar", Placeholder.unparsed("seconds", String.valueOf(pd.remaining))));
            if (pd.remaining % interval == 0) {
                msg.send(p, registered ? "prompt-login" : "prompt-register");
            }
        }, 20L, 20L);
    }

    private void clearPending(Player p) {
        Pending pd = pending.remove(p.getUniqueId());
        if (pd != null) {
            if (pd.task != null) pd.task.cancel();
            if (pd.shimmer != null) pd.shimmer.cancel();
            p.hideBossBar(pd.bar);
        }
    }

    private void authenticate(Player p, String messageKey, boolean logToWebhook) {
        UUID id = p.getUniqueId();
        authed.add(id);
        attempts.remove(id);
        clearPending(p);
        p.removePotionEffect(PotionEffectType.BLINDNESS);
        p.clearTitle();

        final String ip = ip(p);
        final String name = p.getName();
        final long now = System.currentTimeMillis();
        if (cfg().getBoolean("session.enabled", true)) {
            sessions.put(key(name), new Session(ip, now + sessionMillis()));
        }
        async(() -> {
            try {
                db.touchLogin(name, ip, now);
            } catch (Exception e) {
                plugin.getLogger().warning("Could not update login time: " + e.getMessage());
            }
        });

        if (messageKey != null) msg.send(p, messageKey);

        if (cfg().getBoolean("restrictions.hide-join-quit-until-login", true) && announced.add(id)) {
            Bukkit.getServer().broadcast(Component.translatable("multiplayer.player.joined", Component.text(name))
                    .color(NamedTextColor.YELLOW));
        }
        if (logToWebhook) webhook.send("Player logged in", "**" + name + "** authenticated.", 0x43B581);
    }

    // ------------------------------------------------------------ player actions

    public void register(Player p, String pw, String confirm) {
        if (isAuthenticated(p)) { msg.send(p, "already-logged-in"); return; }
        if (!pw.equals(confirm)) { msg.send(p, "password-mismatch"); return; }
        String err = validatePassword(p.getName(), pw);
        if (err != null) { sendPasswordError(p, err); return; }
        if (!busy.add(p.getUniqueId())) return;

        final String ip = ip(p);
        final String name = p.getName();
        final UUID uuid = p.getUniqueId();
        final int maxPerIp = cfg().getInt("accounts.max-per-ip", 3);
        async(() -> {
            try {
                if (db.get(name) != null) { sync(() -> msg.send(p, "already-registered")); return; }
                if (maxPerIp > 0 && db.countByIp(ip) >= maxPerIp) { sync(() -> msg.send(p, "too-many-accounts")); return; }
                String hash = PasswordHasher.hash(pw);
                long now = System.currentTimeMillis();
                db.create(new Database.Account(key(name), name, uuid.toString(), hash, ip, ip, now, now, 1));
                sync(() -> {
                    if (p.isOnline()) {
                        authenticate(p, "register-success", false);
                        webhook.send("New registration", "**" + name + "** created an account.", 0x5865F2);
                    }
                });
            } catch (Exception e) {
                plugin.getLogger().severe("Register failed for " + name + ": " + e.getMessage());
                sync(() -> msg.send(p, "internal-error"));
            } finally {
                busy.remove(uuid);
            }
        });
    }

    public void login(Player p, String pw) {
        if (isAuthenticated(p)) { msg.send(p, "already-logged-in"); return; }
        if (!busy.add(p.getUniqueId())) return;

        final String ip = ip(p);
        final String name = p.getName();
        final UUID uuid = p.getUniqueId();
        async(() -> {
            try {
                Database.Account acc = db.get(name);
                if (acc == null) { sync(() -> msg.send(p, "not-registered")); return; }
                boolean ok = PasswordHasher.verify(pw, acc.hash());
                sync(() -> {
                    if (!p.isOnline()) return;
                    if (ok) authenticate(p, "login-success", true);
                    else failedAttempt(p, ip);
                });
            } catch (Exception e) {
                plugin.getLogger().severe("Login failed for " + name + ": " + e.getMessage());
                sync(() -> msg.send(p, "internal-error"));
            } finally {
                busy.remove(uuid);
            }
        });
    }

    private void failedAttempt(Player p, String ip) {
        int max = Math.max(1, cfg().getInt("max-login-attempts", 3));
        int n = attempts.merge(p.getUniqueId(), 1, Integer::sum);
        webhook.send("Failed login", "**" + p.getName() + "** entered a wrong password (" + n + "/" + max + ").", 0xFAA61A);
        if (n >= max) {
            int mins = cfg().getInt("lockout-minutes", 10);
            if (mins > 0) ipLocks.put(ip, System.currentTimeMillis() + mins * 60_000L);
            webhook.send("Lockout", "**" + p.getName() + "** was kicked after " + max + " failed attempts.", 0xF04747);
            p.kick(msg.get("kick-too-many-attempts"));
        } else {
            msg.send(p, "wrong-password", Placeholder.unparsed("remaining", String.valueOf(max - n)));
        }
    }

    public void changePassword(Player p, String oldPw, String newPw) {
        if (!isAuthenticated(p)) { msg.send(p, "must-login"); return; }
        String err = validatePassword(p.getName(), newPw);
        if (err != null) { sendPasswordError(p, err); return; }
        if (!busy.add(p.getUniqueId())) return;

        final String name = p.getName();
        final UUID uuid = p.getUniqueId();
        async(() -> {
            try {
                Database.Account acc = db.get(name);
                if (acc == null) { sync(() -> msg.send(p, "not-registered")); return; }
                if (!PasswordHasher.verify(oldPw, acc.hash())) { sync(() -> msg.send(p, "wrong-old-password")); return; }
                db.setPassword(name, PasswordHasher.hash(newPw));
                sync(() -> msg.send(p, "password-changed"));
                webhook.send("Password changed", "**" + name + "** changed their password.", 0x5865F2);
            } catch (Exception e) {
                plugin.getLogger().severe("Password change failed: " + e.getMessage());
                sync(() -> msg.send(p, "internal-error"));
            } finally {
                busy.remove(uuid);
            }
        });
    }

    public void logout(Player p) {
        if (!isAuthenticated(p)) { msg.send(p, "not-logged-in"); return; }
        sessions.remove(key(p.getName()));
        lock(p, true);
        msg.send(p, "logged-out");
    }

    public void unregister(Player p, String pw) {
        if (!isAuthenticated(p)) { msg.send(p, "must-login"); return; }
        if (!busy.add(p.getUniqueId())) return;

        final String name = p.getName();
        final UUID uuid = p.getUniqueId();
        async(() -> {
            try {
                Database.Account acc = db.get(name);
                if (acc == null) { sync(() -> msg.send(p, "not-registered")); return; }
                if (!PasswordHasher.verify(pw, acc.hash())) { sync(() -> msg.send(p, "wrong-old-password")); return; }
                db.delete(name);
                sessions.remove(key(name));
                sync(() -> {
                    authed.remove(uuid);
                    p.kick(msg.get("unregistered"));
                });
                webhook.send("Account deleted", "**" + name + "** deleted their own account.", 0xF04747);
            } catch (Exception e) {
                plugin.getLogger().severe("Unregister failed: " + e.getMessage());
                sync(() -> msg.send(p, "internal-error"));
            } finally {
                busy.remove(uuid);
            }
        });
    }

    // ------------------------------------------------------------ admin actions

    public void adminUnregister(CommandSender s, String name) {
        async(() -> {
            try {
                if (db.get(name) == null) { sync(() -> msg.send(s, "account-not-found")); return; }
                db.delete(name);
                sessions.remove(key(name));
                sync(() -> {
                    msg.send(s, "admin-unregistered", Placeholder.unparsed("player", name));
                    Player t = Bukkit.getPlayerExact(name);
                    if (t != null) {
                        authed.remove(t.getUniqueId());
                        t.kick(msg.get("unregistered"));
                    }
                });
            } catch (Exception e) {
                sync(() -> msg.send(s, "internal-error"));
            }
        });
    }

    public void adminSetPassword(CommandSender s, String name, String pw) {
        String err = validatePassword(name, pw);
        if (err != null) { sendPasswordError(s, err); return; }
        async(() -> {
            try {
                if (db.get(name) == null) { sync(() -> msg.send(s, "account-not-found")); return; }
                db.setPassword(name, PasswordHasher.hash(pw));
                sync(() -> msg.send(s, "admin-setpassword", Placeholder.unparsed("player", name)));
            } catch (Exception e) {
                sync(() -> msg.send(s, "internal-error"));
            }
        });
    }

    public void adminForceLogin(CommandSender s, String name) {
        Player t = Bukkit.getPlayerExact(name);
        if (t == null) { msg.send(s, "player-offline"); return; }
        authenticate(t, "forced-login", true);
        msg.send(s, "admin-forcelogin", Placeholder.unparsed("player", t.getName()));
    }

    public void adminInfo(CommandSender s, String name) {
        async(() -> {
            try {
                Database.Account a = db.get(name);
                if (a == null) { sync(() -> msg.send(s, "account-not-found")); return; }
                sync(() -> msg.send(s, "admin-info",
                        Placeholder.unparsed("player", a.realName()),
                        Placeholder.unparsed("registered", DATE.format(java.time.Instant.ofEpochMilli(a.regDate()))),
                        Placeholder.unparsed("lastlogin", DATE.format(java.time.Instant.ofEpochMilli(a.lastLogin()))),
                        Placeholder.unparsed("logins", String.valueOf(a.loginCount())),
                        Placeholder.unparsed("ip", String.valueOf(a.lastIp()))));
            } catch (Exception e) {
                sync(() -> msg.send(s, "internal-error"));
            }
        });
    }
}
