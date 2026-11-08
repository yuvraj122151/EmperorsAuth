package com.emperorssmp.auth;

import org.bukkit.plugin.java.JavaPlugin;

public final class EmperorsAuth extends JavaPlugin {
    private static EmperorsAuth instance;
    private Database database;
    private AuthManager auth;
    private Messages messages;

    @Override
    public void onEnable() {
        instance = this;
        saveDefaultConfig();
        saveResource("messages.yml", false);
        messages = new Messages(this);

        database = new Database(this);
        try {
            database.init();
        } catch (Exception e) {
            getLogger().severe("Could not open the account database: " + e.getMessage());
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        auth = new AuthManager(this, database, messages);
        getServer().getPluginManager().registerEvents(new AuthListener(this, auth), this);

        AuthCommands cmds = new AuthCommands(this, auth, messages);
        for (String name : new String[]{"login", "register", "changepassword", "logout", "unregister", "emperorsauth"}) {
            var cmd = getCommand(name);
            if (cmd != null) {
                cmd.setExecutor(cmds);
                cmd.setTabCompleter(cmds);
            }
        }
        getLogger().info("EmperorsAuth enabled.");
    }

    @Override
    public void onDisable() {
        if (auth != null) auth.shutdown();
        if (database != null) database.close();
    }

    public void reloadAll() {
        reloadConfig();
        messages.reload();
    }

    public Messages messages() {
        return messages;
    }

    /** Other plugins can check this before acting on a player. */
    public static boolean isAuthenticated(org.bukkit.entity.Player p) {
        return instance != null && instance.auth != null && instance.auth.isAuthenticated(p);
    }
}
