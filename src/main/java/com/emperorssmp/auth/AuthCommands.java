package com.emperorssmp.auth;

import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class AuthCommands implements CommandExecutor, TabCompleter {
    private final EmperorsAuth plugin;
    private final AuthManager auth;
    private final Messages msg;

    public AuthCommands(EmperorsAuth plugin, AuthManager auth, Messages msg) {
        this.plugin = plugin;
        this.auth = auth;
        this.msg = msg;
    }

    @Override
    public boolean onCommand(CommandSender s, Command c, String label, String[] a) {
        String n = c.getName().toLowerCase(Locale.ROOT);
        if (n.equals("emperorsauth")) return admin(s, a);

        if (!(s instanceof Player p)) {
            msg.send(s, "players-only");
            return true;
        }
        switch (n) {
            case "login" -> {
                if (a.length != 1) msg.send(p, "usage-login");
                else auth.login(p, a[0]);
            }
            case "register" -> {
                if (a.length != 2) msg.send(p, "usage-register");
                else auth.register(p, a[0], a[1]);
            }
            case "changepassword" -> {
                if (a.length != 2) msg.send(p, "usage-changepassword");
                else auth.changePassword(p, a[0], a[1]);
            }
            case "logout" -> auth.logout(p);
            case "unregister" -> {
                if (a.length != 1) msg.send(p, "usage-unregister");
                else auth.unregister(p, a[0]);
            }
            default -> { return false; }
        }
        return true;
    }

    private boolean admin(CommandSender s, String[] a) {
        if (!s.hasPermission("emperorsauth.admin")) {
            msg.send(s, "no-permission");
            return true;
        }
        if (a.length == 0) {
            msg.send(s, "usage-admin");
            return true;
        }
        switch (a[0].toLowerCase(Locale.ROOT)) {
            case "reload" -> {
                plugin.reloadAll();
                msg.send(s, "admin-reloaded");
            }
            case "info" -> {
                if (a.length < 2) msg.send(s, "usage-admin");
                else auth.adminInfo(s, a[1]);
            }
            case "unregister" -> {
                if (a.length < 2) msg.send(s, "usage-admin");
                else auth.adminUnregister(s, a[1]);
            }
            case "setpassword" -> {
                if (a.length < 3) msg.send(s, "usage-admin");
                else auth.adminSetPassword(s, a[1], a[2]);
            }
            case "forcelogin" -> {
                if (a.length < 2) msg.send(s, "usage-admin");
                else auth.adminForceLogin(s, a[1]);
            }
            default -> msg.send(s, "usage-admin");
        }
        return true;
    }

    @Override
    public List<String> onTabComplete(CommandSender s, Command c, String label, String[] a) {
        List<String> out = new ArrayList<>();
        if (!c.getName().equalsIgnoreCase("emperorsauth") || !s.hasPermission("emperorsauth.admin")) return out;
        if (a.length == 1) {
            for (String o : List.of("reload", "info", "unregister", "setpassword", "forcelogin")) {
                if (o.startsWith(a[0].toLowerCase(Locale.ROOT))) out.add(o);
            }
        } else if (a.length == 2 && !a[0].equalsIgnoreCase("reload")) {
            plugin.getServer().getOnlinePlayers().forEach(p -> {
                if (p.getName().toLowerCase(Locale.ROOT).startsWith(a[1].toLowerCase(Locale.ROOT))) out.add(p.getName());
            });
        }
        return out;
    }
}
