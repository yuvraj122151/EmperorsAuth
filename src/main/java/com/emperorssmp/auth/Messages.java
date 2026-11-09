package com.emperorssmp.auth;

import net.kyori.adventure.audience.Audience;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import net.kyori.adventure.text.minimessage.tag.resolver.TagResolver;
import org.bukkit.configuration.file.YamlConfiguration;

import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public final class Messages {
    private final EmperorsAuth plugin;
    private final MiniMessage mm = MiniMessage.miniMessage();
    private YamlConfiguration cfg;

    public Messages(EmperorsAuth plugin) {
        this.plugin = plugin;
        reload();
    }

    public void reload() {
        cfg = YamlConfiguration.loadConfiguration(new File(plugin.getDataFolder(), "messages.yml"));
        InputStream in = plugin.getResource("messages.yml");
        if (in != null) {
            cfg.setDefaults(YamlConfiguration.loadConfiguration(new InputStreamReader(in, StandardCharsets.UTF_8)));
        }
    }

    public Component get(String key, TagResolver... extra) {
        String raw = cfg.getString(key, "<red>Missing message: " + key);
        TagResolver all = TagResolver.builder()
                .resolver(Placeholder.parsed("prefix", cfg.getString("prefix", "")))
                .resolvers(extra)
                .build();
        return mm.deserialize(raw, all);
    }

    public void send(Audience to, String key, TagResolver... extra) {
        to.sendMessage(get(key, extra));
    }
}
