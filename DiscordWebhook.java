package com.emperorssmp.auth;

import org.bukkit.configuration.file.FileConfiguration;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;

public final class DiscordWebhook {
    private final EmperorsAuth plugin;
    private final HttpClient client = HttpClient.newHttpClient();

    public DiscordWebhook(EmperorsAuth plugin) {
        this.plugin = plugin;
    }

    public void send(String title, String description, int color) {
        FileConfiguration c = plugin.getConfig();
        if (!c.getBoolean("discord-webhook.enabled", false)) return;
        String url = c.getString("discord-webhook.url", "");
        if (url == null || url.isBlank()) return;
        try {
            String json = "{\"embeds\":[{\"title\":\"" + esc(title) + "\",\"description\":\"" + esc(description)
                    + "\",\"color\":" + color + ",\"timestamp\":\"" + Instant.now() + "\"}]}";
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(10))
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();
            client.sendAsync(req, HttpResponse.BodyHandlers.discarding()).exceptionally(ex -> {
                plugin.getLogger().warning("Discord webhook failed: " + ex.getMessage());
                return null;
            });
        } catch (Exception e) {
            plugin.getLogger().warning("Discord webhook error: " + e.getMessage());
        }
    }

    private static String esc(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
