use clap::Parser;
use env_logger::Env;
use log::{debug, error, info};
use reqwest::header;
use serde_json::Value;
use std::{
    collections::HashSet,
    env,
    net::IpAddr,
    str::FromStr,
    time::Duration,
};
use tokio::time;
use trust_dns_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

/// Hetzner Cloud Firewall Updater
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Config {
    /// Hetzner API Token
    #[arg(long, default_value = "")]
    api_token: String,

    /// Hetzner Projekt ID
    #[arg(long, default_value = "")]
    project_id: String,

    /// Firewall ID, die aktualisiert werden soll
    #[arg(long, default_value = "")]
    firewall_id: String,

    /// Name der Regel
    #[arg(long, default_value = "")]
    rule_name: String,

    /// Port der Regel (z. B. "80" oder "22-80")
    #[arg(long, default_value = "")]
    rule_port: String,

    /// Protokoll (z. B. "tcp" oder "udp")
    #[arg(long, default_value = "")]
    rule_protocol: String,

    /// Hosts (Domain oder IP) als komma-separierte Liste
    #[arg(long, default_value = "")]
    hosts: String,

    /// Check-Intervall in Sekunden
    #[arg(long, default_value_t = 60)]
    check_interval: u64,
}

impl Config {
    /// Ergänzt leere Felder mit den entsprechenden Umgebungsvariablen
    fn with_env_vars(mut self) -> Self {
        if self.api_token.is_empty() {
            self.api_token = env::var("HETZNER_API_TOKEN").unwrap_or_default();
        }
        if self.project_id.is_empty() {
            self.project_id = env::var("PROJECT_ID").unwrap_or_default();
        }
        if self.firewall_id.is_empty() {
            self.firewall_id = env::var("FIREWALL_ID").unwrap_or_default();
        }
        if self.rule_name.is_empty() {
            self.rule_name = env::var("RULE_NAME").unwrap_or_default();
        }
        if self.rule_port.is_empty() {
            self.rule_port = env::var("RULE_PORT").unwrap_or_default();
        }
        if self.rule_protocol.is_empty() {
            self.rule_protocol = env::var("RULE_PROTOCOL").unwrap_or_default();
        }
        if self.hosts.is_empty() {
            self.hosts = env::var("HOSTS").unwrap_or_default();
        }
        self
    }

    /// Prüft, ob alle erforderlichen Felder gesetzt sind.
    fn validate(&self) -> Result<(), String> {
        if self.api_token.is_empty() {
            return Err("HETZNER_API_TOKEN fehlt".to_string());
        }
        if self.project_id.is_empty() {
            return Err("PROJECT_ID fehlt".to_string());
        }
        if self.firewall_id.is_empty() {
            return Err("FIREWALL_ID fehlt".to_string());
        }
        if self.rule_name.is_empty() {
            return Err("RULE_NAME fehlt".to_string());
        }
        if self.rule_port.is_empty() {
            return Err("RULE_PORT fehlt".to_string());
        }
        if self.rule_protocol.is_empty() {
            return Err("RULE_PROTOCOL fehlt".to_string());
        }
        if self.hosts.is_empty() {
            return Err("HOSTS fehlt".to_string());
        }
        Ok(())
    }
}

/// Löst einen Host (Domain oder IP) zu einer IP-Adresse auf
async fn resolve_host(
    host: &str,
    resolver: &TokioAsyncResolver,
) -> Result<IpAddr, Box<dyn std::error::Error>> {
    debug!("Versuche, Host '{}' aufzulösen", host);
    if let Ok(ip) = IpAddr::from_str(host) {
        debug!("Host '{}' ist bereits eine IP: {}", host, ip);
        return Ok(ip);
    }
    let response = resolver.lookup_ip(host).await?;
    let ip = response
        .iter()
        .next()
        .ok_or_else(|| format!("Keine IP für Host '{}' gefunden", host))?;
    debug!("Host '{}' aufgelöst zu IP: {}", host, ip);
    Ok(ip)
}

/// Aktualisiert die Firewall-Regeln in der Hetzner Cloud,
/// ohne vorhandene Regeln zu löschen. Bestehende Regeln werden beibehalten,
/// und nur die Regel mit der passenden RULE_NAME wird aktualisiert oder neu hinzugefügt.
/// Hier wird die Regel so gesetzt, dass genau die aktuell per DNS ermittelten IPs eingetragen werden.
async fn update_firewall(
    config: &Config,
    resolved_ips: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let bearer = format!("Bearer {}", config.api_token);

    // Aktuelle Firewall-Konfiguration abrufen
    let get_url = format!("https://api.hetzner.cloud/v1/firewalls/{}", config.firewall_id);
    debug!("Hole aktuelle Firewall-Daten von: {}", get_url);
    let get_response = client
        .get(&get_url)
        .header(header::AUTHORIZATION, &bearer)
        .send()
        .await?;
    let get_text = get_response.text().await?;
    debug!("Aktuelle Firewall-Daten: {}", get_text);

    let get_json: Value = serde_json::from_str(&get_text)?;
    let mut rules = if let Some(arr) = get_json["firewall"]["rules"].as_array() {
        arr.clone()
    } else {
        vec![]
    };

    // Flag, ob die gewünschte Regel vorhanden ist
    let mut rule_found = false;
    for rule in rules.iter_mut() {
        if rule["description"] == config.rule_name && rule["direction"] == "in" {
            // Ersetze source_ips direkt durch die neuen IPs
            rule["source_ips"] = serde_json::json!(resolved_ips);
            // Optional: Port und Protokoll aktualisieren, falls sich diese geändert haben
            rule["port"] = serde_json::json!(config.rule_port);
            rule["protocol"] = serde_json::json!(config.rule_protocol);
            rule_found = true;
            debug!("Vorhandene Regel '{}' aktualisiert.", config.rule_name);
            break;
        }
    }

    // Falls die Regel noch nicht existiert, neue Regel hinzufügen
    if !rule_found {
        let new_rule = serde_json::json!({
            "direction": "in",
            "protocol": config.rule_protocol,
            "port": config.rule_port,
            "source_ips": resolved_ips,
            "description": config.rule_name,
        });
        rules.push(new_rule);
        debug!("Neue Regel '{}' hinzugefügt.", config.rule_name);
    }

    // Payload für das Update erstellen
    let payload = serde_json::json!({ "rules": rules });
    debug!("Payload für Firewall-Update: {:?}", payload);

    // Sende den POST-Request an /actions/set_rules
    let url = format!(
        "https://api.hetzner.cloud/v1/firewalls/{}/actions/set_rules",
        config.firewall_id
    );
    debug!("Sende POST-Anfrage an URL: {}", url);
    let response = client
        .post(&url)
        .header(header::AUTHORIZATION, &bearer)
        .header(header::CONTENT_TYPE, "application/json")
        .json(&payload)
        .send()
        .await?;

    // HTTP-Status vor dem Verbrauch des Body extrahieren
    let status = response.status();
    let response_text = response.text().await?;
    debug!("HTTP-Status: {}", status);
    debug!("API-Antwort: {}", response_text);

    // Prüfe die Antwort anhand des HTTP-Status und des Error-Codes im Body
    if !status.is_success() {
        let error_json: Value = serde_json::from_str(&response_text)?;
        error!(
            "Fehler beim Aktualisieren der Firewall: HTTP {}: {} - {}",
            status,
            error_json["error"]["code"],
            error_json["error"]["message"]
        );
    } else {
        let response_json: Value = serde_json::from_str(&response_text)?;
        if let Some(actions) = response_json["actions"].as_array() {
            let mut has_error = false;
            for action in actions {
                if let Some(err) = action.get("error") {
                    if !err.is_null() {
                        error!("Fehler in Aktion: {} - {}", err["code"], err["message"]);
                        has_error = true;
                    }
                }
            }
            if has_error {
                error!("Mindestens eine Aktion schlug fehl: {}", response_text);
            } else {
                info!("Firewall erfolgreich aktualisiert.");
            }
        } else {
            error!("Aktionen nicht in der API-Antwort gefunden: {}", response_text);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    // Logger konfigurieren: RUST_LOG steuert das Log-Level, Standard ist "warn"
    env_logger::Builder::from_env(Env::default().filter_or("RUST_LOG", "warn")).init();

    let config = Config::parse().with_env_vars();

    // Überprüfe, ob alle benötigten Umgebungsvariablen gesetzt sind
    if let Err(e) = config.validate() {
        eprintln!("Fehler: {}", e);
        std::process::exit(1);
    }

    // DNS-Resolver mit Cloudflare (1.1.1.1) konfigurieren
    let name_server = NameServerConfig {
        socket_addr: "1.1.1.1:53".parse().unwrap(),
        protocol: Protocol::Udp,
        tls_dns_name: None,
        bind_addr: None,
        trust_negative_responses: false,
    };
    let resolver_config = ResolverConfig::from_parts(None, vec![], vec![name_server]);

    // ResolverOpts anpassen, um Caching zu deaktivieren
    let mut resolver_opts = ResolverOpts::default();
    resolver_opts.cache_size = 0;
    let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);

    let hosts: Vec<&str> = config.hosts.split(',').map(|s| s.trim()).collect();
    info!("Starte DNS-Auflösung und Firewall-Update...");

    // Lokaler Cache, um die aufgelösten DNS-IPs zu speichern
    let mut cached_ips: Option<HashSet<String>> = None;

    // Setze ein Interval und Signalbehandlung (z.B. SIGTERM) für ein schnelles Beenden
    let mut interval = time::interval(Duration::from_secs(config.check_interval));
    let shutdown_signal = tokio::signal::ctrl_c();
    // shutdown_signal muss gepinnt werden, da es nicht Unpin ist:
    tokio::pin!(shutdown_signal);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                debug!("Neuer Durchlauf gestartet.");

                let mut new_ips_set = HashSet::new();
                for host in &hosts {
                    match resolve_host(host, &resolver).await {
                        Ok(ip) => {
                            // Umwandlung in CIDR-Notation (IPv4: /32, IPv6: /128)
                            let cidr = if ip.is_ipv4() {
                                format!("{}/32", ip)
                            } else {
                                format!("{}/128", ip)
                            };
                            info!("Aufgelöster Host {} -> {}", host, cidr);
                            new_ips_set.insert(cidr);
                        }
                        Err(e) => error!("Fehler bei der Auflösung von {}: {}", host, e),
                    }
                }

                if new_ips_set.is_empty() {
                    error!("Keine gültigen IPs gefunden. Überspringe Update.");
                    continue;
                }

                // Beim initialen Start (Cache leer) wird das Update immer durchgeführt.
                if let Some(cached) = &cached_ips {
                    if cached == &new_ips_set {
                        debug!("Keine Änderung bei den IPs. Update wird übersprungen.");
                        continue;
                    }
                }

                // Cache aktualisieren
                cached_ips = Some(new_ips_set.clone());
                let resolved_ips: Vec<String> = new_ips_set.into_iter().collect();

                if let Err(e) = update_firewall(&config, resolved_ips).await {
                    error!("Fehler beim Aktualisieren der Firewall: {}", e);
                }
            },
            _ = &mut shutdown_signal => {
                info!("Beendigungssignal empfangen. Programm wird beendet.");
                break;
            },
        }
    }
}