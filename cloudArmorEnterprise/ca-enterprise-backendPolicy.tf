terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
      version = "5.32.0"
    }
  }
}

provider "google" {
  # Configuration options
}

resource "google_compute_security_policy" "infrastructure_as_code_enterprise_security_policy" {
  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable          = true
      rule_visibility = "STANDARD"
    }
  }

  advanced_options_config {
    json_parsing = "STANDARD_WITH_GRAPHQL"
    json_custom_config {
      content_types = ["application/json", "application/vnd.api+json", "application/vnd.collection+json", "application/vnd.hyper+json"]
    }
    log_level    = "VERBOSE"
  }

  description = "cloud armor enterprise template rules"
  name        = "infrastructure-as-code-enterprise-security-policy"

  rule {
    action      = "deny(403)"
    description = "Auto deploy Cloud Armor Adaptive Protection Rule"

    match {
      expr {
        expression = "evaluateAdaptiveProtectionAutoDeploy()"
      }
    }

    preview  = true
    priority = 500
  }

  rule {
    action      = "deny(403)"
    description = "Deny access to specific IP addresses"

    match {
      config {
        src_ip_ranges = ["9.9.9.0/24"]
      }

      versioned_expr = "SRC_IPS_V1"
    }

    preview  = true
    priority = 1000
  }

  rule {
    action      = "deny(403)"
    description = "Block bad networks"

    match {
      expr {
        expression = "origin.asn == 112"
      }
    }

    preview  = true
    priority = 1500
  }

  rule {
    action      = "deny(403)"
    description = "Threat Intelligence - Block Bad IPs"

    match {
      expr {
        expression = "evaluateThreatIntelligence('iplist-known-malicious-ips')"
      }
    }

    priority = 2000
  }

  rule {
    action      = "deny(403)"
    description = "Threat Intelligence - VPN Access"

    match {
      expr {
        expression = "evaluateThreatIntelligence('iplist-vpn-providers')"
      }
    }

    preview  = true
    priority = 2010
  }

  rule {
    action      = "deny(403)"
    description = "Threat Intelligence - Anonymous Proxy"

    match {
      expr {
        expression = "evaluateThreatIntelligence('iplist-anon-proxies')"
      }
    }

    preview  = true
    priority = 2020
  }

  rule {
    action      = "deny(403)"
    description = "Threat Intelligence - Crypto Miners"

    match {
      expr {
        expression = "evaluateThreatIntelligence('iplist-crypto-miners')"
      }
    }

    preview  = true
    priority = 2030
  }

  rule {
    action      = "deny(403)"
    description = "Threat Intelligence - Public Clouds"

    match {
      expr {
        expression = "evaluateThreatIntelligence('iplist-public-clouds')"
      }
    }

    preview  = true
    priority = 2040
  }

  rule {
    action      = "deny(403)"
    description = "Threat Intelligence - Tor Exits"

    match {
      expr {
        expression = "evaluateThreatIntelligence('iplist-tor-exit-nodes')"
      }
    }

    priority = 2050
  }

  rule {
    action      = "deny(403)"
    description = "Threat Intelligence - Search Engines"

    match {
      expr {
        expression = "evaluateThreatIntelligence('iplist-search-engines-crawlers')"
      }
    }

    preview  = true
    priority = 2060
  }

  rule {
    action      = "allow"
    description = "Allow access to IPs in specific CIDR"

    match {
      config {
        src_ip_ranges = ["2.2.2.0/24"]
      }

      versioned_expr = "SRC_IPS_V1"
    }

    preview  = true
    priority = 5000
  }

  rule {
    action      = "deny(403)"
    description = "Deny unused methods"

    match {
      expr {
        expression = "request.method != 'OPTIONS' || request.method != 'POST' || request.method != 'PATCH'"
      }
    }

    preview  = true
    priority = 6000
  }

  rule {
    action      = "deny(403)"
    description = "Block empty refer "

    match {
      expr {
        expression = "has(request.headers['referer']) && request.headers['referer'] != \"\""
      }
    }

    preview  = true
    priority = 6010
  }

  rule {
    action      = "deny(403)"
    description = "Block users from specific countries"

    match {
      expr {
        expression = "origin.region_code == 'CN' || origin.region_code == 'RU'"
      }
    }

    preview  = true
    priority = 7000
  }
  rule {
    action      = "deny(403)"
    description = "Block /.env prob"

    match {
      expr {
        expression = "request.path.lower().urlDecode().contains(\"/.env\")"
      }
    }

    preview  = true
    priority = 8000
  }
  rule {
    action      = "deny(403)"
    description = "Block S3 Config Probe"

    match {
      expr {
        expression = "request.path.lower().urlDecode().contains(\"/.s3cfg\")"
      }
    }

    preview  = true
    priority = 8010
  }
  rule {
    action      = "deny(403)"
    description = "Exposed Docker YAML file"

    match {
      expr {
        expression = "request.path.lower().urlDecode().contains(\"/docker-compose.yml\")"
      }
    }

    preview  = true
    priority = 8020
  }
  rule {
    action      = "deny(403)"
    description = "Exposed Git YAML file"

    match {
      expr {
        expression = "request.path.lower().urlDecode().contains(\"/gitlab-ci.yml\")"
      }
    }

    preview  = true
    priority = 8030
  }
  rule {
    action      = "deny(403)"
    description = "Disallow Sitemap"

    match {
      expr {
        expression = "request.path.lower().urlDecode().contains(\"sitemap.xml\")"
      }
    }

    preview  = true
    priority = 8040
  }
  rule {
    action      = "deny(403)"
    description = "Disallow JSON Config"

    match {
      expr {
        expression = "request.path.lower().urlDecode().contains(\"/config.json\")"
      }
    }

    preview  = true
    priority = 8050
  }
  rule {
    action      = "deny(403)"
    description = "Disallow info and admin php requests"

    match {
      expr {
        expression = "!inIpRange(origin.ip, '9.9.9.0/24') && request.path.lower().urlDecode().contains(\"/info.php\") || request.path.lower().urlDecode().contains(\"/admin/index.php|/phpMyAdmin/index.php\")"
      }
    }

    preview  = true
    priority = 8060
  }
  rule {
    action      = "deny(403)"
    description = "Disallow Git Config"

    match {
      expr {
        expression = "request.path.lower().urlDecode().contains(\"/.git/config\") || request.path.lower().urlDecode().contains(\"/.git/head\")"
      }
    }

    preview  = true
    priority = 8070
  }
  rule {
    action      = "deny(403)"
    description = "Disallow server status"

    match {
      expr {
        expression = "request.path.lower().urlDecode().contains(\"/server-status\")"
      }
    }

    preview  = true
    priority = 8080
  }
  rule {
    action      = "deny(403)"
    description = "Disallow phpstorm code"

    match {
      expr {
        expression = "request.query.lower().urlDecode().contains(\"phpstorm\")"
      }
    }

    preview  = true
    priority = 8090
  }
  rule {
    action      = "deny(403)"
    description = "WordPress Admin - locked down to IP address"

    match {
      expr {
        expression = "!inIpRange(origin.ip, '9.9.9.0/24') && request.path.lower().urlDecode().contains(\"/wp-admin|/login|/admin|/wp-login.php\")"
      }
    }

    preview  = true
    priority = 8100
  }
  rule {
    action      = "deny(403)"
    description = "WordPress - prevent listing of users"

    match {
      expr {
        expression = "!inIpRange(origin.ip, '1.2.3.4/32') && request.query.lower().urlDecode().contains('rest_route=/wp/v2/users/') || request.path.lower().urlDecode().contains('/wp-json/wp/v2/users')"
      }
    }

    preview  = true
    priority = 8110
  }
  rule {
    action      = "deny(403)"
    description = "Drupal Admin - locked down to IP address"

    match {
      expr {
        expression = "!inIpRange(origin.ip, '1.2.3.4/32') && request.query.lower().urlDecode().contains('q=user/login') || request.path.lower().urlDecode().contains('/user/login')"
        }
    }
    preview  = true
    priority = 8120
  }
  rule {
    action      = "deny(403)"
    description = "Malware OS Command"

    match {
      expr {
        expression = "request.path.lower().urlDecode().contains(\"boaform/admin/formLogin\")"
      }
    }

    preview  = true
    priority = 8130
  }
  rule {
    action      = "deny(403)"
    description = "Password theft attempt"

    match {
      expr {
        expression = "request.path.lower().urlDecode().contains(\"/por/login_psw.csp\")"
      }
    }

    preview  = true
    priority = 8140
  }
  rule {
    action      = "deny(403)"
    description = "Login attempt over cgi script"

    match {
      expr {
        expression = "request.path.lower().urlDecode().contains('/cgi-bin/login.cgi') || request.path.lower().urlDecode().contains('/cgi-bin/WebObjects')"
      }
    }
    preview  = true
    priority = 8150
  }
  rule {
    action      = "deny(403)"
    description = "Jenkins Login restricted by IP address"

    match {
      expr {
        expression = "!inIpRange(origin.ip, '1.2.3.4/32') && request.path.lower().urlDecode().contains('/user/admin/configure') || request.path.lower().urlDecode().contains('/jenkins/login')"
      }
    }
    preview  = true
    priority = 8160
  }
  rule {
    action      = "deny(403)"
    description = "Exchange Logon page restricted by IP address"

    match {
      expr {
        expression = "!inIpRange(origin.ip, '9.9.9.0/24') && request.path.lower().urlDecode().contains(\"/exchange/logon.asp\")"
      }
    }

    preview  = true
    priority = 8170
  }
  rule {
    action      = "deny(403)"
    description = "SSL key theft attempt"

    match {
      expr {
        expression = "request.path.lower().urlDecode().contains(\"/.ssl/localhost.key|/.ssh/id_dsa|/.ssh/id_rsa\") || request.path.lower().urlDecode().contains(\"/server.pem|/id_dsa|/id_rsa|/key.pem|/privatekey.key|server.key\")"
      }
    }

    preview  = true
    priority = 8180
  }
  rule {
    action      = "deny(403)"
    description = "JBoss Admin restricted by IP address"

    match {
      expr {
        expression = "!inIpRange(origin.ip, '9.9.9.0/24') && request.path.lower().urlDecode().contains(\"/admin-console/login.seam\")"
      }
    }

    preview  = true
    priority = 8190
  }
  rule {
    action      = "deny(403)"
    description = "MSFT IIS Login restricted by IP address"

    match {
      expr {
        expression = "!inIpRange(origin.ip, '9.9.9.0/24') && request.path.lower().urlDecode().contains(\"/webadmin/default.asp\")"
      }
    }

    preview  = true
    priority = 8200
  }
  rule {
    action      = "deny(403)"
    description = "Deny request for well-known except cert renewal"

    match {
      expr {
        expression = "request.headers['host'].contains('acme-v01.api.letsencrypt.org|acme-v02.api.letsencrypt.org') || origin.asn == 15169 && request.path.lower().urlDecode().contains(\"/.well-known/acme-challenge/|/.well-known/pki-validation/\")"
      }
    }

    preview  = true
    priority = 8210
  }

  rule {
    action      = "deny(403)"
    description = "PHP - OWASP Rule"

    match {
      expr {
        expression = "evaluatePreconfiguredWaf('php-v33-stable', {'sensitivity': 1})"
      }
    }

    preview  = true
    priority = 10000
  }

  rule {
    action      = "deny(403)"
    description = "SQLi - OWASP Rule"

    match {
      expr {
        expression = "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 2})"
      }
    }

    preview  = true
    priority = 11000
  }

  rule {
    action      = "deny(403)"
    description = "XSS - OWASP Rule"

    match {
      expr {
        expression = "evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 1})"
      }
    }

    preview  = true
    priority = 12000
  }

  rule {
    action      = "deny(403)"
    description = "LFI - OWASP Rule"

    match {
      expr {
        expression = "evaluatePreconfiguredWaf('lfi-v33-stable', {'sensitivity': 1})"
      }
    }

    preview  = true
    priority = 13000
  }

  rule {
    action      = "deny(403)"
    description = "RFI - OWASP Rule"

    match {
      expr {
        expression = "evaluatePreconfiguredWaf('rfi-v33-stable', {'sensitivity': 1})"
      }
    }

    preview  = true
    priority = 14000
  }

  rule {
    action      = "deny(403)"
    description = "RCE - OWASP Rule"

    match {
      expr {
        expression = "evaluatePreconfiguredWaf('rce-v33-stable', {'sensitivity': 1})"
      }
    }

    preview  = true
    priority = 15000
  }

  rule {
    action      = "deny(403)"
    description = "Method Enforcement - OWASP Rule"

    match {
      expr {
        expression = "evaluatePreconfiguredWaf('methodenforcement-v33-stable', {'sensitivity': 1})"
      }
    }

    preview  = true
    priority = 16000
  }

  rule {
    action      = "deny(403)"
    description = "Scanner Detection - OWASP Rule"

    match {
      expr {
        expression = "evaluatePreconfiguredWaf('scannerdetection-v33-stable', {'sensitivity': 1})"
      }
    }

    preview  = true
    priority = 17000
  }

  rule {
    action      = "deny(403)"
    description = "Protocol Attack - OWASP Rule"

    match {
      expr {
        expression = "evaluatePreconfiguredWaf('protocolattack-v33-stable', {'sensitivity': 1})"
      }
    }

    preview  = true
    priority = 18000
  }

  rule {
    action      = "deny(403)"
    description = "Session Fixation - OWASP Rule"

    match {
      expr {
        expression = "evaluatePreconfiguredWaf('sessionfixation-v33-stable', {'sensitivity': 1})"
      }
    }

    preview  = true
    priority = 19000
  }

  rule {
    action      = "deny(403)"
    description = "Node.js - OWASP Rule"

    match {
      expr {
        expression = "evaluatePreconfiguredWaf('nodejs-v33-stable', {'sensitivity': 1})"
      }
    }

    preview  = true
    priority = 20000
  }

  rule {
    action      = "deny(403)"
    description = "Java - OWASP Rule"

    match {
      expr {
        expression = "evaluatePreconfiguredWaf('java-v33-stable', {'sensitivity': 3})"
      }
    }

    preview  = true
    priority = 21000
  }

  rule {
    action      = "deny(403)"
    description = "Critical vulnerabilities rule"

    match {
      expr {
        expression = "evaluatePreconfiguredWaf('cve-canary', {'sensitivity':0, 'opt_in_rule_ids': ['owasp-crs-v030001-id044228-cve', 'owasp-crs-v030001-id144228-cve', 'owasp-crs-v030001-id244228-cve', 'owasp-crs-v030001-id344228-cve']})"
      }
    }

    preview  = true
    priority = 22000
  }

  rule {
    action      = "deny(403)"
    description = "JSON - SQL Bypass CVE"

    match {
      expr {
        expression = "evaluatePreconfiguredWaf('json-sqli-canary', {'sensitivity':0, 'opt_in_rule_ids': ['owasp-crs-id942550-sqli']})"
      }
    }

    preview  = true
    priority = 23000
  }

  rule {
    action      = "throttle"
    description = "Rate limit all user IPs"

    match {
      config {
        src_ip_ranges = ["*"]
      }

      versioned_expr = "SRC_IPS_V1"
    }

    preview  = true
    priority = 30000

    rate_limit_options {
      conform_action = "allow"
      enforce_on_key = "ALL"
      exceed_action  = "deny(429)"

      rate_limit_threshold {
        count        = 500
        interval_sec = 60
      }
    }
  }
  rule {
    action      = "allow"
    description = "default rule"

    match {
      config {
        src_ip_ranges = ["*"]
      }

      versioned_expr = "SRC_IPS_V1"
    }

    priority = 2147483647
  }

  type = "CLOUD_ARMOR"
}
