terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
      version = "4.66.0"
    }
  }
}

provider "google" {
  # Configuration options
}

resource "google_compute_security_policy" "policy" {
  name = "infrastructure-as-code-security-policy"
  description = "template rules"
  
  advanced_options_config {
      json_parsing = "STANDARD"
      log_level= "VERBOSE"
  }
  adaptive_protection_config {
      layer_7_ddos_defense_config {
          enable = true
          rule_visibility = "STANDARD"
      }
  }
    type = "CLOUD_ARMOR"

  rule {
    action   = "deny(403)"
    priority = "1000"
    preview = true
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["9.9.9.0/24"]
      }
    }
    description = "Deny access to specific IP addresses"
  }

    rule {
    action   = "throttle"
    priority = "3000"
    preview = true
    rate_limit_options {
          enforce_on_key = "ALL"
          conform_action = "allow"
          exceed_action = "deny(429)"
          rate_limit_threshold {
              count = "100"
              interval_sec = "60" 
          }
      }
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Rate limit all user IPs"
  }
   
   rule {
    action   = "allow"
    priority = "5000"
    preview = true
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["2.2.2.0/24"]
      }
    }
    description = "Allow access to IPs in specific CIDR"
  }

   rule {
    action   = "deny(403)"
    priority = "7000"
    preview = true
    match {
      expr {
        expression = "origin.region_code == 'CN' && origin.region_code == 'RU'"
      }
    }
    description = "Block users from specific countries"
  }

  rule {
    action   = "deny(403)"
    priority = "10000"
    preview = true
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('php-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "PHP - OWASP Rule"
  }

  rule {
    action   = "deny(403)"
    priority = "11000"
    preview = true
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "SQLi - OWASP Rule"
  }
  
  rule {
    action   = "deny(403)"
    priority = "11100"
    preview = true
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('json-sqli-canary', {'sensitivity':0, 'opt_in_rule_ids': ['owasp-crs-id942550-sqli']})"
      }
    }
    description = "SQLi - JSON Synatx Bypass"
  }

  rule {
    action   = "deny(403)"
    priority = "12000"
    preview = true
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "XSS - OWASP Rule"
  }

  rule {
    action   = "deny(403)"
    priority = "13000"
    preview = true
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('lfi-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "LFI - OWASP Rule"
  }

rule {
    action   = "deny(403)"
    priority = "14000"
    preview = true
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('rfi-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "RFI - OWASP Rule"
  }

  rule {
    action   = "deny(403)"
    priority = "15000"
    preview = true
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('rce-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "RCE - OWASP Rule"
  }

  rule {
    action   = "deny(403)"
    priority = "16000"
    preview = true
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('methodenforcement-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "Method Enforcement - OWASP Rule"
  }

  rule {
    action   = "deny(403)"
    priority = "17000"
    preview = true
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('scannerdetection-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "Scanner Detection - OWASP Rule"
  }

rule {
    action   = "deny(403)"
    priority = "18000"
    preview = true
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('protocolattack-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "Protocol Attack - OWASP Rule"
  }

  rule {
    action   = "deny(403)"
    priority = "19000"
    preview = true
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('sessionfixation-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "Session Fixation - OWASP Rule"
  }
rule {
   action   = "deny(403)"
   priority = "20000"
   preview = true
   match {
     expr {
       expression = "evaluatePreconfiguredWaf('nodejs-v33-stable', {'sensitivity': 1})"
     }
   }
   description = "Node.js - OWASP Rule"
 }

rule {
   action   = "deny(403)"
   priority = "21000"
   preview = true
   match {
     expr {
       expression = "evaluatePreconfiguredWaf('java-v33-stable', {'sensitivity': 3})"
     }
   }
   description = "Java - OWASP Rule"
 }

 rule {
   action   = "deny(403)"
   priority = "22000"
   preview = true
   match {
     expr {
       expression = "evaluatePreconfiguredWaf('cve-canary', {'sensitivity': 3})"
     }
   }
   description = "Critical vulnerabilities rule"
 }

  rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "default rule"
  }
}
