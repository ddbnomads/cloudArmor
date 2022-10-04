# Cloud Armor
The Google Cloud Armor service has updated the syntax for pre-defined OWASP rules, https://cloud.google.com/armor/docs/waf-rules . 

This updated terraform contains the complete set of OWASP rules in preview mode with a default fail open. The OWASP rules are set to the most aggressive paranoia level for the respective OWASP signature. For more information on rules tuning, consult the Cloud Armor documentation for WAF rule tuning: https://cloud.google.com/armor/docs/rule-tuning
