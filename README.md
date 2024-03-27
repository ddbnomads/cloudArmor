# Cloud Armor
The Google Cloud Armor service has updated the syntax for pre-defined OWASP rules, https://cloud.google.com/armor/docs/waf-rules . 

These updated terraform files contains the complete set of OWASP rules in preview mode with a default fail open. The OWASP rules are set to the least aggressive paranoia level for the respective OWASP signature. A default rate limit is also provided. The rate limit level is based on a statistical average of requests per second that Google Cloud has seen. You may need to adjust this threshold based upon your specific workload. For more information on rules tuning, consult the Cloud Armor documentation for WAF rule tuning: https://cloud.google.com/armor/docs/rule-tuning

There are two variations of the bootstrap policy set depending on which version of Cloud Armor you are using: STANDARD and ENTERPRISE (aka Cloud Armor Managed Protection, CAMP). The Enterprise version contains additional examples such as threat intelligence lists, referer blocking, and ASN blocking. 
