{
  "subject": {{ toJson .Subject }},
  "keyUsage": ["certSign", "crlSign"],
  "basicConstraints": { "isCA": true, "maxPathLen": 0 },
  "nameConstraints": {
    "critical": true,
    "permittedDNSDomains": ["__LAB_DOMAIN__"],
    "excludedIPRanges": ["0.0.0.0/0", "::/0"]
  }
}
