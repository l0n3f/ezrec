# 🛡️ WAF Bypass Generator

This tool includes a **massive database** of WAF bypass techniques that you can generate on-demand for your bug bounty hunting needs.

## 🚀 Quick Start

Generate bypass payloads for any attack type and WAF:

```bash
# Generate ALL XSS bypasses (89+ payloads)
ezrec evasion waf-bypass --attack-type xss --payload "alert(1)" --output file

# Generate SQLi bypasses for specific WAF (30+ payloads)
ezrec evasion waf-bypass --attack-type sqli --payload "1' OR 1=1--" --waf-type cloudflare --output file

# Generate SSRF bypasses (50+ payloads)
ezrec evasion waf-bypass --attack-type ssrf --payload "http://127.0.0.1" --output file
```

## 📁 Generated Files

All bypass files are saved to the `bypasses/` directory:

- `xss.md` - All XSS bypasses (89+ payloads)
- `xss-cloudflare.md` - Cloudflare-specific XSS (28+ payloads)
- `sqli.md` - All SQLi bypasses (60+ payloads)
- `sqli-modsecurity.md` - ModSecurity-specific SQLi (8+ payloads)
- `ssrf.md` - All SSRF bypasses (50+ payloads)
- `lfi.md` - All LFI bypasses (20+ payloads)
- `rce.md` - All RCE bypasses (20+ payloads)

## 🎯 Attack Types Supported

| Attack Type | Description | Payloads |
|-------------|-------------|----------|
| `xss` | Cross-Site Scripting | 89+ |
| `sqli` | SQL Injection | 60+ |
| `ssrf` | Server-Side Request Forgery | 50+ |
| `lfi` | Local File Inclusion | 20+ |
| `rce` | Remote Code Execution | 20+ |

## 🛡️ WAF Types Supported

| WAF | Code | Specific Payloads |
|-----|------|-------------------|
| Cloudflare | `cloudflare` | ✅ Optimized |
| AWS WAF | `aws_waf` | ✅ Optimized |
| Azure WAF | `azure_waf` | ✅ Optimized |
| ModSecurity | `modsecurity` | ✅ Optimized |
| Imperva | `imperva` | ✅ Optimized |
| Akamai | `akamai` | ✅ Optimized |
| F5 ASM | `f5_asm` | ✅ Optimized |

## 📋 Usage Examples

### Generate All Payloads for an Attack Type
```bash
# All XSS bypasses (generic + WAF-specific)
ezrec evasion waf-bypass --attack-type xss --payload "alert(1)" --output file
```

### Generate WAF-Specific Payloads
```bash
# Cloudflare XSS bypasses only
ezrec evasion waf-bypass --attack-type xss --payload "alert(1)" --waf-type cloudflare --output file

# ModSecurity SQLi bypasses only
ezrec evasion waf-bypass --attack-type sqli --payload "1' OR 1=1--" --waf-type modsecurity --output file
```

### View Payloads in Terminal
```bash
# Display in terminal instead of saving to file
ezrec evasion waf-bypass --attack-type xss --payload "alert(1)" --waf-type cloudflare
```

## 📊 Payload Categories

### XSS Categories (18 categories)
- **Cloudflare Specific** - Unicode, comments, SVG vectors
- **AWS WAF Specific** - Double encoding, mixed encoding
- **ModSecurity Specific** - MySQL comments, whitespace
- **Alternative Vectors** - Event handlers, form elements
- **DOM Based** - innerHTML, appendChild manipulation
- **CSS Based** - Expression, import, animation
- **Encoding** - HTML entities, Unicode, Base64
- **Polyglots** - Multi-context payloads

### SQLi Categories (15 categories)
- **WAF-Specific** - Cloudflare, AWS, ModSecurity, Imperva
- **Comment Injection** - MySQL, multi-line, nested
- **Union Bypasses** - Encoded UNION SELECT variations
- **Boolean Logic** - String/math comparisons
- **Time-based** - SLEEP, BENCHMARK, WAITFOR
- **Error-based** - ExtractValue, UpdateXML, CONVERT
- **Encoding** - URL, Unicode, Hex encoding

### SSRF Categories (10 categories)
- **Localhost Bypasses** - IP variations, domain confusion
- **IP Encoding** - Decimal, hex, octal, mixed
- **IPv6** - Localhost, mapped IPv4
- **Protocol Bypasses** - File, FTP, Gopher, LDAP
- **Cloud Metadata** - AWS, GCP, Azure, DigitalOcean
- **DNS Rebinding** - Wildcard DNS services

## 🔥 Advanced Features

### High-Confidence Payloads
Each payload includes a confidence score (0-100%):
- **95%+** - Proven to work against specific WAFs
- **80-94%** - High success rate
- **60-79%** - Moderate success rate
- **<60%** - Lower success rate, worth trying

### Organized by Effectiveness
Payloads are sorted by:
1. **WAF-specific** techniques (highest success rate)
2. **Generic** techniques (broader compatibility)
3. **Confidence score** (highest first)

### Detailed Documentation
Each generated file includes:
- ✅ **Table of Contents** with navigation
- ✅ **Payload descriptions** and explanations
- ✅ **Confidence scores** for each technique
- ✅ **WAF effectiveness** ratings
- ✅ **Usage examples** and commands
- ✅ **Category breakdown** statistics

## 🎯 Pro Tips

1. **Start WAF-specific**: Always try WAF-specific payloads first for higher success rates
2. **Use confidence scores**: Focus on 80%+ confidence payloads
3. **Combine techniques**: Mix encoding with alternative vectors
4. **Test systematically**: Work through categories methodically
5. **Update regularly**: Regenerate files to get latest techniques

## 🔧 Integration with ezrec

These bypasses integrate seamlessly with the main reconnaissance pipeline:

```bash
# Use during recon with WAF detection
ezrec recon --domain target.com --httpx --xss --waf-detect --waf-bypass --ai

# Generate custom payloads for discovered endpoints
ezrec evasion waf-bypass --attack-type xss --payload "alert(document.domain)" --waf-type cloudflare --output file
```

---

**💡 Remember**: The `bypasses/` directory is created automatically when you generate your first payload file. Each user creates their own custom bypass collection!