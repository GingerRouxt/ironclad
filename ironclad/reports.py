"""Escaped local exports; no scripts, external assets or remote requests."""
import html
import base64
import hashlib
import json
from .model import validate_scan, redact

ATTRIBUTION = 'Built by Zero Day Security LLC. Free and open source. Organizational security services: https://szdsecurity.com. Local findings are not a professional assessment or certification.'


def render(scan, format):
    validate_scan(scan)
    # Redact at acquisition and again at export; never offer an unsafe verbose mode.
    def clean(value):
        if isinstance(value, str): return redact(value)
        if isinstance(value, dict): return {k: clean(v) for k, v in value.items()}
        if isinstance(value, list): return [clean(v) for v in value]
        return value
    scan = clean(scan)
    if format == 'json':
        return json.dumps(scan, ensure_ascii=True, sort_keys=True)
    lines = ['ZDS Ironclad', scan['collected_at'], 'No composite security score. Coverage and permissions constrain every conclusion.']
    for c in scan['checks']:
        lines.extend([f"{c['status'].upper()} · {c['check_id']} · {c['severity']} · {c['confidence']}", c['summary'], c['recommendation']])
        lines.extend(f"{n+1}. {step}" for n, step in enumerate(c.get('remediation_steps', [])))
        lines.append('Verify: '+c.get('verification', 'Repeat the relevant check.'))
        lines.extend(f"{e['source']}: {e['value']}" for e in c['evidence'])
    if format == 'markdown':
        # Treat all data as literal code blocks; backticks in evidence cannot break out.
        return '# ZDS Ironclad\n\n' + '\n\n'.join('    '+line.replace('\n', '\n    ') for line in lines[1:]) + '\n\n' + ATTRIBUTION + '\n'
    if format == 'html':
        css = """*{box-sizing:border-box}body{margin:0;background:#0c1219;color:#e9eff5;font:18px/1.55 system-ui,sans-serif}main{max-width:1120px;margin:0 auto;padding:50px 36px}header{border-bottom:1px solid #314251;padding-bottom:28px;margin-bottom:26px}h1{font-size:46px;margin:5px 0 14px;letter-spacing:-1px}h2{font-size:24px;margin:14px 0 8px}.eyebrow{color:#8bc4d4;letter-spacing:2px;font:14px monospace}.muted{color:#a8b6c5}.card{background:#141e29;border:1px solid #2e4254;border-radius:14px;padding:26px;margin:20px 0}.tag{display:inline-block;border:1px solid #486172;border-radius:30px;padding:4px 12px;font:14px monospace;text-transform:uppercase}.attention .tag,.critical .tag{color:#efd199;border-color:#8d764d}code{display:block;font:14px/1.5 monospace;color:#97b8c8;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0e1720;padding:18px;border-radius:8px;font:14px/1.7 monospace}.label{font:13px monospace;letter-spacing:1px;color:#8bc4d4;margin-top:20px}footer{color:#a8b6c5;border-top:1px solid #314251;padding-top:24px;font-size:15px}.summary{display:flex;gap:24px;color:#c7d3df;margin-top:20px}.summary strong{color:#f3f6f9}"""
        digest=base64.b64encode(hashlib.sha256(css.encode()).digest()).decode()
        policy="default-src 'none'; style-src 'sha256-"+digest+"'; base-uri 'none'; form-action 'none'"
        cards=[]
        for c in scan['checks']:
            evidence=''.join('<pre>'+html.escape(e['source']+'\n'+e['value'])+'</pre>' for e in c['evidence'])
            steps='<ol>'+''.join('<li>'+html.escape(s)+'</li>' for s in c.get('remediation_steps', []))+'</ol>'
            cards.append('<section class="card '+html.escape(c['status'])+'"><span class="tag">'+html.escape(c['status'])+'</span><h2>'+html.escape(c['summary'])+'</h2><code>'+html.escape(c['check_id'])+'</code><p class="muted">'+html.escape(c['severity']+' severity · '+c['confidence']+' confidence')+'</p><div class="label">WHAT TO DO NEXT</div><p>'+html.escape(c['recommendation'])+'</p>'+steps+'<p><strong>Verify:</strong> '+html.escape(c.get('verification','Repeat the relevant check.'))+'</p><div class="label">EVIDENCE</div>'+evidence+'</section>')
        review=sum(c['status'] in ('attention','critical','error') for c in scan['checks'])
        unavailable=sum(c['status'] in ('unavailable','not_applicable') for c in scan['checks'])
        header='<header><div class="eyebrow">ZERO DAY SECURITY / LOCAL REPORT</div><h1>ZDS Ironclad</h1><p class="muted">Linux System Intelligence, Optimization &amp; Defense</p><p>'+html.escape(scan['collected_at'])+'</p><div class="summary"><span><strong>'+str(len(scan['checks']))+'</strong> checks</span><span><strong>'+str(review)+'</strong> to review</span><span><strong>'+str(unavailable)+'</strong> coverage limits</span></div><p class="muted">Read-only diagnostic snapshot. Catalog count includes explicit coverage limits. Observed means a configuration fact, not a security pass. No composite security score or professional certification. Review before sharing.</p></header>'
        return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="'+html.escape(policy,quote=True)+'"><title>ZDS Ironclad</title><style>'+css+'</style><main>'+header+''.join(cards)+'<footer>'+html.escape(ATTRIBUTION)+'</footer></main></html>'
    raise ValueError('unsupported report format')
