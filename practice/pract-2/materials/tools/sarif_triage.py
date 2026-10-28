#!/usr/bin/env python3
"""Label SAST findings in a SARIF file with an LLM through OpenRouter.

For every result the script sends the rule, the message, the trace (codeFlows)
and the code around the line to the model. The model answers with a verdict:
true_positive, false_positive or needs_review. The answer is written back to
the SARIF file in the standard places:

  results[].properties.llmTriage   verdict, confidence, explanation, fix
  results[].suppressions[]         only for false_positive, status "underReview"
  runs[].properties.llmTriage      model, time, number of labeled results

Nothing in the original report is changed or removed.

The key is read from the environment variable OPENROUTER_API_KEY. Use
--dry-run to see the requests without a key and without network.
"""

import argparse
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MODEL = "anthropic/claude-3.5-haiku"
VERDICTS = ("true_positive", "false_positive", "needs_review")
CONTEXT_LINES = 15

SYSTEM_PROMPT = """You are a senior application security engineer who reviews \
results of a static analyzer (SARIF). You get one finding with the analyzer \
trace and the source code around it. Decide if the finding is a real defect.

Answer with one JSON object and nothing else:
{
  "verdict": "true_positive" | "false_positive" | "needs_review",
  "confidence": a number from 0 to 1,
  "explanation": "2-4 short sentences: which path in the code leads to the problem, or why it cannot happen",
  "fix": "a short description of the right fix, or an empty string"
}
Use needs_review when the code shown is not enough to decide. Do not invent \
code that you were not shown."""


def fail(message, code=1):
    print(f"sarif-triage: {message}", file=sys.stderr)
    raise SystemExit(code)


def uri_to_path(uri, source_root):
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme == "file":
        path = Path(urllib.parse.unquote(parsed.path))
    else:
        path = Path(urllib.parse.unquote(uri))
    if path.is_absolute() and path.exists():
        return path
    candidate = Path(source_root) / (path.name if path.is_absolute() else path)
    if candidate.exists():
        return candidate
    # Try the tail of an absolute path inside the source root (src/session.c)
    parts = path.parts
    for i in range(len(parts)):
        candidate = Path(source_root).joinpath(*parts[i:])
        if candidate.is_file():
            return candidate
    return None


def code_excerpt(path, line, context=CONTEXT_LINES):
    lines = path.read_text(errors="replace").splitlines()
    first = max(1, line - context)
    last = min(len(lines), line + context)
    width = len(str(last))
    out = []
    for number in range(first, last + 1):
        marker = ">>" if number == line else "  "
        out.append(f"{marker} {number:>{width}} | {lines[number - 1]}")
    return "\n".join(out)


def trace_steps(result):
    steps = []
    for flow in result.get("codeFlows", []):
        for thread in flow.get("threadFlows", []):
            for item in thread.get("locations", []):
                if item.get("importance") == "unimportant":
                    continue
                location = item.get("location", {})
                region = location.get("physicalLocation", {}).get("region", {})
                text = location.get("message", {}).get("text", "")
                steps.append(f"line {region.get('startLine', '?')}: {text}")
    return steps


def build_prompt(run, result, source_root):
    rule_id = result.get("ruleId", "unknown")
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    rule = next((r for r in rules if r.get("id") == rule_id), {})
    rule_text = rule.get("fullDescription", {}).get("text", "")

    location = (result.get("locations") or [{}])[0].get("physicalLocation", {})
    uri = location.get("artifactLocation", {}).get("uri", "")
    line = location.get("region", {}).get("startLine", 1)
    path = uri_to_path(uri, source_root) if uri else None
    excerpt = code_excerpt(path, line) if path else "(source file not found)"

    steps = trace_steps(result)
    parts = [
        f"Rule: {rule_id}",
        f"Rule description: {rule_text}" if rule_text else "",
        f"Severity: {result.get('level', 'warning')}",
        f"Message: {result.get('message', {}).get('text', '')}",
        f"Location: {path.name if path else uri}:{line}",
        "Analyzer trace (important steps):\n" + "\n".join(f"  {s}" for s in steps) if steps else "",
        f"Source code (the finding is marked with >>):\n{excerpt}",
    ]
    return "\n\n".join(p for p in parts if p)


def chat_url(url):
    """Accept both the base (.../api/v1) and the full (.../chat/completions) URL."""
    url = url.rstrip("/")
    return url if url.endswith("/chat/completions") else url + "/chat/completions"


def call_model(base_url, api_key, model, prompt, timeout, retries=2, json_mode=True):
    payload = {
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    body = json.dumps(payload).encode()
    request = urllib.request.Request(
        chat_url(base_url),
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "sarif-triage/1.0 (+curl-compatible)",
            "X-Title": "SDL practice: SARIF triage",
        },
    )
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = json.load(response)
            return data["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")[:300]
            if error.code in (429, 500, 502, 503, 504) and attempt < retries:
                time.sleep(2 ** attempt)
                continue
            if error.code == 400 and json_mode:
                # some models or providers do not support response_format
                return call_model(base_url, api_key, model, prompt, timeout, retries, json_mode=False)
            if error.code == 401:
                fail(f"OpenRouter does not accept the key (HTTP 401): {detail}")
            if error.code == 403:
                fail(f"OpenRouter refused the request (HTTP 403): {detail}\n"
                     "This is not always a key problem: the block can depend on the network, "
                     "the region or a proxy. Compare with: curl -i https://openrouter.ai/api/v1/models")
            fail(f"OpenRouter returned HTTP {error.code}: {detail}")
        except (urllib.error.URLError, http.client.HTTPException, OSError) as error:
            if attempt < retries:
                time.sleep(2 ** attempt)
                continue
            fail(f"cannot reach OpenRouter: {error}")
        except (KeyError, IndexError, json.JSONDecodeError):
            fail("unexpected response format from OpenRouter")


def parse_answer(text):
    """Return a clean dict from the model answer, or a needs_review fallback."""
    match = re.search(r"\{.*\}", text, re.S)
    try:
        data = json.loads(match.group(0)) if match else {}
    except json.JSONDecodeError:
        data = {}
    verdict = data.get("verdict")
    if verdict not in VERDICTS:
        return {
            "verdict": "needs_review",
            "confidence": 0.0,
            "explanation": "The model answer could not be read: " + text.strip()[:200],
            "fix": "",
        }
    try:
        confidence = min(1.0, max(0.0, float(data.get("confidence", 0))))
    except (TypeError, ValueError):
        confidence = 0.0
    return {
        "verdict": verdict,
        "confidence": confidence,
        "explanation": str(data.get("explanation", "")).strip(),
        "fix": str(data.get("fix", "")).strip(),
    }


def apply_label(result, label, model):
    result.setdefault("properties", {})["llmTriage"] = {**label, "model": model}
    if label["verdict"] == "false_positive":
        result.setdefault("suppressions", []).append({
            "kind": "external",
            "status": "underReview",
            "justification": label["explanation"],
        })


def main():
    parser = argparse.ArgumentParser(description="Label SARIF results with an LLM (OpenRouter).")
    parser.add_argument("sarif", help="input SARIF file, for example /work/reports/sast.sarif")
    parser.add_argument("-o", "--output", help="output file (default: <input>.triaged.sarif next to the input)")
    parser.add_argument("--source-root", default=".", help="folder with the sources (default: current folder)")
    parser.add_argument("--model", default=os.environ.get("OPENROUTER_MODEL") or os.environ.get("OLLAMA_MODEL") or DEFAULT_MODEL,
                        help=f"model (default: {DEFAULT_MODEL}; env OPENROUTER_MODEL or OLLAMA_MODEL)")
    parser.add_argument("--base-url",
                        default=os.environ.get("OPENROUTER_BASE_URL") or os.environ.get("OLLAMA_URL") or DEFAULT_BASE_URL,
                        help="base URL or the full .../chat/completions URL (env OPENROUTER_BASE_URL or OLLAMA_URL)")
    parser.add_argument("--timeout", type=int, default=60, help="seconds for one request")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the requests and stop: no key, no network, no output file")
    args = parser.parse_args()

    sarif_path = Path(args.sarif)
    if not sarif_path.is_file():
        fail(f"file not found: {sarif_path}", 2)
    try:
        report = json.loads(sarif_path.read_text())
    except json.JSONDecodeError as error:
        fail(f"{sarif_path} is not valid JSON: {error}", 2)

    api_key = os.environ.get("OPENROUTER_API_KEY") or os.environ.get("OLLAMA_API_KEY", "")
    if not args.dry_run and not api_key:
        fail("set OPENROUTER_API_KEY (or OLLAMA_API_KEY) (or use --dry-run to see the requests without a key)", 2)

    output = Path(args.output) if args.output else sarif_path.with_name(sarif_path.stem + ".triaged.sarif")
    rows = []
    for run in report.get("runs", []):
        results = run.get("results", [])
        for number, result in enumerate(results, 1):
            prompt = build_prompt(run, result, args.source_root)
            if args.dry_run:
                print(f"===== request {number}/{len(results)} · model {args.model} =====")
                print(prompt)
                print()
                continue
            label = parse_answer(call_model(args.base_url, api_key, args.model, prompt, args.timeout))
            apply_label(result, label, args.model)
            line = (result.get("locations") or [{}])[0].get("physicalLocation", {}).get("region", {}).get("startLine", "?")
            rows.append((result.get("ruleId", ""), line, label))
        if not args.dry_run:
            run.setdefault("properties", {})["llmTriage"] = {
                "model": args.model,
                "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "resultsLabeled": len(results),
            }

    if args.dry_run:
        print("dry run: nothing was sent")
        return

    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(f"model: {args.model}")
    for rule_id, line, label in rows:
        print(f"{rule_id}:{line}  {label['verdict']}  (confidence {label['confidence']:.2f})")
        print(f"  {label['explanation']}")
        if label["fix"]:
            print(f"  fix: {label['fix']}")
    print(f"written: {output}")


if __name__ == "__main__":
    main()
