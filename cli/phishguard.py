"""
PhishGuard AI - Command Line Interface
Usage:
    phishguard scan email.eml
    phishguard train [dataset.csv]
    phishguard version
    phishguard api
"""

import sys
import json
import logging
from pathlib import Path

import click

# Ensure project root is on sys.path when run directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(level=logging.WARNING,
                    format="%(levelname)s: %(message)s")

# ── Helpers ───────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "red",
    "high":     "yellow",
    "medium":   "magenta",
    "low":      "cyan",
}

RISK_COLORS = {
    "critical": "red",
    "high":     "yellow",
    "medium":   "magenta",
    "low":      "green",
}


def _print_banner():
    click.echo(click.style("""
 ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
 ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
 ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
                                                           AI   v1.0.0
""", fg="cyan", bold=True))


def _print_result(result: dict, verbose: bool = False, output_json: bool = False):
    if output_json:
        click.echo(json.dumps(result, indent=2, default=str))
        return

    is_phish = result["is_phishing"]
    verdict_color = "red" if is_phish else "green"
    verdict_text  = "⚠  PHISHING DETECTED" if is_phish else "✓  EMAIL APPEARS SAFE"
    risk_level    = result["risk"]["level"]

    click.echo()
    click.echo("─" * 62)
    click.echo(click.style(f"  VERDICT : {verdict_text}", fg=verdict_color, bold=True))
    click.echo("─" * 62)
    click.echo(f"  Probability : {result['phishing_probability_pct']}% phishing")
    click.echo(f"  Confidence  : {result['confidence']}")
    click.echo(f"  Risk Level  : " +
               click.style(risk_level.upper(), fg=RISK_COLORS.get(risk_level, "white"), bold=True))
    click.echo(f"  Model       : {result['model_info'].get('name', 'Unknown')}")
    click.echo("─" * 62)

    indicators = result.get("indicators", [])
    if indicators:
        click.echo(click.style(f"\n  🚩 Threat Indicators ({len(indicators)} found)\n",
                               fg="yellow", bold=True))
        for ind in indicators:
            sev   = ind["severity"]
            color = SEVERITY_COLORS.get(sev, "white")
            click.echo(
                "  " +
                click.style(f"[{sev.upper():8}]", fg=color, bold=True) +
                f"  {ind['indicator']}"
            )
            if verbose:
                click.echo(click.style(f"             {ind['detail']}", fg="bright_black"))
    else:
        click.echo(click.style("\n  ✓  No phishing indicators detected.\n", fg="green"))

    click.echo()


# ── CLI Group ─────────────────────────────────────────────────────

@click.group()
@click.version_option("1.0.0", prog_name="PhishGuard AI")
def cli():
    """PhishGuard AI — Phishing Email Detection Tool

    Detect phishing emails using machine learning.
    Designed for Kali Linux and security professionals.
    """


# ── scan ──────────────────────────────────────────────────────────

@cli.command()
@click.argument("email_file", type=click.Path(exists=True))
@click.option("--verbose", "-v", is_flag=True, help="Show full indicator details.")
@click.option("--json",    "-j", "output_json", is_flag=True,
              help="Output result as JSON.")
@click.option("--no-banner", is_flag=True, help="Suppress ASCII banner.")
def scan(email_file: str, verbose: bool, output_json: bool, no_banner: bool):
    """Scan EMAIL_FILE (.eml or .txt) for phishing indicators.

    Examples:\n
        phishguard scan suspicious.eml\n
        phishguard scan email.txt --verbose\n
        phishguard scan email.eml --json > result.json
    """
    if not no_banner and not output_json:
        _print_banner()

    # Check model
    if not Path("models/phishguard_best.pkl").exists():
        click.echo(click.style(
            "\n  ✗  No trained model found. Run: phishguard train\n",
            fg="red", bold=True
        ))
        sys.exit(1)

    path = Path(email_file)
    if not output_json:
        click.echo(f"\n  Scanning: {path.name} ...")

    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        click.echo(click.style(f"\n  ✗  Cannot read file: {exc}\n", fg="red"))
        sys.exit(1)

    try:
        from ml.predictor import predict_from_eml_text
        result = predict_from_eml_text(raw)
    except Exception as exc:
        click.echo(click.style(f"\n  ✗  Analysis failed: {exc}\n", fg="red"))
        sys.exit(2)

    _print_result(result, verbose=verbose, output_json=output_json)

    # Exit code: 1 if phishing detected (useful for scripting)
    sys.exit(1 if result["is_phishing"] else 0)


# ── train ─────────────────────────────────────────────────────────

@cli.command()
@click.argument("dataset", required=False,
                type=click.Path(exists=True))
@click.option("--no-banner", is_flag=True)
def train(dataset: str | None, no_banner: bool):
    """Train the phishing detection model.

    Optionally provide a CSV DATASET. If omitted, synthetic
    training data is generated automatically.

    CSV columns: subject, body, sender, reply_to, headers, label
    label: 1=phishing, 0=safe

    Examples:\n
        phishguard train\n
        phishguard train datasets/phishing.csv
    """
    if not no_banner:
        _print_banner()

    click.echo(click.style("\n  ⚙  Starting model training...\n", fg="cyan", bold=True))
    if dataset:
        click.echo(f"  Dataset   : {dataset}")
    else:
        click.echo("  Dataset   : synthetic (3 000 samples)")
    click.echo("  Models    : Naive Bayes, Logistic Regression, Random Forest")
    click.echo()

    try:
        from ml.trainer import run_training_pipeline
        summary = run_training_pipeline(dataset)
    except Exception as exc:
        click.echo(click.style(f"\n  ✗  Training failed: {exc}\n", fg="red"))
        sys.exit(1)

    best   = summary["best_model"]
    mets   = summary["metrics"]
    all_r  = summary.get("all_results", {})

    click.echo("─" * 62)
    click.echo(click.style("  Model Comparison", bold=True))
    click.echo("─" * 62)
    header = f"  {'Model':<22} {'Accuracy':>9} {'F1':>8} {'AUC-ROC':>9} {'Time(s)':>8}"
    click.echo(click.style(header, fg="bright_black"))
    for name, m in all_r.items():
        marker = " ★" if name == best else ""
        color  = "cyan" if name == best else None
        row    = (f"  {name:<22} {m['accuracy']:>9.4f} {m['f1']:>8.4f}"
                  f" {m['auc_roc']:>9.4f} {m.get('training_time_s',0):>7.2f}s{marker}")
        click.echo(click.style(row, fg=color, bold=(name == best)))

    click.echo("─" * 62)
    click.echo(click.style(
        f"\n  ✓  Best model: {best}  (F1={mets['f1']:.4f})\n"
        f"     Saved → models/phishguard_best.pkl\n",
        fg="green", bold=True
    ))


# ── version ───────────────────────────────────────────────────────

@cli.command()
def version():
    """Show PhishGuard AI version and model info."""
    click.echo(click.style("\n  PhishGuard AI  v1.0.0", fg="cyan", bold=True))
    click.echo("  MIT License | github.com/yourusername/phishguard\n")

    model_path = Path("models/phishguard_best.pkl")
    if model_path.exists():
        try:
            import json
            with open("models/model_meta.json") as f:
                meta = json.load(f)
            click.echo(f"  Model      : {meta.get('model_name', 'Unknown')}")
            click.echo(f"  Trained at : {meta.get('trained_at', 'Unknown')}")
            click.echo(f"  Features   : {len(meta.get('feature_names', []))}")
            m = meta.get("best_metrics", {})
            click.echo(f"  Accuracy   : {m.get('accuracy', 'N/A')}")
            click.echo(f"  F1 Score   : {m.get('f1', 'N/A')}")
        except Exception:
            click.echo("  Model      : found (metadata unreadable)")
    else:
        click.echo(click.style("  Model      : NOT TRAINED", fg="yellow"))
        click.echo("  Run: phishguard train")
    click.echo()


# ── api ───────────────────────────────────────────────────────────

@cli.command()
@click.option("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
@click.option("--port", default=5000,        help="Port (default: 5000)")
@click.option("--debug", is_flag=True,       help="Enable Flask debug mode.")
@click.option("--no-banner", is_flag=True)
def api(host: str, port: int, debug: bool, no_banner: bool):
    """Start the PhishGuard AI web server and REST API.

    Examples:\n
        phishguard api\n
        phishguard api --host 0.0.0.0 --port 8080\n
        phishguard api --debug
    """
    if not no_banner:
        _print_banner()
    click.echo(click.style(
        f"\n  🌐  Starting PhishGuard AI web server\n"
        f"      http://{host}:{port}\n",
        fg="cyan", bold=True
    ))
    from app import create_app
    application = create_app({"DEBUG": debug})
    application.run(host=host, port=port, debug=debug)


# ── Entry point ───────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
