# msg-to-pdf

Bulk converter for Outlook `.msg` files to PDFs. Reads the MAPI binary format directly via `olefile` — no Outlook required.

Built to automate the repetitive parts of preparing email exhibits for court filings, audit submissions, and document productions, but useful anywhere you have a folder of `.msg` files that need to become PDFs.

**By using this tool, you consent to the [Disclaimer](#disclaimer).**

## Why use this

- You have hundreds or thousands of `.msg` files and don't want to open each one in Outlook to print to PDF
- You need a single output folder where each email PDF sorts immediately before its attachments alphabetically (handy for review or bundling)
- You want a SHA-256 manifest of every output for integrity verification
- You can't or don't want to use Outlook (licensing, automation constraints, machine doesn't have Outlook installed)

## What it produces

For each `.msg` file in your source folder (recursive), writes to `<output>/Output/`:

- One email PDF named: `YYYYMMDD - <subject> - 00 Email.pdf`
- One file per attachment: `YYYYMMDD - <subject> - NN <attachment_name>` (NN starts at 01 so attachments sort after the email)
- Inline signature images (small images with a Content-ID) are filtered out of the attachment list but still rendered into the email body

Also writes:

- `_manifest.csv` — SHA-256 of every source MSG and every output file
- `_exported.json` — resume log so re-runs skip already-processed files

## Requirements

- Python 3.9+ (uses `zoneinfo`)
- `olefile`: `py -m pip install olefile`
- Microsoft Edge (any recent version) for PDF rendering. If Edge isn't found, falls back to saving each email as HTML.

The PDF rendering uses headless Edge with `--disable-javascript` and `--disable-features=NetworkService`, plus an HTML sanitiser that strips script, iframe, and external resource references, so untrusted email content can be processed without executing it or phoning home.

## Quickstart

1. Install Python and `olefile`, ensure Edge is installed
2. Open `export_emails.py` and edit the CONFIG section near the top:
   - `MSG_FOLDER` — where your `.msg` files live
   - `OUTPUT_DIR` — where you want the output
   - `OUTPUT_TIMEZONE` — IANA timezone name (e.g. `"Australia/Sydney"`, `"America/New_York"`, `"Europe/London"`, default `"UTC"`)
3. Run: `py export_emails.py`
4. Re-runs are safe — already-processed files are skipped

## Limitations

- Embedded `.msg` attachments (forwarded-as-attachment emails) are detected but written as marker `.txt` files rather than recursively converted. Open the parent in Outlook, save the embedded message as a separate `.msg` file, then re-run on it.
- Inline images only render if the source `.msg` uses standard Content-ID (`cid:`) references. Images embedded by other means may not appear in the rendered PDF, though the attachment data is still saved to disk.
- Edge headless is required for PDF output. On platforms without Edge (Linux servers, some macOS configurations), the script falls back to HTML output.

## Security notes

The script defends against several known attack surfaces in untrusted email HTML:

- Path traversal via crafted attachment filenames
- HTML sanitisation strips scripts, iframes, event handlers, external resource fetches, protocol-relative URLs (Windows SMB hash leak vector), and Windows UNC paths
- Edge runs with JavaScript disabled and network service disabled
- SHA-256 manifest provides cryptographic integrity verification of outputs (note: this does not by itself constitute a forensically defensible chain of custody — see Disclaimer)

**Important caveats:**

- The HTML sanitiser is regex-based, which is inherently brittle. Edge running with JavaScript disabled mitigates most execution paths, but a determined attacker could craft an input that bypasses specific sanitiser patterns. If processing emails from a known hostile source, additional precautions (air-gapped machine, process isolation) are recommended.
- For high-security environments, run the rendering machine air-gapped during conversion as belt-and-suspenders.

## Contributing

Issues and pull requests welcome. This started as a personal tool and has been tested against real email corpora, but every Outlook installation produces slightly different `.msg` quirks. If you find a file it can't handle, an issue with a sample (or sanitised hex dump of the relevant streams) is the fastest path to a fix.

## License

MIT — see `LICENSE`.

## Disclaimer

This software is provided "as is" under the MIT License (see LICENSE). The author makes no warranties about its fitness for any particular purpose, including but not limited to use in legal proceedings, regulatory submissions, or any context where data integrity is critical.

**By using this script, you accept that:**

- **You are responsible for verifying output.** This tool processes complex binary file formats and renders untrusted email content. Outputs should be independently verified before relying on them. Do not use this tool's output as the sole basis for any decision with legal, financial, or evidentiary consequences.

- **You are responsible for confidentiality.** The script processes whatever files you point it at. If those files contain privileged, confidential, or personally identifiable information, securing that data — including ensuring the rendering machine is appropriately isolated and that outputs are stored securely — is your responsibility.

- **No chain-of-custody guarantee.** The SHA-256 manifest is provided to assist with integrity verification but does not by itself constitute a forensically defensible chain of custody. For matters requiring forensic-grade evidence handling, engage a qualified eDiscovery vendor.

- **No professional advice.** Nothing in this tool or its documentation constitutes legal, technical, or professional advice. If you are using this for work that requires professional judgement, exercise that judgement independently.

- **The author accepts no liability** for any direct, indirect, incidental, consequential, or other damages arising from the use of this software, including but not limited to loss of data, loss of confidentiality, professional negligence, breach of court rules, or financial loss. Your use of this software is entirely at your own risk.

This software is open source and provided free of charge. Use at your own discretion and within the limits of your own competence and supervision.
