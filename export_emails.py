"""
Bulk .MSG Email Exporter (No Outlook Required)
================================================

Converts a folder of Outlook .msg files into PDFs (one per email), with
each email's attachments saved alongside. Reads the .msg binary format
directly via olefile, so Outlook does not need to be installed or running.

WHY YOU'D USE THIS
------------------
- You have hundreds or thousands of .msg files and don't want to open each
  one in Outlook and File > Print > Save as PDF.
- You need a single output folder where each email PDF sorts immediately
  before its attachments alphabetically (handy for review or bundling).
- You want a SHA-256 manifest of every output for chain-of-custody.
- You can't or don't want to use Outlook (e.g. licensing, automation
  constraints, machine doesn't have Outlook).

Compared to alternatives:
- vs. opening each .msg in Outlook manually: orders of magnitude faster
  and produces deterministic output filenames.
- vs. the `extract-msg` Python library: this script handles the PDF
  rendering step end-to-end, inlines cid: image references so logos and
  signatures actually appear in the body, and produces a manifest for
  integrity verification. extract-msg is great as a parser, but you'd
  still need to wire up HTML sanitisation, PDF rendering, attachment
  naming, and resume logic on top of it.
- vs. forensic-grade tools (Nuix, Magnet AXIOM, etc.): much smaller scope.
  This is a pragmatic batch converter, not a full eDiscovery platform.

WHAT IT PRODUCES
----------------
For each .msg file in MSG_FOLDER (recursive), writes to OUTPUT_DIR/Output/:
- One email PDF named:    YYYYMMDD - <subject> - 00 Email.pdf
- One file per attachment: YYYYMMDD - <subject> - NN <attachment_name>
  (NN starts at 01 so attachments sort after the email)
- Inline signature images (small images with a Content-ID) are filtered
  out of the attachment list but still rendered into the email body.

Also writes:
- _manifest.csv  : SHA-256 of every source MSG and every output file
- _exported.json : resume log so re-runs skip already-processed files

REQUIREMENTS
------------
- Python 3.9+ (uses zoneinfo)
- olefile:        py -m pip install olefile
- Microsoft Edge (any recent version) for the PDF rendering step.
  If Edge isn't found, falls back to saving each email as HTML.

The PDF rendering uses headless Edge with --disable-javascript and
--disable-features=NetworkService, plus an HTML sanitiser that strips
script/iframe/external-resource references, so untrusted email content
can be processed without executing it or phoning home.

QUICKSTART
----------
1. Install Python and olefile, ensure Edge is installed
2. Edit the CONFIG section below — set MSG_FOLDER to your .msg folder
   and OUTPUT_TIMEZONE to your local timezone
3. Run: py export_emails.py
4. Re-runs are safe — already-processed files are skipped

LIMITATIONS
-----------
- Embedded .msg attachments (forwarded-as-attachment emails) are detected
  but written as marker .txt files rather than recursively converted.
  Open the parent in Outlook and save the embedded message as a separate
  .msg file, then re-run on it.
- Inline images only render if the source .msg uses standard Content-ID
  (cid:) references. Images embedded by other means may not appear in
  the rendered PDF, though the attachment data is still saved.
- Edge headless is required for PDF output. On platforms without Edge
  (Linux servers, some macOS configurations), the script falls back to
  HTML output.
"""

import olefile
import os
import re
import shutil
import subprocess
import sys
import time
import json
import csv
import hashlib
import html as html_module
from urllib.parse import quote as url_quote
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import struct
from zoneinfo import ZoneInfo

# ============================================================
# CONFIG - Edit these
# ============================================================

MSG_FOLDER = r"C:\MsgFiles"                              # <-- Your .msg files
OUTPUT_DIR = r"C:\EmailExport"                            # Where everything gets saved
CONVERT_TO_PDF = True                                     # True = PDF, False = HTML only

# Output timezone for date display in PDFs and date prefixes in filenames.
# Set to your local timezone (e.g. "Australia/Sydney", "America/New_York",
# "Europe/London") or leave as "UTC". Uses IANA timezone names.
OUTPUT_TIMEZONE = "UTC"

# Safety limits
MAX_MSG_FILE_SIZE = 500 * 1024 * 1024       # 500 MB max .msg file size
MAX_ATTACHMENT_SIZE = 100 * 1024 * 1024     # 100 MB max per attachment
MAX_HTML_BODY_SIZE = 50 * 1024 * 1024       # 50 MB max for HTML body (DoS guard)
MAX_RECIPIENTS = 1000                        # Sanity cap on recipient table
MAX_ATTACHMENTS = 1000                       # Sanity cap on attachments

# Filename limits
# These keep us well below Windows MAX_PATH (260) once joined with output dir.
# Filesystem limit is 255 per filename component on NTFS/APFS.
MAX_FILENAME_LEN = 180                       # max length of full output filename (no path)
MAX_SUBJECT_IN_FILENAME = 100                # max length for email subject portion
MAX_ATTACH_NAME_IN_FILENAME = 80             # max length for attachment original filename portion
ATTACH_NUMBER_DIGITS = 2                     # zero-padded count: 01, 02. Use 3 for 100+ atts/email.

# ============================================================

try:
    OUTPUT_TZ = ZoneInfo(OUTPUT_TIMEZONE)
except Exception:
    # Fall back to UTC if the user's config is invalid rather than crashing
    print(f"Warning: invalid OUTPUT_TIMEZONE '{OUTPUT_TIMEZONE}' — falling back to UTC")
    OUTPUT_TZ = ZoneInfo("UTC")

# Single output folder — emails and attachments together so they sort
# consistently in alphabetical order when bundled.
OUTPUT_FILES_DIR = os.path.join(OUTPUT_DIR, "Output")
HTML_TEMP = os.path.join(OUTPUT_DIR, "_temp_html")
EDGE_TEMP_PROFILE = os.path.join(OUTPUT_DIR, "_edge_profile")
DONE_LOG = os.path.join(OUTPUT_DIR, "_exported.json")
MANIFEST_CSV = os.path.join(OUTPUT_DIR, "_manifest.csv")


def sha256_file(path):
    """Compute SHA-256 of a file. Returns hex digest, or None on error."""
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def sha256_bytes(data):
    """Compute SHA-256 of raw bytes."""
    try:
        return hashlib.sha256(data).hexdigest()
    except Exception:
        return None


def append_manifest_row(row):
    """
    Append a row to the integrity manifest CSV. Writes a header if the file
    doesn't exist yet. Each row records the source MSG, the output file, its
    type, size, and SHA-256, and the timestamp.
    """
    fieldnames = [
        'timestamp_utc',
        'source_msg_path',
        'source_msg_sha256',
        'output_path',
        'output_type',     # 'email_pdf', 'email_html', 'attachment'
        'output_size',
        'output_sha256',
    ]
    write_header = not os.path.exists(MANIFEST_CSV)
    try:
        with open(MANIFEST_CSV, 'a', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if write_header:
                writer.writeheader()
            writer.writerow(row)
    except Exception as e:
        print(f"  Warning: could not write manifest row: {e}")


def sanitize(name, max_len=80):
    """Remove illegal filename characters and path traversal sequences."""
    if not name:
        return "No Subject"
    # Remove illegal chars (Windows + Unix)
    name = re.sub(r'[<>:"/\\|?*\r\n\t\x00]', '', name)
    # Strip Unicode bidirectional / RTL override characters that can be used
    # to visually disguise filenames (e.g. "report\u202Etxt.exe" displays as
    # "reportexe.txt" in some viewers). Covers LRM/RLM, LRE/RLE/PDF/LRO/RLO,
    # and the isolate codepoints (LRI/RLI/FSI/PDI).
    name = re.sub(r'[\u200e\u200f\u202a-\u202e\u2066-\u2069]', '', name)
    # Strip any sequence of dots at the start (prevents .. traversal and hidden files)
    name = re.sub(r'^\.+', '', name)
    # Collapse whitespace
    name = re.sub(r'\s+', ' ', name)
    # Strip trailing dots and spaces (Windows reserved)
    name = name.strip().rstrip('. ')
    # Reject Windows reserved names
    reserved = {'CON', 'PRN', 'AUX', 'NUL',
                'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
                'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'}
    if name.upper().split('.')[0] in reserved:
        name = '_' + name
    if not name:
        return "No Subject"
    return name[:max_len]


def truncate_with_hash(text, max_len, hash_source=None):
    """
    Truncate text to max_len. If truncation occurs, append a 4-char hex hash
    of `hash_source` (defaults to the original text) so two strings that
    match in their first max_len chars still produce distinct names.

    The hash is computed from the FULL original input, so identical inputs
    always produce identical outputs (deterministic).
    """
    if hash_source is None:
        hash_source = text
    if len(text) <= max_len:
        return text
    short_hash = hashlib.sha256(hash_source.encode('utf-8', errors='replace')).hexdigest()[:4]
    # Reserve space for " [xxxx]" suffix (7 chars)
    suffix = f" [{short_hash}]"
    keep = max_len - len(suffix)
    if keep < 1:
        # max_len is too small to fit even the hash — just return the hash
        return suffix.strip()
    truncated = text[:keep].rstrip(' .-')
    return truncated + suffix


def build_email_filename(date_str, subject, ext):
    """
    Build the email's output filename:
        <date> - <subject> - 00 Email.<ext>

    The "- 00 Email" suffix ensures the email file sorts BEFORE its
    attachments (which use 01, 02, ...) when the bundle directory is
    listed alphabetically. ASCII sort of ' - ' vs '.' would otherwise
    place the email AFTER its attachments.

    Truncates subject if necessary, with a hash suffix to keep names unique
    across emails whose long subjects share a common prefix.

    Returns the full filename (no directory).
    """
    safe_subject = sanitize(subject, max_len=10000)  # don't truncate yet, do it ourselves
    truncated_subject = truncate_with_hash(safe_subject, MAX_SUBJECT_IN_FILENAME)
    num_str = "0" * ATTACH_NUMBER_DIGITS  # e.g. "00" for 2-digit, "000" for 3-digit
    filename = f"{date_str} - {truncated_subject} - {num_str} Email.{ext}"

    # Final safety check: if the whole thing exceeds MAX_FILENAME_LEN
    # (could happen with a tiny MAX_SUBJECT_IN_FILENAME), fall back further.
    if len(filename) > MAX_FILENAME_LEN:
        # Aggressive fallback: just date + hash + ext
        h = hashlib.sha256(safe_subject.encode('utf-8', errors='replace')).hexdigest()[:8]
        filename = f"{date_str} - [{h}] - {num_str} Email.{ext}"
    return filename


def build_attachment_filename(date_str, subject, attach_index, attach_filename):
    """
    Build an attachment's output filename:
        <date> - <subject> - <NN> <attachment_name>

    Where:
      - subject is truncated to MAX_SUBJECT_IN_FILENAME (with hash if cut)
      - NN is the zero-padded attach_index (01, 02, ... preserves original
        in-email order)
      - attachment_name keeps its original extension

    Returns the full filename (no directory).
    """
    # Sanitize and truncate subject the same way as build_email_filename
    safe_subject = sanitize(subject, max_len=10000)
    truncated_subject = truncate_with_hash(safe_subject, MAX_SUBJECT_IN_FILENAME)

    # Sanitize attachment filename, splitting name and extension first
    base, ext = os.path.splitext(attach_filename)
    safe_base = sanitize(base, max_len=10000)
    # Keep extension lowercase, conservative length
    safe_ext = re.sub(r'[^A-Za-z0-9]', '', ext)[:10]
    truncated_base = truncate_with_hash(safe_base, MAX_ATTACH_NAME_IN_FILENAME,
                                         hash_source=attach_filename)

    num_str = f"{attach_index:0{ATTACH_NUMBER_DIGITS}d}"

    if safe_ext:
        filename = f"{date_str} - {truncated_subject} - {num_str} {truncated_base}.{safe_ext}"
    else:
        filename = f"{date_str} - {truncated_subject} - {num_str} {truncated_base}"

    # Final safety: if total length still exceeds limit, hash the whole subject portion
    if len(filename) > MAX_FILENAME_LEN:
        h = hashlib.sha256(safe_subject.encode('utf-8', errors='replace')).hexdigest()[:8]
        if safe_ext:
            filename = f"{date_str} - [{h}] - {num_str} {truncated_base}.{safe_ext}"
        else:
            filename = f"{date_str} - [{h}] - {num_str} {truncated_base}"
        # If STILL too long (very long attachment name), truncate the attach name
        if len(filename) > MAX_FILENAME_LEN:
            ah = hashlib.sha256(attach_filename.encode('utf-8', errors='replace')).hexdigest()[:6]
            if safe_ext:
                filename = f"{date_str} - [{h}] - {num_str} [{ah}].{safe_ext}"
            else:
                filename = f"{date_str} - [{h}] - {num_str} [{ah}]"
    return filename


def safe_join(directory, filename):
    """
    Safely join a filename to a directory. Verifies the result is contained
    within the directory. Returns None if the join would escape.
    """
    directory_abs = os.path.realpath(os.path.abspath(directory))
    candidate_abs = os.path.realpath(os.path.abspath(os.path.join(directory, filename)))

    # Check that candidate_abs is inside directory_abs
    try:
        common = os.path.commonpath([directory_abs, candidate_abs])
    except ValueError:
        # Different drives on Windows
        return None

    if common != directory_abs:
        return None
    if candidate_abs == directory_abs:
        # Filename resolved to the directory itself (e.g. empty or '.')
        return None
    return candidate_abs


def unique_path(directory, filename):
    """
    Avoid overwriting — appends (1), (2), etc.
    Verifies the resolved path stays within `directory` (path traversal protection).

    Note: This is not atomic. There's a small TOCTOU window between
    os.path.exists() and the subsequent open(). Safe for single-threaded
    use; do not call from multiple threads/processes without external locking.

    Returns None if filename can't be safely placed in directory.
    """
    safe = safe_join(directory, filename)
    if safe is None:
        return None

    base, ext = os.path.splitext(safe)
    candidate = safe
    counter = 1
    # Verify each candidate also stays inside directory
    while os.path.exists(candidate):
        candidate = f"{base} ({counter}){ext}"
        # Re-verify the candidate after appending counter
        if safe_join(directory, os.path.basename(candidate)) is None:
            return None
        counter += 1
        if counter > 9999:  # Sanity cap
            return None
    return candidate


def find_edge():
    """
    Locate Edge executable. Tries common install paths first, then falls back
    to PATH lookup for non-standard locations (MSIX installs, user-local, etc.).
    """
    paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    # Fallback: PATH lookup
    found = shutil.which('msedge') or shutil.which('msedge.exe')
    if found and os.path.exists(found):
        return found
    return None


def is_valid_pdf(path):
    """Check that a file is a valid PDF by reading its magic bytes."""
    try:
        with open(path, 'rb') as f:
            header = f.read(5)
        return header == b'%PDF-'
    except Exception:
        return False


def _safe_remove(path):
    """Best-effort delete, suppress errors."""
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def html_to_pdf(html_path, pdf_path, edge_exe):
    """
    Convert HTML to PDF using Edge headless with isolated profile.
    Validates output by checking PDF magic bytes — size alone isn't enough,
    a corrupted partial write could pass a size check but fail to open.
    """
    posix_path = html_path.replace("\\", "/")
    encoded = url_quote(posix_path, safe="/:@")
    file_url = f"file:///{encoded}"

    proc = None
    try:
        # Use Popen so we can kill the process if it times out.
        # subprocess.run() with timeout doesn't actually kill the child cleanly
        # on all platforms, which can leave orphaned Edge processes holding
        # locks on EDGE_TEMP_PROFILE during cleanup.
        proc = subprocess.Popen(
            [
                edge_exe,
                "--headless",
                "--disable-gpu",
                "--disable-javascript",          # Prevent malicious JS in email body
                "--disable-extensions",
                "--disable-features=NetworkService",
                f"--print-to-pdf={pdf_path}",
                "--no-pdf-header-footer",
                f"--user-data-dir={EDGE_TEMP_PROFILE}",
                file_url,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            stdout, stderr = proc.communicate(timeout=60)
            returncode = proc.returncode
        except subprocess.TimeoutExpired:
            print(f"    PDF conversion timed out — killing Edge process")
            proc.kill()
            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            _safe_remove(pdf_path)
            return False

        if returncode != 0:
            print(f"    Edge exited with code {returncode}")
            _safe_remove(pdf_path)
            return False

        # Validate output: must exist, have content, AND be a real PDF
        if not os.path.exists(pdf_path):
            return False
        if os.path.getsize(pdf_path) < 100:
            _safe_remove(pdf_path)
            return False
        if not is_valid_pdf(pdf_path):
            print(f"    Edge produced invalid PDF (no %PDF- header)")
            _safe_remove(pdf_path)
            return False
        return True

    except Exception as e:
        print(f"    PDF conversion failed: {e}")
        # Make sure no orphaned process is left behind
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
                proc.communicate(timeout=5)
            except Exception:
                pass
        _safe_remove(pdf_path)
        return False


def clean_html_temp(html_file):
    """Remove an HTML file."""
    try:
        if os.path.exists(html_file):
            os.remove(html_file)
    except Exception:
        pass


def sanitize_html_body(html_str):
    """
    Strip dangerous HTML before embedding in PDF output.
    Removes <script>, <iframe>, event handlers, and external resource fetches.

    Also strips structural document wrappers (<html>, <head>, <body>, <!DOCTYPE>).
    Outlook stores the body as a complete HTML document with its own
    <html>/<head>/<body> tags. When that gets injected inside our template's
    own <body>, Edge headless (and other Chromium-based renderers) sometimes
    interpret the nested document as introducing a new paged-media context,
    which forces a page break between our header and the email body. The
    nested wrappers contribute nothing useful — all the actual content sits
    inside them — so removing them eliminates the page-break bug without
    losing any content.
    """
    if not html_str:
        return html_str

    # Strip DOCTYPE declarations — these don't belong inside a body fragment
    # and some renderers treat a second DOCTYPE as starting a new document.
    html_str = re.sub(r'<!DOCTYPE[^>]*>', '', html_str, flags=re.IGNORECASE)
    # Remove <html>, <head>, <body> opening AND closing tags (preserve their
    # children). Outlook always wraps body content in a full document — we
    # want just the content. Use individual patterns rather than a loop so
    # the intent is greppable.
    html_str = re.sub(r'</?html\b[^>]*>', '', html_str, flags=re.IGNORECASE)
    html_str = re.sub(r'<head\b[^>]*>.*?</head>', '', html_str,
                      flags=re.IGNORECASE | re.DOTALL)
    # Catch unclosed <head> too, just in case
    html_str = re.sub(r'</?head\b[^>]*>', '', html_str, flags=re.IGNORECASE)
    html_str = re.sub(r'</?body\b[^>]*>', '', html_str, flags=re.IGNORECASE)

    # Remove script tags and content
    html_str = re.sub(r'<script\b[^>]*>.*?</script>', '', html_str,
                      flags=re.IGNORECASE | re.DOTALL)
    # Remove style tags that could contain expression() or url()
    html_str = re.sub(r'<style\b[^>]*>.*?</style>', '', html_str,
                      flags=re.IGNORECASE | re.DOTALL)
    # Remove iframe, object, embed, applet, form
    for tag in ('iframe', 'object', 'embed', 'applet', 'form'):
        html_str = re.sub(rf'<{tag}\b[^>]*>.*?</{tag}>', '', html_str,
                          flags=re.IGNORECASE | re.DOTALL)
        html_str = re.sub(rf'<{tag}\b[^>]*/?>', '', html_str, flags=re.IGNORECASE)
    # Strip <base> — would redirect relative resource loads to attacker host.
    # It's a void element (no closing tag), so only the opening pattern is needed.
    html_str = re.sub(r'<base\b[^>]*/?>', '', html_str, flags=re.IGNORECASE)
    # Strip <meta http-equiv="refresh"> which could redirect to file:// or external URLs
    html_str = re.sub(
        r'<meta\b[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*>',
        '', html_str, flags=re.IGNORECASE
    )
    # Remove event handler attributes (onclick, onload, onerror, etc.)
    html_str = re.sub(r'\son\w+\s*=\s*"[^"]*"', '', html_str, flags=re.IGNORECASE)
    html_str = re.sub(r"\son\w+\s*=\s*'[^']*'", '', html_str, flags=re.IGNORECASE)
    html_str = re.sub(r'\son\w+\s*=\s*[^\s>]+', '', html_str, flags=re.IGNORECASE)
    # Remove javascript: URLs
    html_str = re.sub(r'(href|src|action)\s*=\s*["\']?\s*javascript:[^"\'>\s]*["\']?',
                      r'\1="#"', html_str, flags=re.IGNORECASE)
    # Remove data: URLs in src/href that aren't safe raster images.
    # Allows png, jpeg, gif, webp, bmp. Blocks everything else including
    # data:image/svg+xml (SVG can contain inline scripts and external refs).
    html_str = re.sub(
        r'(href|src)\s*=\s*["\']data:(?!image/(?:png|jpe?g|gif|webp|bmp)\b)[^"\']*["\']',
        r'\1="#"', html_str, flags=re.IGNORECASE
    )
    # Block external image/resource loads to prevent tracking pixels and exfiltration
    # Replace src/href with http(s):// schemes
    html_str = re.sub(
        r'(src|href)\s*=\s*["\']https?://[^"\']*["\']',
        r'\1="#"', html_str, flags=re.IGNORECASE
    )
    # Block file:// scheme in src/href — prevents Edge from attempting local
    # file reads during PDF rendering (e.g. <img src="file:///etc/passwd">).
    # Even with --disable-features=NetworkService, file:// access is a separate
    # vector that needs explicit blocking.
    html_str = re.sub(
        r'(src|href)\s*=\s*["\']file://[^"\']*["\']',
        r'\1="#"', html_str, flags=re.IGNORECASE
    )
    # Block protocol-relative URLs and Windows UNC paths in src/href.
    # On Windows, when Edge renders our temp HTML via file://, a
    # protocol-relative URL like <img src="//evil.com/track.gif"> resolves
    # to an SMB share lookup. This is the classic Outlook NTLM-hash-leak
    # vector — the rendering machine would attempt to authenticate against
    # an attacker-controlled host. UNC paths (\\server\share\file) have
    # the same effect. Block both schemes.
    html_str = re.sub(
        r'(src|href)\s*=\s*["\']\s*//[^"\']*["\']',
        r'\1="#"', html_str, flags=re.IGNORECASE
    )
    html_str = re.sub(
        r'(src|href)\s*=\s*["\']\s*\\\\[^"\']*["\']',
        r'\1="#"', html_str, flags=re.IGNORECASE
    )
    # Block CSS url() with external refs in inline style attributes —
    # these can also load tracking pixels, e.g. style="background:url(http://tracker.com/x.gif)"
    html_str = re.sub(
        r'url\s*\(\s*["\']?\s*https?://[^)]*\)',
        'url("#")', html_str, flags=re.IGNORECASE
    )
    # Same for file:// inside CSS url()
    html_str = re.sub(
        r'url\s*\(\s*["\']?\s*file://[^)]*\)',
        'url("#")', html_str, flags=re.IGNORECASE
    )
    # Same for protocol-relative // inside CSS url() — same SMB hash-leak
    # vector as the src/href case above.
    html_str = re.sub(
        r'url\s*\(\s*["\']?\s*//[^)]*\)',
        'url("#")', html_str, flags=re.IGNORECASE
    )

    # Note on residual sanitiser surface: regex-based HTML sanitisation
    # cannot fully cover variants like tab-stripped scheme names
    # (`java\tscript:`) or entity-encoded schemes (`&#106;avascript:`).
    # These are mitigated by the `--disable-javascript` flag passed to Edge
    # in html_to_pdf(), so they don't represent an execution path. If JS
    # is ever re-enabled, this sanitiser must be replaced with a parser-
    # based one (bleach / lxml.html.clean).
    return html_str


# Mapping of image file extensions to MIME types for data URI generation.
# Only includes types Edge can render safely. SVG is intentionally excluded
# (can contain inline scripts/external refs).
_EXT_TO_MIME = {
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.bmp': 'image/bmp',
    '.webp': 'image/webp',
}


def _guess_image_mime(filename, data):
    """
    Determine MIME type for inline embedding.
    Prefers the file extension; falls back to magic-byte sniffing for safety.
    Returns None if the file isn't a recognised image type — caller should
    leave the cid: reference alone rather than embedding unknown bytes.
    """
    if not filename or not data:
        return None
    ext = os.path.splitext(filename.lower())[1]
    mime = _EXT_TO_MIME.get(ext)
    if mime:
        return mime
    # No extension or unknown — sniff magic bytes
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'image/png'
    if data.startswith(b'\xff\xd8\xff'):
        return 'image/jpeg'
    if data.startswith(b'GIF87a') or data.startswith(b'GIF89a'):
        return 'image/gif'
    if data.startswith(b'BM'):
        return 'image/bmp'
    if data.startswith(b'RIFF') and data[8:12] == b'WEBP':
        return 'image/webp'
    return None


# Reasonable upper bound on total inlined-image payload per email. Keeps PDFs
# from ballooning if an email has dozens of large embedded images. Each
# additional image above this threshold stays as cid: (and renders as a
# broken-image icon, signalling to the reader that something was clipped).
MAX_INLINE_IMAGE_TOTAL_BYTES = 30 * 1024 * 1024  # 30 MB combined


def inline_cid_images(html_str, attachments):
    """
    Replace cid: references in <img src="cid:..."> with inline data URIs
    sourced from the attachment list.

    Outlook stores inline images (logos, signatures, pasted screenshots) as
    separate attachments with a Content-ID (CID), referenced in the HTML body
    via src="cid:<id>". Browsers can't resolve cid: URLs — they need a real
    MIME source. By rewriting them to base64 data URIs, the rendered PDF
    shows the images as they appeared in Outlook.

    Matching is lenient:
      - The CID in the HTML may have an "@hostname" suffix (e.g.
        "image001.png@01D9.E8B4") that's not in the attachment's CID property
      - The CID is matched case-insensitively
      - The leading "cid:" prefix is stripped before comparison

    Non-image attachments and unknown formats are left as-is (the cid:
    reference will simply not render, which is acceptable).

    A total payload cap prevents PDF size explosion from many large images.

    Returns the rewritten HTML string.
    """
    if not html_str or not attachments:
        return html_str

    # Build a CID → (mime, base64_data) lookup. Lowercase the CID and strip
    # any "@hostname" suffix for tolerant matching against body references.
    cid_map = {}
    for att in attachments:
        # Skip embedded MSG markers and attachments without a CID
        if att.get('is_embedded_marker'):
            continue
        att_cid = (att.get('cid') or '').strip()
        if not att_cid:
            continue
        att_data = att.get('data')
        if not att_data:
            continue
        mime = _guess_image_mime(att.get('filename', ''), att_data)
        if not mime:
            continue  # not an image we can safely inline

        # Normalise the CID: lowercase, strip surrounding angle brackets if
        # any (some MAPI sources include them), strip the @hostname suffix.
        normalised = att_cid.lower().strip('<>').split('@')[0]
        if normalised:
            cid_map[normalised] = (mime, att_data)

    if not cid_map:
        return html_str

    # Track how much we've inlined so far so we can stop if we'd blow the cap
    inlined_total = [0]  # boxed so the inner closure can mutate

    import base64 as _b64

    def replace_cid(match):
        attr = match.group(1)  # 'src' or 'href'
        quote = match.group(2)  # quote char
        cid_value = match.group(3)
        # Match the same normalisation as cid_map keys
        normalised = cid_value.lower().strip('<>').split('@')[0]
        entry = cid_map.get(normalised)
        if not entry:
            # No matching attachment — leave the reference as-is so the
            # caller can see something was meant to be there.
            return match.group(0)
        mime, data = entry
        if inlined_total[0] + len(data) > MAX_INLINE_IMAGE_TOTAL_BYTES:
            # Hit the per-email inline cap; leave subsequent CIDs unresolved
            return match.group(0)
        inlined_total[0] += len(data)
        try:
            b64 = _b64.b64encode(data).decode('ascii')
        except Exception:
            return match.group(0)
        return f'{attr}={quote}data:{mime};base64,{b64}{quote}'

    # Match src="cid:..." or src='cid:...' (case-insensitive). Tolerate
    # whitespace around the equals sign.
    html_str = re.sub(
        r'(src|href)\s*=\s*(["\'])cid:([^"\']+)\2',
        replace_cid, html_str, flags=re.IGNORECASE
    )

    return html_str


# ============================================================
# MSG Reader using olefile — handles null bytes properly
# ============================================================

def read_msg_property(ole, stream_path):
    """
    Read a Unicode (PT_UNICODE) string property from the MSG file.
    Returns "" if unreadable or wrong encoding (rather than guessing,
    which could silently corrupt the output text).
    """
    try:
        if ole.exists(stream_path):
            data = ole.openstream(stream_path).read()
            # Unicode MAPI strings (001F suffix) are always UTF-16-LE.
            # If decode fails, the property is malformed — return empty
            # rather than guessing with another codec.
            try:
                text = data.decode('utf-16-le')
            except (UnicodeDecodeError, ValueError):
                return ""
            # Strip null characters (UTF-16 string terminator)
            return text.replace('\x00', '').strip()
    except Exception:
        pass
    return ""


def read_msg_binary(ole, stream_path):
    """Read binary data from the MSG file."""
    try:
        if ole.exists(stream_path):
            return ole.openstream(stream_path).read()
    except Exception:
        pass
    return None


def read_internet_cpid(ole):
    """
    Read PR_INTERNET_CPID (0x3FDE0003) — the codepage MAPI uses for
    PT_BINARY string streams (notably the HTML body when stored as 0x10130102).
    Returns codepage as int, or None if not present/readable.

    Reads from the top-level __properties_version1.0 stream. Property type
    PT_LONG (0x0003) values are stored INLINE in the property entry (8 bytes
    after the tag), unlike string properties.

    Uses ONLY the MS-OXMSG spec-mandated header_size of 32 for the top-level
    properties stream. Earlier versions tried multiple sizes (32, 24, 28, 36)
    as defensive fallbacks, but that creates a silent-corruption vector:
    junk bytes at the wrong offset can coincidentally match the CPID tag and
    return a wrong codepage with no error indication. For a single
    authoritative property like CPID, the spec-compliant offset is the only
    safe choice. The fallback is to return None and let the caller fall
    through to meta charset / cp1252 / utf-8 detection.
    """
    try:
        if not ole.exists('__properties_version1.0'):
            return None
        props_data = ole.openstream('__properties_version1.0').read()
    except Exception:
        return None

    # MS-OXMSG: top-level message properties stream has a 32-byte header.
    offset = 32
    while offset + 16 <= len(props_data):
        try:
            prop_tag = struct.unpack_from('<I', props_data, offset)[0]
            if prop_tag == 0x3FDE0003:  # PR_INTERNET_CPID, PT_LONG
                cpid = struct.unpack_from('<I', props_data, offset + 8)[0]
                if 1 <= cpid < 65536:
                    return cpid
        except struct.error:
            break
        offset += 16
    return None


# Mapping of common Windows codepage IDs to Python codec names.
# Covers the codepages that show up in real-world Outlook MSG files.
CPID_TO_CODEC = {
    1252: 'cp1252',           # Windows Western European (most common in EN Outlook)
    1250: 'cp1250',           # Windows Central European
    1251: 'cp1251',           # Windows Cyrillic
    1253: 'cp1253',           # Windows Greek
    1254: 'cp1254',           # Windows Turkish
    1255: 'cp1255',           # Windows Hebrew
    1256: 'cp1256',           # Windows Arabic
    1257: 'cp1257',           # Windows Baltic
    1258: 'cp1258',           # Windows Vietnamese
    932: 'shift_jis',         # Japanese
    936: 'gbk',               # Chinese Simplified
    949: 'cp949',             # Korean
    950: 'big5',              # Chinese Traditional
    65001: 'utf-8',           # UTF-8
    1200: 'utf-16-le',        # UTF-16 LE
    20127: 'ascii',           # US-ASCII
    28591: 'iso-8859-1',      # ISO Latin-1
    28592: 'iso-8859-2',
    28599: 'iso-8859-9',
    28605: 'iso-8859-15',
}


def decode_html_body_bytes(ole, html_bytes):
    """
    Decode PT_BINARY HTML body bytes using the correct codepage.

    Resolution order:
      1. PR_INTERNET_CPID property (the authoritative MAPI codepage)
      2. <meta charset="..."> in the first 4KB of the body
      3. Windows-1252 (the most common Outlook default)
      4. UTF-8 with errors='replace' (last-ditch)

    Always returns a str, never None (uses errors='replace' as final fallback).
    """
    # Method 1: PR_INTERNET_CPID
    cpid = read_internet_cpid(ole)
    if cpid is not None:
        codec = CPID_TO_CODEC.get(cpid)
        if codec is None:
            # Try the raw "cpNNNN" name — covers many less common codepages
            codec = f'cp{cpid}'
        try:
            return html_bytes.decode(codec)
        except (UnicodeDecodeError, LookupError):
            pass  # fall through

    # Method 2: <meta charset="..."> declared in the HTML
    # Only scan the first 4KB to avoid scanning very large bodies
    head = html_bytes[:4096]
    # Try a few common forms — be lenient about quoting and whitespace
    for pattern in (
        rb'<meta[^>]+charset\s*=\s*["\']?\s*([A-Za-z0-9_\-]+)',
        rb'<meta[^>]+content\s*=\s*["\'][^"\']*charset\s*=\s*([A-Za-z0-9_\-]+)',
    ):
        m = re.search(pattern, head, re.IGNORECASE)
        if m:
            declared = m.group(1).decode('ascii', errors='replace').lower()
            # Normalise common aliases
            alias = {
                'utf8': 'utf-8',
                'utf16': 'utf-16',
                'iso88591': 'iso-8859-1',
                'iso885915': 'iso-8859-15',
                'windows1252': 'cp1252',
            }.get(declared.replace('-', '').replace('_', ''), declared)
            try:
                return html_bytes.decode(alias)
            except (UnicodeDecodeError, LookupError):
                pass

    # Method 3: Windows-1252 — most common Outlook default for English-language
    # corporate environments. Almost every byte is valid in cp1252, so this
    # rarely throws.
    try:
        return html_bytes.decode('cp1252')
    except UnicodeDecodeError:
        pass

    # Method 4: UTF-8 with replacement as last resort
    return html_bytes.decode('utf-8', errors='replace')


def filetime_to_datetime(filetime_val):
    """Convert Windows FILETIME to Python datetime in configured output timezone."""
    if filetime_val <= 0:
        return None
    try:
        timestamp = (filetime_val - 116444736000000000) / 10000000
        if timestamp < 0 or timestamp > 4102444800:  # before 1970 or after 2100
            return None
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.astimezone(OUTPUT_TZ)
    except (OSError, ValueError, OverflowError):
        return None


def read_msg_date(ole):
    """Extract the sent date from MSG properties — tries multiple sources."""

    # Method 1: Check binary date streams directly
    # PR_MESSAGE_DELIVERY_TIME first — this is what Outlook displays
    date_streams = [
        '__substg1.0_0E060040',  # PR_MESSAGE_DELIVERY_TIME (Outlook uses this)
        '__substg1.0_00390040',  # PR_CLIENT_SUBMIT_TIME
        '__substg1.0_30070040',  # PR_CREATION_TIME
    ]
    for stream in date_streams:
        try:
            if ole.exists(stream):
                data = ole.openstream(stream).read()
                if len(data) == 8:
                    filetime = struct.unpack('<Q', data)[0]
                    dt = filetime_to_datetime(filetime)
                    if dt:
                        return dt
        except Exception:
            pass

    # Method 2: Scan the properties stream for any date property
    # Ordered by priority — delivery time first (matches Outlook)
    date_tags_priority = [
        0x0E060040,  # PR_MESSAGE_DELIVERY_TIME (Outlook uses this)
        0x00390040,  # PR_CLIENT_SUBMIT_TIME
        0x30070040,  # PR_CREATION_TIME
        0x30080040,  # PR_LAST_MODIFICATION_TIME
        0x00060040,  # PR_CREATION_TIME (alt)
    ]

    try:
        if ole.exists('__properties_version1.0'):
            props_data = ole.openstream('__properties_version1.0').read()
            # MS-OXMSG: top-level message properties stream has a 32-byte
            # header. Earlier versions tried multiple sizes (32, 24, 28, 36)
            # as defensive fallbacks, but that creates a silent-corruption
            # surface: junk bytes at the wrong offset can coincidentally
            # match a date property tag AND have the following 8 bytes parse
            # as a valid filetime, returning a WRONG date with no error
            # indication. A silently-misdated email is materially worse than
            # falling through to the transport-headers Date: line. Restrict
            # to the spec offset only (same fix already applied to
            # read_internet_cpid).
            all_found = {}
            offset = 32
            while offset + 16 <= len(props_data):
                prop_tag = struct.unpack_from('<I', props_data, offset)[0]
                if prop_tag in date_tags_priority:
                    filetime = struct.unpack_from('<Q', props_data, offset + 8)[0]
                    dt = filetime_to_datetime(filetime)
                    if dt and prop_tag not in all_found:
                        all_found[prop_tag] = dt
                offset += 16
            # Apply priority across the result set
            for tag in date_tags_priority:
                if tag in all_found:
                    return all_found[tag]
    except Exception:
        pass

    # Method 3: Fallback to transport headers Date: field
    headers = read_msg_property(ole, '__substg1.0_007D001F')
    if headers:
        for line in headers.split('\n'):
            line = line.strip()
            if line.lower().startswith('date:'):
                date_str = line[5:].strip()
                try:
                    dt = parsedate_to_datetime(date_str)
                    return dt.astimezone(OUTPUT_TZ)
                except Exception:
                    pass

    return None


def parse_msg(msg_path):
    """Parse a .msg file and return its components."""
    ole = olefile.OleFileIO(msg_path)

    try:
        # Read basic properties (001F = Unicode string property type)
        subject = read_msg_property(ole, '__substg1.0_0037001F')

        # Sender — get display name and email from MAPI properties
        sender_name = read_msg_property(ole, '__substg1.0_0C1A001F')
        # If sender name is missing or looks like an email, try the "on behalf of" name
        if not sender_name or '@' in sender_name:
            representing_name = read_msg_property(ole, '__substg1.0_0042001F')  # PR_SENT_REPRESENTING_NAME
            if representing_name and '@' not in representing_name:
                sender_name = representing_name
        sender_email = read_msg_property(ole, '__substg1.0_0065001F')
        if not sender_email:
            sender_email = read_msg_property(ole, '__substg1.0_0C1F001F')
        if not sender_email:
            sender_email = read_msg_property(ole, '__substg1.0_5D01001F')
        if not sender_email:
            sender_email = read_msg_property(ole, '__substg1.0_5D02001F')

        # Build sender display
        if sender_name and sender_email and sender_name != sender_email:
            sender = f"{sender_name} <{sender_email}>"
        elif sender_email:
            sender = sender_email
        elif sender_name:
            sender = sender_name
        else:
            sender = "Unknown"

        # Recipients — try MAPI display properties first
        to_field = read_msg_property(ole, '__substg1.0_0E04001F') or ""
        cc_field = read_msg_property(ole, '__substg1.0_0E03001F') or ""
        bcc_field = read_msg_property(ole, '__substg1.0_0E02001F') or ""

        # Try to enrich with email addresses from recipient table
        to_parts = []
        cc_parts = []
        bcc_parts = []
        all_entries = ['/'.join(e) for e in ole.listdir(streams=True, storages=True)]

        # Scan for all recipient storage prefixes in advance — handles gaps
        # in numbering (e.g. #00000000 and #00000002 with #00000001 missing).
        # The MSG spec doesn't guarantee sequential numbering.
        recip_prefix_pattern = re.compile(
            r'^(__recip_version1\.0_#[0-9A-Fa-f]{8})/', re.IGNORECASE
        )
        recip_prefixes = set()
        for entry in all_entries:
            m = recip_prefix_pattern.match(entry)
            if m:
                recip_prefixes.add(m.group(1))
        # Sort hex-numerically for deterministic output
        sorted_recip_prefixes = sorted(recip_prefixes)[:MAX_RECIPIENTS]

        for prefix in sorted_recip_prefixes:
            recip_name = read_msg_property(ole, f'{prefix}/__substg1.0_3001001F')
            recip_email = read_msg_property(ole, f'{prefix}/__substg1.0_39FE001F')
            if not recip_email:
                recip_email = read_msg_property(ole, f'{prefix}/__substg1.0_3003001F')

            if recip_name and recip_email and recip_name != recip_email:
                recip_display = f"{recip_name} <{recip_email}>"
            elif recip_email:
                recip_display = recip_email
            elif recip_name:
                recip_display = recip_name
            else:
                continue

            # Recipient type: 1=To, 2=CC
            # Recipient property streams have either an 8-byte or 24-byte header
            # depending on MSG version. Try both starting offsets.
            recip_type = 1
            try:
                recip_props_path = f'{prefix}/__properties_version1.0'
                if ole.exists(recip_props_path):
                    rp_data = ole.openstream(recip_props_path).read()
                    found = False
                    for start_off in (8, 24):
                        off = start_off
                        while off + 16 <= len(rp_data):
                            ptag = struct.unpack_from('<I', rp_data, off)[0]
                            if ptag == 0x0C150003:  # PR_RECIPIENT_TYPE
                                val = struct.unpack_from('<I', rp_data, off + 8)[0]
                                # Sanity-check: valid recipient types are 1-3
                                if val in (1, 2, 3):
                                    recip_type = val
                                    found = True
                                    break
                            off += 16
                        if found:
                            break
            except Exception:
                pass

            # Route by recipient type (1=To, 2=CC, 3=BCC). Anything unexpected
            # falls back to To since that's what Outlook does for unknown types.
            if recip_type == 2:
                cc_parts.append(recip_display)
            elif recip_type == 3:
                bcc_parts.append(recip_display)
            else:
                to_parts.append(recip_display)

        # Use recipient table results if they have email addresses, otherwise keep MAPI display
        if to_parts and any('@' in p for p in to_parts):
            to_field = '; '.join(to_parts)
        if cc_parts and any('@' in p for p in cc_parts):
            cc_field = '; '.join(cc_parts)
        if bcc_parts and any('@' in p for p in bcc_parts):
            bcc_field = '; '.join(bcc_parts)
        elif bcc_parts and not bcc_field:
            # Even without email addresses, surface the BCC display names so
            # they don't silently disappear.
            bcc_field = '; '.join(bcc_parts)

        # Last resort: try transport headers for From/To enrichment
        headers = read_msg_property(ole, '__substg1.0_007D001F')
        if headers:
            from_match = re.search(r'^From:\s*(.+?)(?:\n(?![ \t])|\Z)', headers, re.MULTILINE | re.DOTALL)
            if from_match:
                hdr_from = re.sub(r'\s+', ' ', from_match.group(1)).strip()
                if '@' in hdr_from and '@' not in sender:
                    sender = hdr_from
            to_match = re.search(r'^To:\s*(.+?)(?:\n(?![ \t])|\Z)', headers, re.MULTILINE | re.DOTALL)
            if to_match:
                hdr_to = re.sub(r'\s+', ' ', to_match.group(1)).strip()
                if '@' in hdr_to and '@' not in to_field:
                    to_field = hdr_to

        # Get date
        sent_date = read_msg_date(ole)

        # Body — try HTML first, then plain text
        # Two streams may contain the HTML body:
        #   __substg1.0_1013001F : PT_UNICODE (UTF-16-LE per MAPI spec)
        #   __substg1.0_10130102 : PT_BINARY (raw bytes in originator's codepage)
        # The previous version of this script decoded both as UTF-8, which
        # corrupts non-ASCII text (smart quotes, em dashes, accented chars
        # very common in Outlook output).
        html_body_str = None

        # Method A: PT_UNICODE stream (preferred; decoded by read_msg_property
        # which knows UTF-16-LE).
        html_body_str = read_msg_property(ole, '__substg1.0_1013001F') or None

        # Method B: PT_BINARY stream — need to figure out the codepage
        if not html_body_str:
            html_body = read_msg_binary(ole, '__substg1.0_10130102')

            # Cap HTML body size before any processing — prevents OOM and ReDoS
            # exposure from a maliciously huge body. Falls through to plain text.
            if html_body and len(html_body) > MAX_HTML_BODY_SIZE:
                print(f"  Skipping oversized HTML body: "
                      f"{len(html_body) // (1024*1024)} MB > "
                      f"{MAX_HTML_BODY_SIZE // (1024*1024)} MB limit "
                      f"(falling back to plain text)")
                html_body = None

            if html_body:
                html_body_str = decode_html_body_bytes(ole, html_body)

        plain_body = read_msg_property(ole, '__substg1.0_1000001F')

        # Strip null characters that might have survived the decode
        if html_body_str:
            html_body_str = html_body_str.replace('\x00', '')

        # Extract attachments — find all attachment storages
        # Scan for all attachment prefixes in advance — handles gaps in numbering.
        attachments = []
        att_prefix_pattern = re.compile(
            r'^(__attach_version1\.0_#[0-9A-Fa-f]{8})/', re.IGNORECASE
        )
        att_prefixes = set()
        for entry in all_entries:
            m = att_prefix_pattern.match(entry)
            if m:
                att_prefixes.add(m.group(1))
        sorted_att_prefixes = sorted(att_prefixes)[:MAX_ATTACHMENTS]

        for i, prefix in enumerate(sorted_att_prefixes):
            # Get attachment filename
            att_long = read_msg_property(ole, f'{prefix}/__substg1.0_3707001F')
            att_short = read_msg_property(ole, f'{prefix}/__substg1.0_3704001F')
            att_filename = att_long or att_short or f"attachment_{i}"

            # Detect embedded MSG attachments (PR_ATTACH_METHOD = 5).
            # These are stored as a sub-storage at __substg1.0_3701000D rather
            # than as binary data at __substg1.0_37010102. Previous versions
            # of this script silently dropped them — forwarded-as-attachment
            # emails can be the most important content in a chain, so we
            # surface them with a marker file instead.
            embedded_msg_storage = f'{prefix}/__substg1.0_3701000D'
            is_embedded_msg = any(
                e.startswith(embedded_msg_storage + '/') or e == embedded_msg_storage
                for e in all_entries
            )

            if is_embedded_msg:
                # Try to read the embedded message's subject/sender for a
                # useful warning. Fall back to filename if unreadable.
                try:
                    inner_subject = read_msg_property(
                        ole, f'{embedded_msg_storage}/__substg1.0_0037001F'
                    )
                    inner_sender = read_msg_property(
                        ole, f'{embedded_msg_storage}/__substg1.0_0C1A001F'
                    )
                except Exception:
                    inner_subject = None
                    inner_sender = None

                # Build a readable label. Prefer the embedded message's own
                # subject/sender; fall back to the parent's att_filename.
                label_parts = []
                if inner_subject:
                    label_parts.append(f'subject="{inner_subject}"')
                if inner_sender:
                    label_parts.append(f'from="{inner_sender}"')
                if not label_parts:
                    label_parts.append(f'filename="{att_filename}"')
                inner_desc = ', '.join(label_parts)

                print(f"    NOTE: Embedded email attachment detected "
                      f"({inner_desc}). Saving as .msg.embedded marker file. "
                      f"To convert this embedded email to PDF, open the parent "
                      f"email in Outlook and save the attachment as a separate "
                      f".msg file, then re-run this script on that file.")

                # Save a small marker file so the user can see the embedded
                # email exists in the output and knows to handle it manually.
                # We don't reconstruct the full embedded MSG (which would
                # require rebuilding the OLE structure) — instead we record
                # what we know and let the manifest preserve provenance.
                marker_filename = att_filename
                if not marker_filename.lower().endswith('.msg'):
                    marker_filename = f"{att_filename}.msg.embedded.txt"
                else:
                    marker_filename = f"{att_filename}.embedded.txt"

                marker_content = (
                    "Embedded email attachment (could not be auto-extracted)\n"
                    "=" * 60 + "\n\n"
                    f"Parent email subject: {subject or '(unknown)'}\n"
                    f"Embedded email subject: {inner_subject or '(unknown)'}\n"
                    f"Embedded email sender: {inner_sender or '(unknown)'}\n\n"
                    "To extract this embedded email:\n"
                    "  1. Open the parent .msg file in Outlook\n"
                    "  2. Drag the embedded email attachment to your desktop "
                    "as a .msg file\n"
                    "  3. Run this script on the extracted .msg file\n"
                ).encode('utf-8')

                attachments.append({
                    'filename': marker_filename,
                    'data': marker_content,
                    'cid': '',
                    'size': len(marker_content),
                    'is_embedded_marker': True,
                })
                continue

            # Standard attachment: get binary data
            att_data = read_msg_binary(ole, f'{prefix}/__substg1.0_37010102')

            # Get content ID (for inline image detection)
            att_cid = read_msg_property(ole, f'{prefix}/__substg1.0_3712001F')

            if att_data:
                # Enforce size cap
                if len(att_data) > MAX_ATTACHMENT_SIZE:
                    print(f"    Skipping oversized attachment: {att_filename} "
                          f"({len(att_data) // (1024*1024)} MB > "
                          f"{MAX_ATTACHMENT_SIZE // (1024*1024)} MB limit)")
                else:
                    attachments.append({
                        'filename': att_filename,
                        'data': att_data,
                        'cid': att_cid,
                        'size': len(att_data),
                    })
            else:
                # No data found AND not an embedded MSG — flag this so the
                # user knows the attachment couldn't be extracted (rather
                # than silently dropping it like before).
                print(f"    WARNING: Could not extract data for attachment "
                      f"'{att_filename}'. The attachment may use an "
                      f"unsupported method (e.g. OLE-linked). Skipping.")

        return {
            'subject': subject,
            'sender': sender,
            'to': to_field,
            'cc': cc_field,
            'bcc': bcc_field,
            'date': sent_date,
            'html_body': html_body_str,
            'plain_body': plain_body,
            'attachments': attachments,
        }

    finally:
        ole.close()


def is_real_attachment(att):
    """
    Filter out inline signature images (Content-ID present + small size).
    Only the Content-ID rule is reliable — using filename patterns alone
    would discard legitimate small attachments named "image2024.png" etc.
    Embedded-MSG marker files are always kept.
    """
    if att.get('is_embedded_marker'):
        return True

    filename = att['filename'].lower()
    is_image = filename.endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'))

    if is_image and att['cid'] and att['size'] < 50000:
        # Has a Content-ID (marker for inline embedding) AND is small =
        # almost certainly a signature/inline image, not a real attachment
        return False

    return True


def build_email_html(msg_data, attachment_display_list=None):
    """
    Build an HTML representation of the email matching the "classic" Outlook
    print format — the layout produced when File > Print is used in Outlook.

    Format characteristics:
      - No logo or branding at the top
      - Bold field labels with colons: "From:", "Sent:", "To:", "Cc:",
        "Subject:", "Attachments:"
      - Full weekday + full date + 12-hour AM/PM time
        (e.g. "Thursday, 16 December 2021 9:52 AM")
      - Attachments listed inline in the header table, semicolon-separated
      - Horizontal rule under the header block
      - Body content rendered with original formatting

    attachment_display_list: optional list of (filename, size_bytes) tuples.
        Sizes are unused (classic format doesn't show them) but kept in the
        signature for compatibility.
    """
    # Escape header fields to prevent injection into the template
    sender = html_module.escape(msg_data['sender'] or "Unknown")
    to = html_module.escape(msg_data['to'] or "")
    cc = html_module.escape(msg_data['cc'] or "")
    bcc = html_module.escape(msg_data.get('bcc') or "")
    subject = html_module.escape(msg_data['subject'] or "No Subject")

    if msg_data['date']:
        # Match classic Outlook print: "Thursday, 16 December 2021 9:52 AM"
        # Full weekday, day (no leading zero), full month name, year, 12-hour
        # time with AM/PM.
        # strftime always pads %d with a leading zero, so strip it manually
        # for the day-of-month value to match Outlook's output exactly.
        raw = msg_data['date'].strftime('%A, %d %B %Y %I:%M %p')
        # Strip leading zero from day-of-month: "Thursday, 06 December..." -> "Thursday, 6 December..."
        raw = re.sub(r'^(\w+), 0(\d )', r'\1, \2', raw)
        # Strip leading zero from hour: "9:52 AM" not "09:52 AM"
        raw = re.sub(r' 0(\d:)', r' \1', raw)
        date_display = html_module.escape(raw)
    else:
        date_display = ""

    # Use HTML body if available — but first inline cid: image references
    # (Outlook stores inline images as separate attachments referenced by
    # Content-ID), then sanitise to strip scripts and external resource
    # references. Plain text gets fully escaped.
    if msg_data['html_body']:
        body_html = msg_data['html_body']
        # Inline cid: references using the attachment data. This must happen
        # BEFORE sanitisation because the sanitiser blocks any data: URI
        # whose MIME type isn't a recognised raster image — but the inliner
        # only produces those types, so its output is sanitiser-safe.
        attachments = msg_data.get('attachments') or []
        body_html = inline_cid_images(body_html, attachments)
        body = sanitize_html_body(body_html)
    elif msg_data['plain_body']:
        body_text = html_module.escape(msg_data['plain_body'])
        body_text = body_text.replace('\n', '<br>\n')
        body = f"<div style='font-family: Calibri, Arial, sans-serif; font-size: 11pt;'>{body_text}</div>"
    else:
        body = "<p>(No content)</p>"

    # Header rows — classic Outlook print format. Labels are bold with colons.
    def row(label, value):
        return (f'<tr><td class="hdr-label">{label}:</td>'
                f'<td class="hdr-value">{value}</td></tr>')

    rows = [
        row("From", sender),
        row("Sent", date_display),
        row("To", to),
    ]
    if cc:
        rows.append(row("Cc", cc))
    if bcc:
        rows.append(row("Bcc", bcc))
    rows.append(row("Subject", subject))

    # Attachments listed inline in the header table, semicolon-separated
    if attachment_display_list:
        filenames = "; ".join(
            html_module.escape(fn) for fn, _ in attachment_display_list
        )
        rows.append(row("Attachments", filenames))

    header_rows = "\n    ".join(rows)

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'">
<style>
    body {{
        font-family: Calibri, Arial, sans-serif;
        margin: 40px 32px 32px 32px;
        color: #000;
        font-size: 11pt;
    }}
    .header-table {{
        border-collapse: collapse;
        margin-bottom: 14px;
        width: 100%;
    }}
    .header-table td {{
        padding: 1px 0;
        font-size: 10.5pt;
        vertical-align: top;
    }}
    .hdr-label {{
        font-weight: 700;
        padding-right: 24px;
        white-space: nowrap;
        min-width: 100px;
    }}
    .hdr-value {{
        color: #000;
        word-break: break-word;
    }}
    .header-divider {{
        border: none;
        border-top: 1px solid #000;
        margin: 0 0 14px 0;
    }}
    .header-divider-top {{
        border: none;
        border-top: 1.5px solid #000;
        margin: 0 0 10px 0;
    }}
    .body-container {{
        margin-top: 0;
    }}
</style>
</head>
<body>
<hr class="header-divider-top">
<table class="header-table">
    {header_rows}
</table>
<hr class="header-divider">
<div class="body-container">
{body}
</div>
</body>
</html>"""
    return html


def find_msg_files(folder):
    """Recursively find all .msg files in folder and subfolders."""
    msg_files = []
    for root, dirs, files in os.walk(folder):
        for f in files:
            if f.lower().endswith('.msg'):
                msg_files.append(os.path.join(root, f))
    msg_files.sort()
    return msg_files


def load_done_log():
    if os.path.exists(DONE_LOG):
        try:
            with open(DONE_LOG, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Validate structure — must be a list of strings
                if isinstance(data, list) and all(isinstance(x, str) for x in data):
                    return set(data)
                else:
                    print("  Warning: progress log is malformed, ignoring")
                    return set()
        except Exception:
            return set()
    return set()


def save_done_log(done_set):
    try:
        with open(DONE_LOG, 'w', encoding='utf-8') as f:
            json.dump(sorted(done_set), f, indent=2)
    except Exception as e:
        print(f"  Warning: could not save progress log: {e}")


def main():
    if not os.path.isdir(MSG_FOLDER):
        print(f"ERROR: MSG_FOLDER does not exist: {MSG_FOLDER}")
        print("Edit the CONFIG section at the top of this script.")
        sys.exit(1)

    for d in [OUTPUT_FILES_DIR, HTML_TEMP]:
        os.makedirs(d, exist_ok=True)

    msg_files = find_msg_files(MSG_FOLDER)
    total = len(msg_files)
    if total == 0:
        print(f"No .msg files found in {MSG_FOLDER}")
        sys.exit(0)
    print(f"Found {total} .msg files in {MSG_FOLDER}")

    done = load_done_log()
    if done:
        print(f"Resume log found: {len(done)} already processed")

    edge_exe = None
    if CONVERT_TO_PDF:
        edge_exe = find_edge()
        if edge_exe:
            print(f"Edge found: {edge_exe}")
            print("Emails will be saved as PDF")
        else:
            print("Edge not found — emails will be saved as HTML instead")

    print("=" * 60)

    exported = 0
    skipped = 0
    errors = 0
    start = time.time()

    try:
        for i, msg_path in enumerate(msg_files, 1):
            if msg_path in done:
                skipped += 1
                continue

            # Size check before parsing — prevent oversized files from being loaded
            try:
                file_size = os.path.getsize(msg_path)
                if file_size > MAX_MSG_FILE_SIZE:
                    print(f"  [{i}/{total}] SKIPPED (too large: {file_size // (1024*1024)} MB): "
                          f"{os.path.basename(msg_path)}")
                    errors += 1
                    continue
                if file_size == 0:
                    print(f"  [{i}/{total}] SKIPPED (empty file): {os.path.basename(msg_path)}")
                    errors += 1
                    continue
            except Exception as e:
                print(f"  [{i}/{total}] ERROR checking size: {e}")
                errors += 1
                continue

            try:
                # Hash the source MSG once — used in every manifest row for this email
                source_msg_sha256 = sha256_file(msg_path) or ""
                timestamp_utc = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

                msg_data = parse_msg(msg_path)

                # Date string for filename
                if msg_data['date']:
                    dt = msg_data['date']
                    date_str = f"{dt.year:04d}{dt.month:02d}{dt.day:02d}"
                else:
                    date_str = "00000000"

                raw_subject = msg_data['subject'] or "No Subject"

                # Build email filename using the truncate-with-hash builder
                email_pdf_name = build_email_filename(date_str, raw_subject, "pdf")
                email_html_name = build_email_filename(date_str, raw_subject, "html")

                # --- Save email as HTML then convert to PDF ---
                # Build the attachment display list for the email body — shows what
                # was attached, matching how Outlook prints a saved email. Uses
                # the raw attachment list (before is_real_attachment filtering)
                # so inline signature images don't show, but excludes embedded
                # MSG marker files (those are notes for the user, not attachments).
                attach_display = [
                    (a['filename'], a['size'])
                    for a in msg_data['attachments']
                    if is_real_attachment(a) and not a.get('is_embedded_marker')
                ]
                email_html = build_email_html(msg_data, attach_display)
                html_file = unique_path(HTML_TEMP, email_html_name)
                if html_file is None:
                    print(f"  [{i}/{total}] ERROR: unsafe filename for {os.path.basename(msg_path)}")
                    errors += 1
                    continue

                with open(html_file, 'w', encoding='utf-8') as f:
                    f.write(email_html)

                output_email_path = None
                output_email_type = None

                if CONVERT_TO_PDF and edge_exe:
                    pdf_file = unique_path(OUTPUT_FILES_DIR, email_pdf_name)
                    if pdf_file is None:
                        print(f"  [{i}/{total}] ERROR: unsafe pdf path for {os.path.basename(msg_path)}")
                        clean_html_temp(html_file)
                        errors += 1
                        continue

                    success = html_to_pdf(html_file, pdf_file, edge_exe)

                    if not success:
                        fallback = unique_path(OUTPUT_FILES_DIR, email_html_name)
                        if fallback is not None:
                            try:
                                shutil.move(html_file, fallback)
                                print(f"  [{i}/{total}] PDF failed, saved HTML: {os.path.basename(fallback)}")
                                output_email_path = fallback
                                output_email_type = 'email_html'
                            except Exception as e:
                                print(f"  [{i}/{total}] PDF failed and HTML save failed: {e}")
                                clean_html_temp(html_file)
                                errors += 1
                                continue
                        else:
                            clean_html_temp(html_file)
                            errors += 1
                            continue
                    else:
                        clean_html_temp(html_file)
                        output_email_path = pdf_file
                        output_email_type = 'email_pdf'
                else:
                    final_html = unique_path(OUTPUT_FILES_DIR, email_html_name)
                    if final_html is None:
                        clean_html_temp(html_file)
                        errors += 1
                        continue
                    shutil.move(html_file, final_html)
                    output_email_path = final_html
                    output_email_type = 'email_html'

                # Record email output in manifest
                if output_email_path:
                    try:
                        out_size = os.path.getsize(output_email_path)
                        out_sha = sha256_file(output_email_path) or ""
                        append_manifest_row({
                            'timestamp_utc': timestamp_utc,
                            'source_msg_path': msg_path,
                            'source_msg_sha256': source_msg_sha256,
                            'output_path': output_email_path,
                            'output_type': output_email_type,
                            'output_size': out_size,
                            'output_sha256': out_sha,
                        })
                    except Exception as e:
                        print(f"  [{i}/{total}] Warning: manifest write failed for email: {e}")

                # --- Save attachments ---
                # Use enumerate(start=1) to give each attachment a 1-based number.
                # Skipped (signature) attachments don't get a number, so the
                # numbering reflects ORDER OF SAVED attachments. If you'd rather
                # the numbers reflect order in the original email (including
                # skipped sigs), change `enumerate(saved_atts, start=1)` to use
                # the original index from msg_data['attachments'].
                saved_atts = [a for a in msg_data['attachments'] if is_real_attachment(a)]
                for att_idx, att in enumerate(saved_atts, start=1):
                    att_name = build_attachment_filename(
                        date_str, raw_subject, att_idx, att['filename']
                    )
                    att_path = unique_path(OUTPUT_FILES_DIR, att_name)
                    if att_path is None:
                        print(f"  [{i}/{total}] WARNING: unsafe attachment filename skipped: "
                              f"{att['filename']}")
                        continue

                    try:
                        with open(att_path, 'wb') as f:
                            f.write(att['data'])
                        # Record attachment in manifest
                        try:
                            append_manifest_row({
                                'timestamp_utc': timestamp_utc,
                                'source_msg_path': msg_path,
                                'source_msg_sha256': source_msg_sha256,
                                'output_path': att_path,
                                'output_type': 'attachment',
                                'output_size': len(att['data']),
                                'output_sha256': sha256_bytes(att['data']) or "",
                            })
                        except Exception as e:
                            print(f"  [{i}/{total}] Warning: manifest write failed for attachment: {e}")
                    except Exception as e:
                        print(f"  [{i}/{total}] WARNING: could not save attachment "
                              f"{att['filename']}: {e}")

                done.add(msg_path)
                exported += 1
                if exported % 10 == 0 or exported < 5:
                    print(f"  [{i}/{total}] {os.path.splitext(email_pdf_name)[0]}")

                if exported % 50 == 0:
                    save_done_log(done)

            except Exception as e:
                errors += 1
                print(f"  [{i}/{total}] ERROR processing {os.path.basename(msg_path)}: {e}")

    finally:
        # Always save progress and clean up temp dirs, even on crash/Ctrl+C
        save_done_log(done)
        for temp_dir in [HTML_TEMP, EDGE_TEMP_PROFILE]:
            try:
                if os.path.isdir(temp_dir):
                    shutil.rmtree(temp_dir)
            except Exception:
                pass

    elapsed = time.time() - start

    print("\n" + "=" * 60)
    print(f"Done in {elapsed:.0f}s")
    print(f"  Exported:     {exported}")
    print(f"  Skipped:      {skipped} (already existed)")
    print(f"  Errors:       {errors}")
    print(f"  Output:       {OUTPUT_FILES_DIR}")
    if os.path.exists(MANIFEST_CSV):
        print(f"  Manifest:     {MANIFEST_CSV}")


if __name__ == "__main__":
    main()
