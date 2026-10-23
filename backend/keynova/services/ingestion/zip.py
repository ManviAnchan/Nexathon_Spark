import os
import zipfile
from pathlib import Path

MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_FILES = 10000
MAX_RATIO = 100

class ZipSlipSecurityError(Exception):
    pass

class DecompressionBombError(Exception):
    pass

def safe_extract_zip(zip_path: Path, target_dir: Path) -> int:
    """
    Safely extracts a ZIP archive into target_dir with Zip-Slip path validation
    and decompression bomb safeguards.
    Returns the number of extracted files.
    """
    target_dir = target_dir.resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    total_uncompressed_bytes = 0
    extracted_count = 0

    with zipfile.ZipFile(zip_path, 'r') as zf:
        # Check overall file count
        infolist = zf.infolist()
        if len(infolist) > MAX_FILES:
            raise DecompressionBombError(f"Archive exceeds maximum file limit ({len(infolist)} > {MAX_FILES})")

        for member in infolist:
            # Check compressed vs uncompressed ratio
            if member.compress_size > 0:
                ratio = member.file_size / member.compress_size
                if ratio > MAX_RATIO:
                    raise DecompressionBombError(f"Decompression bomb ratio ({ratio:.1f}:1) detected on {member.filename}")

            total_uncompressed_bytes += member.file_size
            if total_uncompressed_bytes > MAX_UNCOMPRESSED_BYTES:
                raise DecompressionBombError(f"Uncompressed archive exceeds size limit ({total_uncompressed_bytes} bytes)")

            # Zip-Slip check: canonical path resolution
            destination_path = (target_dir / member.filename).resolve()
            try:
                common = os.path.commonpath([str(target_dir), str(destination_path)])
                if common != str(target_dir):
                    raise ZipSlipSecurityError(f"Malicious Zip-Slip path detected: {member.filename}")
            except ValueError:
                raise ZipSlipSecurityError(f"Invalid path traversal in archive: {member.filename}")

            # Extract directory or file
            if member.is_dir():
                destination_path.mkdir(parents=True, exist_ok=True)
            else:
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as source, open(destination_path, "wb") as target:
                    target.write(source.read())
                extracted_count += 1

    return extracted_count
