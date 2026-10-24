import os
import json
import sqlite3
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

AST_RULE_VERSION = "keynova-ast-v1.0.0"

class AstCacheManager:
    """
    Content-addressable SQLite caching engine for AST parsing and findings.
    Provides O(1) retrieval for unchanged source files based on content SHA-256.
    """
    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        self._conn: Optional[sqlite3.Connection] = None
        if db_path is None:
            cache_dir = Path(os.getenv("KEYNOVA_CACHE_DIR", Path.cwd() / ".keynova_cache"))
            cache_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = cache_dir / "ast_cache.db"
        elif str(db_path) == ":memory:":
            self.db_path = Path(":memory:")
        else:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path), timeout=10.0, check_same_thread=False)
            if str(self.db_path) != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")
                self._conn.execute("PRAGMA synchronous = NORMAL")
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ast_cache (
                    cache_key TEXT PRIMARY KEY,
                    file_path TEXT,
                    findings_json TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache_stats (
                    id INTEGER PRIMARY KEY,
                    hits INTEGER DEFAULT 0,
                    misses INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                INSERT OR IGNORE INTO cache_stats (id, hits, misses) VALUES (1, 0, 0)
            """)
            conn.commit()

    @staticmethod
    def compute_key(content: str, rule_version: str = AST_RULE_VERSION) -> str:
        return hashlib.sha256(content.encode("utf-8") + rule_version.encode("utf-8")).hexdigest()

    def get(self, content: str, rule_version: str = AST_RULE_VERSION) -> Optional[List[Dict[str, Any]]]:
        """
        Retrieves cached findings list if content hash matches.
        Increments hit/miss counters.
        """
        cache_key = self.compute_key(content, rule_version)
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT findings_json FROM ast_cache WHERE cache_key = ?", (cache_key,))
                row = cursor.fetchone()
                if row:
                    conn.execute("UPDATE cache_stats SET hits = hits + 1 WHERE id = 1")
                    conn.commit()
                    return json.loads(row[0])
                else:
                    conn.execute("UPDATE cache_stats SET misses = misses + 1 WHERE id = 1")
                    conn.commit()
                    return None
        except Exception:
            return None

    def set(
        self,
        content: str,
        findings: List[Dict[str, Any]],
        file_path: str = "",
        rule_version: str = AST_RULE_VERSION
    ) -> None:
        """
        Caches findings list for the given file content.
        """
        cache_key = self.compute_key(content, rule_version)
        serialized = json.dumps(findings)
        try:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO ast_cache (cache_key, file_path, findings_json)
                    VALUES (?, ?, ?)
                    ON CONFLICT(cache_key) DO UPDATE SET
                        file_path = excluded.file_path,
                        findings_json = excluded.findings_json
                    """,
                    (cache_key, file_path, serialized)
                )
                conn.commit()
        except Exception:
            pass

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns cache utilization metrics: hits, misses, total, and hit ratio.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT hits, misses FROM cache_stats WHERE id = 1")
                row = cursor.fetchone()
                hits = row[0] if row else 0
                misses = row[1] if row else 0
                total = hits + misses
                hit_ratio = round(hits / total, 4) if total > 0 else 0.0
                return {
                    "hits": hits,
                    "misses": misses,
                    "total_requests": total,
                    "hit_ratio": hit_ratio,
                    "bypass_ratio": round(1.0 - hit_ratio, 4) if total > 0 else 0.0
                }
        except Exception:
            return {"hits": 0, "misses": 0, "total_requests": 0, "hit_ratio": 0.0, "bypass_ratio": 0.0}

    def clear(self) -> None:
        """Truncates the cache and resets stats."""
        try:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM ast_cache")
                conn.execute("UPDATE cache_stats SET hits = 0, misses = 0 WHERE id = 1")
                conn.commit()
        except Exception:
            pass

_DEFAULT_MANAGER: Optional[AstCacheManager] = None

def get_ast_cache() -> AstCacheManager:
    global _DEFAULT_MANAGER
    if _DEFAULT_MANAGER is None:
        _DEFAULT_MANAGER = AstCacheManager()
    return _DEFAULT_MANAGER
