#!/usr/bin/env python3
"""
=============================================================================
Module: ip_manager.py
Chức năng: Quản lý Blacklist / Whitelist IP cho Zero-Touch IDPS.
         - In-memory cache (set) cho O(1) lookup mỗi flow
         - Persist xuống JSON file sau mỗi thay đổi
         - Thread-safe với threading.Lock()
=============================================================================
"""

import json
import logging
import threading
from pathlib import Path

logger = logging.getLogger("Autodefense.IPManager")


class IPManager:
    """Quản lý Blacklist và Whitelist IP với in-memory cache + JSON persistence."""

    def __init__(self, config_dir: str = "/app/configs"):
        self.config_dir = Path(config_dir)
        self.blacklist_path = self.config_dir / "blacklist.json"
        self.whitelist_path = self.config_dir / "whitelist.json"

        self._blacklist: set = set()
        self._whitelist: set = set()
        self._lock = threading.Lock()

        self._load()

    # -----------------------------------------------------------------
    #  Load / Save
    # -----------------------------------------------------------------

    def _load(self):
        """Load cả 2 file JSON vào memory. Tạo mới nếu chưa tồn tại."""
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Load Blacklist
        if self.blacklist_path.exists():
            try:
                with open(self.blacklist_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._blacklist = set(data.get("ips", []))
                logger.info(f"Loaded blacklist: {len(self._blacklist)} IPs")
            except (json.JSONDecodeError, KeyError) as e:
                logger.error(f"Lỗi đọc blacklist.json: {e}. Tạo mới.")
                self._blacklist = set()
                self._save_blacklist()
        else:
            logger.info("blacklist.json chưa tồn tại. Tạo mới.")
            self._blacklist = set()
            self._save_blacklist()

        # Load Whitelist
        if self.whitelist_path.exists():
            try:
                with open(self.whitelist_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._whitelist = set(data.get("ips", []))
                logger.info(f"Loaded whitelist: {len(self._whitelist)} IPs")
            except (json.JSONDecodeError, KeyError) as e:
                logger.error(f"Lỗi đọc whitelist.json: {e}. Tạo mới với defaults.")
                self._whitelist = {"192.168.226.1", "192.168.226.151", "127.0.0.1"}
                self._save_whitelist()
        else:
            logger.info("whitelist.json chưa tồn tại. Tạo mới với defaults.")
            self._whitelist = {"192.168.226.1", "192.168.226.151", "127.0.0.1"}
            self._save_whitelist()

    def _save_blacklist(self):
        """Persist blacklist set xuống JSON file."""
        try:
            data = {
                "description": "IP Blacklist - Auto-blocked by IDPS ML detection + manual entries",
                "ips": sorted(list(self._blacklist))
            }
            with open(self.blacklist_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
        except IOError as e:
            logger.error(f"Không thể ghi blacklist.json: {e}")

    def _save_whitelist(self):
        """Persist whitelist set xuống JSON file."""
        try:
            data = {
                "description": "IP Whitelist - Trusted IPs (admin, gateway, internal services)",
                "ips": sorted(list(self._whitelist))
            }
            with open(self.whitelist_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
        except IOError as e:
            logger.error(f"Không thể ghi whitelist.json: {e}")

    # -----------------------------------------------------------------
    #  Check methods (O(1) lookup)
    # -----------------------------------------------------------------

    def is_blacklisted(self, ip: str) -> bool:
        """Kiểm tra IP có trong blacklist không."""
        with self._lock:
            return ip in self._blacklist

    def is_whitelisted(self, ip: str) -> bool:
        """Kiểm tra IP có trong whitelist không."""
        with self._lock:
            return ip in self._whitelist

    # -----------------------------------------------------------------
    #  Blacklist operations
    # -----------------------------------------------------------------

    def add_to_blacklist(self, ip: str, reason: str = "") -> bool:
        """
        Thêm IP vào blacklist + persist xuống JSON.
        Return True nếu thêm mới, False nếu đã tồn tại.
        """
        with self._lock:
            if ip in self._blacklist:
                return False
            self._blacklist.add(ip)
            self._save_blacklist()
            logger.info(f"Đã thêm {ip} vào Blacklist. Lý do: {reason}")
            return True

    def remove_from_blacklist(self, ip: str) -> bool:
        """
        Xóa IP khỏi blacklist + persist.
        Return True nếu xóa thành công, False nếu IP không tồn tại.
        """
        with self._lock:
            if ip not in self._blacklist:
                return False
            self._blacklist.discard(ip)
            self._save_blacklist()
            logger.info(f"Đã xóa {ip} khỏi Blacklist.")
            return True

    # -----------------------------------------------------------------
    #  Whitelist operations
    # -----------------------------------------------------------------

    def add_to_whitelist(self, ip: str) -> bool:
        """Thêm IP vào whitelist + persist."""
        with self._lock:
            if ip in self._whitelist:
                return False
            self._whitelist.add(ip)
            self._save_whitelist()
            logger.info(f"Đã thêm {ip} vào Whitelist.")
            return True

    def remove_from_whitelist(self, ip: str) -> bool:
        """Xóa IP khỏi whitelist + persist."""
        with self._lock:
            if ip not in self._whitelist:
                return False
            self._whitelist.discard(ip)
            self._save_whitelist()
            logger.info(f"Đã xóa {ip} khỏi Whitelist.")
            return True

    # -----------------------------------------------------------------
    #  Info / Debug
    # -----------------------------------------------------------------

    def get_blacklist(self) -> list:
        """Trả về danh sách IP trong blacklist."""
        with self._lock:
            return sorted(list(self._blacklist))

    def get_whitelist(self) -> list:
        """Trả về danh sách IP trong whitelist."""
        with self._lock:
            return sorted(list(self._whitelist))

    def __repr__(self) -> str:
        return (
            f"IPManager(blacklist={len(self._blacklist)} IPs, "
            f"whitelist={len(self._whitelist)} IPs)"
        )
