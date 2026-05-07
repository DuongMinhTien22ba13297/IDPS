#!/usr/bin/env python3
"""
=============================================================================
Module: auto_firewall.py
Chức năng: Tự động hóa iptables để block/unblock IP tấn công.
         - Validate IP trước khi thực thi (phòng injection)
         - Duplicate check để tránh insert rule trùng
         - Protected IPs không bao giờ bị block
         - Timeout 5s cho mỗi lệnh iptables
=============================================================================
"""

import ipaddress
import logging
import subprocess
from typing import Optional

logger = logging.getLogger("Autodefense.AutoFirewall")

# IPs không bao giờ được block (gateway, localhost, host machine)
PROTECTED_IPS = frozenset([
    "127.0.0.1",
    "192.168.226.1",
    "192.168.226.151",
])

# Timeout cho mỗi lệnh iptables (giây)
IPTABLES_TIMEOUT = 1


class AutoFirewall:
    """Quản lý iptables rules để auto-block/unblock IP tấn công."""

    def __init__(self):
        self._blocked_ips: set = set()
        self._sync_from_iptables()

    # -----------------------------------------------------------------
    #  Initialization
    # -----------------------------------------------------------------

    def _sync_from_iptables(self):
        """
        Đồng bộ danh sách IP đã block từ iptables hiện tại.
        Chạy khi khởi tạo để cache không bị lệch sau restart container.
        """
        try:
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
                capture_output=True, text=True, timeout=IPTABLES_TIMEOUT
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.split()
                    # Format: num  DROP  all  --  x.x.x.x  0.0.0.0/0
                    if len(parts) >= 5 and parts[1] == "DROP":
                        ip = parts[4]
                        if self._is_valid_ip(ip):
                            self._blocked_ips.add(ip)
                logger.info(f"Đồng bộ iptables: {len(self._blocked_ips)} IP đang bị block")
            else:
                logger.warning(f"Không thể đọc iptables: {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            logger.error("Timeout khi đọc iptables rules")
        except FileNotFoundError:
            logger.error("iptables không tìm thấy. Đảm bảo chạy trong container privileged!")
        except Exception as e:
            logger.error(f"Lỗi sync iptables: {e}")

    # -----------------------------------------------------------------
    #  Validation
    # -----------------------------------------------------------------

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Validate IP address format (phòng injection)."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_protected(ip: str) -> bool:
        """Kiểm tra IP có được bảo vệ (không cho phép block)."""
        return ip in PROTECTED_IPS

    # -----------------------------------------------------------------
    #  Core Operations
    # -----------------------------------------------------------------

    def block_ip(self, src_ip: str, reason: str = "") -> bool:
        """
        Block IP bằng iptables: iptables -I INPUT -s {src_ip} -j DROP

        Args:
            src_ip: IP cần block
            reason: Lý do block (để logging)

        Returns:
            True nếu block thành công (rule mới được thêm)
            False nếu đã bị block rồi, IP không hợp lệ, hoặc lỗi
        """
        # Validate IP
        if not self._is_valid_ip(src_ip):
            logger.error(f"IP không hợp lệ: '{src_ip}' — từ chối block")
            return False

        # Check protected
        if self._is_protected(src_ip):
            logger.warning(f"IP {src_ip} thuộc danh sách PROTECTED — từ chối block")
            return False

        # Check duplicate (từ cache)
        if src_ip in self._blocked_ips:
            logger.debug(f"IP {src_ip} đã bị block trước đó — skip")
            return False

        # Double-check bằng iptables -C (check rule tồn tại)
        if self._check_rule_exists(src_ip):
            self._blocked_ips.add(src_ip)  # Sync cache
            logger.debug(f"IP {src_ip} đã có rule trong iptables — skip")
            return False

        # Thực thi iptables -I INPUT -s {src_ip} -j DROP
        try:
            result = subprocess.run(
                ["iptables", "-I", "INPUT", "-s", src_ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=IPTABLES_TIMEOUT
            )
            if result.returncode == 0:
                self._blocked_ips.add(src_ip)
                logger.info(
                    f"AUTO_BLOCKED: {src_ip} | Lý do: {reason}"
                )
                return True
            else:
                logger.error(f"iptables block thất bại cho {src_ip}: {result.stderr.strip()}")
                return False

        except subprocess.TimeoutExpired:
            logger.error(f"Timeout khi block IP {src_ip}")
            return False
        except Exception as e:
            logger.error(f"Lỗi block IP {src_ip}: {e}")
            return False

    def unblock_ip(self, src_ip: str) -> bool:
        """
        Unblock IP: iptables -D INPUT -s {src_ip} -j DROP

        Returns:
            True nếu unblock thành công, False nếu lỗi hoặc IP chưa bị block
        """
        if not self._is_valid_ip(src_ip):
            logger.error(f"IP không hợp lệ: '{src_ip}' — từ chối unblock")
            return False

        try:
            result = subprocess.run(
                ["iptables", "-D", "INPUT", "-s", src_ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=IPTABLES_TIMEOUT
            )
            if result.returncode == 0:
                self._blocked_ips.discard(src_ip)
                logger.info(f"UNBLOCKED: {src_ip}")
                return True
            else:
                logger.warning(f"Không thể unblock {src_ip}: {result.stderr.strip()}")
                return False

        except subprocess.TimeoutExpired:
            logger.error(f"Timeout khi unblock IP {src_ip}")
            return False
        except Exception as e:
            logger.error(f"Lỗi unblock IP {src_ip}: {e}")
            return False

    # -----------------------------------------------------------------
    #  Query methods
    # -----------------------------------------------------------------

    def _check_rule_exists(self, src_ip: str) -> bool:
        """Kiểm tra rule iptables đã tồn tại bằng iptables -C."""
        try:
            result = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", src_ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=IPTABLES_TIMEOUT
            )
            return result.returncode == 0
        except Exception:
            return False

    def is_blocked(self, src_ip: str) -> bool:
        """Kiểm tra IP có đang bị block không (check cache trước, iptables sau)."""
        if src_ip in self._blocked_ips:
            return True
        # Fallback: check trực tiếp iptables
        if self._check_rule_exists(src_ip):
            self._blocked_ips.add(src_ip)
            return True
        return False

    def get_blocked_list(self) -> list:
        """Trả về danh sách IP đang bị block."""
        return sorted(list(self._blocked_ips))

    def get_blocked_count(self) -> int:
        """Trả về số lượng IP đang bị block."""
        return len(self._blocked_ips)

    def __repr__(self) -> str:
        return f"AutoFirewall(blocked={len(self._blocked_ips)} IPs)"
