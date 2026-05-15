#!/usr/bin/env python3
"""
=============================================================================
Tên file   : threat_evaluator.py
Mục tiêu   : Thực hiện dự đoán (Inference) mức độ đe dọa của các luồng mạng bằng mô hình ML.
             Sử dụng cấu trúc 2 lớp XGBoost để tối ưu hóa giữa việc phát hiện nhanh 
             và phân loại chi tiết.
Input      :
  - features : Vector 30 đặc trưng trích xuất từ realtime_extractor.
  - models/  : Các file mô hình đã huấn luyện (.pkl).
  - configs/thresholds.json : Các ngưỡng tin cậy để ra quyết định (chặn/cảnh báo).
Output     :
  - dict : Kết quả đánh giá gồm: có phải tấn công không, độ tin cậy, loại tấn công, 
           và thời gian xử lý.
Quy trình  :
  1. Khởi tạo: Load đồng thời Active Model (Binary), Classification Model (Multi-class) 
     và LabelEncoder vào bộ nhớ.
  2. Validate: Kiểm tra tính hợp lệ của vector đặc trưng đầu vào.
  3. Binary Inference: Tính toán xác suất Attack/Benign.
  4. Multi-class Inference: Xác định loại tấn công cụ thể và tổng xác suất tấn công.
  5. Kết hợp: So sánh kết quả từ cả 2 model để đưa ra kết luận cuối cùng (Confidence cao nhất).
=============================================================================
"""

import json
import logging
import time
from pathlib import Path

import joblib
import numpy as np

logger = logging.getLogger("Autodefense.ThreatEvaluator")


class ThreatEvaluator:
    """
    ML Inference engine cho IDPS.
    Load 2 mô hình XGBoost + LabelEncoder một lần khi khởi tạo,
    sau đó evaluate từng flow vector 30 features.
    """

    def __init__(self, models_dir: str = "/app/models", config_dir: str = "/app/configs"):
        self.models_dir = Path(models_dir)
        self.config_dir = Path(config_dir)

        # Load thresholds từ config
        self._load_thresholds()

        # Load ML models + LabelEncoder
        self._load_models()

    # -----------------------------------------------------------------
    #  Initialization
    # -----------------------------------------------------------------

    def _load_thresholds(self):
        """Load confidence thresholds từ configs/thresholds.json."""
        thresholds_path = self.config_dir / "thresholds.json"
        try:
            if thresholds_path.exists():
                with open(thresholds_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                self.auto_block_threshold = cfg.get("auto_block_threshold", 0.85)
                self.alert_threshold = cfg.get("alert_threshold", 0.60)
                self.whitelist_alert_threshold = cfg.get("whitelist_alert_threshold", 0.85)
                logger.info(
                    f"Loaded thresholds: auto_block={self.auto_block_threshold}, "
                    f"alert={self.alert_threshold}, "
                    f"whitelist_alert={self.whitelist_alert_threshold}"
                )
            else:
                logger.warning("thresholds.json không tồn tại. Dùng giá trị mặc định.")
                self.auto_block_threshold = 0.85
                self.alert_threshold = 0.60
                self.whitelist_alert_threshold = 0.85
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Lỗi đọc thresholds.json: {e}. Dùng giá trị mặc định.")
            self.auto_block_threshold = 0.85
            self.alert_threshold = 0.60
            self.whitelist_alert_threshold = 0.85

    def _load_models(self):
        """Load 3 artifacts: active_model, classification_model, label_encoder."""
        active_path = self.models_dir / "active_model.pkl"
        classification_path = self.models_dir / "classification_model.pkl"
        encoder_path = self.models_dir / "label_encoder.pkl"

        # Kiểm tra file tồn tại
        for path in [active_path, classification_path, encoder_path]:
            if not path.exists():
                raise FileNotFoundError(
                    f"Model file không tồn tại: {path}. "
                    f"Hãy chạy offline_training.py trước!"
                )

        logger.info("Đang load ML models...")
        start = time.time()

        self.active_model = joblib.load(active_path)
        logger.info(f"active_model.pkl loaded ({active_path.stat().st_size / 1024:.0f} KB)")

        self.classification_model = joblib.load(classification_path)
        logger.info(f"classification_model.pkl loaded ({classification_path.stat().st_size / 1024:.0f} KB)")

        self.label_encoder = joblib.load(encoder_path)
        logger.info(f"label_encoder.pkl loaded (classes: {list(self.label_encoder.classes_)})")

        elapsed = (time.time() - start) * 1000
        logger.info(f"Tất cả models đã load xong trong {elapsed:.0f}ms")

    # -----------------------------------------------------------------
    #  Core Inference
    # -----------------------------------------------------------------

    def evaluate(self, features: np.ndarray) -> dict:
        """
        Chạy ML inference trên vector 30 features.
        
        Chiến lược: Chạy SONG SONG cả binary và multiclass model.
        - Binary model: xác suất Attack (0.0 - 1.0)
        - Multiclass model: phân loại chi tiết (BENIGN + 6 loại attack)
        - Kết quả cuối: dùng giá trị CAO HƠN giữa binary attack score
          và multiclass non-BENIGN score.

        Args:
            features: NumPy array shape (30,) từ realtime_extractor.extract_features()

        Returns:
            dict: {
                "is_attack": bool,
                "confidence": float,          # Xác suất là Attack (0.0 - 1.0)
                "attack_type": str | None,    # Tên loại tấn công (nếu là attack)
                "attack_confidence": float,   # Confidence của multiclass prediction
                "inference_time_ms": float    # Thời gian inference (ms)
            }
        """
        start = time.time()

        # Validate input
        if features.shape != (30,):
            logger.error(f"Feature vector không hợp lệ: shape={features.shape}, expected=(30,)")
            return {
                "is_attack": False,
                "confidence": 0.0,
                "attack_type": None,
                "attack_confidence": 0.0,
                "inference_time_ms": 0.0
            }

        # Reshape cho sklearn: (1, 30)
        X = features.reshape(1, -1)

        # Xử lý NaN/Inf trong features (phòng trường hợp realtime data bất thường)
        if np.any(np.isnan(X)) or np.any(np.isinf(X)):
            logger.warning("Feature vector chứa NaN/Inf. Thay thế bằng 0.")
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        # ---- Step 1: Binary Inference ----
        binary_proba = self.active_model.predict_proba(X)[0]
        binary_attack_score = float(binary_proba[1])  # Xác suất là Attack (class 1)

        # ---- Step 2: Multiclass Inference (LUÔN CHẠY) ----
        attack_type = None
        attack_confidence = 0.0
        multi_attack_score = 0.0
        multi_proba = None

        try:
            multi_proba = self.classification_model.predict_proba(X)[0]
            predicted_class_idx = int(np.argmax(multi_proba))
            attack_confidence = float(multi_proba[predicted_class_idx])

            # Decode index → tên loại tấn công
            predicted_label = self.label_encoder.inverse_transform([predicted_class_idx])[0]

            # Tính tổng xác suất tấn công từ multiclass (1 - P(BENIGN))
            benign_idx = list(self.label_encoder.classes_).index("BENIGN") if "BENIGN" in self.label_encoder.classes_ else 0
            multi_attack_score = float(1.0 - multi_proba[benign_idx])

            if predicted_label.upper() != "BENIGN":
                attack_type = predicted_label
            else:
                attack_type = None

        except Exception as e:
            logger.error(f"Lỗi multiclass inference: {e}")
            attack_type = "Unknown"
            attack_confidence = 0.0

        # ---- Step 3: Kết hợp kết quả ----
        # Dùng giá trị CAO HƠN giữa binary attack score và multiclass attack score
        confidence = max(binary_attack_score, multi_attack_score)
        is_attack = confidence > self.auto_block_threshold

        # Nếu multiclass predict BENIGN nhưng binary cho Attack cao → hiển thị chi tiết loại tấn công có xác suất cao nhất
        if attack_type is None and confidence > self.alert_threshold:
            if multi_proba is not None:
                classes_list = list(self.label_encoder.classes_)
                benign_idx = classes_list.index("BENIGN") if "BENIGN" in classes_list else 0
                non_benign_probs = [(i, multi_proba[i]) for i in range(len(classes_list)) if i != benign_idx]
                
                if non_benign_probs:
                    highest_attack_idx = max(non_benign_probs, key=lambda x: x[1])[0]
                    highest_attack_label = self.label_encoder.inverse_transform([highest_attack_idx])[0]
                    attack_type = f"Suspicious (Binary=Attack, Multi={highest_attack_label})"
                else:
                    attack_type = "Suspicious (Binary=Attack, Multi=Unknown)"
            else:
                attack_type = "Suspicious (Binary=Attack, Multi=Unknown)"

        # Thêm biến chứa xác suất của tất cả các lớp
        class_probabilities = {}
        if multi_proba is not None:
            for i, c in enumerate(self.label_encoder.classes_):
                safe_key = str(c).replace(" ", "_").replace("/", "_")
                class_probabilities[safe_key] = round(float(multi_proba[i]), 4)

        elapsed_ms = (time.time() - start) * 1000

        result = {
            "is_attack": is_attack,
            "confidence": confidence,
            "binary_score": binary_attack_score,
            "multi_score": multi_attack_score,
            "attack_type": attack_type,
            "attack_confidence": attack_confidence,
            "inference_time_ms": round(elapsed_ms, 2),
            "class_probabilities": class_probabilities
        }

        return result

    # -----------------------------------------------------------------
    #  Info / Debug
    # -----------------------------------------------------------------

    def get_model_info(self) -> dict:
        """Trả về thông tin về các model đã load."""
        return {
            "active_model_type": type(self.active_model).__name__,
            "classification_model_type": type(self.classification_model).__name__,
            "num_classes": len(self.label_encoder.classes_),
            "class_names": list(self.label_encoder.classes_),
            "auto_block_threshold": self.auto_block_threshold,
            "alert_threshold": self.alert_threshold,
        }

    def __repr__(self) -> str:
        return (
            f"ThreatEvaluator("
            f"classes={list(self.label_encoder.classes_)}, "
            f"threshold={self.auto_block_threshold})"
        )
