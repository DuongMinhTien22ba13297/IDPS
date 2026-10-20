#!/usr/bin/env python3
"""
=============================================================================
Tên file   : threat_evaluator.py
Mục tiêu   : Thực hiện dự đoán (Inference) mức độ đe dọa của các luồng mạng bằng mô hình ML.
             Sử dụng hai mô hình XGBoost chạy song song để phát hiện và phân loại.
Input      :
  - features : Vector đặc trưng theo model_metadata.json/feature_names_in_.
  - models/  : Hai model, model_metadata.json và LabelEncoder fallback cho artifact cũ.
  - configs/thresholds.json : Các ngưỡng tin cậy để ra quyết định (chặn/cảnh báo).
Output     :
  - dict : Kết quả đánh giá gồm: có phải tấn công không, độ tin cậy, loại tấn công,
           và thời gian xử lý.
Ngày sửa: 2026-09-08
Lí do sửa: Nâng runtime lên 21 features và kiểm tra chéo metadata/model artifacts.
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
    sau đó evaluate từng flow vector theo metadata của model.
    """

    def __init__(self, models_dir: str = "/app/models", config_dir: str = "/app/configs"):
        self.models_dir = Path(models_dir)
        self.config_dir = Path(config_dir)

        # Load thresholds từ config
        self._load_thresholds()

        # Load ML models + LabelEncoder
        self._load_models()

    #  Initialization

    def _load_thresholds(self):
        """Load confidence thresholds từ configs/thresholds.json."""
        thresholds_path = self.config_dir / "thresholds.json"
        try:
            if thresholds_path.exists():
                with open(thresholds_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                self.auto_block_threshold = cfg.get("auto_block_threshold", 0.85)
                self.alert_threshold = cfg.get("alert_threshold", 0.60)
                # Hard cap correlation score khi ML=Benign (tránh ET Open alerts tự block)
                self.suricata_only_max_score = cfg.get("suricata_only_max_score", 0.30)
                logger.info(
                    f"Loaded thresholds: auto_block={self.auto_block_threshold}, "
                    f"alert={self.alert_threshold}, "
                    f"suricata_only_max_score={self.suricata_only_max_score}"
                )
            else:
                logger.warning("thresholds.json không tồn tại. Dùng giá trị mặc định.")
                self.auto_block_threshold = 0.85
                self.alert_threshold = 0.60
                self.suricata_only_max_score = 0.30
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Lỗi đọc thresholds.json: {e}. Dùng giá trị mặc định.")
            self.auto_block_threshold = 0.85
            self.alert_threshold = 0.60
            self.suricata_only_max_score = 0.30

    def _load_models(self):
        """Load model artifacts rồi khóa schema feature/class cho inference."""
        active_path = self.models_dir / "active_model.pkl"
        classification_path = self.models_dir / "classification_model.pkl"
        encoder_path = self.models_dir / "label_encoder.pkl"
        metadata_path = self.models_dir / "model_metadata.json"

        # Hai model luôn bắt buộc. Metadata mới cung cấp class names trực tiếp;
        # label_encoder.pkl chỉ còn là fallback cho legacy artifacts.
        for path in [active_path, classification_path]:
            if not path.exists():
                raise FileNotFoundError(
                    f"Model file không tồn tại: {path}. "
                    f"Hãy chạy offline_training.py trước!"
                )

        self.model_metadata = {}
        if metadata_path.exists():
            try:
                with open(metadata_path, "r", encoding="utf-8") as f:
                    self.model_metadata = json.load(f)
                logger.info(
                    "model_metadata.json loaded (experiment=%s)",
                    self.model_metadata.get("experiment_id", "unknown"),
                )
            except (json.JSONDecodeError, IOError) as e:
                raise ValueError(f"Không thể đọc model metadata: {e}") from e
        else:
            logger.warning(
                "model_metadata.json không tồn tại; dùng label_encoder.pkl và "
                "suy ra schema từ feature_names_in_."
            )

        logger.info("Đang load ML models...")
        start = time.time()

        self.active_model = joblib.load(active_path)
        logger.info(f"active_model.pkl loaded ({active_path.stat().st_size / 1024:.0f} KB)")

        self.classification_model = joblib.load(classification_path)
        logger.info(f"classification_model.pkl loaded ({classification_path.stat().st_size / 1024:.0f} KB)")

        metadata_classes = [
            str(name) for name in self.model_metadata.get("classes", [])
        ]
        if metadata_classes:
            # Tránh unpickle LabelEncoder khác phiên bản scikit-learn trên host.
            self.label_encoder = None
            self.class_names = metadata_classes
            logger.info("Class names loaded from model metadata: %s", self.class_names)
        else:
            if not encoder_path.exists():
                raise FileNotFoundError(
                    "Thiếu cả classes trong model_metadata.json và label_encoder.pkl."
                )
            self.label_encoder = joblib.load(encoder_path)
            self.class_names = [str(name) for name in self.label_encoder.classes_]
            logger.info("Legacy label_encoder.pkl loaded (classes: %s)", self.class_names)

        self._validate_model_schema()

        elapsed = (time.time() - start) * 1000
        logger.info(f"Tất cả models đã load xong trong {elapsed:.0f}ms")

    @staticmethod
    def _model_feature_names(model) -> list[str]:
        names = getattr(model, "feature_names_in_", None)
        return [str(name) for name in names] if names is not None else []

    def _validate_model_schema(self):
        """Fail fast nếu hai model, metadata hoặc encoder không cùng schema."""
        active_count = int(getattr(self.active_model, "n_features_in_", 0))
        classification_count = int(
            getattr(self.classification_model, "n_features_in_", 0)
        )
        if active_count <= 0 or classification_count <= 0:
            raise ValueError("Model không công bố n_features_in_; không thể khóa schema runtime.")
        if active_count != classification_count:
            raise ValueError(
                "Hai model không cùng số feature: "
                f"binary={active_count}, multiclass={classification_count}."
            )

        active_names = self._model_feature_names(self.active_model)
        classification_names = self._model_feature_names(self.classification_model)
        if active_names and classification_names and active_names != classification_names:
            raise ValueError("Hai model không cùng thứ tự feature_names_in_.")

        metadata_names = [
            str(name) for name in self.model_metadata.get("selected_features", [])
        ]
        model_names = active_names or classification_names
        if metadata_names and model_names and metadata_names != model_names:
            raise ValueError(
                "selected_features trong metadata không khớp feature_names_in_ của model."
            )

        self.feature_names = metadata_names or model_names
        if len(self.feature_names) != active_count:
            raise ValueError(
                f"Schema có {len(self.feature_names)} tên nhưng model cần {active_count} feature."
            )
        self.n_features = active_count
        self.experiment_id = self.model_metadata.get("experiment_id", "legacy-artifacts")

        model_class_count = len(getattr(self.classification_model, "classes_", []))
        if model_class_count != len(self.class_names):
            raise ValueError(
                "Số lớp của multiclass model không khớp class schema: "
                f"model={model_class_count}, schema={len(self.class_names)}."
            )

        logger.info(
            "Validated model schema: experiment=%s features=%d classes=%d",
            self.experiment_id,
            self.n_features,
            len(self.class_names),
        )

    #  Core Inference

    def evaluate(self, features: np.ndarray) -> dict:
        """
        Chạy ML inference trên vector theo schema đã khóa khi load model.
        
        Chiến lược: Chạy SONG SONG cả binary và multiclass model.
        - Binary model: xác suất Attack (0.0 - 1.0)
        - Multiclass model: phân loại chi tiết (BENIGN + 5 loại attack)
        - Kết quả cuối: dùng giá trị CAO HƠN giữa binary attack score
          và multiclass non-BENIGN score.

        Args:
            features: NumPy array shape (n_features,) từ realtime_extractor.

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
        try:
            features_array = np.asarray(features, dtype=np.float64)
        except (TypeError, ValueError) as e:
            logger.error(f"Không thể chuyển feature vector sang float64: {e}")
            return {
                "is_attack": False,
                "confidence": 0.0,
                "attack_type": None,
                "attack_confidence": 0.0,
                "inference_time_ms": 0.0
            }

        expected_shape = (self.n_features,)
        if features_array.shape != expected_shape:
            logger.error(
                "Feature vector không hợp lệ: shape=%s, expected=%s",
                features_array.shape,
                expected_shape,
            )
            return {
                "is_attack": False,
                "confidence": 0.0,
                "attack_type": None,
                "attack_confidence": 0.0,
                "inference_time_ms": 0.0
            }

        # Reshape cho sklearn: (1, n_features)
        X = features_array.reshape(1, -1)

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

            # Decode index → tên loại tấn công theo schema đã khóa.
            predicted_label = self.class_names[predicted_class_idx]

            # Tính tổng xác suất tấn công từ multiclass (1 - P(BENIGN))
            benign_idx = self.class_names.index("BENIGN") if "BENIGN" in self.class_names else 0
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
                classes_list = self.class_names
                benign_idx = classes_list.index("BENIGN") if "BENIGN" in classes_list else 0
                non_benign_probs = [(i, multi_proba[i]) for i in range(len(classes_list)) if i != benign_idx]
                
                if non_benign_probs:
                    highest_attack_idx = max(non_benign_probs, key=lambda x: x[1])[0]
                    highest_attack_label = classes_list[highest_attack_idx]
                    attack_type = f"Suspicious (Binary=Attack, Multi={highest_attack_label})"
                else:
                    attack_type = "Suspicious (Binary=Attack, Multi=Unknown)"
            else:
                attack_type = "Suspicious (Binary=Attack, Multi=Unknown)"

        # Thêm biến chứa xác suất của tất cả các lớp
        class_probabilities = {}
        if multi_proba is not None:
            for i, c in enumerate(self.class_names):
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

    #  Info / Debug

    def get_model_info(self) -> dict:
        """Trả về thông tin về các model đã load."""
        return {
            "active_model_type": type(self.active_model).__name__,
            "classification_model_type": type(self.classification_model).__name__,
            "num_classes": len(self.class_names),
            "class_names": list(self.class_names),
            "experiment_id": self.experiment_id,
            "feature_count": self.n_features,
            "feature_names": list(self.feature_names),
            "auto_block_threshold": self.auto_block_threshold,
            "alert_threshold": self.alert_threshold,
        }

    def __repr__(self) -> str:
        return (
            f"ThreatEvaluator("
            f"experiment={self.experiment_id}, "
            f"features={self.n_features}, "
            f"classes={self.class_names}, "
            f"threshold={self.auto_block_threshold})"
        )
