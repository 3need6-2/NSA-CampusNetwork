"""IsolationForest-based user behavior anomaly detection for campus network traffic."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from utils.constants import SUSPICIOUS_PORTS, FEATURE_NAMES

logger = logging.getLogger(__name__)


@dataclass
class AnomalyConfig:
    """Configuration for ML anomaly detection parameters."""

    contamination: float = 0.1
    random_state: int = 42
    top_n: int = 10
    min_users: int = 5


class MLAnomalyDetector:
    """User-level anomaly detector using IsolationForest."""

    def __init__(self, df: Optional[pd.DataFrame], config: Optional[AnomalyConfig] = None) -> None:
        """Initialize the detector with a DataFrame and optional config."""
        self.df: pd.DataFrame = df.copy() if df is not None else pd.DataFrame()
        self.config: AnomalyConfig = config or AnomalyConfig()

    def detect(self) -> Dict[str, Any]:
        """Run IsolationForest anomaly detection on user traffic features."""
        if self.df.empty or "user" not in self.df.columns:
            return self._empty_report("数据为空或缺少 user 列。")

        try:
            features_df = self._build_features()
        except Exception as exc:
            logger.exception("ML 特征构造失败")
            return self._empty_report(f"特征构造失败: {exc}")

        if len(features_df) < self.config.min_users:
            return self._empty_report(
                f"用户数 {len(features_df)} 少于 {self.config.min_users}，跳过 ML 检测。"
            )

        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
        except ImportError:
            return self._empty_report("scikit-learn 未安装，已跳过 ML 检测。")

        feature_matrix = features_df[FEATURE_NAMES].to_numpy(dtype=float)
        scaler = StandardScaler()
        scaled = scaler.fit_transform(feature_matrix)

        # 自动收缩 contamination 防止用户少时报错
        contamination = min(self.config.contamination, max(1 / len(features_df), 0.01))

        model = IsolationForest(
            n_estimators=120,
            contamination=contamination,
            random_state=self.config.random_state,
        )
        model.fit(scaled)
        raw_scores = model.score_samples(scaled)        # 越小越异常
        predictions = model.predict(scaled)              # -1 异常, 1 正常

        # 归一化为 0-100 风险分数：异常用户越远离正常分布，分数越高
        normalized = self._normalize_scores(raw_scores)
        features_df = features_df.assign(
            anomaly_score=normalized,
            is_anomaly=(predictions == -1),
        )

        anomalies = (
            features_df[features_df["is_anomaly"]]
            .sort_values("anomaly_score", ascending=False)
            .head(self.config.top_n)
        )

        anomaly_records = [self._format_record(row) for _, row in anomalies.iterrows()]
        normal_count = int((~features_df["is_anomaly"]).sum())

        return {
            "status": "ok",
            "model": "IsolationForest",
            "config": {
                "contamination": round(contamination, 4),
                "n_estimators": 120,
                "feature_count": len(FEATURE_NAMES),
            },
            "summary": {
                "total_users": int(len(features_df)),
                "anomaly_users": int(features_df["is_anomaly"].sum()),
                "normal_users": normal_count,
                "max_score": float(round(features_df["anomaly_score"].max(), 2)),
                "median_score": float(round(features_df["anomaly_score"].median(), 2)),
            },
            "anomalies": anomaly_records,
            "feature_names": FEATURE_NAMES,
        }

    def detect_lof(self) -> Dict[str, Any]:
        """Run LocalOutlierFactor anomaly detection on user traffic features."""
        if self.df.empty or "user" not in self.df.columns:
            return self._empty_report("数据为空或缺少 user 列。")

        try:
            features_df = self._build_features()
        except Exception as exc:
            logger.exception("ML 特征构造失败")
            return self._empty_report(f"特征构造失败: {exc}")

        if len(features_df) < self.config.min_users:
            return self._empty_report(
                f"用户数 {len(features_df)} 少于 {self.config.min_users}，跳过 ML 检测。"
            )

        try:
            from sklearn.neighbors import LocalOutlierFactor
            from sklearn.preprocessing import StandardScaler
        except ImportError:
            return self._empty_report("scikit-learn 未安装，已跳过 ML 检测。")

        feature_matrix = features_df[FEATURE_NAMES].to_numpy(dtype=float)
        scaler = StandardScaler()
        scaled = scaler.fit_transform(feature_matrix)

        contamination = min(self.config.contamination, max(1 / len(features_df), 0.01))

        model = LocalOutlierFactor(
            n_neighbors=20,
            contamination=contamination,
            novelty=False,
        )
        predictions = model.fit_predict(scaled)
        raw_scores = -model.negative_outlier_factor_

        normalized = self._normalize_scores(raw_scores)
        features_df = features_df.assign(
            anomaly_score=normalized,
            is_anomaly=(predictions == -1),
        )

        anomalies = (
            features_df[features_df["is_anomaly"]]
            .sort_values("anomaly_score", ascending=False)
            .head(self.config.top_n)
        )

        anomaly_records = [self._format_record(row) for _, row in anomalies.iterrows()]
        normal_count = int((~features_df["is_anomaly"]).sum())

        return {
            "status": "ok",
            "model": "LocalOutlierFactor",
            "config": {
                "contamination": round(contamination, 4),
                "n_neighbors": 20,
                "feature_count": len(FEATURE_NAMES),
            },
            "summary": {
                "total_users": int(len(features_df)),
                "anomaly_users": int(features_df["is_anomaly"].sum()),
                "normal_users": normal_count,
                "max_score": float(round(features_df["anomaly_score"].max(), 2)),
                "median_score": float(round(features_df["anomaly_score"].median(), 2)),
            },
            "anomalies": anomaly_records,
            "feature_names": FEATURE_NAMES,
        }

    def detect_svm(self) -> Dict[str, Any]:
        """Run OneClassSVM anomaly detection on user traffic features."""
        if self.df.empty or "user" not in self.df.columns:
            return self._empty_report("数据为空或缺少 user 列。")

        try:
            features_df = self._build_features()
        except Exception as exc:
            logger.exception("ML 特征构造失败")
            return self._empty_report(f"特征构造失败: {exc}")

        if len(features_df) < self.config.min_users:
            return self._empty_report(
                f"用户数 {len(features_df)} 少于 {self.config.min_users}，跳过 ML 检测。"
            )

        try:
            from sklearn.svm import OneClassSVM
            from sklearn.preprocessing import StandardScaler
        except ImportError:
            return self._empty_report("scikit-learn 未安装，已跳过 ML 检测。")

        feature_matrix = features_df[FEATURE_NAMES].to_numpy(dtype=float)
        scaler = StandardScaler()
        scaled = scaler.fit_transform(feature_matrix)

        nu = min(self.config.contamination, max(1 / len(features_df), 0.01))

        model = OneClassSVM(
            nu=nu,
            kernel="rbf",
            gamma="auto",
        )
        model.fit(scaled)
        raw_scores = model.score_samples(scaled)
        predictions = model.predict(scaled)

        normalized = self._normalize_scores(raw_scores)
        features_df = features_df.assign(
            anomaly_score=normalized,
            is_anomaly=(predictions == -1),
        )

        anomalies = (
            features_df[features_df["is_anomaly"]]
            .sort_values("anomaly_score", ascending=False)
            .head(self.config.top_n)
        )

        anomaly_records = [self._format_record(row) for _, row in anomalies.iterrows()]
        normal_count = int((~features_df["is_anomaly"]).sum())

        return {
            "status": "ok",
            "model": "OneClassSVM",
            "config": {
                "nu": round(nu, 4),
                "kernel": "rbf",
                "feature_count": len(FEATURE_NAMES),
            },
            "summary": {
                "total_users": int(len(features_df)),
                "anomaly_users": int(features_df["is_anomaly"].sum()),
                "normal_users": normal_count,
                "max_score": float(round(features_df["anomaly_score"].max(), 2)),
                "median_score": float(round(features_df["anomaly_score"].median(), 2)),
            },
            "anomalies": anomaly_records,
            "feature_names": FEATURE_NAMES,
        }

    def detect_ensemble(self) -> Dict[str, Any]:
        """Run all 3 models and return consensus anomalies flagged by >=2 models."""
        results = []
        models_info = []

        for name, method in [("IsolationForest", self.detect),
                             ("LocalOutlierFactor", self.detect_lof),
                             ("OneClassSVM", self.detect_svm)]:
            result = method()
            if result["status"] == "ok":
                models_info.append(name)
                results.append(result)

        if len(results) < 2:
            return self._empty_report("少于 2 个模型成功运行，无法进行集成检测。")

        user_votes: Dict[str, List[str]] = {}
        for result in results:
            for anomaly in result["anomalies"]:
                user = anomaly["user"]
                user_votes.setdefault(user, []).append(result["model"])

        consensus_users = {u for u, votes in user_votes.items() if len(votes) >= 2}

        user_scores: Dict[str, List[float]] = {}
        for result in results:
            for anomaly in result["anomalies"]:
                user = anomaly["user"]
                user_scores.setdefault(user, []).append(anomaly["anomaly_score"])

        consensus_records = []
        seen = set()
        for result in results:
            for anomaly in result["anomalies"]:
                if anomaly["user"] in consensus_users and anomaly["user"] not in seen:
                    avg_score = round(sum(user_scores[anomaly["user"]]) / len(user_scores[anomaly["user"]]), 2)
                    record = dict(anomaly)
                    record["anomaly_score"] = avg_score
                    record["voting_models"] = user_votes[anomaly["user"]]
                    consensus_records.append(record)
                    seen.add(anomaly["user"])

        consensus_records.sort(key=lambda r: r["anomaly_score"], reverse=True)
        consensus_records = consensus_records[:self.config.top_n]

        total_users = max(r["summary"]["total_users"] for r in results)

        median_score = 0.0
        max_score = 0.0
        if consensus_records:
            scores = [r["anomaly_score"] for r in consensus_records]
            max_score = float(round(max(scores), 2))
            sorted_scores = sorted(scores)
            median_score = float(round(sorted_scores[len(sorted_scores) // 2], 2))

        return {
            "status": "ok",
            "model": "Ensemble",
            "config": {
                "models": models_info,
                "min_consensus": 2,
                "top_n": self.config.top_n,
            },
            "summary": {
                "total_users": total_users,
                "anomaly_users": len(consensus_records),
                "normal_users": max(0, total_users - len(consensus_records)),
                "max_score": max_score,
                "median_score": median_score,
            },
            "anomalies": consensus_records,
            "feature_names": FEATURE_NAMES,
        }

    def _build_features(self) -> pd.DataFrame:
        """Build a feature matrix from user traffic data for anomaly detection."""
        df = self.df.copy()

        # 标准化字段
        for col in ["bytes", "src_port", "dst_port"]:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            df["hour"] = df["timestamp"].dt.hour.fillna(0).astype(int)

        # 缺失列补默认值
        for col in ["dst_ip", "dst_port", "protocol"]:
            if col not in df.columns:
                df[col] = "unknown"
        if "hour" not in df.columns:
            df["hour"] = 0

        df["is_night"] = df["hour"].between(0, 5)
        df["is_dns"] = df["dst_port"] == 53
        df["is_suspicious_port"] = df["dst_port"].isin(SUSPICIOUS_PORTS)

        per_user_hour = df.groupby(["user", "hour"])["bytes"].sum().unstack(fill_value=0)
        max_hour_bytes = per_user_hour.max(axis=1)
        active_hour_count = (per_user_hour > 0).sum(axis=1)

        agg = df.groupby("user").agg(
            total_bytes=("bytes", "sum"),
            total_packets=("bytes", "count"),
            unique_dst_ips=("dst_ip", "nunique"),
            unique_dst_ports=("dst_port", "nunique"),
            suspicious_port_hits=("is_suspicious_port", "sum"),
            dns_query_count=("is_dns", "sum"),
            night_bytes=("bytes", lambda s: s[df.loc[s.index, "is_night"]].sum()),
        )

        agg["night_byte_ratio"] = np.where(
            agg["total_bytes"] > 0,
            agg["night_bytes"] / agg["total_bytes"],
            0.0,
        )
        agg["max_hour_bytes"] = max_hour_bytes.reindex(agg.index, fill_value=0)
        agg["active_hour_count"] = active_hour_count.reindex(agg.index, fill_value=0)
        agg["avg_bytes_per_packet"] = np.where(
            agg["total_packets"] > 0,
            agg["total_bytes"] / agg["total_packets"],
            0.0,
        )

        return agg[FEATURE_NAMES].fillna(0).astype(float)

    @staticmethod
    def _normalize_scores(raw_scores: np.ndarray) -> np.ndarray:
        """Map IsolationForest score_samples (lower = more anomalous) to a 0-100 scale."""
        if len(raw_scores) == 0:
            return raw_scores
        inverted = -raw_scores
        lo, hi = float(inverted.min()), float(inverted.max())
        if hi - lo < 1e-9:
            return np.full_like(inverted, 50.0)
        scaled = (inverted - lo) / (hi - lo) * 100.0
        return np.round(scaled, 2)

    @staticmethod
    def _format_record(row: pd.Series) -> Dict[str, Any]:
        """Format an anomaly record into a structured dictionary with top features."""
        feature_dict = {name: float(round(row[name], 2)) for name in FEATURE_NAMES}
        zscore = (
            (row[FEATURE_NAMES] - row[FEATURE_NAMES].mean())
            / (row[FEATURE_NAMES].std(ddof=0) or 1.0)
        )
        top_features = zscore.abs().sort_values(ascending=False).head(3).index.tolist()
        evidence = [
            f"{name}={feature_dict[name]:.2f}"
            for name in top_features
        ]
        return {
            "user": str(row.name),
            "anomaly_score": float(row["anomaly_score"]),
            "severity": _severity_from_score(float(row["anomaly_score"])),
            "evidence": evidence,
            "features": feature_dict,
        }

    @staticmethod
    def _empty_report(message: str) -> Dict[str, Any]:
        """Return an empty/skipped report structure."""
        return {
            "status": "skipped",
            "message": message,
            "model": "IsolationForest",
            "summary": {
                "total_users": 0,
                "anomaly_users": 0,
                "normal_users": 0,
                "max_score": 0.0,
                "median_score": 0.0,
            },
            "anomalies": [],
            "feature_names": FEATURE_NAMES,
        }


def _severity_from_score(score: float) -> str:
    """Convert a numeric anomaly score to a severity level string."""
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def detect_anomalies(df: pd.DataFrame, config: Optional[AnomalyConfig] = None) -> Dict[str, Any]:
    """Convenience function to run anomaly detection."""
    return MLAnomalyDetector(df, config).detect()
