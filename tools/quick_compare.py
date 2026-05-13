#!/usr/bin/env python3
"""Quick comparison of baseline vs tuned seed metrics"""
import json

baseline = json.load(open("world_best_definitive_report.json"))
tuned = json.load(open("world_best_definitive_report_tuned.json"))

print("SEED-BY-SEED COMPARISON\n")
print("Seed | Baseline TP | Tuned TP | Lost | Baseline FP | Tuned FP | Reduced")
print("-" * 70)

for b_seed, t_seed in zip(baseline["per_seed"], tuned["per_seed"]):
    seed = b_seed["seed"]
    b_tp = b_seed["web"]["tp"]
    t_tp = t_seed["web"]["tp"]
    lost = b_tp - t_tp
    b_fp = b_seed["web"]["fp"]
    t_fp = t_seed["web"]["fp"]
    reduced = b_fp - t_fp
    print(f"{seed:4d} | {b_tp:11d} | {t_tp:8d} | {lost:4d} | {b_fp:10d} | {t_fp:8d} | {reduced:7d}")

print("\nAGGREGATE CHANGE:")
b_agg = baseline["aggregate"]["web"]
t_agg = tuned["aggregate"]["web"]
print(f"TP: {b_agg['tp']} -> {t_agg['tp']} (lost {b_agg['tp'] - t_agg['tp']})")
print(f"FP: {b_agg['fp']} -> {t_agg['fp']} (reduced {b_agg['fp'] - t_agg['fp']})")
print(f"Recall: {b_agg['recall_pct']:.2f}% -> {t_agg['recall_pct']:.2f}% (change {t_agg['recall_pct'] - b_agg['recall_pct']:.2f}%)")
print(f"Precision: {b_agg['precision_pct']:.2f}% -> {t_agg['precision_pct']:.2f}% (change {t_agg['precision_pct'] - b_agg['precision_pct']:.2f}%)")
