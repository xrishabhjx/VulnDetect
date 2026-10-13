# Risk model evaluation report

## Primary task: KEV catalog membership

A negative means the CVE is not listed in the sampled KEV catalog snapshot; it does not mean confirmed unexploited. Both variants use identical train/test CVEs and tuning.

| Model | Precision | Recall | F1 | ROC-AUC | PR-AUC |
|---|---:|---:|---:|---:|---:|
| with_epss | 0.930 | 0.883 | 0.906 | 0.949 | 0.949 |
| without_epss | 0.814 | 0.800 | 0.807 | 0.872 | 0.851 |
| cvss_only | 0.739 | 0.850 | 0.791 | 0.840 | 0.801 |
| epss_only | 0.970 | 0.533 | 0.688 | 0.920 | 0.920 |
| random_base_rate_matched | 0.533 | 0.533 | 0.533 | 0.521 | 0.532 |

## EPSS ablation

Compare `with_epss` to `without_epss`: the latter excludes both epss_score and cvss_epss_interaction. A difference on this shared holdout is evidence about incremental performance beyond EPSS for predicting KEV membership, not a causal result or proof of future generalization.

## Supplementary weak-proxy labels

EPSS-threshold labels are stored separately in `data/processed/weak_proxy_sample.parquet` and excluded from primary model training and metrics. Any analysis on them is exploratory and circular with EPSS.

## Feature importance and limitations

Charts: `feature_importance.png` (with EPSS) and `feature_importance_no_epss.png` (without EPSS). Importances represent model reliance, not causal effects. Balanced sampling changes prevalence; the probabilities are not calibrated real-world exploitation likelihoods.
