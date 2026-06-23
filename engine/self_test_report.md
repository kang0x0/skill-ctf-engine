# Self-Test Report — Skill-CTF Track B Engine

## Test Results

| Test Case | Verdict | Confidence | Category | Notes |
|-----------|---------|-----------|----------|-------|
| skill-benign-001 | benign | 0.0 | — | 纯 Hello World 代码，无任何可疑特征 |
| skill-malicious-001 | malicious | 0.9 | AST01 | exec/requests/敏感文件读取全部检出 |
| skill-suspicious-001 | suspicious | 0.4 | AST03 | 权限声明过大但无实际恶意代码 |

## Detection Rate (Self-Reported)

| Metric | Value |
|--------|-------|
| Recall (检出率) | 100% (1/1 恶意样本) |
| Precision (精确率) | 100% (无误报) |
| F₂ Score | 1.0 |
| 检测耗时(单 Skill) | <0.1s |
| 峰值内存 | <50MB |