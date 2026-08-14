#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""模型评估指标库(eval 侧入口)。

数学本体在 agent/metrics.py —— agent 工具(model_eval/model_compare)直接
依赖它,依赖方向是 eval -> agent,不允许 agent 反向依赖 eval。本文件是
规格路径的薄转发,保持 eval/model_eval.py 可导入。

用法:from model_eval import evaluate, compare, champion_beats_challenger
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.metrics import (auc, ks, confusion, evaluate, compare,  # noqa: F401,E402
                           champion_beats_challenger)
