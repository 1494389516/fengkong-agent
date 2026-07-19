#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""合成数据生成器:生成带标签的较大规模事件样本,让指标和图表有分辨率。

生成三类欺诈模式(与手工样本同构,但带噪声和规模):
  coupon_bot   刷券脚本:单设备 + 多 IP 轮换,短间隔批量 coupon_claim;
               少量"慢速 bot"(间隔 10~25s)制造阈值张力
  cashout_ring 套现团伙:3~6 账号共用一台模拟器设备,各自领券后下小额单
  stolen       盗号/盗卡:老号盗用(高 KYC 高 LTV,大额)与新号盗卡
               (注册数小时即下 300~2500 中额单,只有账龄错配规则能抓)
正常用户里混入少量"重度用户"(快速连领 2~3 张券)和"大额正常单"(会被
R003 大额规则 review —— 有意为之的误伤张力,宽口径 precision 不会是 1)。

名单故意不完整(部分欺诈资源未收录),否则 R001 一条规则就全包了,
行为规则(R002/R003)测不出价值。

用法:
  python3 data/gen_sample.py                    # 默认规模,输出到 data/gen/
  python3 data/gen_sample.py --normal 300 --bots 15 --rings 8 --stolen 10
  python3 data/gen_sample.py --out /tmp/x --seed 7   # eval 用小规模+固定种子
之后 FK_DATASET=gen python3 main.py(或 eval)即切换到生成集。
时间基点固定(T0),同参数同种子输出完全可复现。
"""
import argparse
import json
import random
from pathlib import Path

T0 = 1784000000  # 固定时间基点,保证可复现
DAY = 86400

CITIES = [("北京", 39.9, 116.41), ("上海", 31.23, 121.47), ("广州", 23.13, 113.26),
          ("深圳", 22.54, 114.06), ("成都", 30.57, 104.07), ("杭州", 30.27, 120.15),
          ("武汉", 30.59, 114.31), ("西安", 34.34, 108.94)]


class Gen:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.events = []
        self.labels = {}
        self.blacklist = []
        self.accounts = {}
        self.ip_intel = {}
        self.reports = []
        self._report_seq = 0

    def emit(self, uid, ip, device, etype, ts, amount=None):
        e = {"uid": uid, "ip": ip, "device_id": device, "type": etype, "ts": int(ts)}
        if amount is not None:
            e["amount"] = round(amount, 2)
        self.events.append(e)

    def seg_intel(self, ip, typ, city=None, risk="low", note=None):
        """登记 IP 网段情报(同段首次登记生效)。city 为 (名, lat, lon) 或 None。"""
        seg = ip.rsplit(".", 1)[0]
        entry = {"type": typ, "carrier": None, "city": None, "lat": None, "lon": None, "risk": risk}
        if city:
            entry.update({"city": city[0],
                          "lat": round(city[1] + self.rng.uniform(-0.05, 0.05), 4),
                          "lon": round(city[2] + self.rng.uniform(-0.05, 0.05), 4)})
        if note:
            entry["note"] = note
        self.ip_intel.setdefault(seg, entry)

    def report(self, uid, ts, category, text, status):
        self._report_seq += 1
        self.reports.append({"report_id": self._report_seq, "reported_uid": uid,
                             "reporter": "g_rpt_%04d" % self.rng.randint(1, 9999),
                             "ts": int(ts), "category": category, "text": text, "status": status})

    def register(self, uid, registered_at, channel, method, ip, device, kyc, ltv, rebind=0):
        self.accounts[uid] = {
            "registered_at": int(registered_at),
            "register_channel": channel,
            "register_method": method,
            "register_ip": ip,
            "register_device": device,
            "kyc_level": kyc,
            "ltv": round(ltv, 2),
            "phone_rebind_count": rebind,
        }

    # ---- 正常用户:每天 1~3 个会话,登录 -> 偶尔领券/下单,间隔分钟到小时级 ----
    def normal_user(self, i, days):
        r = self.rng
        uid = "g_norm_%04d" % i
        device = "g_dev_n%04d" % i
        ips = ["10.%d.%d.%d" % (r.randint(0, 200), r.randint(0, 250), r.randint(1, 250))
               for _ in range(r.randint(1, 3))]
        home = r.choice(CITIES)  # 正常用户的多个网段都在常驻城市,不产生地理跳变
        for ip in ips:
            self.seg_intel(ip, r.choice(["residential", "mobile"]), home, "low")
        heavy = r.random() < 0.05      # 重度用户:快速连领券(R002 的近失样本)
        big_spender = r.random() < 0.03  # 大额正常单:会踩中 R003 大额 review(有意误伤张力)
        for d in range(days):
            for _ in range(r.randint(1, 3)):
                t = T0 + d * DAY + r.randint(8 * 3600, 23 * 3600)
                ip = r.choice(ips)
                self.emit(uid, ip, device, "login", t)
                t += r.randint(60, 900)
                if r.random() < 0.5:
                    amount = r.uniform(1200, 4000) if big_spender and r.random() < 0.5 \
                        else r.uniform(15, 400)
                    self.emit(uid, ip, device, "order", t, amount)
                    t += r.randint(120, 1800)
                if r.random() < (0.6 if heavy else 0.25):
                    claims = r.randint(2, 3) if heavy else 1
                    for _ in range(claims):
                        t += r.randint(45, 300) if heavy else r.randint(300, 3600)
                        self.emit(uid, ip, device, "coupon_claim", t)
        # 老账号(注册远早于观察窗),LTV = 观察窗内消费 + 历史存量
        spent = sum(e.get("amount", 0) for e in self.events if e["uid"] == uid)
        self.register(uid, T0 - r.randint(30, 400) * DAY,
                      r.choice(["appstore_organic", "android_store", "web_organic"]),
                      "phone", ips[0], device, r.choice([1, 2]),
                      spent + r.uniform(0, 2000))
        if r.random() < 0.01:  # 恶意/误举报噪音:正常用户偶被举报,核实后不属实
            self.report(uid, T0 + r.randint(0, days * DAY), "promo_abuse",
                        "怀疑抢券", "dismissed")
        self.labels[uid] = {"label": "normal", "note": "生成:正常用户"}

    # ---- 刷券 bot:多 IP 轮换 + 短间隔批量领券 ----
    def coupon_bot(self, i, days):
        r = self.rng
        uid = "g_bot_%03d" % i
        device = "g_dev_bot%03d" % i
        ips = ["203.0.113.%d" % r.randint(100, 250) for _ in range(r.randint(3, 8))]
        self.seg_intel(ips[0], "idc", ("曼谷", 13.75, 100.5), "high", "已知代理池出没网段")
        slow = r.random() < 0.3  # 慢速 bot:间隔 10~25s,测试阈值边界
        for d in range(r.randint(1, days)):
            t = T0 + d * DAY + r.randint(0, 23 * 3600)
            for _ in range(r.randint(15, 40)):
                t += r.randint(10, 25) if slow else r.randint(2, 8)
                self.emit(uid, r.choice(ips), device, "coupon_claim", t)
        if r.random() < 0.4:  # 名单不完整:只有部分 bot 设备被收录
            self.blacklist.append({"dimension": "device_id", "value": device, "list": "gray",
                                   "reason": "生成:批量行为设备指纹", "added_at": "2026-07-15"})
        # 新注册 + 渠道包 + 无 KYC 零消费:bot 的典型出生证明
        self.register(uid, T0 - r.randint(0, 2 * DAY), "web_promo", "email",
                      ips[0], device, 0, 0.0)
        self.labels[uid] = {"label": "fraud", "note": "生成:刷券脚本%s" % ("(慢速)" if slow else "")}

    # ---- 套现团伙:共用模拟器设备,领券 -> 小额单 ----
    def cashout_ring(self, i, days):
        r = self.rng
        device = "g_dev_emu%03d" % i
        members = r.randint(3, 6)
        if r.random() < 0.5:  # 一半团伙设备在灰名单里
            self.blacklist.append({"dimension": "device_id", "value": device, "list": "gray",
                                   "reason": "生成:模拟器特征", "added_at": "2026-07-12"})
        for m in range(members):
            uid = "g_ring_%03d_%d" % (i, m)
            ip = "198.51.100.%d" % r.randint(1, 250)
            self.seg_intel(ip, "idc", ("上海", 31.23, 121.47), "medium", "云主机段")
            t = T0 + r.randint(0, days - 1) * DAY + m * r.randint(1800, 5400)
            # 批量注册:开工前几分钟到两小时,邀请渠道,同一台设备
            self.register(uid, t - r.randint(600, 7200), "invite", "phone",
                          ip, device, 0, 0.0)
            self.emit(uid, ip, device, "login", t)
            for _ in range(r.randint(3, 5)):
                t += r.randint(120, 600)
                self.emit(uid, ip, device, "coupon_claim", t)
            t += r.randint(300, 900)
            amount = r.uniform(9.9, 19.9)
            self.emit(uid, ip, device, "order", t, amount)
            self.accounts[uid]["ltv"] = round(amount, 2)
            self.labels[uid] = {"label": "fraud", "note": "生成:套现团伙 ring%03d" % i}

    # ---- 盗号/盗卡销赃,两个变体 ----
    # takeover:老号被盗(高 KYC 高 LTV,案发设备非注册设备)—— R001/R003/自身基线的场景
    # fresh:新注册号 + 盗卡下中额单(300~2500,可低于 R003 大额线)—— R004 的专属场景,
    #        金额落在 [r004_min_amount, r003_high_amount) 区间时只有账龄错配能抓到它
    def stolen(self, i, days):
        r = self.rng
        uid = "g_stl_%03d" % i
        device = "g_dev_s%03d" % i
        t = T0 + r.randint(0, days - 1) * DAY + r.randint(3600, 23 * 3600)
        fresh = r.random() < 0.5
        if fresh:
            # 新号盗卡:秒拨段(地理不可信,不参与跳变计算 —— 这正是秒拨的意义)
            ip = "192.0.2.%d" % r.randint(1, 250)
            self.seg_intel(ip, "proxy", None, "high", "秒拨池,地理位置漂移不可信")
            self.register(uid, t - r.randint(600, 43200), "web_promo", "email",
                          ip, device, 0, 0.0)
            note = "生成:新号盗卡"
        else:
            # 老号盗用:机主刚在常驻城市下线,盗号者 15~60 分钟后从境外机房上线
            # —— 物理不可能的移动速度,geo_jump 信号的来源
            ip = "203.0.113.%d" % r.randint(30, 99)
            self.seg_intel(ip, "idc", ("曼谷", 13.75, 100.5), "high", "已知代理池出没网段")
            home_ip = "10.9.%d.%d" % (r.randint(0, 250), r.randint(1, 250))
            home = r.choice(CITIES)
            self.seg_intel(home_ip, "residential", home, "low")
            owner_device = "g_dev_owner%03d" % i
            self.register(uid, T0 - r.randint(200, 700) * DAY, "appstore_organic", "phone",
                          home_ip, owner_device, 2, r.uniform(2000, 20000), rebind=1)
            self.emit(uid, home_ip, owner_device, "login", t - r.randint(900, 3600))
            self.report(uid, t + r.randint(3600, DAY), "unauthorized_charge",
                        "机主申诉:本人未操作,账号异地下单", "verified")
            note = "生成:老号盗用销赃"
        if r.random() < 0.5:  # 一半坏 IP 已被名单收录
            self.blacklist.append({"dimension": "ip", "value": ip, "list": "black",
                                   "reason": "生成:代理池出口,批量盗号", "added_at": "2026-07-10"})
        self.emit(uid, ip, device, "login", t)
        for _ in range(r.randint(1, 2)):
            t += r.randint(120, 600)
            amount = r.uniform(300, 2500) if fresh else r.uniform(1000, 8000)
            self.emit(uid, ip, device, "order", t, amount)
        self.labels[uid] = {"label": "fraud", "note": note}


def main():
    ap = argparse.ArgumentParser(description="生成合成风控样本到 data/gen/")
    ap.add_argument("--normal", type=int, default=200)
    ap.add_argument("--bots", type=int, default=10)
    ap.add_argument("--rings", type=int, default=6)
    ap.add_argument("--stolen", type=int, default=8)
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, default=Path(__file__).parent / "gen")
    args = ap.parse_args()

    g = Gen(random.Random(args.seed))
    for i in range(args.normal):
        g.normal_user(i, args.days)
    for i in range(args.bots):
        g.coupon_bot(i, args.days)
    for i in range(args.rings):
        g.cashout_ring(i, args.days)
    for i in range(args.stolen):
        g.stolen(i, args.days)
    g.events.sort(key=lambda e: e["ts"])

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "events_sample.json").write_text(
        json.dumps(g.events, ensure_ascii=False, indent=1), encoding="utf-8")
    (args.out / "labels.json").write_text(
        json.dumps(g.labels, ensure_ascii=False, indent=1), encoding="utf-8")
    (args.out / "blacklist.json").write_text(
        json.dumps(g.blacklist, ensure_ascii=False, indent=1), encoding="utf-8")
    (args.out / "accounts.json").write_text(
        json.dumps(g.accounts, ensure_ascii=False, indent=1), encoding="utf-8")
    (args.out / "ip_intel.json").write_text(
        json.dumps(g.ip_intel, ensure_ascii=False, indent=1), encoding="utf-8")
    (args.out / "reports.json").write_text(
        json.dumps(g.reports, ensure_ascii=False, indent=1), encoding="utf-8")
    fraud = sum(1 for v in g.labels.values() if v["label"] == "fraud")
    print("生成完成 -> %s" % args.out)
    print("  事件 %d 条 · 账号 %d(fraud %d / normal %d)· 名单 %d 条" % (
        len(g.events), len(g.labels), fraud, len(g.labels) - fraud, len(g.blacklist)))
    print("  切换使用:FK_DATASET=gen python3 main.py")


if __name__ == "__main__":
    main()
