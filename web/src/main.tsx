import { createRoot } from "react-dom/client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  CalendarRange,
  Check,
  ChevronLeft,
  ChevronRight,
  CircleGauge,
  Copy,
  Database,
  Filter,
  FilterX,
  ImageIcon,
  KeyRound,
  LogOut,
  Network,
  RefreshCw,
  Server,
  Settings2,
  ShieldCheck,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import "./styles.css";
import "./security.css";
import "./theme.css";

type Summary = {
  requests: number;
  counted_requests: number;
  external_requests: number;
  success: number;
  success_rate: number;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  free_models: number;
  active_proxies: number;
};
type Proxy = {
  id: number;
  uri: string;
  scheme: string;
  host: string;
  port: number;
  username?: string;
  enabled: boolean;
  health_status: string;
  failure_count: number;
  usage_state?: "unused" | "in_use" | "cooldown";
  cooldown_until?: string;
  expires_at?: string;
  last_checked_at?: string;
  last_check_ok?: boolean;
  last_latency_ms?: number;
};
type ProxyPage = {
  items: Proxy[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
};
type Model = {
  id: number;
  model_id: string;
  display_name: string;
  is_free: boolean;
  free_reason: string;
  refreshed_at: string;
};
type RequestRow = {
  id: number;
  created_at: string;
  request_kind?: string;
  model: string;
  proxy_uri?: string;
  status: string;
  status_code: number;
  error_origin?: "none" | "user" | "external" | "internal";
  latency_ms: number;
  first_token_latency_ms?: number;
  retry_count: number;
  prompt_tokens?: number;
  completion_tokens?: number;
  total_tokens?: number;
  error_message?: string;
};
type UsagePage = {
  items: RequestRow[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
  models: string[];
};
type UsageRates = {
  window_seconds: number;
  rpm: number;
  tpm: number;
  measured_at: string;
};
type DailyUsage = {
  day: string;
  requests: number;
  tokens: number;
};
type ProxyFilterState = "all" | "unverified" | "healthy" | "cooldown" | "timeout" | "disabled";
type UsageTimePreset = "all" | "1h" | "24h" | "7d" | "30d" | "custom";
type UsageFilters = {
  time: UsageTimePreset;
  model: string;
  status: "" | "success" | "error" | "external";
  customFrom: string;
  customTo: string;
};

const api = async (path: string, init: RequestInit = {}) => {
  const r = await fetch(path, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(init.headers || {}) },
    ...init,
  });
  if (r.status === 401) throw new Error("AUTH");
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || "请求失败");
  return data;
};
const fmt = (n: number) => new Intl.NumberFormat("zh-CN").format(n || 0);
const fmtDuration = (minutes: number) => {
  if (minutes <= 0) return "0 分钟";
  if (minutes < 60) return `${minutes} 分钟`;
  if (minutes < 60 * 24) {
    const h = Math.floor(minutes / 60);
    const m = minutes % 60;
    return m > 0 ? `${h} 小时 ${m} 分` : `${h} 小时`;
  }
  const d = Math.floor(minutes / (60 * 24));
  const h = Math.floor((minutes % (60 * 24)) / 60);
  return h > 0 ? `${d} 天 ${h} 小时` : `${d} 天`;
};
const relTime = (iso?: string) => {
  if (!iso) return "";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "";
  const diff = Math.max(0, Date.now() - t);
  if (diff < 60_000) return "刚刚";
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
  if (diff < 86400_000) return `${Math.floor(diff / 3600_000)} 小时前`;
  return `${Math.floor(diff / 86400_000)} 天前`;
};
const countdownText = (iso?: string) => {
  if (!iso) return "";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "";
  const diff = Math.max(0, t - Date.now());
  if (diff <= 0) return "即将开始";
  const h = Math.floor(diff / 3600_000);
  const m = Math.floor((diff % 3600_000) / 60_000);
  const s = Math.floor((diff % 60_000) / 1000);
  if (h > 0) return `${h} 小时 ${m} 分`;
  if (m > 0) return `${m} 分 ${s} 秒`;
  return `${s} 秒`;
};
const headersToText = (headers?: Record<string, string>) =>
  Object.entries(headers || {})
    .map(([name, value]) => `${name}: ${value}`)
    .join("\n");
const parseHeaderText = (text: string) => {
  const headers: Record<string, string> = {};
  for (const [index, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line) continue;
    const separator = line.indexOf(":");
    if (separator < 1)
      throw new Error(`第 ${index + 1} 行必须使用 Header-Name: value 格式`);
    const name = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (!name) throw new Error(`第 ${index + 1} 行缺少请求头名称`);
    headers[name] = value;
  }
  return headers;
};

const useDocumentVisible = () => {
  const [visible, setVisible] = useState(() => document.visibilityState !== "hidden");
  useEffect(() => {
    const update = () => setVisible(document.visibilityState !== "hidden");
    document.addEventListener("visibilitychange", update);
    return () => document.removeEventListener("visibilitychange", update);
  }, []);
  return visible;
};

function Login({ onLogin }: { onLogin: () => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      await api("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ password }),
      });
      onLogin();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  return (
    <main className="login-shell">
      <div className="login-mark">
        <span>R</span>
        <div>
          <b>Relay Desk</b>
          <small>Free model gateway</small>
        </div>
      </div>
      <form className="login-card" onSubmit={submit}>
        <div className="eyebrow">管理员登录</div>
        <h1>
          欢迎回来
        </h1>
        <p>登录 Relay Desk，管理模型、代理与使用记录。</p>
        <label>
          管理员密码
          <input
            autoFocus
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="输入密码"
          />
        </label>
        {error && <div className="error-line">{error}</div>}
        <button className="primary wide" type="submit">
          <ShieldCheck size={17} />
          进入控制台
        </button>
      </form>
      <div className="login-foot">OpenAI-compatible relay · v0.1</div>
    </main>
  );
}

function App() {
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [page, setPage] = useState("overview");
  const [toast, setToast] = useState("");
	const handleLogin = useCallback(() => setAuthed(true), []);
	const handleLogout = useCallback(() => {
		void api("/api/auth/logout", { method: "POST" }).catch(() => undefined).finally(() =>
			setAuthed(false),
		);
	}, []);
  useEffect(() => {
    api("/api/auth/me")
      .then(() => setAuthed(true))
      .catch(() => setAuthed(false));
  }, []);
  useEffect(() => {
    if (toast) {
      const t = setTimeout(() => setToast(""), 2600);
      return () => clearTimeout(t);
    }
  }, [toast]);
  if (authed === null)
    return (
      <div className="boot">
        <CircleGauge className="spin" />
        正在连接控制台
      </div>
    );
  if (!authed) return <Login onLogin={handleLogin} />;
  return (
    <Console
      page={page}
      setPage={setPage}
      notify={setToast}
      onLogout={handleLogout}
      toast={toast}
    />
  );
}

function Console({
  page,
  setPage,
  notify,
  onLogout,
  toast,
}: {
  page: string;
  setPage: (v: string) => void;
  notify: (v: string) => void;
  onLogout: () => void;
  toast: string;
}) {
	const documentVisible = useDocumentVisible();
  const [summary, setSummary] = useState<Summary>({
    requests: 0,
    counted_requests: 0,
    external_requests: 0,
    success: 0,
    success_rate: 0,
    prompt_tokens: 0,
    completion_tokens: 0,
    total_tokens: 0,
    free_models: 0,
    active_proxies: 0,
  });
  const [models, setModels] = useState<Model[]>([]);
  const [rows, setRows] = useState<RequestRow[]>([]);
  const [upstream, setUpstream] = useState<any>({});
  const [poolInfo, setPoolInfo] = useState<any>(null);
  const [proxyRefreshToken, setProxyRefreshToken] = useState(0);
	const [usageRefreshToken, setUsageRefreshToken] = useState(0);
	const loadSequence = useRef(0);
	const load = useCallback(async () => {
		const sequence = ++loadSequence.current;
		try {
      const [s, m, r, u, h] = await Promise.all([
        api("/api/stats/summary"),
        api("/api/models/free"),
        api("/api/usage/requests?limit=25"),
        api("/api/settings/upstream"),
        api("/api/settings/healthcheck"),
      ]);
			if (sequence !== loadSequence.current) return;
			setSummary(s);
      setModels(m);
      setRows(r);
      setUpstream(u);
      setPoolInfo(h);
		} catch (e) {
			if ((e as Error).message === "AUTH") onLogout();
		}
	}, [onLogout]);
	useEffect(() => {
		if (!documentVisible) return;
		void load();
		const timer = window.setInterval(load, 30_000);
		return () => window.clearInterval(timer);
	}, [documentVisible, load]);
  const nav = [
    ["overview", "Overview", "仪表盘", CircleGauge],
    ["proxies", "Proxy pool", "代理池", Network],
    ["models", "Free models", "模型与网关", Database],
    ["usage", "Usage log", "使用记录", Activity],
    ["settings", "Settings", "设置", Settings2],
  ] as const;
  return (
    <div className="app-shell">
      <aside>
        <div className="brand">
          <div className="brand-icon">R</div>
          <div>
            <strong>Relay Desk</strong>
            <small>FREE MODEL GATEWAY</small>
          </div>
        </div>
        <div className="nav-label">CONTROL ROOM</div>
        <nav>
          {nav.map(([id, en, zh, Icon]) => (
            <button
              key={id}
              className={page === id ? "active" : ""}
              aria-current={page === id ? "page" : undefined}
              aria-label={`${zh}（${en}）`}
              onClick={() => setPage(id)}
            >
              <Icon size={17} />
              <span>
                <b>{en}</b>
                <small>{zh}</small>
              </span>
              {page === id && <ChevronRight size={15} />}
            </button>
          ))}
        </nav>
        <div className="aside-note">
          <span className="pulse" />
          Gateway online
          <br />
          <small>SQLite · encrypted secrets</small>
        </div>
        <button className="logout" onClick={onLogout}>
          <LogOut size={16} />
          退出
        </button>
      </aside>
      <main className="main">
        <header>
          <div>
            <div className="crumb">
              Relay Desk <ChevronRight size={13} />
              {nav.find((n) => n[0] === page)?.[2]}
            </div>
            <h2>{nav.find((n) => n[0] === page)?.[2]}</h2>
          </div>
          <div className="header-actions">
            <span className="endpoint">
              <span className="dot green" /> :8080 /v1
            </span>
            <button
              className="icon-btn"
              title="刷新数据"
              onClick={() => {
                load();
                setProxyRefreshToken((current) => current + 1);
                setUsageRefreshToken((current) => current + 1);
                notify("数据已刷新");
              }}
            >
              <RefreshCw size={17} />
            </button>
          </div>
        </header>
        {page === "overview" && (
          <Overview summary={summary} models={models} rows={rows} pool={poolInfo} />
        )}{" "}
        {page === "proxies" && (
          <Proxies
            upstream={upstream}
            reload={load}
            notify={notify}
            refreshToken={proxyRefreshToken}
          />
        )}{" "}
        {page === "models" && (
          <Models
            models={models}
            upstream={upstream}
            reload={load}
            notify={notify}
          />
        )}{" "}
        {page === "usage" && (
          <Usage
            notify={notify}
            onLogout={onLogout}
            refreshToken={usageRefreshToken}
          />
        )}{" "}
        {page === "settings" && (
          <SettingsPage notify={notify} onLogout={onLogout} />
        )}{" "}
        {toast && (
          <div className="toast">
            <Check size={15} />
            {toast}
          </div>
        )}
      </main>
    </div>
  );
}

function Stat({
  label,
  value,
  detail,
  accent,
}: {
  label: string;
  value: string;
  detail: string;
  accent?: string;
}) {
  return (
    <div className="stat">
      <div className="stat-top">
        <span>{label}</span>
        <span className="stat-accent" style={{ color: accent }}>
          <ArrowUpRight size={14} />
        </span>
      </div>
      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  );
}
function Overview({
  summary,
  models,
  rows,
  pool,
}: {
  summary: Summary;
  models: Model[];
  rows: RequestRow[];
  pool: any;
}) {
  const success = summary.success_rate * 100;
  const countedRequests = summary.counted_requests || summary.requests;
  return (
    <div className="page">
      <section className="hero-band">
        <div>
          <div className="eyebrow">实时网关监控</div>
          <h1>
            请求在流动。
            <br />
            <em>信号保持清晰。</em>
          </h1>
          <p>
            一个安静、可追踪的 Free 模型通道。代理池负责路径，控制台负责判断。
          </p>
        </div>
        <div className="hero-orbit">
          <div className="orbit-ring r1" />
          <div className="orbit-ring r2" />
          <div className="orbit-core">
            <span className="pulse" />
            在线
          </div>
        </div>
      </section>
      <section className="stat-grid">
        <Stat
          label="总请求数"
          value={fmt(summary.requests)}
          detail="全历史累计"
          accent="#c9684a"
        />
        <Stat
          label="当日 Token"
          value={fmt(summary.total_tokens)}
          detail={`${fmt(summary.prompt_tokens)} 输入 · ${fmt(summary.completion_tokens)} 输出`}
          accent="#416b5a"
        />
        <Stat
          label="免费模型"
          value={fmt(summary.free_models)}
          detail="网关可用"
          accent="#c49b3a"
        />
        <Stat
          label="可用代理"
          value={fmt(summary.active_proxies)}
          detail="参与轮换"
          accent="#5d78a4"
        />
        <Stat
          label="成功率"
          value={`${success.toFixed(1)}%`}
          detail={`${fmt(summary.success)} / ${fmt(countedRequests)} 有效请求成功`}
          accent="#6d8b75"
        />
      </section>
      {pool && (
        <section className="panel pool-card">
          <div className="panel-head">
            <div>
              <span className="eyebrow">PROXY POOL</span>
              <h3>池子可用性</h3>
            </div>
            <span className="count-chip">
              可用 {pool.healthy_proxies ?? 0} / {pool.total_proxies ?? 0}
            </span>
          </div>
          <div className="pool-progress">
            {pool.total_proxies > 0 && (
              <div
                className="pool-progress-healthy"
                style={{
                  width: `${
                    ((pool.healthy_proxies || 0) / pool.total_proxies) * 100
                  }%`,
                }}
              />
            )}
          </div>
          <p className="muted pool-meta">
            健康 {pool.healthy_proxies ?? 0} · 冷却 {pool.cooldown_proxies ?? 0}{" "}
            · 未验证 {pool.unknown_proxies ?? 0}
            {pool.running
              ? " · 健康检查进行中…"
              : pool.next_run_at
                ? ` · 下次检查 ${countdownText(pool.next_run_at)}`
                : ""}
          </p>
        </section>
      )}
      <section className="two-col">
        <div className="panel">
          <div className="panel-head">
            <div>
              <span className="eyebrow">路由概览</span>
              <h3>免费模型</h3>
            </div>
            <span className="count-chip">{models.length} 个可用</span>
          </div>
          {models.length === 0 ? (
            <Empty text="还没有可用的 Free 模型" />
          ) : (
            <div className="model-list">
              {models.slice(0, 6).map((m) => (
                <div className="model-row" key={m.model_id}>
                  <span className="model-swatch">✦</span>
                  <div>
                    <b>{m.model_id}</b>
                    <small>
                      {m.free_reason.replaceAll("_", " ")} · 更新于{" "}
                      {new Date(m.refreshed_at).toLocaleDateString()}
                    </small>
                  </div>
                  <span className="status-tag">FREE</span>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="panel">
          <div className="panel-head">
            <div>
              <span className="eyebrow">最近流量</span>
              <h3>最新请求</h3>
            </div>
            <span className="count-chip">显示 {rows.length} 条</span>
          </div>
          {rows.length === 0 ? (
            <Empty text="请求记录会出现在这里" />
          ) : (
            <div className="mini-table">
              {rows.slice(0, 5).map((r) => (
                <div className="mini-row" key={r.id}>
                  <span
                    className={`status-dot ${r.status === "success" ? "ok" : r.error_origin === "external" ? "neutral" : "bad"}`}
                  />
                  <div>
                    <b>{r.model}</b>
                    <small>
                      {new Date(r.created_at).toLocaleTimeString()} ·{" "}
                      {r.proxy_uri || "direct"}
                    </small>
                  </div>
                  <strong>{r.total_tokens ? fmt(r.total_tokens) : "—"}</strong>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

function Proxies({
  upstream,
  reload,
  notify,
  refreshToken,
}: {
  upstream: any;
  reload: () => Promise<void>;
  notify: (v: string) => void;
	refreshToken: number;
}) {
	const documentVisible = useDocumentVisible();
	const [text, setText] = useState("");
  const [subscriptionURL, setSubscriptionURL] = useState("");
  const [expiry, setExpiry] = useState("0");
  const [customExpiry, setCustomExpiry] = useState("");
  const [proxies, setProxies] = useState<Proxy[]>([]);
  const [proxyPage, setProxyPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<number[]>([]);
  const [busy, setBusy] = useState(false);
  const [proxyState, setProxyState] = useState<ProxyFilterState>("all");
  const [sessionLimit, setSessionLimit] = useState(
    String(upstream.session_proxy_request_limit ?? 50),
  );
  const [quotaCooldown, setQuotaCooldown] = useState(
    String(upstream.quota_429_cooldown_minutes ?? 1440),
  );
  const [hcInterval, setHcInterval] = useState("120");
  const [hcTestURL, setHcTestURL] = useState("");
  const [hcMaxFailures, setHcMaxFailures] = useState("3");
  const [hcStatus, setHcStatus] = useState<any>(null);
  const [testingId, setTestingId] = useState<number | null>(null);
  const [testResult, setTestResult] = useState<{
    id: number;
    ok: boolean;
    latency_ms?: number;
    timed_out?: boolean;
    error?: string;
  } | null>(null);
  const [latencyBusy, setLatencyBusy] = useState(false);
	const [nowTick, setNowTick] = useState(Date.now());
	useEffect(() => {
		if (!documentVisible) return;
		setNowTick(Date.now());
		const timer = window.setInterval(() => setNowTick(Date.now()), 30_000);
		return () => window.clearInterval(timer);
	}, [documentVisible]);
  const loadProxies = useCallback(
    async (requestedPage: number, requestedPageSize: number) => {
      setLoading(true);
      try {
        const params = new URLSearchParams({
          page: String(requestedPage),
          page_size: String(requestedPageSize),
          state: proxyState,
        });
        const data = (await api(
          `/api/proxies?${params.toString()}`,
        )) as ProxyPage;
        setProxies(data.items);
        setProxyPage(data.page);
        setPageSize(data.page_size);
        setTotal(data.total);
        setTotalPages(data.total_pages);
        setSelected((current) =>
          current.filter((id) => data.items.some((proxy) => proxy.id === id)),
        );
      } catch (e) {
        notify((e as Error).message);
      } finally {
        setLoading(false);
      }
    },
    [notify, proxyState],
  );
  useEffect(() => {
    void loadProxies(proxyPage, pageSize);
  }, [loadProxies, pageSize, proxyPage, refreshToken]);
  useEffect(
    () => setSessionLimit(String(upstream.session_proxy_request_limit ?? 50)),
    [upstream.session_proxy_request_limit],
  );
  useEffect(
    () =>
      setQuotaCooldown(String(upstream.quota_429_cooldown_minutes ?? 1440)),
    [upstream.quota_429_cooldown_minutes],
  );
  const loadHealthCheck = useCallback(async () => {
    try {
      const d = await api("/api/settings/healthcheck");
      setHcStatus(d);
      setHcInterval(String(d.interval_minutes ?? 120));
      setHcTestURL(d.test_url || "");
      setHcMaxFailures(String(d.max_failures ?? 3));
    } catch {
      /* 忽略 */
    }
  }, []);
  useEffect(() => {
    void loadHealthCheck();
  }, [loadHealthCheck, refreshToken]);
  const saveHealthCheck = async () => {
    const interval = Number(hcInterval);
    if (!Number.isInteger(interval) || interval < 0 || interval > 10080) {
      notify("请输入 0 到 10080 之间的整数");
      return;
    }
    const maxFailures = Number(hcMaxFailures);
    if (!Number.isInteger(maxFailures) || maxFailures < 0 || maxFailures > 100000) {
      notify("连续失败次数请输入 0 到 100000 之间的整数");
      return;
    }
    setBusy(true);
    try {
      await api("/api/settings/healthcheck", {
        method: "PUT",
        body: JSON.stringify({
          interval_minutes: interval,
          test_url: hcTestURL.trim(),
          max_failures: maxFailures,
        }),
      });
      notify("健康检查配置已保存");
      await loadHealthCheck();
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const runHealthCheck = async () => {
    setBusy(true);
    try {
      await api("/api/settings/healthcheck/run", { method: "POST" });
      notify("健康检查已启动");
      setTimeout(() => void loadHealthCheck(), 3000);
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const runUnverifiedCheck = async () => {
    setBusy(true);
    try {
      await api("/api/settings/healthcheck/run-unverified", { method: "POST" });
      notify("未验证节点测试已启动");
      setTimeout(() => void loadHealthCheck(), 3000);
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const refreshAfterMutation = async (requestedPage = proxyPage) => {
    await reload();
    if (requestedPage !== proxyPage) {
      setProxyPage(requestedPage);
      return;
    }
    await loadProxies(requestedPage, pageSize);
  };
  const importIt = async () => {
    if (!text.trim()) return;
    const payload: any = { text };
    if (expiry === "custom") {
      if (!customExpiry) {
        notify("请选择到期时间");
        return;
      }
      payload.expires_at = new Date(customExpiry).toISOString();
    } else if (expiry !== "0") {
      payload.expires_in_days = Number(expiry);
    }
    setBusy(true);
    try {
      const d = await api("/api/proxies/import", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      const ok = d.results.filter((x: any) => x.status === "imported").length;
      notify(`已导入 ${ok} 个代理${expiry === "0" ? "" : "，已设置有效期"}`);
      setText("");
      await refreshAfterMutation(1);
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const importSubscription = async () => {
    const url = subscriptionURL.trim();
    if (!url) return;
    setBusy(true);
    try {
      const d = await api("/api/proxies/import-subscription", {
        method: "POST",
        body: JSON.stringify({ subscription_url: url }),
      });
      notify(`订阅导入完成：新增 ${d.imported ?? 0} 个节点`);
      setSubscriptionURL("");
      await refreshAfterMutation(1);
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const importMihomo = async () => {
    setBusy(true);
    try {
      const d = await api("/api/settings/mihomo/nodes");
      const lines = (d.nodes as string[]).map((n) => `mihomo://${n}`);
      if (!lines.length) {
        notify("mihomo 中没有可导入的节点");
        return;
      }
      setText(lines.join("\n"));
      notify(`已载入 ${lines.length} 个 mihomo 节点，点击“导入代理”确认`);
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const testOne = async (p: Proxy) => {
    setTestingId(p.id);
    setTestResult(null);
    try {
      const d = await api(`/api/proxies/${p.id}/test`, { method: "POST" });
      setTestResult({ id: p.id, ok: true, latency_ms: d.latency_ms });
      notify(`测试通过${d.latency_ms !== undefined ? ` · ${d.latency_ms}ms` : ""}`);
      await refreshAfterMutation();
    } catch (e) {
      setTestResult({ id: p.id, ok: false, error: (e as Error).message });
    } finally {
      setTestingId(null);
    }
  };
  const runLatencyTest = async () => {
    if (!proxies.length) return;
    setLatencyBusy(true);
    try {
      const params = new URLSearchParams();
      if (proxyState !== "all") params.set("state", proxyState);
      params.set("page", String(proxyPage));
      params.set("page_size", String(Math.min(pageSize, 200)));
      const d = await api(`/api/proxies/latency-test?${params.toString()}`, {
        method: "POST",
      });
      notify(
        `测延时完成：${d.checked} 个 · 通过 ${d.passed} · 超时 ${d.timed_out ?? 0} · 失败 ${d.failed}`,
      );
      await refreshAfterMutation();
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setLatencyBusy(false);
    }
  };
  const toggle = async (p: Proxy) => {
    setBusy(true);
    try {
      await api(`/api/proxies/${p.id}`, {
        method: "PATCH",
        body: JSON.stringify({ enabled: !p.enabled }),
      });
      await refreshAfterMutation();
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const remove = async (p: Proxy) => {
    if (!confirm(`删除 ${p.uri}？`)) return;
    setBusy(true);
    try {
      await api(`/api/proxies/${p.id}`, { method: "DELETE" });
      notify("代理已删除");
      await refreshAfterMutation();
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const toggleSelected = (id: number) =>
    setSelected((current) =>
      current.includes(id) ? current.filter((x) => x !== id) : [...current, id],
    );
  const allSelected =
    proxies.length > 0 && proxies.every((proxy) => selected.includes(proxy.id));
  const bulkDelete = async () => {
    if (!selected.length || !confirm(`删除选中的 ${selected.length} 个代理？`))
      return;
    setBusy(true);
    try {
      const d = await api("/api/proxies/bulk-delete", {
        method: "POST",
        body: JSON.stringify({ ids: selected }),
      });
      notify(`已删除 ${d.deleted} 个代理`);
      setSelected([]);
      await refreshAfterMutation();
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const purgeDisabled = async () => {
    if (!confirm("删除全部禁用的代理？此操作不可恢复。")) return;
    setBusy(true);
    try {
      const d = await api("/api/proxies/bulk-delete", {
        method: "POST",
        body: JSON.stringify({ all_disabled: true }),
      });
      notify(`已删除 ${d.deleted} 个禁用代理`);
      setSelected([]);
      await refreshAfterMutation();
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const proxyStatus = (proxy: Proxy) => {
    if (!proxy.enabled) return { label: "已禁用", className: "disabled" };
    if (proxy.health_status === "unknown")
      return { label: "未验证", className: "unknown" };
    if (proxy.health_status === "timeout")
      return { label: "超时", className: "timeout" };
    if (proxy.usage_state === "cooldown")
      return { label: "冷却中", className: "cooldown" };
    if (proxy.usage_state === "in_use")
      return { label: "使用中", className: "in-use" };
    return { label: "健康", className: "healthy" };
  };
  return (
    <div className="page">
      <div className="page-intro">
        <div>
          <div className="eyebrow">NETWORK PATHS</div>
          <h1>代理池</h1>
          <p>用多条路径保持模型请求的可达性。支持 HTTP、HTTPS、SOCKS5 与 mihomo 节点。</p>
        </div>
        <div className="big-number">
          <strong>{fmt(total)}</strong>
          <small>managed paths</small>
        </div>
      </div>
      {hcStatus && (
        <section className="pool-overview">
          <div className="pool-overview-stats">
            <div className="pool-stat">
              <span className="pool-stat-dot ok" />
              <div>
                <strong>{hcStatus.healthy_proxies ?? "—"}</strong>
                <small>健康可用</small>
              </div>
            </div>
            <div className="pool-stat">
              <span className="pool-stat-dot cool" />
              <div>
                <strong>{hcStatus.cooldown_proxies ?? "—"}</strong>
                <small>冷却中</small>
              </div>
            </div>
            <div className="pool-stat">
              <span className="pool-stat-dot timeout" />
              <div>
                <strong>{hcStatus.timeout_proxies ?? "—"}</strong>
                <small>超时</small>
              </div>
            </div>
            <div className="pool-stat">
              <span className="pool-stat-dot unknown" />
              <div>
                <strong>{hcStatus.unknown_proxies ?? "—"}</strong>
                <small>未验证</small>
              </div>
            </div>
            <div className="pool-stat">
              <span className="pool-stat-dot disabled" />
              <div>
                <strong>{hcStatus.disabled_proxies ?? "—"}</strong>
                <small>禁用</small>
              </div>
            </div>
          </div>
          <div className="pool-overview-rail">
            <div className="pool-progress">
              {hcStatus.total_proxies > 0 && (
                <div
                  className="pool-progress-healthy"
                  style={{
                    width: `${
                      ((hcStatus.healthy_proxies || 0) /
                        hcStatus.total_proxies) *
                      100
                    }%`,
                  }}
                />
              )}
            </div>
            <span className="pool-next">
              {hcStatus.running
                ? "健康检查进行中…"
                : hcStatus.next_run_at
                  ? `下次检查：${countdownText(hcStatus.next_run_at)}`
                  : "健康检查未启用"}
            </span>
            {hcStatus.last_run_at && (
              <span className="pool-last">
                上次 {relTime(hcStatus.last_run_at)} · 通过{" "}
                {hcStatus.last_passed} · 失败 {hcStatus.last_failed}
              </span>
            )}
          </div>
        </section>
      )}
      <section className="panel routing-panel">
        <div className="panel-head">
          <div>
            <h3>路由与健康</h3>
            <p className="muted">
              会话路由决定 IP 如何固定与切换；健康检查定期验证所有代理的可用性
            </p>
          </div>
          <Network size={20} />
        </div>
        <div className="routing-section">
          <h4>会话路由</h4>
          <div className="routing-controls">
            <label>
              单会话 / 单代理请求额度
              <input
                type="number"
                min="0"
                max="100000"
                value={sessionLimit}
                onChange={(e) => setSessionLimit(e.target.value)}
              />
              <small className="field-help">
                默认 50。设为 0 时不按请求次数切换，只在上游 429
                或代理故障时切换。
              </small>
            </label>
            <label>
              429 后冷却时长（分钟）
              <input
                type="number"
                min="0"
                max="10080"
                value={quotaCooldown}
                onChange={(e) => setQuotaCooldown(e.target.value)}
              />
              <small className="field-help">
                上游返回 429（IP 额度耗尽）后，该代理进入冷却
                {Number(quotaCooldown) > 0
                  ? `（${fmtDuration(Number(quotaCooldown))}）`
                  : "，0 表示不冷却"}
                。默认 {fmtDuration(1440)}。
              </small>
            </label>
            <button
              className="secondary"
              disabled={busy}
              onClick={async () => {
                const limit = Number(sessionLimit);
                if (!Number.isInteger(limit) || limit < 0 || limit > 100000) {
                  notify("请输入 0 到 100000 之间的整数");
                  return;
                }
                const cooldown = Number(quotaCooldown);
                if (
                  !Number.isInteger(cooldown) ||
                  cooldown < 0 ||
                  cooldown > 10080
                ) {
                  notify("请输入 0 到 10080 之间的整数");
                  return;
                }
                setBusy(true);
                try {
                  await api("/api/settings/routing", {
                    method: "PUT",
                    body: JSON.stringify({
                      session_proxy_request_limit: limit,
                      quota_429_cooldown_minutes: cooldown,
                    }),
                  });
                  notify("会话路由配置已保存");
                  reload();
                } catch (e) {
                  notify((e as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              保存配置
            </button>
          </div>
        </div>
        <div className="routing-section">
          <h4>
            健康检查
            <ShieldCheck size={15} />
          </h4>
          <div className="routing-controls">
            <label>
              检查间隔（分钟）
              <input
                type="number"
                min="0"
                max="10080"
                value={hcInterval}
                onChange={(e) => setHcInterval(e.target.value)}
              />
              <small className="field-help">
                默认 120（每 2 小时）。设为 0 关闭定时检查。失败的代理冷却
                {Number(hcInterval) > 0
                  ? ` ${fmtDuration(Number(hcInterval))}（下次检查时重新测试）`
                  : "（当前已关闭）"}
                。
              </small>
            </label>
            <label>
              测试地址（可选）
              <input
                value={hcTestURL}
                onChange={(e) => setHcTestURL(e.target.value)}
                placeholder="留空自动使用上游聊天接口"
              />
              <small className="field-help">
                留空时会向配置的上游发送 max_tokens=1
                的真实请求（能检测 IP 额度耗尽）；未配置上游时使用
                gstatic.com/generate_204。
              </small>
            </label>
            <label>
              连续失败删除阈值
              <input
                type="number"
                min={0}
                value={hcMaxFailures}
                onChange={(e) => setHcMaxFailures(e.target.value)}
              />
              <small className="field-help">
                连续失败（含外网不通）达到该次数自动禁用节点，0 表示关闭自动禁用。
              </small>
            </label>
            <div className="config-actions">
              <button className="secondary" onClick={saveHealthCheck} disabled={busy}>
                保存配置
              </button>
              <button
                className="secondary"
                onClick={runHealthCheck}
                disabled={busy || hcStatus?.running}
              >
                {hcStatus?.running ? "测试进行中…" : "立即测试"}
              </button>
              <button
                className="secondary"
                onClick={runUnverifiedCheck}
                disabled={busy || hcStatus?.running}
              >
                测试未验证
              </button>
            </div>
            {hcStatus?.last_run_at && (
              <p className="muted">
                上次运行：
                {new Date(hcStatus.last_run_at).toLocaleString("zh-CN")} · 通过{" "}
                {hcStatus.last_passed} · 失败 {hcStatus.last_failed} · 耗时{" "}
                {hcStatus.last_duration_s} 秒
                {hcStatus.running && " · 正在运行…"}
              </p>
            )}
          </div>
        </div>
      </section>
      <section className="panel import-panel">
        <div className="panel-head">
          <div>
            <h3>批量导入</h3>
            <p className="muted">
              每行一个代理：http://…、socks5://…，或 mihomo://节点名
            </p>
          </div>
          <Upload size={20} />
        </div>
        <label className="subscription-import">
          <span>机场订阅地址</span>
          <div className="subscription-import-row">
            <input
              type="url"
              value={subscriptionURL}
              onChange={(e) => setSubscriptionURL(e.target.value)}
              placeholder="https://example.com/subscription"
            />
            <button className="secondary" onClick={importSubscription} disabled={busy || !subscriptionURL.trim()}>
              从订阅导入
            </button>
          </div>
          <small className="field-help">自动下载并解析 vless 节点，写入 Mihomo 对应地区分组和当前代理池。</small>
        </label>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={"http://10.0.0.2:8080\nsocks5://user:pass@10.0.0.3:1080"}
        />
        <div className="expiry-controls">
          <label>
            有效期
            <select value={expiry} onChange={(e) => setExpiry(e.target.value)}>
              <option value="0">永久</option>
              <option value="1">1 天</option>
              <option value="7">7 天</option>
              <option value="30">30 天</option>
              <option value="90">90 天</option>
              <option value="custom">自定义到期时间</option>
            </select>
          </label>
          {expiry === "custom" && (
            <label>
              到期时间
              <input
                type="datetime-local"
                value={customExpiry}
                onChange={(e) => setCustomExpiry(e.target.value)}
                min={new Date().toISOString().slice(0, 16)}
              />
            </label>
          )}
        </div>
        <button className="primary" onClick={importIt} disabled={busy}>
          <Upload size={16} />
          {busy ? "导入中…" : "导入代理"}
        </button>
        <button
          className="secondary"
          onClick={importMihomo}
          disabled={busy}
          style={{ marginLeft: 8 }}
        >
          从 mihomo 载入节点
        </button>
      </section>
      <section className="panel">
        <div className="panel-head">
          <div>
            <h3>当前路径</h3>
            <p className="muted">失败路径会短暂冷却；到期代理会自动删除。</p>
          </div>
          <div className="proxy-actions">
            <label className="proxy-state-filter">
              <span>筛选</span>
              <select
                value={proxyState}
                disabled={loading || busy}
                onChange={(event) => {
                  setProxyState(event.target.value as ProxyFilterState);
                  setProxyPage(1);
                  setSelected([]);
                }}
              >
                <option value="all">全部代理</option>
                <option value="unverified">未验证</option>
                <option value="healthy">健康</option>
                <option value="cooldown">冷却中</option>
                <option value="timeout">超时</option>
                <option value="disabled">禁用</option>
              </select>
            </label>
            <label className="select-all">
              <input
                type="checkbox"
                checked={allSelected}
                onChange={(e) =>
                  setSelected(e.target.checked ? proxies.map((p) => p.id) : [])
                }
                disabled={!proxies.length || loading || busy}
              />
              <span>全选本页</span>
            </label>
            <button
              className="danger-button"
              onClick={bulkDelete}
              disabled={!selected.length || busy || loading}
            >
              <Trash2 size={14} />
              删除选中
            </button>
            <button
              className="danger-button"
              onClick={purgeDisabled}
              disabled={busy || loading}
            >
              <Trash2 size={14} />
              清理全部禁用
            </button>
            <button
              className="secondary"
              onClick={runLatencyTest}
              disabled={busy || loading || latencyBusy || !proxies.length}
              title="对谷歌测延时（当前筛选范围内全部节点，含禁用节点）"
            >
              <CircleGauge size={14} />
              {latencyBusy ? "测延时中…" : "测延时"}
            </button>
            <span className="count-chip">{fmt(total)} 条</span>
          </div>
        </div>
        <div className={`data-table ${loading ? "is-loading" : ""}`}>
          <div className="table-head">
            <span>URI</span>
            <span>状态</span>
            <span>失败次数</span>
            <span>操作</span>
          </div>
          {proxies.map((p) => {
            const status = proxyStatus(p);
            const schemeTag =
              p.scheme === "mihomo"
                ? { label: "MIHOMO", className: "badge-mihomo" }
                : p.scheme === "socks5" || p.scheme === "socks5h"
                  ? { label: "SOCKS5", className: "badge-socks" }
                  : { label: "HTTP", className: "badge-http" };
            return (
            <div className="table-row" key={p.id}>
              <div className="proxy-uri-cell">
                <input
                  type="checkbox"
                  checked={selected.includes(p.id)}
                  onChange={() => toggleSelected(p.id)}
                  disabled={loading || busy}
                  aria-label={`选择 ${p.uri}`}
                />
                <div>
                  <b className="mono" title={p.uri}>
                    {p.scheme === "mihomo"
                      ? p.host
                      : p.uri.replace(/^[a-z0-9]+:\/\//, "")}
                  </b>
                  <small>
                    <span className={`scheme-badge ${schemeTag.className}`}>
                      {schemeTag.label}
                    </span>
                    {p.scheme === "mihomo"
                      ? " 经 mihomo 桥接"
                      : ` ${p.host}:${p.port}`}
                    {p.expires_at
                      ? ` · 到期 ${new Date(p.expires_at).toLocaleDateString()}`
                      : ""}
                  </small>
                </div>
              </div>
              <span className={`health ${status.className}`}>
                <i />
                {status.label}
                <small className="check-note">
                  {p.last_checked_at
                    ? `${relTime(p.last_checked_at)}${
                        p.last_check_ok ? " 验证通过" : " 验证失败"
                      }`
                    : "未检查"}
                  {p.last_latency_ms !== undefined ? ` · ${p.last_latency_ms}ms` : ""}
                </small>
              </span>
              <span>{p.failure_count}</span>
              <div className="row-actions">
                {testResult?.id === p.id && (
                  <span
                    className={`test-feedback ${testResult.ok ? "ok" : "fail"}`}
                    title={testResult.error || ""}
                  >
                    {testResult.ok
                      ? `通过${testResult.latency_ms !== undefined ? ` · ${testResult.latency_ms}ms` : ""}`
                      : "失败"}
                  </span>
                )}
                <button
                  className="text-btn"
                  title="立即测试"
                  disabled={busy || loading || testingId !== null}
                  onClick={() => testOne(p)}
                >
                  {testingId === p.id ? "测试中…" : "测试"}
                </button>
                <button
                  className="text-btn"
                  disabled={busy || loading}
                  onClick={() => toggle(p)}
                >
                  {p.enabled ? "禁用" : "启用"}
                </button>
                <button
                  className="danger-icon"
                  title="删除"
                  disabled={busy || loading}
                  onClick={() => remove(p)}
                >
                  <Trash2 size={15} />
                </button>
              </div>
            </div>
            );
          })}
          {loading && proxies.length === 0 && <SkeletonRows rows={5} cols={4} />}
          {!loading && proxies.length === 0 && (
            <Empty text="先导入第一条代理路径" />
          )}
        </div>
        <div className="proxy-pagination" aria-label="代理分页">
          <span className="pagination-range" aria-live="polite">
            {total === 0
              ? "0 / 0"
              : `${(proxyPage - 1) * pageSize + 1}-${Math.min(proxyPage * pageSize, total)} / ${fmt(total)}`}
          </span>
          <label className="page-size-control">
            <span>每页</span>
            <select
              value={pageSize}
              disabled={loading}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setProxyPage(1);
              }}
            >
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={200}>200</option>
            </select>
          </label>
          <div className="page-navigation">
            <button
              className="icon-btn"
              type="button"
              title="上一页"
              aria-label="上一页"
              disabled={loading || proxyPage <= 1}
              onClick={() =>
                setProxyPage((current) => Math.max(1, current - 1))
              }
            >
              <ChevronLeft size={16} />
            </button>
            <span className="page-indicator">
              第 {proxyPage} / {totalPages} 页
            </span>
            <button
              className="icon-btn"
              type="button"
              title="下一页"
              aria-label="下一页"
              disabled={loading || proxyPage >= totalPages}
              onClick={() =>
                setProxyPage((current) => Math.min(totalPages, current + 1))
              }
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}

function Models({
  models,
  upstream,
  reload,
  notify,
}: {
  models: Model[];
  upstream: any;
  reload: () => void;
  notify: (v: string) => void;
}) {
	const upstreamHeadersText = headersToText(upstream.custom_headers);
	const [base, setBase] = useState(upstream.base_url || "");
  const [key, setKey] = useState("");
  const [visionBase, setVisionBase] = useState(upstream.vision_base_url || "");
  const [visionKey, setVisionKey] = useState("");
  const [visionModel, setVisionModel] = useState(upstream.vision_model || "");
  const [visionUseProxy, setVisionUseProxy] = useState(
    upstream.vision_use_proxy !== false,
  );
	const [headers, setHeaders] = useState(upstreamHeadersText);
  const [clientKey, setClientKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [testResult, setTestResult] = useState<any>(null);
  const [mihomo, setMihomo] = useState<any>({});
  const [mihomoControl, setMihomoControl] = useState("");
  const [mihomoSecret, setMihomoSecret] = useState("");
  const [mihomoEntry, setMihomoEntry] = useState("");
  const [mihomoSelector, setMihomoSelector] = useState("");
  const [mihomoBusy, setMihomoBusy] = useState(false);
  useEffect(() => {
    (async () => {
      try {
        const d = await api("/api/settings/mihomo");
        setMihomo(d);
        setMihomoControl(d.control_url || "");
        setMihomoEntry(d.entry_proxy || "");
        setMihomoSelector(d.selector || "");
      } catch {
        /* 未配置 mihomo 时静默 */
      }
      try {
        const d = await api("/api/settings/client-key");
        if (d.client_key) setClientKey(d.client_key);
      } catch {
        /* 未配置 client key 时静默 */
      }
    })();
  }, []);
  useEffect(() => {
    setBase(upstream.base_url || "");
    setVisionBase(upstream.vision_base_url || "");
    setVisionModel(upstream.vision_model || "");
    setVisionUseProxy(upstream.vision_use_proxy !== false);
		setHeaders(upstreamHeadersText);
  }, [
    upstream.base_url,
		upstreamHeadersText,
    upstream.vision_base_url,
    upstream.vision_model,
    upstream.vision_use_proxy,
  ]);
  const save = async () => {
    let customHeaders: Record<string, string>;
    try {
      customHeaders = parseHeaderText(headers);
    } catch (e) {
      notify((e as Error).message);
      return;
    }
    setBusy(true);
    try {
      await api("/api/settings/upstream", {
        method: "PUT",
        body: JSON.stringify({
          base_url: base,
          api_key: key,
          vision_base_url: visionBase,
          vision_api_key: visionKey,
          vision_model: visionModel,
          vision_use_proxy: visionUseProxy,
          custom_headers: customHeaders,
        }),
      });
      notify("上游配置已保存");
      setKey("");
      setVisionKey("");
      reload();
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const refresh = async () => {
    setBusy(true);
    try {
      const d = await api("/api/settings/models/refresh", { method: "POST" });
      notify(d.warning || `已刷新 ${d.free_model_count} 个 Free 模型`);
      reload();
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const rotate = async () => {
    if (!confirm("轮换后旧客户端 Key 会立即失效，继续？")) return;
    try {
      const d = await api("/api/settings/client-key/rotate", {
        method: "POST",
      });
      setClientKey(d.client_key);
      notify("新 Key 已生成，请立即复制");
    } catch (e) {
      notify((e as Error).message);
    }
  };
  const testKey = async () => {
    setBusy(true);
    setTestResult(null);
    try {
      const d = await api("/api/settings/upstream/test", { method: "POST" });
      setTestResult(d);
      notify("上游 Key 测试完成");
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const saveMihomo = async () => {
    setMihomoBusy(true);
    try {
      await api("/api/settings/mihomo", {
        method: "PUT",
        body: JSON.stringify({
          control_url: mihomoControl,
          secret: mihomoSecret,
          entry_proxy: mihomoEntry,
          selector: mihomoSelector,
        }),
      });
      notify("mihomo 桥接配置已保存");
      setMihomoSecret("");
      reload();
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setMihomoBusy(false);
    }
  };
  const copy = () => {
    navigator.clipboard?.writeText(`${location.origin}/v1`);
    notify("网关地址已复制");
  };
  const copyKey = () => {
    navigator.clipboard?.writeText(clientKey);
    notify("客户端 Key 已复制");
  };
  return (
    <div className="page">
      <div className="page-intro">
        <div>
          <div className="eyebrow">MODEL DIRECTORY</div>
          <h1>模型与网关</h1>
          <p>从上游拉取模型，只把真正免费的路径交给客户端。</p>
        </div>
        <button className="primary" onClick={refresh} disabled={busy}>
          <RefreshCw size={16} />
          {busy ? "刷新中…" : "刷新模型"}
        </button>
      </div>
      <section className="config-grid">
        <div className="panel">
          <div className="panel-head">
            <div>
              <h3>上游端点</h3>
              <p className="muted">凭证只在服务器侧使用</p>
            </div>
            <Server size={20} />
          </div>
          <label>
            Base URL
            <input
              value={base}
              onChange={(e) => setBase(e.target.value)}
              placeholder="https://api.example.com"
            />
          </label>
          <label>
            API Key
            <input
              type="password"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder={
                upstream.has_api_key
                  ? "已保存 · 留空保持不变"
                  : "输入上游 OpenCode / Zen Key"
              }
            />
            <small className="field-help">
              这里填写上游 OpenCode / Zen API Key，不是下面的网关 Key。粘贴带
              Bearer 前缀的值也会自动处理。
            </small>
          </label>
          <label>
            自定义请求头
            <textarea
              className="headers-input"
              value={headers}
              onChange={(e) => setHeaders(e.target.value)}
              spellCheck={false}
              placeholder={
                "User-Agent: opencode/1.18.12 ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.13\nx-opencode-client: cli"
              }
            />
          </label>
          <p className="muted header-note">
            每行一个 <code>Header-Name: value</code>
            。模型刷新和聊天请求都会使用这些值。
          </p>
          <div className="config-actions">
            <button className="secondary" onClick={save} disabled={busy}>
              保存配置
            </button>
            <button className="secondary" onClick={testKey} disabled={busy}>
              测试上游 Key
            </button>
          </div>
          {testResult && (
            <div className="test-result">
              <b>测试模型：{testResult.model}</b>
              <span>
                直连：
                {testResult.direct?.status_code ||
                  testResult.direct?.status}{" "}
                {testResult.direct?.message || ""}
              </span>
              <span>
                代理：
                {testResult.proxy?.status_code || testResult.proxy?.status}{" "}
                {testResult.proxy?.message || ""}
              </span>
            </div>
          )}
          {upstream.last_model_refresh_error && (
            <div className="error-line">
              {upstream.last_model_refresh_error}
            </div>
          )}
        </div>
        <div className="panel">
          <div className="panel-head">
            <div>
              <h3>mihomo 桥接</h3>
              <p className="muted">
                把 mihomo 节点作为代理池路径，转发前自动切换到对应节点
              </p>
            </div>
            <Network size={20} />
          </div>
          <label>
            控制 API 地址
            <input
              value={mihomoControl}
              onChange={(e) => setMihomoControl(e.target.value)}
              placeholder="http://172.25.0.1:9090"
            />
            <small className="field-help">
              mihomo external-controller 地址；容器内请填宿主机网关 IP
            </small>
          </label>
          <label>
            Secret
            <input
              type="password"
              value={mihomoSecret}
              onChange={(e) => setMihomoSecret(e.target.value)}
              placeholder={
                mihomo.has_secret ? "已保存 · 留空保持不变" : "mihomo 控制 API 密码"
              }
            />
          </label>
          <label>
            入口代理
            <input
              value={mihomoEntry}
              onChange={(e) => setMihomoEntry(e.target.value)}
              placeholder="socks5://172.25.0.1:7890"
            />
            <small className="field-help">
              mihomo mixed-port 入口，支持 http/https/socks5
            </small>
          </label>
          <label>
            节点选择器组名
            <input
              value={mihomoSelector}
              onChange={(e) => setMihomoSelector(e.target.value)}
              placeholder="🚀节点选择"
            />
            <small className="field-help">
              留空默认使用 🚀节点选择；请保证该选择器在 mihomo 中存在
            </small>
          </label>
          <div className="config-actions">
            <button
              className="secondary"
              onClick={saveMihomo}
              disabled={mihomoBusy}
            >
              保存 mihomo 配置
            </button>
          </div>
        </div>
        <div className="panel gateway-card">
          <div className="eyebrow">CLIENT GATEWAY</div>
          <h3>给 OpenCode 的地址</h3>
          <div className="copy-field">
            <code>{location.origin}/v1</code>
            <button className="icon-btn" title="复制地址" onClick={copy}>
              <Copy size={15} />
            </button>
          </div>
          <div className="gateway-meta">
            <span>
              <KeyRound size={14} />
              客户端 Key
            </span>
            <button className="text-btn" onClick={rotate}>
              轮换 Key
            </button>
          </div>
          {clientKey && (
            <div className="copy-field">
              <code>{clientKey}</code>
              <button className="icon-btn" title="复制 Key" onClick={copyKey}>
                <Copy size={15} />
              </button>
            </div>
          )}
          <p className="muted small">
            这是给 OpenCode 客户端使用的网关 Key，以 ocp- 开头；不要把它填入上游
            API Key。Key 会一直显示在此处，轮换后旧 Key 立即失效。
          </p>
        </div>
      </section>
      <section className="panel vision-helper-panel">
        <div className="panel-head">
          <div>
            <span className="eyebrow">OPTIONAL VISION BRIDGE</span>
            <h3>图片辅助模型</h3>
            <p className="muted">
              使用独立供应商的多模态模型先描述图片，再交给纯文本模型处理。
            </p>
          </div>
          <ImageIcon size={20} />
        </div>
        <div className="vision-grid">
          <label>
            辅助 Base URL
            <input
              value={visionBase}
              onChange={(e) => setVisionBase(e.target.value)}
              placeholder="https://vision-provider.example.com"
            />
          </label>
          <label>
            辅助模型 ID
            <input
              value={visionModel}
              onChange={(e) => setVisionModel(e.target.value)}
              placeholder="provider/vision-model"
            />
          </label>
          <label>
            辅助 API Key
            <input
              type="password"
              value={visionKey}
              onChange={(e) => setVisionKey(e.target.value)}
              placeholder={
                upstream.has_vision_api_key
                  ? "已保存 · 留空保持不变"
                  : "输入辅助供应商 API Key"
              }
            />
          </label>
        </div>
        <label className="vision-proxy-toggle">
          <input
            type="checkbox"
            checked={visionUseProxy}
            onChange={(e) => setVisionUseProxy(e.target.checked)}
          />
          <span>
            <b>使用代理池</b>
            <small>
              {visionUseProxy
                ? "图片辅助请求通过当前选中的代理发送。"
                : "图片辅助请求直接连接供应商；主模型请求仍使用代理池。"}
            </small>
          </span>
        </label>
        <p className="muted vision-helper-note">
          三项同时填写后启用。辅助请求不会使用 OpenCode 上游
          Key，也不会把图片内容写入使用记录；请点击上方“保存配置”生效。
        </p>
      </section>
      <section className="panel">
        <div className="panel-head">
          <div>
            <h3>Free 模型</h3>
            <p className="muted">
              {upstream.last_model_refresh_at
                ? `最近刷新 ${new Date(upstream.last_model_refresh_at).toLocaleString()}`
                : "尚未刷新"}
            </p>
          </div>
          <span className="count-chip">{models.length} available</span>
        </div>
        <div className="model-grid">
          {models.map((m) => (
            <div className="model-card" key={m.model_id}>
              <div className="model-card-top">
                <span className="model-swatch">✦</span>
                <span className="status-tag">FREE</span>
              </div>
              <b>{m.model_id}</b>
              <small>{m.display_name}</small>
              <span className="reason">
                {m.free_reason.replaceAll("_", " ")}
              </span>
            </div>
          ))}
          {models.length === 0 && <Empty text="刷新上游以发现 Free 模型" />}
        </div>
      </section>
    </div>
  );
}

function PasswordCard({ notify }: { notify: (v: string) => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    if (next.length < 8) {
      notify("新密码至少需要 8 个字符");
      return;
    }
    setBusy(true);
    try {
      await api("/api/auth/password", {
        method: "POST",
        body: JSON.stringify({ current, new: next }),
      });
      setCurrent("");
      setNext("");
      notify("管理员密码已更新，请重新登录");
      window.setTimeout(() => window.location.reload(), 500);
    } catch (e) {
      notify((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="panel security-panel">
      <div className="panel-head">
        <div>
          <span className="eyebrow">SECURITY</span>
          <h3>管理员密码</h3>
          <p className="muted">修改后会撤销所有控制台会话并要求重新登录。</p>
        </div>
        <KeyRound size={20} />
      </div>
      <div className="password-grid">
        <label>
          当前密码
          <input
            type="password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
          />
        </label>
        <label>
          新密码
          <input
            type="password"
            value={next}
            maxLength={72}
            onChange={(e) => setNext(e.target.value)}
            placeholder="至少 8 个字符"
          />
        </label>
        <button className="secondary" onClick={submit} disabled={busy}>
          更新密码
        </button>
      </div>
    </section>
  );
}

function SettingsPage({
  notify,
  onLogout,
}: {
  notify: (value: string) => void;
  onLogout: () => void;
}) {
  const [retentionDays, setRetentionDays] = useState(90);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let active = true;
    api("/api/settings/usage-retention")
      .then((data) => {
        if (active) setRetentionDays(data.usage_retention_days);
      })
      .catch((error) => {
        if ((error as Error).message === "AUTH") onLogout();
        else notify((error as Error).message);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [notify, onLogout]);

  const saveRetention = async () => {
    setSaving(true);
    try {
      const data = await api("/api/settings/usage-retention", {
        method: "PUT",
        body: JSON.stringify({ usage_retention_days: retentionDays }),
      });
      setRetentionDays(data.usage_retention_days);
      notify("使用记录保留时间已保存");
    } catch (error) {
      if ((error as Error).message === "AUTH") onLogout();
      else notify((error as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="page">
      <div className="page-intro">
        <div>
          <div className="eyebrow">CONSOLE SETTINGS</div>
          <h1>设置</h1>
          <p>管理控制台访问和使用记录保留策略。</p>
        </div>
      </div>
      <PasswordCard notify={notify} />
      <section className="panel retention-panel">
        <div className="panel-head">
          <div>
            <span className="eyebrow">DATA RETENTION</span>
            <h3>使用记录保留时间</h3>
            <p className="muted">超过保留期限的请求记录会自动删除。</p>
          </div>
          <Database size={20} />
        </div>
        <div className="retention-controls">
          <label>
            保留期限
            <select
              value={retentionDays}
              disabled={loading || saving}
              onChange={(event) => setRetentionDays(Number(event.target.value))}
            >
              <option value={7}>7 天</option>
              <option value={30}>30 天</option>
              <option value={90}>90 天</option>
              <option value={180}>180 天</option>
            </select>
          </label>
          <button
            className="secondary"
            onClick={saveRetention}
            disabled={loading || saving}
          >
            {saving ? "保存中…" : "保存设置"}
          </button>
        </div>
      </section>
    </div>
  );
}

const usageTimeOptions: Array<{ value: UsageTimePreset; label: string }> = [
  { value: "all", label: "全部" },
  { value: "1h", label: "近 1 小时" },
  { value: "24h", label: "近 24 小时" },
  { value: "7d", label: "近 7 天" },
  { value: "30d", label: "近 30 天" },
  { value: "custom", label: "自定义" },
];

const emptyUsageFilters = (): UsageFilters => ({
  time: "all",
  model: "",
  status: "",
  customFrom: "",
  customTo: "",
});

const formatDuration = (milliseconds?: number) => {
  if (milliseconds === undefined || milliseconds === null) return "—";
  if (milliseconds < 1000) return `${Math.round(milliseconds)} ms`;
  return `${new Intl.NumberFormat("zh-CN", {
    minimumFractionDigits: 0,
    maximumFractionDigits: 2,
  }).format(milliseconds / 1000)} s`;
};

function Usage({
  notify,
  onLogout,
  refreshToken,
}: {
  notify: (value: string) => void;
  onLogout: () => void;
	refreshToken: number;
}) {
	const documentVisible = useDocumentVisible();
	const [rows, setRows] = useState<RequestRow[]>([]);
  const [models, setModels] = useState<string[]>([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [draftFilters, setDraftFilters] = useState<UsageFilters>(
    emptyUsageFilters,
  );
  const [appliedFilters, setAppliedFilters] = useState<UsageFilters>(
    emptyUsageFilters,
  );
  const [rates, setRates] = useState<UsageRates>({
    window_seconds: 60,
    rpm: 0,
    tpm: 0,
    measured_at: "",
  });
  const [dailyUsage, setDailyUsage] = useState<DailyUsage[]>([]);
  const [selected, setSelected] = useState<RequestRow | null>(null);

  const requestPath = useMemo(() => {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(pageSize),
    });
    const durations: Partial<Record<UsageTimePreset, number>> = {
      "1h": 60 * 60 * 1000,
      "24h": 24 * 60 * 60 * 1000,
      "7d": 7 * 24 * 60 * 60 * 1000,
      "30d": 30 * 24 * 60 * 60 * 1000,
    };
    const duration = durations[appliedFilters.time];
    if (duration) {
      params.set("from", new Date(Date.now() - duration).toISOString());
    } else if (appliedFilters.time === "custom") {
      params.set("from", new Date(appliedFilters.customFrom).toISOString());
      params.set("to", new Date(appliedFilters.customTo).toISOString());
    }
    if (appliedFilters.model) params.set("model", appliedFilters.model);
    if (appliedFilters.status) params.set("status", appliedFilters.status);
    return `/api/usage/requests?${params.toString()}`;
  }, [appliedFilters, page, pageSize, refreshToken]);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setLoading(true);
    api(requestPath, { signal: controller.signal })
      .then((data: UsagePage) => {
        if (!active) return;
        setRows(data.items);
        setModels(data.models);
        setTotal(data.total);
        setTotalPages(data.total_pages);
        if (data.page !== page) setPage(data.page);
      })
      .catch((error) => {
        if ((error as Error).name === "AbortError") return;
        if ((error as Error).message === "AUTH") {
          onLogout();
          return;
        }
        notify((error as Error).message);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [requestPath]);

	useEffect(() => {
		if (!documentVisible) return;
		let active = true;
    const loadRates = async () => {
      try {
        const data = (await api("/api/usage/rates")) as UsageRates;
        if (active) setRates(data);
      } catch (error) {
        if ((error as Error).message === "AUTH") onLogout();
      }
    };
    void loadRates();
    const timer = window.setInterval(loadRates, 10_000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
	}, [documentVisible, refreshToken]);

  useEffect(() => {
    let active = true;
    api("/api/stats/timeseries")
      .then((data: DailyUsage[]) => {
        if (active) setDailyUsage(data);
      })
      .catch((error) => {
        if ((error as Error).message === "AUTH") onLogout();
        else notify((error as Error).message);
      });
    return () => {
      active = false;
    };
  }, [notify, onLogout, refreshToken]);

  const applyFilters = (event: React.FormEvent) => {
    event.preventDefault();
    if (draftFilters.time === "custom") {
      if (!draftFilters.customFrom || !draftFilters.customTo) {
        notify("请选择自定义时间的开始和结束");
        return;
      }
      const from = new Date(draftFilters.customFrom);
      const to = new Date(draftFilters.customTo);
      if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) {
        notify("自定义时间格式无效");
        return;
      }
      if (from > to) {
        notify("开始时间不能晚于结束时间");
        return;
      }
    }
    setAppliedFilters({ ...draftFilters });
    setPage(1);
  };

  const clearFilters = () => {
    const cleared = emptyUsageFilters();
    setDraftFilters(cleared);
    setAppliedFilters(cleared);
    setPage(1);
  };

  return (
    <div className="page">
      <div className="page-intro usage-page-intro">
        <div>
          <div className="eyebrow">AUDIT TRAIL</div>
          <h1>使用记录</h1>
          <p>按模型、时间与结果检查每次上游调用的吞吐和响应速度。</p>
        </div>
        <div className="usage-rate-rail" aria-label="最近 60 秒速率">
          <div className="usage-rate-context">
            <Activity size={16} />
            <span>
              <b>实时速率</b>
              <small>
                全局最近 {rates.window_seconds} 秒
                {rates.measured_at
                  ? ` · ${new Date(rates.measured_at).toLocaleTimeString()}`
                  : ""}
              </small>
            </span>
          </div>
          <div className="usage-rate-value">
            <span>RPM</span>
            <strong>{fmt(rates.rpm)}</strong>
          </div>
          <div className="usage-rate-value">
            <span>TPM</span>
            <strong>{fmt(rates.tpm)}</strong>
          </div>
        </div>
      </div>
      <section className="panel daily-usage-panel">
        <div className="panel-head">
          <div>
            <span className="eyebrow">DAILY TOTALS</span>
            <h3>每日 Token</h3>
            <p className="muted">按北京时间 00:00 汇总，保留最近 30 个自然日。</p>
          </div>
          <span className="count-chip">{dailyUsage.length} 天</span>
        </div>
        <div className="daily-usage-scroll">
          <div className="daily-usage-table">
            <div className="daily-usage-head">
              <span>日期</span>
              <span>请求数</span>
              <span>总 Token</span>
            </div>
            {dailyUsage.map((day) => (
              <div className="daily-usage-row" key={day.day}>
                <span>{day.day}</span>
                <span>{fmt(day.requests)}</span>
                <strong>{fmt(day.tokens)}</strong>
              </div>
            ))}
            {dailyUsage.length === 0 && <Empty text="暂无每日 Token 汇总" />}
          </div>
        </div>
      </section>
      <section className="panel">
        <form className="usage-filters" onSubmit={applyFilters}>
          <div className="usage-filter-time">
            <label>
              <CalendarRange size={14} /> 时间范围
            </label>
            <div className="time-segments" role="group" aria-label="时间范围">
              {usageTimeOptions.map((option) => (
                <button
                  type="button"
                  key={option.value}
                  className={draftFilters.time === option.value ? "active" : ""}
                  aria-pressed={draftFilters.time === option.value}
                  onClick={() =>
                    setDraftFilters((current) => ({
                      ...current,
                      time: option.value,
                    }))
                  }
                >
                  {option.label}
                </button>
              ))}
            </div>
          </div>
          <label className="usage-filter-select">
            <span>模型</span>
            <select
              value={draftFilters.model}
              onChange={(event) =>
                setDraftFilters((current) => ({
                  ...current,
                  model: event.target.value,
                }))
              }
            >
              <option value="">全部模型</option>
              {models.map((model) => (
                <option value={model} key={model}>
                  {model}
                </option>
              ))}
            </select>
          </label>
          <label className="usage-filter-select usage-result-filter">
            <span>请求结果</span>
            <select
              value={draftFilters.status}
              onChange={(event) =>
                setDraftFilters((current) => ({
                  ...current,
                  status: event.target.value as UsageFilters["status"],
                }))
              }
            >
              <option value="">全部结果</option>
              <option value="success">成功</option>
              <option value="error">用户错误</option>
              <option value="external">外部异常</option>
            </select>
          </label>
          {draftFilters.time === "custom" && (
            <div className="usage-custom-range">
              <label>
                <span>开始时间</span>
                <input
                  type="datetime-local"
                  value={draftFilters.customFrom}
                  onChange={(event) =>
                    setDraftFilters((current) => ({
                      ...current,
                      customFrom: event.target.value,
                    }))
                  }
                />
              </label>
              <label>
                <span>结束时间</span>
                <input
                  type="datetime-local"
                  value={draftFilters.customTo}
                  onChange={(event) =>
                    setDraftFilters((current) => ({
                      ...current,
                      customTo: event.target.value,
                    }))
                  }
                />
              </label>
            </div>
          )}
          <div className="usage-filter-actions">
            <button className="primary" type="submit" disabled={loading}>
              <Filter size={14} />
              应用筛选
            </button>
            <button
              className="secondary"
              type="button"
              onClick={clearFilters}
              disabled={loading}
            >
              <FilterX size={14} />
              清除
            </button>
          </div>
        </form>
        <div className="panel-head">
          <div>
            <h3>请求记录</h3>
            <p className="muted">全部历史记录 · 最新完成优先</p>
          </div>
          <span className="count-chip">{fmt(total)} 条记录</span>
        </div>
        <div className="usage-table-scroll">
          <div className={`data-table usage-table ${loading ? "is-loading" : ""}`}>
            <div className="table-head">
              <span>模型 / 完成时间</span>
              <span>请求结果</span>
              <span>输入 Token</span>
              <span>输出 Token</span>
              <span>首字耗时</span>
              <span>总耗时</span>
              <span>路径</span>
            </div>
            {rows.map((r) => (
              <div
                className="table-row clickable-row"
                key={r.id}
                title="点击查看详情"
                onClick={() => setSelected(r)}
              >
                <div>
                  <div className="request-model-line">
                    <b title={r.model}>{r.model}</b>
                    {r.request_kind === "vision_helper" && (
                      <span className="helper-tag">图片辅助</span>
                    )}
                  </div>
                  <small>{new Date(r.created_at).toLocaleString()}</small>
                </div>
                <div className="usage-result-cell">
                  <span
                    className={`health ${r.status === "success" ? "healthy" : r.error_origin === "external" ? "external" : r.error_origin === "internal" ? "internal" : "cooldown"}`}
                  >
                    <i />
                    {r.status === "success"
                      ? "成功"
                      : r.error_origin === "external"
                        ? "外部异常"
                        : r.error_origin === "internal"
                          ? "内部步骤"
                          : `HTTP ${r.status_code}`}
                  </span>
                  {r.error_message && (
                    <small className="request-error" title={r.error_message}>
                      {r.error_message}
                    </small>
                  )}
                </div>
                <span className="usage-number">
                  {r.prompt_tokens === undefined ? "—" : fmt(r.prompt_tokens)}
                </span>
                <span className="usage-number">
                  {r.completion_tokens === undefined
                    ? "—"
                    : fmt(r.completion_tokens)}
                </span>
                <span className="usage-duration">
                  {formatDuration(r.first_token_latency_ms)}
                </span>
                <span className="usage-duration">
                  {formatDuration(r.latency_ms)}
                </span>
                <span className="mono tiny usage-path" title={r.proxy_uri || "direct"}>
                  {r.proxy_uri || "direct"}
                </span>
              </div>
            ))}
            {loading && rows.length === 0 && <SkeletonRows rows={6} cols={7} />}
            {!loading && rows.length === 0 && (
              <Empty text="当前筛选条件下没有使用记录" />
            )}
          </div>
        </div>
        <div className="usage-pagination" aria-label="使用记录分页">
          <span className="pagination-range" aria-live="polite">
            {total === 0
              ? "0 / 0"
              : `${(page - 1) * pageSize + 1}-${Math.min(page * pageSize, total)} / ${fmt(total)}`}
          </span>
          <label className="page-size-control">
            <span>每页</span>
            <select
              value={pageSize}
              disabled={loading}
              onChange={(event) => {
                setPageSize(Number(event.target.value));
                setPage(1);
              }}
            >
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </label>
          <div className="page-navigation">
            <button
              className="icon-btn"
              type="button"
              title="上一页"
              aria-label="上一页"
              disabled={loading || page <= 1}
              onClick={() => setPage((current) => Math.max(1, current - 1))}
            >
              <ChevronLeft size={16} />
            </button>
            <span className="page-indicator">
              第 {page} / {totalPages} 页
            </span>
            <button
              className="icon-btn"
              type="button"
              title="下一页"
              aria-label="下一页"
              disabled={loading || page >= totalPages}
              onClick={() =>
                setPage((current) => Math.min(totalPages, current + 1))
              }
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </section>
      {selected && (
        <div className="drawer-overlay" onClick={() => setSelected(null)}>
          <div className="drawer" onClick={(e) => e.stopPropagation()}>
            <div className="drawer-head">
              <div>
                <span className="eyebrow">REQUEST DETAIL</span>
                <h3>{selected.model}</h3>
              </div>
              <button
                className="icon-btn"
                title="关闭"
                onClick={() => setSelected(null)}
              >
                <X size={16} />
              </button>
            </div>
            <dl className="drawer-grid">
              <div>
                <dt>完成时间</dt>
                <dd>{new Date(selected.created_at).toLocaleString()}</dd>
              </div>
              <div>
                <dt>结果</dt>
                <dd>
                  <span
                    className={`health ${selected.status === "success" ? "healthy" : selected.error_origin === "external" ? "external" : selected.error_origin === "internal" ? "internal" : "cooldown"}`}
                  >
                    <i />
                    {selected.status === "success"
                      ? "成功"
                      : selected.error_origin === "external"
                        ? "外部异常"
                        : selected.error_origin === "internal"
                          ? "内部步骤"
                          : `HTTP ${selected.status_code}`}
                  </span>
                </dd>
              </div>
              <div>
                <dt>路径</dt>
                <dd className="mono">{selected.proxy_uri || "direct"}</dd>
              </div>
              <div>
                <dt>重试次数</dt>
                <dd>{selected.retry_count}</dd>
              </div>
              <div>
                <dt>首字耗时</dt>
                <dd>{formatDuration(selected.first_token_latency_ms)}</dd>
              </div>
              <div>
                <dt>总耗时</dt>
                <dd>{formatDuration(selected.latency_ms)}</dd>
              </div>
              <div>
                <dt>输入 Token</dt>
                <dd>
                  {selected.prompt_tokens === undefined
                    ? "—"
                    : fmt(selected.prompt_tokens)}
                </dd>
              </div>
              <div>
                <dt>输出 Token</dt>
                <dd>
                  {selected.completion_tokens === undefined
                    ? "—"
                    : fmt(selected.completion_tokens)}
                </dd>
              </div>
              <div>
                <dt>合计 Token</dt>
                <dd>
                  {selected.total_tokens === undefined
                    ? "—"
                    : fmt(selected.total_tokens)}
                </dd>
              </div>
            </dl>
            {selected.error_message && (
              <div className="drawer-error">
                <span>错误信息</span>
                <pre>{selected.error_message}</pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
function SkeletonRows({
  rows = 5,
  cols = 4,
}: {
  rows?: number;
  cols?: number;
}) {
  return (
    <>
      {Array.from({ length: rows }, (_, i) => (
        <div className="table-row skeleton-row" key={i}>
          {Array.from({ length: cols }, (_, j) => (
            <span
              className="skeleton-bar"
              key={j}
              style={{
                width: `${52 + ((i * 41 + j * 29) % 42)}%`,
                maxWidth: j === 0 ? 380 : 140,
              }}
            />
          ))}
        </div>
      ))}
    </>
  );
}
function Empty({ text }: { text: string }) {
  return (
    <div className="empty">
      <Database size={19} />
      <span>{text}</span>
    </div>
  );
}
export default App;

const root = document.getElementById("root");
if (!root) throw new Error("Root element not found");
createRoot(root).render(<App />);
