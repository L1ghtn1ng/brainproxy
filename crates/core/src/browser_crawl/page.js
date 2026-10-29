// brainproxy browser crawl: runs in every document before the page's own scripts
// (Page.addScriptToEvaluateOnNewDocument). It notes client-side routes, window.open URLs,
// elements given click handlers and DOM activity, silences dialogs, and lets the crawler
// list links, clickable elements, forms and fields, fill fields and click elements.
(() => {
  if (window.__bp) return;
  const bp = { routes: [], opened: [], listeners: new WeakSet(), lastMutation: 0, fieldEls: [] };
  Object.defineProperty(window, "__bp", { value: bp, enumerable: false });
  const now = () => performance.now();
  bp.lastMutation = now();
  const abs = (u) => {
    try {
      return new URL(String(u), location.href).href;
    } catch (e) {
      return null;
    }
  };

  // Elements with click-like listeners (before the page adds any).
  const CLICK_EVENTS = new Set(["click", "dblclick", "mousedown", "mouseup", "pointerdown", "pointerup", "touchstart"]);
  const add = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, fn, opts) {
    try {
      if (CLICK_EVENTS.has(type) && this instanceof Element) bp.listeners.add(this);
    } catch (e) {}
    return add.call(this, type, fn, opts);
  };

  // Client-side routes.
  for (const m of ["pushState", "replaceState"]) {
    const orig = history[m];
    history[m] = function (state, title, url) {
      if (url != null) {
        const a = abs(url);
        if (a) bp.routes.push(a);
      }
      bp.lastMutation = now();
      return orig.apply(this, arguments);
    };
  }
  addEventListener("hashchange", () => {
    bp.routes.push(location.href);
    bp.lastMutation = now();
  });

  // Nobody answers dialogs; confirm() says no. Pop-ups are noted, not opened.
  window.alert = () => {};
  window.confirm = () => false;
  window.prompt = () => null;
  window.print = () => {};
  window.open = function (u) {
    const a = u == null ? null : abs(u);
    if (a) bp.opened.push(a);
    return null;
  };

  new MutationObserver(() => {
    bp.lastMutation = now();
  }).observe(document, { subtree: true, childList: true, attributes: true, characterData: true });

  const clean = (s) => String(s || "").replace(/\s+/g, " ").trim().slice(0, 80);
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return false;
    const s = getComputedStyle(el);
    return s.visibility !== "hidden" && s.display !== "none" && s.opacity !== "0";
  };
  const label = (el) =>
    clean(
      el.getAttribute("aria-label") ||
        el.innerText ||
        (el.tagName === "INPUT" ? el.value : "") ||
        el.getAttribute("title") ||
        el.getAttribute("alt") ||
        (el.querySelector("img[alt]") || {}).alt ||
        "",
    );
  // A real link is followed by loading its URL; "#" and javascript: links are clicked.
  const realLink = (el) => {
    const h = el.getAttribute("href");
    return h != null && h.trim() !== "" && !/^\s*(#\s*$|javascript:)/i.test(h);
  };

  bp.quiet = () => [document.readyState, now() - bp.lastMutation];

  bp.links = () => {
    const out = new Set();
    const put = (v) => {
      if (!v || /^\s*(javascript:|mailto:|tel:|data:|blob:)/i.test(v)) return;
      const a = abs(v.trim());
      if (a) out.add(a);
    };
    for (const el of document.querySelectorAll("a[href],area[href]")) put(el.getAttribute("href"));
    for (const el of document.querySelectorAll("[data-href],[data-url],[routerlink],[ng-href]"))
      put(el.getAttribute("data-href") || el.getAttribute("data-url") || el.getAttribute("routerlink") || el.getAttribute("ng-href"));
    for (const el of document.querySelectorAll("iframe[src],frame[src]")) put(el.getAttribute("src"));
    return [...out].slice(0, 500);
  };

  const CLICKY =
    "a,button,summary,[onclick],input[type=button],input[type=submit],input[type=image]," +
    "[role=button],[role=link],[role=menuitem],[role=menuitemcheckbox],[role=menuitemradio]," +
    "[role=tab],[role=option],[role=treeitem],[role=switch]";
  const clickables = () => {
    const found = [];
    const seen = new Set();
    const put = (el) => {
      if (!seen.has(el)) {
        seen.add(el);
        found.push(el);
      }
    };
    for (const el of document.querySelectorAll(CLICKY)) if (!(el.tagName === "A" && realLink(el))) put(el);
    const semantic = new Set(found);
    const all = document.body ? document.body.getElementsByTagName("*") : [];
    let n = 0;
    for (const el of all) {
      if (++n > 5000) break;
      if (seen.has(el)) continue;
      if (bp.listeners.has(el) || typeof el.onclick === "function") {
        put(el);
        continue;
      }
      // The outermost element of a region with a pointer cursor (frameworks that
      // delegate events from the root leave no other trace).
      const p = el.parentElement;
      if (getComputedStyle(el).cursor === "pointer" && !(p && getComputedStyle(p).cursor === "pointer")) put(el);
    }
    // Found by listener or cursor only: not a page-sized container (frameworks listen
    // on the root), and not inside another clickable (clicking that one is enough).
    const area = innerWidth * innerHeight;
    for (const el of found) {
      const r = el.getBoundingClientRect();
      if (!semantic.has(el) && (el === document.body || r.width * r.height > 0.5 * area)) seen.delete(el);
    }
    return found.filter((el) => {
      const link = el.closest("a[href]");
      if (!seen.has(el) || el.disabled || (link && realLink(link)) || !visible(el)) return false;
      if (semantic.has(el)) return true;
      for (let a = el.parentElement, i = 0; a && i < 6; a = a.parentElement, i++) if (seen.has(a)) return false;
      return true;
    });
  };

  const describe = (el) => {
    const tag = el.tagName.toLowerCase();
    const type = (el.getAttribute("type") || "").toLowerCase();
    const form = el.form || el.closest("form");
    const submits =
      !!form &&
      ((tag === "button" && (el.getAttribute("type") || "submit").toLowerCase() === "submit") ||
        (tag === "input" && (type === "submit" || type === "image")));
    return {
      tag,
      role: (el.getAttribute("role") || "").toLowerCase(),
      type,
      text: label(el),
      id: el.id || "",
      name: el.getAttribute("name") || "",
      class: clean(typeof el.className === "string" ? el.className : ""),
      title: clean(el.getAttribute("title")),
      href: el.getAttribute("href") || "",
      submits,
      action: submits ? form.action || location.href : "",
    };
  };

  // Each clickable with a key: its description plus its position among equal ones.
  const keyed = () => {
    const counts = {};
    return clickables()
      .slice(0, 300)
      .map((el) => {
        const d = describe(el);
        const sig = [d.tag, d.role, d.type, d.text, d.id].join("|");
        const n = (counts[sig] = (counts[sig] || 0) + 1);
        d.key = sig + "#" + n;
        return [el, d];
      });
  };
  const find = (key) => (keyed().find(([, d]) => d.key === key) || [])[0];

  const forms = () =>
    [...document.forms].map((f, i) => ({
      key: "form#" + (i + 1),
      action: f.action || location.href,
      method: (f.getAttribute("method") || "get").toLowerCase(),
      has_submit: [...f.elements].some((e) => {
        const t = (e.getAttribute("type") || (e.tagName === "BUTTON" ? "submit" : "")).toLowerCase();
        return (t === "submit" || t === "image") && visible(e);
      }),
    }));

  bp.snapshot = () => {
    // Everything opens in this tab.
    for (const el of document.querySelectorAll("form[target],a[target]")) el.removeAttribute("target");
    return {
      url: location.href,
      title: document.title,
      links: bp.links(),
      routes: bp.routes.splice(0),
      opened: bp.opened.splice(0),
      clickables: keyed().map(([, d]) => d),
      forms: forms(),
    };
  };

  // Scrolls the element into view; where to click it and whether it is on top there.
  bp.locate = (key) => {
    const el = find(key);
    if (!el) return null;
    el.scrollIntoView({ block: "center", inline: "center" });
    const r = el.getBoundingClientRect();
    const x = r.left + r.width / 2;
    const y = r.top + r.height / 2;
    const hit = document.elementFromPoint(x, y);
    return { x, y, hit: !!hit && (hit === el || el.contains(hit)) };
  };
  bp.click = (key) => {
    const el = find(key);
    if (!el) return false;
    el.click();
    return true;
  };
  bp.submit = (key) => {
    const f = document.forms[Number(key.split("#")[1]) - 1];
    if (!f) return false;
    f.removeAttribute("target");
    if (f.requestSubmit) f.requestSubmit();
    else f.submit();
    return true;
  };

  bp.fields = () => {
    bp.fieldEls = [...document.querySelectorAll("input,textarea,select")].filter(
      (el) => !el.disabled && !el.readOnly && visible(el),
    );
    return bp.fieldEls.map((el, i) => ({
      i,
      tag: el.tagName.toLowerCase(),
      type: (el.type || "").toLowerCase(),
      name: el.name || el.id || el.getAttribute("aria-label") || el.placeholder || "",
      value: el.value || "",
      required: !!el.required,
      checked: !!el.checked,
      options: el.tagName === "SELECT" ? [...el.options].map((o) => o.value) : [],
    }));
  };
  // Sets values the way typing does, so frameworks that track input events see them.
  bp.setFields = (pairs) => {
    for (const [i, v] of pairs) {
      const el = bp.fieldEls[i];
      if (!el || !el.isConnected) continue;
      if (v === true) {
        if (!el.checked) el.click();
        continue;
      }
      const proto =
        el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : el.tagName === "SELECT" ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto, "value").set.call(el, v);
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
    }
    return true;
  };
})();
