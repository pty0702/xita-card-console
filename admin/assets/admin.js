(() => {
  "use strict";

  function init() {
    const find = (selector, root = document) => {
      try { return root.querySelector(selector); } catch { return null; }
    };
    const createForm = find("#create-form");
    const batchForm = find("#batch-form");
    const rowChecks = batchForm ? Array.from(batchForm.elements).filter(input =>
      input.matches(".row-check") && !input.disabled) : [];
    const dialog = find("#confirm-dialog");
    const submissions = new Map();
    const approved = new WeakSet();
    const feedbackTimers = new Map();
    let pending = null;
    let toastTimer;

    function notify(message) {
      const toast = find("#toast");
      if (!toast) return;
      clearTimeout(toastTimer);
      toast.setAttribute("role", "status");
      toast.setAttribute("aria-live", "polite");
      toast.hidden = false;
      toast.textContent = message;
      toast.classList.add("show");
      toastTimer = setTimeout(() => {
        toast.classList.remove("show");
        toast.hidden = true;
      }, 2800);
    }

    function feedback(button, message) {
      const previous = feedbackTimers.get(button);
      if (previous) clearTimeout(previous.timer);
      const label = previous ? previous.label : button.getAttribute("aria-label");
      button.setAttribute("aria-label", message);
      const timer = setTimeout(() => {
        if (label === null) button.removeAttribute("aria-label");
        else button.setAttribute("aria-label", label);
        feedbackTimers.delete(button);
      }, 1800);
      feedbackTimers.set(button, { label, timer });
    }

    async function copy(button) {
      const target = button.hasAttribute("data-copy-target")
        ? find(button.dataset.copyTarget) : null;
      const value = target
        ? ("value" in target ? target.value : target.textContent)
        : button.dataset.copy;
      if (!value) {
        notify("没有可复制的内容");
        feedback(button, "没有可复制的内容");
        return;
      }
      let copied = false;
      if (window.isSecureContext && navigator.clipboard?.writeText) {
        try {
          await navigator.clipboard.writeText(value);
          copied = true;
        } catch { /* 剪贴板权限不可用时，继续使用本地复制回退。 */ }
      }
      if (!copied) {
        const active = document.activeElement;
        const textarea = document.createElement("textarea");
        textarea.value = value;
        textarea.readOnly = true;
        textarea.style.cssText = "position:fixed;left:-9999px;top:0;opacity:0";
        document.body.append(textarea);
        textarea.select();
        textarea.setSelectionRange(0, textarea.value.length);
        try { copied = document.execCommand("copy"); } catch { copied = false; }
        textarea.remove();
        if (active instanceof HTMLElement) active.focus({ preventScroll: true });
      }
      const message = copied ? "已复制到剪贴板" : "复制失败，请手动选择复制";
      notify(message);
      feedback(button, message);
    }

    function toggleMenu(open) {
      document.body.classList.toggle("nav-open", open);
      document.querySelectorAll("[data-menu-toggle]").forEach(button => {
        button.setAttribute("aria-expanded", String(open));
      });
    }

    function updateCreate() {
      if (!createForm) return;
      const kind = find('[name="kind"]:checked', createForm)?.value || "时间卡";
      createForm.querySelectorAll("[data-kind-field]").forEach(field => {
        const active = field.dataset.kindField === kind;
        field.hidden = !active;
        field.querySelectorAll("input,select,textarea").forEach(input => {
          input.disabled = !active;
          input.required = active;
        });
      });
      const days = find('[name="days"]', createForm);
      const points = find('[name="points"]', createForm);
      const quantity = find("#quantity", createForm) || find('[name="num"]', createForm);
      const values = {
        "#summary-kind": kind,
        "#summary-quantity": quantity?.value || "—",
        "#summary-validity": kind === "永久卡" ? "永久有效"
          : kind === "点数卡" ? (points?.value || "—") + " 点"
          : (days?.value || "—") + " 天"
      };
      Object.entries(values).forEach(([selector, text]) => {
        const element = find(selector);
        if (element) element.textContent = text;
      });
      createForm.querySelectorAll("[data-days]").forEach(button => {
        const active = kind === "时间卡" && button.dataset.days === days?.value;
        button.classList.toggle("is-active", active);
        button.setAttribute("aria-pressed", String(active));
      });
    }

    function filterLogs(input) {
      const query = input.value.trim().toLocaleLowerCase();
      let count = 0;
      document.querySelectorAll("[data-log-row]").forEach(row => {
        row.hidden = !row.textContent.toLocaleLowerCase().includes(query);
        if (!row.hidden) count += 1;
      });
      const counter = find("#log-count");
      if (counter) counter.textContent = String(count);
      document.querySelectorAll("[data-log-empty]").forEach(empty => {
        empty.hidden = count > 0;
      });
    }

    function updateBatch() {
      const count = rowChecks.filter(input => input.checked).length;
      const all = find("#check-all");
      if (all) {
        all.checked = rowChecks.length > 0 && count === rowChecks.length;
        all.indeterminate = count > 0 && count < rowChecks.length;
        all.disabled = rowChecks.length === 0;
      }
      const counter = find("#batch-count");
      if (counter) counter.textContent = "已选 " + count + " 张";
      return count;
    }

    function cancelConfirmation() {
      const action = pending;
      pending = null;
      if (dialog?.open) dialog.close();
      if (action?.trigger instanceof HTMLElement && action.trigger.isConnected) {
        action.trigger.focus({ preventScroll: true });
      }
      return action;
    }

    function acceptConfirmation() {
      const action = cancelConfirmation();
      if (!action) return;
      const { form, submitter } = action;
      approved.add(form);
      try {
        if (typeof form.requestSubmit === "function") {
          if (submitter?.form === form && !submitter.disabled) form.requestSubmit(submitter);
          else form.requestSubmit();
        } else {
          // 旧浏览器仍通过按钮触发原生校验和 submit 事件。
          const button = submitter || document.createElement("button");
          if (!submitter) {
            button.type = "submit";
            button.hidden = true;
            form.append(button);
          }
          button.click();
          if (!submitter) button.remove();
        }
      } finally {
        approved.delete(form);
      }
    }

    function lockSubmission(form) {
      const controls = Array.from(form.querySelectorAll(
        'button:not([type]),button[type="submit"],input[type="submit"],input[type="image"]'
      )).filter(button => !button.disabled).map(button => ({
        button, label: button.tagName === "INPUT" ? button.value : button.innerHTML
      }));
      form.setAttribute("aria-busy", "true");
      const state = { controls, timer: null };
      submissions.set(form, state);
      // 等浏览器收集表单数据后再禁用，避免丢失提交按钮的 name/value。
      state.timer = setTimeout(() => controls.forEach(({ button }) => {
        button.disabled = true;
        if (button.tagName === "INPUT") button.value = "处理中…";
        else button.textContent = "处理中…";
      }), 0);
    }

    document.addEventListener("submit", event => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement) || event.defaultPrevented) return;
      if (submissions.has(form)) {
        event.preventDefault();
        return;
      }
      if (!form.checkValidity()) {
        event.preventDefault();
        form.reportValidity();
        return;
      }
      const selected = form === batchForm ? updateBatch() : null;
      if (selected === 0) {
        event.preventDefault();
        notify("请先选择要操作的卡密");
        return;
      }
      if (form.hasAttribute("data-confirm") && !approved.delete(form)) {
        let message = form.dataset.confirm || "确定执行此操作？";
        if (form === batchForm) {
          const operation = find('[name="act"]', form);
          const label = operation?.selectedOptions[0]?.textContent.trim() || "批量操作";
          message = "确定对已选的 " + selected + " 张卡密执行「" + label + "」？";
          if (operation?.value === "delete") message += "删除后不可恢复。";
        }
        if (dialog && typeof dialog.showModal === "function") {
          event.preventDefault();
          cancelConfirmation();
          const text = find(".dialog-message", dialog);
          if (text) text.textContent = message;
          pending = {
            form, submitter: event.submitter || null,
            trigger: event.submitter || document.activeElement
          };
          dialog.showModal();
          return;
        }
        if (!window.confirm(message)) {
          event.preventDefault();
          return;
        }
      }
      if (form.method.toLowerCase() === "post") lockSubmission(form);
    });

    document.addEventListener("click", event => {
      if (!(event.target instanceof Element)) return;
      const target = event.target;
      const copyButton = target.closest("[data-copy],[data-copy-target]");
      if (copyButton) {
        event.preventDefault();
        void copy(copyButton);
        return;
      }
      const menuButton = target.closest("[data-menu-toggle]");
      if (menuButton) {
        event.preventDefault();
        toggleMenu(!document.body.classList.contains("nav-open"));
        return;
      }
      if (target.closest("#mobile-backdrop,nav a")) toggleMenu(false);
      const passwordButton = target.closest("[data-toggle-password]");
      if (passwordButton) {
        event.preventDefault();
        const input = find(passwordButton.dataset.togglePassword);
        if (!input) return;
        const visible = input.type === "password";
        input.type = visible ? "text" : "password";
        passwordButton.setAttribute("aria-pressed", String(visible));
        passwordButton.setAttribute("aria-label", visible ? "隐藏密码" : "显示密码");
        return;
      }
      const daysButton = target.closest("[data-days]");
      if (daysButton && createForm?.contains(daysButton)) {
        event.preventDefault();
        const input = find('[name="days"]', createForm);
        if (input && !input.disabled) {
          input.value = daysButton.dataset.days;
          updateCreate();
        }
        return;
      }
      if (target.closest("[data-dialog-cancel]")) {
        event.preventDefault();
        cancelConfirmation();
        return;
      }
      if (target.closest("[data-dialog-accept]")) {
        event.preventDefault();
        acceptConfirmation();
        return;
      }
      if (dialog?.open && target === dialog) {
        const bounds = dialog.getBoundingClientRect();
        if (event.clientX < bounds.left || event.clientX > bounds.right ||
            event.clientY < bounds.top || event.clientY > bounds.bottom) {
          cancelConfirmation();
        }
      }
      if (target.closest("#download-cards")) {
        event.preventDefault();
        const text = find("#generated-cards")?.value;
        if (!text) return notify("没有可下载的卡密");
        const url = URL.createObjectURL(new Blob(["\uFEFF", text], {
          type: "text/plain;charset=utf-8"
        }));
        const link = document.createElement("a");
        link.href = url;
        link.download = "cards.txt";
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        notify("已开始下载卡密文件");
      }
    });

    document.addEventListener("input", event => {
      if (!(event.target instanceof Element)) return;
      if (event.target.matches("[data-filter-log]")) filterLogs(event.target);
      if (createForm?.contains(event.target) &&
          event.target.matches('[name="num"],[name="days"],[name="points"]')) updateCreate();
    });
    document.addEventListener("change", event => {
      if (!(event.target instanceof Element)) return;
      if (event.target.matches("#check-all")) {
        rowChecks.forEach(input => { input.checked = event.target.checked; });
        updateBatch();
      } else if (event.target.matches(".row-check")) updateBatch();
      if (createForm?.contains(event.target) &&
          event.target.matches('[name="kind"]')) updateCreate();
    });
    document.addEventListener("keydown", event => {
      if (event.key === "Escape") toggleMenu(false);
    });
    if (dialog) {
      dialog.addEventListener("cancel", event => {
        event.preventDefault();
        cancelConfirmation();
      });
      dialog.addEventListener("close", () => {
        if (pending) cancelConfirmation();
      });
    }
    window.addEventListener("pageshow", () => {
      submissions.forEach(({ controls, timer }, form) => {
        clearTimeout(timer);
        form.removeAttribute("aria-busy");
        controls.forEach(({ button, label }) => {
          button.disabled = false;
          if (button.tagName === "INPUT") button.value = label;
          else button.innerHTML = label;
        });
      });
      submissions.clear();
      updateBatch();
    });

    if (createForm) {
      [["days", "30"], ["points", "100"]].forEach(([name, fallback]) => {
        const input = find('[name="' + name + '"]', createForm);
        if (input) {
          input.min = "1";
          if (!input.value || Number(input.value) < 1) input.value = fallback;
        }
      });
      updateCreate();
    }
    const logFilter = find("[data-filter-log]");
    if (logFilter) filterLogs(logFilter);
    updateBatch();
    toggleMenu(false);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
