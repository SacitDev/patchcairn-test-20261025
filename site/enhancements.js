(() => {
  'use strict';

  const root = document.documentElement;
  const scene = document.getElementById('night-circuit');
  const preference = window.matchMedia('(prefers-reduced-motion: reduce)');
  const canObserve = typeof window.IntersectionObserver === 'function';
  const revealed = new WeakSet();
  const active = new Set();
  let pageActive = true;

  function allowed() {
    return !preference.matches && !document.hidden && pageActive;
  }

  function settle(region) {
    region.classList.remove('is-entering');
    active.delete(region);
  }

  function settleAll() {
    for (const region of active) region.classList.remove('is-entering');
    active.clear();
  }

  function enter(region) {
    if (!allowed() || active.has(region)) return;
    active.add(region);
    region.classList.add('is-entering');
  }

  function updateMotion() {
    root.classList.toggle('motion-suspended', !allowed());
    if (!allowed()) settleAll();
  }

  if (canObserve) {
    const regions = new Set(document.querySelectorAll('.motion-region'));
    if (scene) regions.add(scene);

    const observer = new window.IntersectionObserver((entries) => {
      for (const entry of entries) {
        const visible = entry.isIntersecting && entry.intersectionRatio >= 0.12;
        entry.target.classList.toggle('is-in-view', visible);
        if (!visible) settle(entry.target);
        if (visible && !revealed.has(entry.target)) {
          revealed.add(entry.target);
          enter(entry.target);
        }
      }
    }, { threshold: [0, 0.12, 0.5] });

    root.classList.add('motion-ready');
    for (const region of regions) {
      observer.observe(region);
      region.addEventListener('animationend', (event) => {
        const sceneFinished = region === scene && event.target.classList.contains('hero-laptop') && event.animationName === 'nc-edge-light';
        const regionFinished = event.target === region && event.animationName === 'nc-region-entry';
        if (sceneFinished || regionFinished) settle(region);
      });
    }

    if (scene) {
      const replay = (event) => {
        if (!revealed.has(scene) || !scene.classList.contains('is-in-view')) return;
        if (event.type === 'focusin' && event.relatedTarget && scene.contains(event.relatedTarget)) return;
        enter(scene);
      };
      scene.addEventListener('pointerenter', replay);
      scene.addEventListener('pointerdown', replay);
      scene.addEventListener('focusin', replay);
    }
  }

  document.addEventListener('visibilitychange', updateMotion);
  window.addEventListener('beforeprint', settleAll);
  window.addEventListener('pagehide', () => {
    pageActive = false;
    updateMotion();
  });
  window.addEventListener('pageshow', () => {
    pageActive = true;
    updateMotion();
  });
  if (typeof preference.addEventListener === 'function') {
    preference.addEventListener('change', updateMotion);
  } else if (typeof preference.addListener === 'function') {
    preference.addListener(updateMotion);
  }
  updateMotion();
})();
