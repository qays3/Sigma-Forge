import { api } from "./api.js";
import { store } from "./store.js";

const cache = {
  signature: "",
  analysis: null,
  coverage: null,
  targets: null,
  attack: null,
};

function signature(rules) {
  return rules.map((r) => r.id).join("|");
}

store.onChange(() => {
  cache.signature = "";
  cache.analysis = null;
  cache.coverage = null;
});

export const state = {
  async rules() {
    return store.all();
  },

  async analysis() {
    const rules = await store.all();
    const sig = signature(rules);
    if (cache.analysis && cache.signature === sig) return { rules, analysis: cache.analysis };
    const analysis = rules.length ? await api.analyze(rules) : { summary: null, rules: [] };
    cache.signature = sig;
    cache.analysis = analysis;
    cache.coverage = null;
    return { rules, analysis };
  },

  async coverage() {
    const rules = await store.all();
    const sig = signature(rules);
    if (cache.coverage && cache.signature === sig) return { rules, coverage: cache.coverage };
    const coverage = await api.coverage(rules);
    if (cache.signature !== sig) {
      cache.analysis = null;
      cache.signature = sig;
    }
    cache.coverage = coverage;
    return { rules, coverage };
  },

  async targets() {
    if (!cache.targets) cache.targets = (await api.targets()).targets;
    return cache.targets;
  },

  async attack() {
    if (!cache.attack) cache.attack = await api.attack();
    return cache.attack;
  },

  fileFor(key, rules) {
    const file = key.slice(0, key.lastIndexOf("#"));
    return rules.find((r) => r.name === file);
  },
};
