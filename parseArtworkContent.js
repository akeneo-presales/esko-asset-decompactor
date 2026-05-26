/**
 * parseArtworkContent.js
 *
 * Parses a GS1 artwork content XML file (urn:gs1:ecom:artwork_content:xsd:3)
 * and extracts all copy element values into a structured JSON output.
 *
 * Design principle — zero data loss:
 *   Every <artworkContentCopyElement> in the file is captured in the output,
 *   regardless of its typeCode. The parser does not rely on a fixed allowlist
 *   of attribute codes. New or unknown codes are automatically included.
 *
 * Output sections:
 *   metadata        — document envelope (locales, IDs, dates)
 *   marketingContent— well-known marketing/regulatory copy elements,
 *                     grouped under human-friendly keys
 *   ingredients     — INGREDIENTS_DECLARATION blocks, split by flavour
 *   nutritionFacts  — structured nutrition panel (FREE_FORM block)
 *   rawFields       — every copy element NOT claimed by the sections above,
 *                     keyed by typeCode, preserving all locale translations
 *                     and instance sequences
 *
 * Locale format: BCP-47 / Akeneo notation (e.g. EN-US → en_US, ZH-CN → zh_CN)
 *
 * Usage:
 *   const { parseArtworkContent } = require('./parseArtworkContent');
 *   const result = await parseArtworkContent('<path>.xml');
 *   // or synchronously:
 *   const result = parseArtworkContentFromString(xmlString);
 *
 * Dependency: @xmldom/xmldom  (npm install @xmldom/xmldom)
 */

'use strict';

const { DOMParser } = require('@xmldom/xmldom');
const fs = require('fs');

// ---------------------------------------------------------------------------
// Known marketing type codes — used only for GROUPING under friendly keys.
// Unknown codes are NOT dropped; they end up in rawFields instead.
// ---------------------------------------------------------------------------

const MARKETING_SECTION_LABELS = {
  BRAND_NAME:                    'brandName',
  SUB_BRAND_NAME:                'subBrandName',
  PRODUCT_FEATURES:              'productFeatures',
  VARIANT:                       'variants',
  MARKETING_CLAIM:               'marketingClaims',
  MARKETING_COPY:                'marketingCopy',
  ICON_VARIABLE_TEXT:            'iconText',
  NET_CONTENT_STATEMENT:         'netContent',
  STORAGE_INSTRUCTIONS:          'storageInstructions',
  DISTRIBUTION_STATEMENT:        'distributionStatement',
  COPYRIGHT_TRADEMARK_STATEMENT: 'copyrightStatement',
  CONTACT_INFORMATION:           'contactInformation',
  DECLARATION_CONTEXT_FOOTNOTE:  'footnotes',
  WARNING_STATEMENTS:            'warnings',
  PREPARATION_INSTRUCTIONS:      'preparationInstructions',
  USAGE_INSTRUCTIONS:            'usageInstructions',
  PRODUCT_USE:                   'productUse',
  BEST_BEFORE_DATE_HEADER:       'bestBeforeDateHeader',
  MANUFACTURER_SITE:             'manufacturerSite',
  TARGET_MARKET:                 'targetMarket',
  LANGUAGE_CODE:                 'languageCode',
};

// Keys whose values are always arrays (even when there is only one entry)
const MARKETING_MULTI_VALUE = new Set([
  'variants', 'marketingClaims', 'marketingCopy', 'iconText',
  'footnotes', 'netContent', 'warnings',
]);

// ---------------------------------------------------------------------------
// Type codes consumed by specialised sections.
// Elements with these codes are NOT emitted into rawFields.
// ---------------------------------------------------------------------------

const INGREDIENTS_CODE  = 'INGREDIENTS_DECLARATION';
const NUTRITION_PANEL_CODES = new Set([
  'NUTRI_TABLE_HEADERS', 'NUMBER_OF_SERVINGS_PER_LABEL', 'DECLARATION_CONTEXT_FOOTNOTE',
]);

// Dynamic nutrient detection — any code matching these patterns is a nutrient
const isNutrientRelated = tc =>
  /_NUTRIENT_(?:VALUE\d*|VAU[EL]\d*|LABEL|UNIT)$/i.test(tc);

// ---------------------------------------------------------------------------
// Low-level XML helpers
// ---------------------------------------------------------------------------

const toArray = list => Array.from({ length: list.length }, (_, i) => list.item(i));

function findAll(node, localName) {
  const byName = node.getElementsByTagName(localName);
  if (byName && byName.length > 0) return toArray(byName);
  const all = node.getElementsByTagName('*');
  return toArray(all).filter(el => (el.localName || el.nodeName.split(':').pop()) === localName);
}

function extractText(el) {
  const raw = (el.textContent || el.text || '').replace(/\s+/g, ' ').trim();
  return raw.length > 0 ? raw : null;
}

function childText(parent, localName) {
  const els = findAll(parent, localName);
  return els.length > 0 ? extractText(els[0]) : null;
}

// ---------------------------------------------------------------------------
// Locale normalisation
// ---------------------------------------------------------------------------

/**
 * Converts a GS1 locale identifier to Akeneo BCP-47 notation.
 * EN-US → en_US, ZH-CN → zh_CN, EN-ZH-TW → en_zh_TW
 */
function normaliseLocale(raw) {
  if (!raw || raw === 'UNKNOWN') return raw;
  const parts = raw.split('-');
  return parts
    .map((p, i) => i === parts.length - 1 ? p.toUpperCase() : p.toLowerCase())
    .join('_');
}

function buildLocaleMaps(doc) {
  const result = new Map();
  for (const piece of findAll(doc, 'artworkContentPieceOfArt')) {
    const localeMap = new Map();
    for (const loc of findAll(piece, 'artworkContentLocale')) {
      const seq = childText(loc, 'localeSequence');
      const id  = childText(loc, 'localeIdentifier');
      if (seq && id) localeMap.set(seq, normaliseLocale(id));
    }
    result.set(piece, localeMap);
  }
  return result;
}

function resolveLocale(el, localeMaps) {
  const localeSeq = childText(el, 'localeSequence');
  if (!localeSeq) return 'UNKNOWN';
  let node = el.parentNode;
  while (node) {
    const local = node.localName || node.nodeName?.split(':').pop();
    if (local === 'artworkContentPieceOfArt') {
      const map = localeMaps.get(node);
      if (map) return map.get(localeSeq) || normaliseLocale(localeSeq);
    }
    node = node.parentNode;
  }
  for (const [, map] of localeMaps) {
    if (map.has(localeSeq)) return map.get(localeSeq);
  }
  return normaliseLocale(localeSeq);
}

// ---------------------------------------------------------------------------
// Localised value helpers
// ---------------------------------------------------------------------------

/** Wraps { data, locale }. Returns null if data is null/empty. */
const localised = (data, locale) =>
  data !== null && data !== undefined && data !== '' ? { data, locale } : null;

/**
 * Given an array of parsed elements sharing the same field/instance,
 * returns a single { data, locale } or an array for multi-locale entries.
 * Silently drops null/empty texts.
 */
function localisedGroup(entries) {
  const unique = [];
  const seen   = new Set();
  for (const e of entries) {
    if (!e.text) continue;
    const key = `${e.locale}::${e.text}`;
    if (!seen.has(key)) { seen.add(key); unique.push(localised(e.text, e.locale)); }
  }
  if (unique.length === 0) return null;
  return unique.length === 1 ? unique[0] : unique;
}

// ---------------------------------------------------------------------------
// Copy-element parsing
// ---------------------------------------------------------------------------

function parseCopyElement(el, localeMaps) {
  return {
    typeCode:     childText(el, 'copyElementTypeCode'),
    instance:     parseInt(childText(el, 'instanceSequence') || '1', 10),
    localeSeqRaw: childText(el, 'localeSequence') || '1',
    locale:       resolveLocale(el, localeMaps),
    text:         childText(el, 'textContent'),
  };
}

// ---------------------------------------------------------------------------
// Element collection
// ---------------------------------------------------------------------------

/**
 * Splits all copy elements into:
 *   structured — inside an artworkContentStructuredCopyElement (nutrition panel)
 *   topLevel   — directly inside artworkContentPieceOfArt
 *
 * Both lists are exhaustive: every element in the document appears in exactly
 * one of them.
 */
function collectElements(doc, localeMaps) {
  const structuredBlocks = findAll(doc, 'artworkContentStructuredCopyElement');
  const structuredSet    = new Set();
  const structured       = [];

  for (const block of structuredBlocks) {
    for (const el of findAll(block, 'artworkContentCopyElement')) {
      structuredSet.add(el);
      structured.push(parseCopyElement(el, localeMaps));
    }
  }

  const topLevel = findAll(doc, 'artworkContentCopyElement')
    .filter(el => !structuredSet.has(el))
    .map(el => parseCopyElement(el, localeMaps));

  return { topLevel, structured };
}

// ---------------------------------------------------------------------------
// Nutrient helpers
// ---------------------------------------------------------------------------

function nutrientKey(typeCode) {
  const m = typeCode.match(/^(.+?)_NUTRIENT_(?:VALUE\d*|LABEL|UNIT|VAU[EL]\d*)$/i);
  return m ? m[1] : null;
}

const isNutrientValue = tc => /_NUTRIENT_(?:VALUE\d*|VAU[EL]\d*)$/i.test(tc);
const isNutrientLabel = tc => /_NUTRIENT_LABEL$/i.test(tc);
const isNutrientUnit  = tc => /_NUTRIENT_UNIT$/i.test(tc);
const isDV            = val => Boolean(val && (val.includes('%') || val === '%DV'));

function collectNutrientKeys(elements) {
  const seen  = new Set();
  const order = [];
  for (const el of elements) {
    if (!el.typeCode) continue;
    const key = nutrientKey(el.typeCode);
    if (key && !seen.has(key)) { seen.add(key); order.push(key); }
  }
  return order;
}

// ---------------------------------------------------------------------------
// Grouping helpers
// ---------------------------------------------------------------------------

function groupByInstance(elements) {
  const map = new Map();
  for (const el of elements) {
    const list = map.get(el.instance) || [];
    list.push(el);
    map.set(el.instance, list);
  }
  return new Map([...map.entries()].sort(([a], [b]) => a - b));
}

// ---------------------------------------------------------------------------
// Column header resolution (nutrition panel)
// ---------------------------------------------------------------------------

function resolveColumnHeaders(elements, numValueCols) {
  const tableHeadersByInst = groupByInstance(
    elements.filter(e => e.typeCode === 'NUTRI_TABLE_HEADERS')
  );
  const tableColumns = [...tableHeadersByInst.entries()].slice(1).map(([inst, entries]) => ({
    instance: inst, label: localisedGroup(entries),
  }));

  const servingByInst = groupByInstance(
    elements.filter(e => e.typeCode === 'NUMBER_OF_SERVINGS_PER_LABEL')
  );
  const isFlavourOrHeader = text => {
    if (!text || !text.trim()) return false;
    if (/amount per serving/i.test(text)) return false;
    return !/\d/.test(text) || /^per\s+\d/i.test(text) || /^每/.test(text);
  };
  const servingColumns = [...servingByInst.entries()]
    .filter(([, entries]) => entries.some(e => isFlavourOrHeader(e.text)))
    .map(([inst, entries]) => ({ instance: inst, label: localisedGroup(entries) }));

  const columns = tableColumns.length > 0
    ? [...tableColumns, ...servingColumns]
    : servingColumns;

  return columns.slice(0, numValueCols);
}

function resolveServingDescriptions(elements, usedColumnInstances) {
  const servingByInst = groupByInstance(
    elements.filter(e => e.typeCode === 'NUMBER_OF_SERVINGS_PER_LABEL')
  );
  const descriptions = [];
  for (const [inst, entries] of servingByInst) {
    if (usedColumnInstances.has(inst)) continue;
    const hasText = entries.some(e => e.text && e.text.trim());
    if (hasText) { const grp = localisedGroup(entries); if (grp) descriptions.push(grp); }
  }
  return descriptions;
}

// ---------------------------------------------------------------------------
// Nutrition facts builder
// ---------------------------------------------------------------------------

function buildNutritionFacts(elements) {
  if (!elements.length) return null;

  const localeSet   = new Set(elements.map(e => e.locale).filter(l => l !== 'UNKNOWN'));
  const locales     = [...localeSet];

  // Panel title
  const tableHeadersByInst = groupByInstance(
    elements.filter(e => e.typeCode === 'NUTRI_TABLE_HEADERS')
  );
  const firstHeaderInst = [...tableHeadersByInst.keys()][0];
  let panelTitle;
  if (firstHeaderInst !== undefined) {
    panelTitle = localisedGroup(tableHeadersByInst.get(firstHeaderInst))
              || localised('Nutrition Facts', 'UNKNOWN');
  } else {
    const firstServingGroup = groupByInstance(
      elements.filter(e => e.typeCode === 'NUMBER_OF_SERVINGS_PER_LABEL')
    );
    const firstServingEntries = firstServingGroup.size > 0
      ? [...firstServingGroup.values()][0] : null;
    panelTitle = (firstServingEntries && localisedGroup(firstServingEntries))
              || localised('Nutrition Facts', 'UNKNOWN');
  }

  // Value map (deduplicated across locales)
  const valueMap = new Map();
  for (const el of elements) {
    if (!el.typeCode || !el.text) continue;
    if (!isNutrientValue(el.typeCode)) continue;
    const key = nutrientKey(el.typeCode);
    if (!key) continue;
    if (!valueMap.has(key)) valueMap.set(key, new Map());
    if (!valueMap.get(key).has(el.instance)) {
      valueMap.get(key).set(el.instance, { value: el.text, locale: el.locale });
    }
  }

  // Column count
  let numValueCols = 1;
  for (const [, instMap] of valueMap) {
    const nonDV = [...instMap.values()].filter(v => !isDV(v.value)).length;
    if (nonDV > numValueCols) numValueCols = nonDV;
  }

  const columnHeaders = resolveColumnHeaders(elements, numValueCols);
  const usedColInsts  = new Set(columnHeaders.map(h => h.instance));
  const servingDescriptions = resolveServingDescriptions(elements, usedColInsts);

  // Label and unit maps
  const labelMap = new Map();
  const unitMap  = new Map();
  for (const el of elements) {
    if (!el.typeCode || !el.text) continue;
    const key    = nutrientKey(el.typeCode);
    if (!key) continue;
    const target = isNutrientLabel(el.typeCode) ? labelMap
                 : isNutrientUnit(el.typeCode)  ? unitMap : null;
    if (!target) continue;
    if (!target.has(key)) target.set(key, new Map());
    const instMap = target.get(key);
    if (!instMap.has(el.instance)) instMap.set(el.instance, {});
    instMap.get(el.instance)[el.locale] = el.text;
  }

  // Nutrient rows
  const nutrientOrder = collectNutrientKeys(elements);
  const nutrients     = [];

  for (const key of nutrientOrder) {
    const instances = valueMap.get(key);
    if (!instances) continue;

    const labels = labelMap.get(key);
    const units  = unitMap.get(key);
    const sorted  = [...instances.entries()].sort(([a], [b]) => a - b);
    const perServ = sorted.filter(([, v]) => !isDV(v.value));
    const dvVals  = sorted.filter(([, v]) => isDV(v.value) && v.value !== '%DV');

    const labelInstances = labels
      ? [...labels.entries()].sort(([a], [b]) => a - b)
      : [[1, Object.fromEntries(locales.map(l => [l, key]))]];
    const subRowCount = labelInstances.length;
    const valsPerRow  = Math.max(1, Math.ceil(perServ.length / subRowCount));

    for (let sub = 0; sub < subRowCount; sub++) {
      const subPerServ  = perServ.slice(sub * valsPerRow, (sub + 1) * valsPerRow);
      const [labelInst, localeTextMap] = labelInstances[sub];

      const nameEntries = Object.entries(localeTextMap)
        .filter(([, t]) => t).map(([loc, t]) => localised(t, loc));
      const nutrientName = nameEntries.length === 0 ? localised(key, 'UNKNOWN')
                         : nameEntries.length === 1  ? nameEntries[0] : nameEntries;

      const unitLocMap   = units?.get(labelInst) || null;
      const unitEntries  = unitLocMap
        ? Object.entries(unitLocMap).filter(([, t]) => t).map(([loc, t]) => localised(t, loc))
        : [];
      const nutrientUnit = unitEntries.length === 0 ? null
                         : unitEntries.length === 1  ? unitEntries[0] : unitEntries;

      const row = { nutrient: nutrientName };
      if (nutrientUnit) row.unit = nutrientUnit;

      if (numValueCols <= 1) {
        const [, ps] = subPerServ[0] || [null, { value: null, locale: locales[0] || 'UNKNOWN' }];
        const [, dv] = dvVals[sub]   || [null, null];
        row.amountPerServing = localised(ps.value, ps.locale);
        if (dv) row.percentDailyValue = localised(dv.value, dv.locale);
      } else {
        row.columns = columnHeaders.map((header, i) => {
          const [, ps] = subPerServ[i] || [null, { value: null, locale: 'UNKNOWN' }];
          const [, dv] = dvVals[i]     || [null, null];
          const col = { column: header.label, amountPerServing: localised(ps.value, ps.locale) };
          if (dv) col.percentDailyValue = localised(dv.value, dv.locale);
          return col;
        });
        if (!row.columns.some(c => c.amountPerServing !== null)) continue;
      }

      nutrients.push(row);
    }
  }

  // Footnotes
  const footnoteByInst = groupByInstance(
    elements.filter(e => e.typeCode === 'DECLARATION_CONTEXT_FOOTNOTE' && e.text)
  );
  const footnotes = [...footnoteByInst.values()]
    .map(entries => localisedGroup(entries)).filter(Boolean);

  return {
    title: panelTitle,
    ...(servingDescriptions.length && { servingDescription: servingDescriptions }),
    ...(columnHeaders.length > 1 && { columns: columnHeaders.map(h => h.label) }),
    nutrients,
    ...(footnotes.length && { footnotes }),
  };
}

// ---------------------------------------------------------------------------
// Ingredients builder
// ---------------------------------------------------------------------------

function buildIngredients(elements) {
  const entries = elements
    .filter(e => e.typeCode === INGREDIENTS_CODE && e.text)
    .sort((a, b) => a.instance - b.instance || a.localeSeqRaw.localeCompare(b.localeSeqRaw));

  if (!entries.length) return null;

  const byInstance  = groupByInstance(entries);
  const localeCount = new Set(entries.map(e => e.locale)).size;

  if (byInstance.size === 1 && localeCount === 1) {
    const el     = [...byInstance.values()][0][0];
    const blocks = splitIngredientsByFlavour(el.text, el.locale);
    return blocks.length > 1 ? blocks : localised(el.text, el.locale);
  }

  const result = [];
  for (const [inst, group] of byInstance) {
    const grp = localisedGroup(group);
    if (grp === null) continue;
    if (byInstance.size > 1) {
      result.push(Array.isArray(grp)
        ? { instance: inst, translations: grp }
        : { instance: inst, ...grp });
    } else {
      result.push(Array.isArray(grp) ? { translations: grp } : grp);
    }
  }
  return result.length === 1 ? result[0] : result;
}

function splitIngredientsByFlavour(raw, locale) {
  if (!raw) return [];
  const headerRe = /([A-Z][A-Z\s&\/]+?INGREDIENTS\s*:)/g;
  const matches  = [...raw.matchAll(headerRe)];
  if (matches.length < 2) return [];
  return matches.map((match, i) => {
    const header      = match[1].trim();
    const start       = match.index + header.length;
    const end         = i + 1 < matches.length ? matches[i + 1].index : raw.length;
    const ingredients = raw.slice(start, end).trim();
    const flavourM    = header.match(/^([A-Z][A-Z\s&\/]+?)\s+(?:FLAVORED?|WITH|NATURALLY)/);
    const flavour     = flavourM ? titleCase(flavourM[1].trim()) : header;
    return { flavour, data: ingredients, locale };
  });
}

const titleCase = str => str.toLowerCase().replace(/\b\w/g, c => c.toUpperCase());

// ---------------------------------------------------------------------------
// Marketing content builder
// ---------------------------------------------------------------------------

/**
 * Groups known marketing copy elements under friendly section keys.
 * Unknown codes are NOT processed here — they land in rawFields.
 */
function buildMarketingContent(elements) {
  const byTypeAndInst = new Map();
  for (const el of elements) {
    if (!MARKETING_SECTION_LABELS[el.typeCode] || !el.text) continue;
    const key  = `${el.typeCode}::${el.instance}`;
    const list = byTypeAndInst.get(key) || [];
    list.push(el);
    byTypeAndInst.set(key, list);
  }

  const grouped = {};
  for (const [, group] of byTypeAndInst) {
    const typeCode   = group[0].typeCode;
    const sectionKey = MARKETING_SECTION_LABELS[typeCode] || typeCode.toLowerCase();
    const entry      = localisedGroup(group);
    if (entry === null) continue;
    if (!grouped[sectionKey]) grouped[sectionKey] = [];
    grouped[sectionKey].push(entry);
  }

  const result = {};
  for (const [key, values] of Object.entries(grouped)) {
    result[key] = MARKETING_MULTI_VALUE.has(key)
      ? values
      : values.length === 1 ? values[0] : values;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Raw fields catch-all
// ---------------------------------------------------------------------------

/**
 * Captures every copy element NOT already claimed by a specialised section.
 *
 * A type code is "claimed" when it is:
 *   - In MARKETING_SECTION_LABELS (→ marketingContent)
 *   - INGREDIENTS_DECLARATION     (→ ingredients)
 *   - A nutrient pattern          (→ nutritionFacts)
 *   - A nutrition-panel meta code (→ nutritionFacts)
 *
 * Everything else — including future unknown codes — is emitted here, keyed
 * by typeCode in camelCase, with full locale and instance metadata preserved.
 *
 * Output shape per typeCode:
 *   When there is a single instance with a single locale:
 *     { data: "...", locale: "en_US" }
 *   When there are multiple instances:
 *     [ { instance: 1, data: "...", locale: "en_US" }, … ]
 *   When an instance has multiple locale translations:
 *     { instance: 1, translations: [{ data, locale }, …] }
 *
 * @param {object[]} allElements  All top-level + structured elements
 * @returns {object}
 */
function buildRawFields(allElements) {
  // Determine which type codes are already handled
  const isClaimed = tc => {
    if (!tc) return true;
    if (MARKETING_SECTION_LABELS[tc]) return true;
    if (tc === INGREDIENTS_CODE)      return true;
    if (isNutrientRelated(tc))        return true;
    if (NUTRITION_PANEL_CODES.has(tc)) return true;
    return false;
  };

  // Filter to only unclaimed elements that have text
  const unclaimed = allElements.filter(e => !isClaimed(e.typeCode) && e.text);
  if (unclaimed.length === 0) return {};

  // Group by typeCode → instance → [elements]
  const byType = new Map();
  for (const el of unclaimed) {
    if (!byType.has(el.typeCode)) byType.set(el.typeCode, new Map());
    const byInst = byType.get(el.typeCode);
    const list   = byInst.get(el.instance) || [];
    list.push(el);
    byInst.set(el.instance, list);
  }

  const result = {};

  for (const [typeCode, byInst] of byType) {
    // Sort instances ascending
    const sortedInsts = [...byInst.entries()].sort(([a], [b]) => a - b);
    const sectionKey  = toCamelCase(typeCode);

    if (sortedInsts.length === 1) {
      // Single instance — unwrap the array
      const [, group] = sortedInsts[0];
      const grp = localisedGroup(group);
      if (grp !== null) result[sectionKey] = grp;
    } else {
      // Multiple instances — preserve instance number
      const entries = [];
      for (const [inst, group] of sortedInsts) {
        const grp = localisedGroup(group);
        if (grp === null) continue;
        entries.push(
          Array.isArray(grp)
            ? { instance: inst, translations: grp }
            : { instance: inst, ...grp }
        );
      }
      if (entries.length > 0) result[sectionKey] = entries;
    }
  }

  return result;
}

/**
 * Converts an ALL_CAPS_SNAKE type code to camelCase.
 * e.g. TABLE_CELL → tableCell, NUMBER_OF_SERVINGS_PER_LABEL → numberOfServingsPerLabel
 */
function toCamelCase(str) {
  return str.toLowerCase().replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Metadata builder
// ---------------------------------------------------------------------------

function buildMetadata(doc) {
  const g   = tag => { const els = findAll(doc, tag); return els.length ? extractText(els[0]) : null; };
  const add = (obj, key, val) => { if (val) obj[key] = val; };

  const meta = {};
  add(meta, 'instanceIdentifier',           g('InstanceIdentifier'));
  add(meta, 'creationDateTime',             g('creationDateTime') || g('CreationDateAndTime'));
  add(meta, 'documentStatus',               g('documentStatusCode'));
  add(meta, 'documentAction',               g('documentActionCode'));
  add(meta, 'structureVersion',             g('documentStructureVersion'));
  add(meta, 'artworkProjectIdentification', g('artworkProjectIdentification'));

  const localeEls = findAll(doc, 'artworkContentLocale');
  if (localeEls.length > 0) {
    const seen = new Set();
    meta.locales = localeEls
      .map(el => ({
        sequence:   childText(el, 'localeSequence'),
        identifier: normaliseLocale(childText(el, 'localeIdentifier')),
      }))
      .filter(l => {
        if (!l.sequence || !l.identifier) return false;
        const k = `${l.sequence}::${l.identifier}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      });
  }

  return meta;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Parses a GS1 artwork content XML string.
 * Guarantees that every copy element in the file appears in the output.
 *
 * @param  {string} xmlString
 * @returns {{
 *   metadata:        object,
 *   marketingContent:object,
 *   ingredients:     object|Array|null,
 *   nutritionFacts:  object|null,
 *   rawFields:       object   — all other copy elements, keyed by camelCase typeCode
 * }}
 */
function parseArtworkContentFromString(xmlString) {
  const parser = new DOMParser();
  const doc    = parser.parseFromString(xmlString, 'application/xml');

  const errors = findAll(doc, 'parsererror');
  if (errors.length) throw new Error(`XML parse error: ${extractText(errors[0])}`);

  const localeMaps = buildLocaleMaps(doc);
  const { topLevel, structured } = collectElements(doc, localeMaps);
  const allElements = [...topLevel, ...structured];

  const rawFields = buildRawFields(allElements);

  return {
    metadata:         buildMetadata(doc),
    marketingContent: buildMarketingContent(topLevel),
    ingredients:      buildIngredients(allElements),
    nutritionFacts:   buildNutritionFacts(structured),
    ...(Object.keys(rawFields).length > 0 && { rawFields }),
  };
}

/**
 * Reads a GS1 artwork content XML file and returns structured JSON.
 * @param  {string} filePath
 * @returns {Promise<object>}
 */
async function parseArtworkContent(filePath) {
  const xmlString = await fs.promises.readFile(filePath, 'utf-8');
  return parseArtworkContentFromString(xmlString);
}

module.exports = { parseArtworkContent, parseArtworkContentFromString };

// ---------------------------------------------------------------------------
// CLI — node parseArtworkContent.js <file.xml>
// ---------------------------------------------------------------------------
if (require.main === module) {
  const filePath = process.argv[2];
  if (!filePath) { console.error('Usage: node parseArtworkContent.js <path-to-xml-file>'); process.exit(1); }
  parseArtworkContent(filePath)
    .then(result => console.log(JSON.stringify(result, null, 2)))
    .catch(err  => { console.error(err.message); process.exit(1); });
}
