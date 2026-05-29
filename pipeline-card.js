/**
 * pipeline-card.js — Google Cloud Function
 *
 * Triggered by a com.akeneo.pim.v1.product.updated.delta CloudEvent.
 *
 * When any of the 5 pipeline boolean attributes changes on a product:
 *   1. Regenerates an SVG enrichment pipeline status card
 *   2. Checks completeness on the distri_and_retailers channel — if ≥ 50%,
 *      generates a commercial PDF fact sheet, uploads it to a PDF asset family
 *      and assigns it to the Product_Fact_Sheet_PDF asset collection attribute
 *
 * Environment variables (all required):
 *   AKENEO_HOST                        PIM base URL (no trailing slash)
 *   AKENEO_CLIENT_ID                   OAuth2 client ID
 *   AKENEO_CLIENT_SECRET               OAuth2 client secret
 *   AKENEO_USERNAME                    PIM user login
 *   AKENEO_PASSWORD                    PIM user password
 *   AKENEO_WEBHOOK_SECRET              HMAC-SHA256 secret for signature verification
 *   AKENEO_PIPELINE_CARD_ATTRIBUTE     Product textarea attribute for the SVG card
 *   AKENEO_PRODUCT_NAME_ATTRIBUTE      Product text attribute for the product name label
 *   AKENEO_PDF_ASSET_FAMILY            Asset family code for PDF fact sheets
 *   AKENEO_PDF_ASSET_COLLECTION_ATTR   Product asset collection attribute to assign the PDF
 *
 * Optional environment variables:
 *   AKENEO_COMPLETENESS_CHANNEL        Channel to check completeness on (default: distri_and_retailers)
 *   AKENEO_COMPLETENESS_THRESHOLD      Minimum completeness % to trigger PDF (default: 50)
 *   AKENEO_PIPELINE_STEP_1_ATTR        (default: Initial_product_data_received_from_ESKO)
 *   AKENEO_PIPELINE_STEP_2_ATTR        (default: AI_Checks___Content_Enrichment_triggered)
 *   AKENEO_PIPELINE_STEP_3_ATTR        (default: Final_Legal_Compliance_Approval)
 *   AKENEO_PIPELINE_STEP_4_ATTR        (default: Product_Live_on_all_channels)
 *   AKENEO_PIPELINE_STEP_5_ATTR        (default: 100_Omnichannel_Readiness)
 *
 * Dependencies: node-fetch, pdfkit
 */

'use strict';

const crypto      = require('crypto');
const fetch       = require('node-fetch');
const PDFDocument = require('pdfkit');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const EXPECTED_EVENT_TYPE = 'com.akeneo.pim.v1.product.updated.delta';

const DEFAULT_STEP_ATTRS = [
  'Initial_product_data_received_from_ESKO',
  'AI_Checks___Content_Enrichment_triggered',
  'Final_Legal_Compliance_Approval',
  'Product_Live_on_all_channels',
  '100_Omnichannel_Readiness',
];

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

function getConfig() {
  const required = [
    'AKENEO_HOST',
    'AKENEO_CLIENT_ID',
    'AKENEO_CLIENT_SECRET',
    'AKENEO_USERNAME',
    'AKENEO_PASSWORD',
    'AKENEO_WEBHOOK_SECRET',
    'AKENEO_PIPELINE_CARD_ATTRIBUTE',
    'AKENEO_PRODUCT_NAME_ATTRIBUTE',
    'AKENEO_PDF_ASSET_FAMILY',
    'AKENEO_PDF_ASSET_COLLECTION_ATTR',
  ];
  const missing = required.filter(k => !process.env[k]);
  if (missing.length) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }

  const stepAttrs = DEFAULT_STEP_ATTRS.map(
    (def, i) => process.env[`AKENEO_PIPELINE_STEP_${i + 1}_ATTR`] || def
  );

  return {
    host:                 process.env.AKENEO_HOST.replace(/\/$/, ''),
    clientId:             process.env.AKENEO_CLIENT_ID,
    clientSecret:         process.env.AKENEO_CLIENT_SECRET,
    username:             process.env.AKENEO_USERNAME,
    password:             process.env.AKENEO_PASSWORD,
    webhookSecret:        process.env.AKENEO_WEBHOOK_SECRET,
    cardAttribute:        process.env.AKENEO_PIPELINE_CARD_ATTRIBUTE,
    productNameAttr:      process.env.AKENEO_PRODUCT_NAME_ATTRIBUTE,
    pdfAssetFamily:       process.env.AKENEO_PDF_ASSET_FAMILY,
    pdfAssetCollectionAttr: process.env.AKENEO_PDF_ASSET_COLLECTION_ATTR,
    completenessChannel:  process.env.AKENEO_COMPLETENESS_CHANNEL   || 'distri_and_retailers',
    completenessThreshold: parseInt(process.env.AKENEO_COMPLETENESS_THRESHOLD || '50', 10),
    stepAttrs,
  };
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

function verifySignature(req, secret) {
  const receivedSig = req.headers['x-akeneo-signature-primary'];
  if (!receivedSig) {
    return { valid: false, reason: 'Missing X-AKENEO-SIGNATURE-PRIMARY header.' };
  }

  const rawBody = req.rawBody
    ? req.rawBody
    : Buffer.from(JSON.stringify(req.body));

  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');

  let valid;
  try {
    valid = crypto.timingSafeEqual(
      Buffer.from(expected,    'hex'),
      Buffer.from(receivedSig, 'hex')
    );
  } catch {
    valid = false;
  }

  return valid
    ? { valid: true }
    : { valid: false, reason: 'Signature mismatch — request may not originate from Akeneo.' };
}

// ---------------------------------------------------------------------------
// CloudEvent parsing
// ---------------------------------------------------------------------------

class ValidationError extends Error { constructor(m) { super(m); this.name = 'ValidationError'; } }
class IgnoredEventError extends Error { constructor(m) { super(m); this.name = 'IgnoredEventError'; } }

/**
 * Parses and validates the incoming product.updated.delta CloudEvent.
 *
 * Per the official docs (https://api.akeneo.com/event-platform/available-events.html):
 *
 *   data.product.uuid        — always present — primary product identifier
 *   data.product.identifier  — optional — only when send_product_identifier is
 *                              enabled on the subscription
 *   data.product.changes.values — { attrCode: [{ previous, new, type, locale, scope }] }
 *                                 Note: field is "scope", not "channel" (product delta)
 *
 * @param {object} body
 * @returns {{ eventId, eventTime, productUuid, productIdentifier, changedValues }}
 */
function parseCloudEvent(body) {
  if (!body || typeof body !== 'object') {
    throw new ValidationError('Request body is missing or not a JSON object.');
  }
  if (body.specversion !== '1.0') {
    throw new ValidationError(`Unexpected CloudEvents specversion: "${body.specversion}". Expected "1.0".`);
  }
  if (body.type !== EXPECTED_EVENT_TYPE) {
    throw new IgnoredEventError(`Event type "${body.type}" is not handled. Expected "${EXPECTED_EVENT_TYPE}".`);
  }

  const data = body.data;
  if (!data?.product) {
    throw new ValidationError('CloudEvent data.product is missing.');
  }

  // uuid is the canonical product identifier — always present
  const productUuid = data.product.uuid;
  if (!productUuid) {
    throw new ValidationError('CloudEvent data.product.uuid is missing.');
  }

  // identifier is optional — only present when send_product_identifier is enabled
  const productIdentifier = data.product.identifier || null;

  const changedValues = data.product.changes?.values;
  if (!changedValues || typeof changedValues !== 'object') {
    // changes.values may be absent when only non-value properties changed
    // (e.g. family, categories, groups) — treat as no relevant change
    return {
      eventId:           body.id,
      eventTime:         body.time,
      productUuid,
      productIdentifier,
      changedValues:     {},
    };
  }

  return {
    eventId:           body.id,
    eventTime:         body.time,
    productUuid,
    productIdentifier,
    changedValues,
  };
}

/**
 * Returns true when at least one of the 5 pipeline step attributes has a
 * meaningful change in the delta — i.e. the attribute is in changedValues
 * AND at least one of its entries has a `previous` value that differs from
 * its `new` value.
 *
 * The product name attribute is intentionally excluded: a product name change
 * alone should not trigger a card regeneration.
 *
 * The delta entry shape per attribute:
 *   changedValues[attrCode] = [
 *     { previous: true|false|null, new: true|false|null, locale: null, channel: null }
 *   ]
 *
 * @param {object}   changedValues  data.product.changes.values from the event
 * @param {string[]} stepAttrs      The 5 pipeline step attribute codes
 * @returns {boolean}
 */
function hasPipelineChange(changedValues, stepAttrs) {
  for (const attr of stepAttrs) {
    const entries = changedValues[attr];
    if (!Array.isArray(entries)) continue;

    // At least one entry must have a genuinely different previous → new value
    const hasRealChange = entries.some(entry => entry.previous !== entry.new);
    if (hasRealChange) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Akeneo API helpers
// ---------------------------------------------------------------------------

async function getAccessToken(cfg) {
  const credentials = Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString('base64');
  const res = await fetch(`${cfg.host}/api/oauth/v1/token`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Basic ${credentials}` },
    body:    JSON.stringify({ grant_type: 'password', username: cfg.username, password: cfg.password }),
  });
  if (!res.ok) throw new Error(`Akeneo auth failed (${res.status}): ${await res.text()}`);
  const data = await res.json();
  if (!data.access_token) throw new Error('Akeneo auth response missing access_token');
  return data.access_token;
}

/**
 * Fetches a product record by UUID and returns its values map.
 *
 * Uses the UUID-based endpoint which is always available regardless of
 * whether send_product_identifier is enabled on the subscription.
 * The identifier-based endpoint (/products/{identifier}) does not accept
 * UUIDs and returns 404 when passed one.
 *
 * @param {string} host
 * @param {string} token
 * @param {string} productUuid
 * @returns {Promise<object>}  Akeneo product values: { attrCode: [{ data, locale, scope }] }
 */
async function fetchProductValues(host, token, productUuid) {
  const url = `${host}/api/rest/v1/products-uuid/${encodeURIComponent(productUuid)}`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) throw new Error(`Failed to fetch product "${productUuid}" (${res.status}): ${await res.text()}`);
  const product = await res.json();
  return product.values || {};
}

/**
 * Reads a scalar value from an Akeneo product values map.
 * Tries locale=null/scope=null first, then falls back to first entry found.
 *
 * @param {object}      values      Product values map
 * @param {string}      attrCode    Attribute code
 * @returns {*}                     The raw data value (boolean, string, null, etc.)
 */
function readValue(values, attrCode) {
  const entries = values[attrCode];
  if (!entries || !entries.length) return null;
  // Prefer non-localised, non-scoped entry
  const canonical = entries.find(e => e.locale === null && e.scope === null);
  return (canonical ?? entries[0]).data ?? null;
}

/**
 * Writes the SVG card to the product's textarea attribute.
 *
 * @param {string} host
 * @param {string} token
 * @param {string} productIdentifier
 * @param {string} attribute
 * @param {string} svgString
 */
async function writePipelineCard(host, token, productUuid, attribute, svgString) {
  const LIMIT = 65535;
  if (svgString.length > LIMIT) {
    throw new Error(`Pipeline card SVG (${svgString.length} chars) exceeds Akeneo's ${LIMIT}-char textarea limit.`);
  }
  const url  = `${host}/api/rest/v1/products-uuid/${encodeURIComponent(productUuid)}`;
  const body = {
    values: { [attribute]: [{ locale: null, scope: null, data: svgString }] },
  };
  const res = await fetch(url, {
    method:  'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`Failed to write pipeline card (${res.status}): ${await res.text()}`);
  }
  console.log(`  Pipeline card written to "${attribute}" on product "${productUuid}" (${svgString.length} chars).`);
}

// ---------------------------------------------------------------------------
// Completeness helpers
// ---------------------------------------------------------------------------

/**
 * Fetches the full product record including completenesses.
 * completenesses shape: [ { channel, locale, ratio }, … ]
 */
async function fetchProductWithCompleteness(host, token, productUuid) {
  const url = `${host}/api/rest/v1/products-uuid/${encodeURIComponent(productUuid)}?with_completenesses=true`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) throw new Error(`Failed to fetch product completeness "${productUuid}" (${res.status}): ${await res.text()}`);
  return res.json();
}

/**
 * Returns the highest completeness ratio across all locales for a channel,
 * or null if the channel is absent from the completenesses array.
 */
function getChannelCompleteness(completenesses, channel) {
  if (!Array.isArray(completenesses)) return null;
  const entries = completenesses.filter(c => c.channel === channel);
  if (!entries.length) return null;
  return Math.max(...entries.map(c => c.ratio ?? 0));
}

// ---------------------------------------------------------------------------
// PDF fact sheet generator
// ---------------------------------------------------------------------------

/**
 * Generates a commercial product fact sheet PDF from the product's values.
 * Returns a Buffer containing the PDF binary.
 *
 * @param {{
 *   productUuid:  string,
 *   productName:  string,
 *   values:       object,
 *   completeness: number,
 *   channel:      string,
 * }} opts
 * @returns {Promise<Buffer>}
 */
function generateFactSheetPdf({ productUuid, productName, values, completeness, channel }) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    const doc    = new PDFDocument({ size: 'A4', margin: 50, info: {
      Title:   `Product Fact Sheet — ${productName}`,
      Author:  'Akeneo PIM',
      Subject: 'Commercial product fact sheet',
    }});

    doc.on('data',  chunk => chunks.push(chunk));
    doc.on('end',   ()    => resolve(Buffer.concat(chunks)));
    doc.on('error', err   => reject(err));

    const W      = doc.page.width - 100;
    const PURPLE = '#4F46E5';
    const DARK   = '#1E1B4B';
    const GREY   = '#6B7280';
    const GREEN  = '#22C55E';
    const ORANGE = '#F97316';

    // Header band
    doc.rect(50, 50, W, 80).fill(PURPLE);
    doc.fillColor('white').font('Helvetica-Bold').fontSize(20)
       .text(productName, 66, 66, { width: W - 32, lineBreak: false });
    doc.font('Helvetica').fontSize(10)
       .text(`UUID: ${productUuid}`, 66, 94, { width: W - 32 })
       .text(`Generated: ${new Date().toUTCString()}`, 66, 108, { width: W - 32 });
    doc.moveDown(4.5);

    // Completeness bar
    const barY  = doc.y;
    const fill  = Math.round((completeness / 100) * W);
    const color = completeness >= 50 ? GREEN : ORANGE;
    doc.rect(50, barY, W,    18).fill('#E5E7EB');
    doc.rect(50, barY, fill, 18).fill(color);
    doc.fillColor(DARK).font('Helvetica-Bold').fontSize(10)
       .text(`${channel} completeness: ${completeness}%`, 55, barY + 4);
    doc.moveDown(1.5);

    // Section renderer
    const renderSection = (title, rows) => {
      if (!rows.length) return;
      doc.rect(50, doc.y, W, 20).fill('#F8F7FF');
      doc.fillColor(PURPLE).font('Helvetica-Bold').fontSize(11)
         .text(title, 56, doc.y - 16);
      doc.moveDown(0.3);
      let alt = false;
      for (const [key, val] of rows) {
        if (doc.y > doc.page.height - 100) doc.addPage();
        const rowY = doc.y;
        if (alt) doc.rect(50, rowY, W, 18).fill('#F9FAFB');
        doc.fillColor(GREY).font('Helvetica-Bold').fontSize(9)
           .text(key, 56, rowY + 4, { width: 180 });
        doc.fillColor(DARK).font('Helvetica').fontSize(9)
           .text(String(val).slice(0, 300), 240, rowY + 4, { width: W - 196, lineBreak: false });
        doc.moveDown(0.85);
        alt = !alt;
      }
      doc.moveDown(0.5);
    };

    // Collect attributes
    const globalRows = [], scopedRows = [];
    for (const [attrCode, entries] of Object.entries(values)) {
      if (!Array.isArray(entries)) continue;
      for (const entry of entries) {
        const data = entry.data;
        if (data === null || data === undefined || data === '') continue;
        let displayVal = Array.isArray(data) ? data.join(', ')
                       : typeof data === 'object' ? JSON.stringify(data)
                       : String(data);
        if (displayVal.length > 400) displayVal = displayVal.slice(0, 397) + '…';
        const label = (entry.locale || entry.scope)
          ? `${attrCode} [${[entry.locale, entry.scope].filter(Boolean).join('/')}]`
          : attrCode;
        if (!entry.locale && !entry.scope) globalRows.push([attrCode, displayVal]);
        else                               scopedRows.push([label, displayVal]);
      }
    }

    renderSection('Global attributes', globalRows);
    renderSection('Localised / scoped attributes', scopedRows);

    // Footer
    const footerY = doc.page.height - 40;
    doc.rect(50, footerY - 8, W, 0.5).fill('#E5E7EB');
    doc.fillColor(GREY).font('Helvetica').fontSize(8)
       .text('Generated by Akeneo PIM · Esko Asset Decompactor', 50, footerY, { align: 'center', width: W });

    doc.end();
  });
}

/**
 * Uploads a PDF buffer, upserts the asset record in the PDF family, then
 * appends the asset code to the product's asset collection attribute.
 *
 * Uses a deterministic asset code so re-runs upsert the same record.
 */
async function uploadAndAssignFactSheet(
  host, token, productUuid, productName,
  pdfAssetFamily, pdfAssetCollectionAttr, mainMediaAttr, pdfBuffer
) {
  // Deterministic asset code
  const sanitised = (productName || productUuid)
    .replace(/[^a-zA-Z0-9]/g, '_').replace(/_{2,}/g, '_')
    .replace(/^_|_$/g, '').slice(0, 40);
  const uuid8     = productUuid.replace(/-/g, '').slice(0, 8);
  const assetCode = `fact_sheet_${sanitised}_${uuid8}`.slice(0, 255);
  const filename  = `${assetCode}.pdf`;

  // 1. Upload binary
  const boundary = `----FactSheetUpload${Date.now()}`;
  const header   = Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: application/pdf\r\n\r\n`
  );
  const footer   = Buffer.from(`\r\n--${boundary}--\r\n`);
  const body     = Buffer.concat([header, pdfBuffer, footer]);

  const uploadRes = await fetch(`${host}/api/rest/v1/asset-media-files`, {
    method:  'POST',
    headers: {
      Authorization:    `Bearer ${token}`,
      'Content-Type':  `multipart/form-data; boundary=${boundary}`,
      'Content-Length': String(body.length),
    },
    body,
  });
  if (!uploadRes.ok) throw new Error(`PDF upload failed (${uploadRes.status}): ${await uploadRes.text()}`);

  const location = uploadRes.headers.get('location') || '';
  let pathname;
  try { pathname = new URL(location).pathname; } catch { pathname = location; }
  const assetFilePath = pathname.replace(/^\/api\/rest\/v1\/asset-media-files\//, '');
  if (!assetFilePath || assetFilePath === pathname)
    throw new Error(`PDF upload succeeded but could not parse Location header: "${location}"`);
  console.log(`  PDF uploaded → ${assetFilePath}`);

  // 2. Upsert asset record
  const assetRes = await fetch(
    `${host}/api/rest/v1/asset-families/${encodeURIComponent(pdfAssetFamily)}/assets/${encodeURIComponent(assetCode)}`,
    {
      method:  'PATCH',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body:    JSON.stringify({ code: assetCode, values: { [mainMediaAttr]: [{ locale: null, channel: null, data: assetFilePath }] } }),
    }
  );
  if (assetRes.status !== 201 && assetRes.status !== 204)
    throw new Error(`Asset record upsert failed (${assetRes.status}): ${await assetRes.text()}`);
  console.log(`  Asset record "${assetCode}" upserted in family "${pdfAssetFamily}".`);

  // 3. Append asset to product collection (read-modify-write)
  const productRes = await fetch(
    `${host}/api/rest/v1/products-uuid/${encodeURIComponent(productUuid)}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!productRes.ok) throw new Error(`Re-fetch for asset assignment failed (${productRes.status})`);
  const product       = await productRes.json();
  const existing      = product.values?.[pdfAssetCollectionAttr]?.[0]?.data || [];
  const newCodes      = existing.includes(assetCode) ? existing : [...existing, assetCode];

  const patchRes = await fetch(
    `${host}/api/rest/v1/products-uuid/${encodeURIComponent(productUuid)}`,
    {
      method:  'PATCH',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body:    JSON.stringify({ values: { [pdfAssetCollectionAttr]: [{ locale: null, scope: null, data: newCodes }] } }),
    }
  );
  if (!patchRes.ok) throw new Error(`Asset collection PATCH failed (${patchRes.status}): ${await patchRes.text()}`);
  console.log(`  Asset "${assetCode}" assigned to "${pdfAssetCollectionAttr}" on "${productUuid}".`);

  return assetCode;
}

// ---------------------------------------------------------------------------
// SVG card generator
// ---------------------------------------------------------------------------

/**
 * Applies the coloring rules from the spec and returns a token object
 * for one step.
 *
 * @param {boolean|null} value
 * @returns {{
 *   BAR, BORDER, CIRCLE_BG, CIRCLE_BORDER, ICON, ICON_COLOR,
 *   PILL_BG, PILL_BORDER, PILL_COLOR, STATUS
 * }}
 */
function stepTokens(value) {
  const done = value === true;
  return done ? {
    BAR:           '#22C55E',
    BORDER:        '#BBF7D0',
    CIRCLE_BG:     '#F0FDF4',
    CIRCLE_BORDER: '#BBF7D0',
    ICON:          '✓',
    ICON_COLOR:    '#15803D',
    PILL_BG:       '#F0FDF4',
    PILL_BORDER:   '#BBF7D0',
    PILL_COLOR:    '#15803D',
    STATUS:        'done',
  } : {
    BAR:           '#F97316',
    BORDER:        '#FED7AA',
    CIRCLE_BG:     '#FFF7ED',
    CIRCLE_BORDER: '#FED7AA',
    ICON:          '?',
    ICON_COLOR:    '#F97316',
    PILL_BG:       '#FFF7ED',
    PILL_BORDER:   '#FED7AA',
    PILL_COLOR:    '#C2410C',
    STATUS:        'pending',
  };
}

/**
 * Generates the SVG enrichment pipeline card as a string.
 *
 * Strictly implements the template from the spec — every {{PLACEHOLDER}}
 * is replaced with the computed value for that product.
 *
 * @param {{
 *   identifier:  string,
 *   productName: string,
 *   steps:       Array<boolean|null>   — exactly 5 values
 * }} opts
 * @returns {string}  Raw SVG markup
 */
function generatePipelineCard({ identifier, productName, steps }) {
  const s = steps.map(v => stepTokens(v));
  const pipelineDone = steps.filter(v => v === true).length;

  const footerDotBg     = pipelineDone === 5 ? '#D1FAE5' : '#FFF7ED';
  const footerDotFill   = pipelineDone === 5 ? '#22C55E' : '#F97316';
  const footerDotBorder = pipelineDone === 5 ? '#BBF7D0' : '#FED7AA';

  // Escape XML special characters for safe embedding in SVG text
  const esc = str => String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

  // Truncate long strings to avoid SVG text overflow
  const trunc = (str, n) => str.length > n ? str.slice(0, n - 1) + '…' : str;

  const name = esc(trunc(productName || identifier, 42));
  const id   = esc(trunc(identifier, 20));

  return `<svg viewBox="0 0 1000 370" width="1000" height="370" xmlns="http://www.w3.org/2000/svg" role="img" font-family="Inter, system-ui, sans-serif"><title>Enrichment pipeline — ${name}</title><rect width="1000" height="370" rx="12" fill="#F8F7FF"/><rect x="0" y="0" width="6" height="370" rx="3" fill="#6366F1"/><rect x="6" y="0" width="988" height="80" rx="10" fill="#4F46E5"/><rect x="6" y="60" width="988" height="20" fill="#4F46E5"/><rect x="22" y="16" width="140" height="18" rx="9" fill="rgba(255,255,255,0.18)"/><text x="92" y="29" text-anchor="middle" fill="white" font-size="11" font-weight="500">${id}</text><text x="22" y="62" fill="white" font-size="22" font-weight="700">${name}</text><text x="978" y="29" text-anchor="end" fill="rgba(255,255,255,0.55)" font-size="11">snacks · esko PIM</text><text x="500" y="118" text-anchor="middle" fill="#9CA3AF" font-size="11" letter-spacing="1">ENRICHMENT WORKFLOW PIPELINE</text><line x1="22" y1="127" x2="978" y2="127" stroke="#E5E7EB" stroke-width="0.5"/><line x1="210" y1="232" x2="238" y2="232" stroke="#D1D5DB" stroke-width="2" stroke-dasharray="4 3"/><line x1="410" y1="232" x2="438" y2="232" stroke="#D1D5DB" stroke-width="2" stroke-dasharray="4 3"/><line x1="610" y1="232" x2="638" y2="232" stroke="#D1D5DB" stroke-width="2" stroke-dasharray="4 3"/><line x1="810" y1="232" x2="838" y2="232" stroke="#D1D5DB" stroke-width="2" stroke-dasharray="4 3"/><polygon points="238,228 245,232 238,236" fill="#D1D5DB"/><polygon points="438,228 445,232 438,236" fill="#D1D5DB"/><polygon points="638,228 645,232 638,236" fill="#D1D5DB"/><polygon points="838,228 845,232 838,236" fill="#D1D5DB"/><rect x="22" y="140" width="188" height="180" rx="10" fill="white" stroke="${s[0].BORDER}" stroke-width="1.5"/><rect x="22" y="140" width="188" height="6" rx="5" fill="${s[0].BAR}"/><rect x="22" y="144" width="188" height="3" fill="${s[0].BAR}"/><circle cx="116" cy="205" r="36" fill="${s[0].CIRCLE_BG}" stroke="${s[0].CIRCLE_BORDER}" stroke-width="2"/><text x="116" y="214" text-anchor="middle" fill="${s[0].ICON_COLOR}" font-size="32" font-weight="700">${s[0].ICON}</text><text x="116" y="258" text-anchor="middle" fill="#1E1B4B" font-size="12" font-weight="600">Received</text><text x="116" y="273" text-anchor="middle" fill="#1E1B4B" font-size="12" font-weight="600">from ESKO</text><rect x="46" y="288" width="140" height="22" rx="11" fill="${s[0].PILL_BG}" stroke="${s[0].PILL_BORDER}" stroke-width="1"/><circle cx="64" cy="299" r="5" fill="${s[0].BAR}"/><text x="116" y="303" text-anchor="middle" fill="${s[0].PILL_COLOR}" font-size="11" font-weight="600">${s[0].STATUS}</text><rect x="238" y="140" width="172" height="180" rx="10" fill="white" stroke="${s[1].BORDER}" stroke-width="1.5"/><rect x="238" y="140" width="172" height="6" rx="5" fill="${s[1].BAR}"/><rect x="238" y="144" width="172" height="3" fill="${s[1].BAR}"/><circle cx="324" cy="205" r="36" fill="${s[1].CIRCLE_BG}" stroke="${s[1].CIRCLE_BORDER}" stroke-width="2"/><text x="324" y="214" text-anchor="middle" fill="${s[1].ICON_COLOR}" font-size="32" font-weight="700">${s[1].ICON}</text><text x="324" y="258" text-anchor="middle" fill="#1E1B4B" font-size="12" font-weight="600">AI Checks &amp;</text><text x="324" y="273" text-anchor="middle" fill="#1E1B4B" font-size="12" font-weight="600">Content Enrichment</text><rect x="254" y="288" width="140" height="22" rx="11" fill="${s[1].PILL_BG}" stroke="${s[1].PILL_BORDER}" stroke-width="1"/><circle cx="272" cy="299" r="5" fill="${s[1].BAR}"/><text x="324" y="303" text-anchor="middle" fill="${s[1].PILL_COLOR}" font-size="11" font-weight="600">${s[1].STATUS}</text><rect x="438" y="140" width="172" height="180" rx="10" fill="white" stroke="${s[2].BORDER}" stroke-width="1.5"/><rect x="438" y="140" width="172" height="6" rx="5" fill="${s[2].BAR}"/><rect x="438" y="144" width="172" height="3" fill="${s[2].BAR}"/><circle cx="524" cy="205" r="36" fill="${s[2].CIRCLE_BG}" stroke="${s[2].CIRCLE_BORDER}" stroke-width="2"/><text x="524" y="214" text-anchor="middle" fill="${s[2].ICON_COLOR}" font-size="32" font-weight="700">${s[2].ICON}</text><text x="524" y="258" text-anchor="middle" fill="#1E1B4B" font-size="12" font-weight="600">Final Legal /</text><text x="524" y="273" text-anchor="middle" fill="#1E1B4B" font-size="12" font-weight="600">Compliance Approval</text><rect x="454" y="288" width="140" height="22" rx="11" fill="${s[2].PILL_BG}" stroke="${s[2].PILL_BORDER}" stroke-width="1"/><circle cx="472" cy="299" r="5" fill="${s[2].BAR}"/><text x="524" y="303" text-anchor="middle" fill="${s[2].PILL_COLOR}" font-size="11" font-weight="600">${s[2].STATUS}</text><rect x="638" y="140" width="172" height="180" rx="10" fill="white" stroke="${s[3].BORDER}" stroke-width="1.5"/><rect x="638" y="140" width="172" height="6" rx="5" fill="${s[3].BAR}"/><rect x="638" y="144" width="172" height="3" fill="${s[3].BAR}"/><circle cx="724" cy="205" r="36" fill="${s[3].CIRCLE_BG}" stroke="${s[3].CIRCLE_BORDER}" stroke-width="2"/><text x="724" y="214" text-anchor="middle" fill="${s[3].ICON_COLOR}" font-size="32" font-weight="700">${s[3].ICON}</text><text x="724" y="258" text-anchor="middle" fill="#1E1B4B" font-size="12" font-weight="600">Product Live</text><text x="724" y="273" text-anchor="middle" fill="#1E1B4B" font-size="12" font-weight="600">on all channels</text><rect x="654" y="288" width="140" height="22" rx="11" fill="${s[3].PILL_BG}" stroke="${s[3].PILL_BORDER}" stroke-width="1"/><circle cx="672" cy="299" r="5" fill="${s[3].BAR}"/><text x="724" y="303" text-anchor="middle" fill="${s[3].PILL_COLOR}" font-size="11" font-weight="600">${s[3].STATUS}</text><rect x="838" y="140" width="140" height="180" rx="10" fill="white" stroke="${s[4].BORDER}" stroke-width="1.5"/><rect x="838" y="140" width="140" height="6" rx="5" fill="${s[4].BAR}"/><rect x="838" y="144" width="140" height="3" fill="${s[4].BAR}"/><circle cx="908" cy="205" r="36" fill="${s[4].CIRCLE_BG}" stroke="${s[4].CIRCLE_BORDER}" stroke-width="2"/><text x="908" y="214" text-anchor="middle" fill="${s[4].ICON_COLOR}" font-size="32" font-weight="700">${s[4].ICON}</text><text x="908" y="258" text-anchor="middle" fill="#1E1B4B" font-size="12" font-weight="600">100%</text><text x="908" y="273" text-anchor="middle" fill="#1E1B4B" font-size="12" font-weight="600">Omnichannel</text><rect x="858" y="288" width="100" height="22" rx="11" fill="${s[4].PILL_BG}" stroke="${s[4].PILL_BORDER}" stroke-width="1"/><circle cx="872" cy="299" r="5" fill="${s[4].BAR}"/><text x="908" y="303" text-anchor="middle" fill="${s[4].PILL_COLOR}" font-size="11" font-weight="600">${s[4].STATUS}</text><line x1="22" y1="334" x2="978" y2="334" stroke="#E5E7EB" stroke-width="0.5"/><circle cx="36" cy="352" r="5" fill="${footerDotBg}" stroke="${footerDotBorder}" stroke-width="1"/><circle cx="36" cy="352" r="3" fill="${footerDotFill}"/><text x="48" y="356" fill="#9CA3AF" font-size="10">${pipelineDone} / 5 steps completed</text><circle cx="968" cy="352" r="4" fill="#D1FAE5"/><circle cx="968" cy="352" r="2.5" fill="#10B981"/><text x="958" y="356" text-anchor="end" fill="#10B981" font-size="10">live</text></svg>`;
}

// ---------------------------------------------------------------------------
// Cloud Function entry point
// ---------------------------------------------------------------------------

/**
 * Google Cloud Function HTTP handler.
 *
 * Receives a com.akeneo.pim.v1.product.updated.delta CloudEvent.
 * Regenerates the SVG enrichment pipeline card whenever any of the
 * 5 pipeline boolean attributes (or the product name) changes.
 *
 * Responds:
 *   200 { status: "processed", productIdentifier, pipelineDone, cardAttribute }
 *   200 { status: "skipped",   reason }
 *   401 { status: "error",     error }   — signature failure
 *   400 { status: "error",     error }   — malformed event
 *   500 { status: "error",     error }   — internal error
 *
 * @param {import('@google-cloud/functions-framework').Request}  req
 * @param {import('@google-cloud/functions-framework').Response} res
 */
exports.generatePipelineCard = async (req, res) => {
  try {
    // ── 0. Config ─────────────────────────────────────────────────────────
    const cfg = getConfig();

    // ── 1. Verify HMAC-SHA256 signature ───────────────────────────────────
    const { valid, reason: sigReason } = verifySignature(req, cfg.webhookSecret);
    if (!valid) {
      console.warn(`Signature verification failed: ${sigReason}`);
      return res.status(401).json({ status: 'error', error: sigReason });
    }
    console.log('✓ Signature verified.');

    // ── 2. Parse & validate the CloudEvent ───────────────────────────────
    let parsed;
    try {
      parsed = parseCloudEvent(req.body);
    } catch (err) {
      if (err instanceof IgnoredEventError) {
        console.log(`Skipping event: ${err.message}`);
        return res.status(200).json({ status: 'skipped', reason: err.message });
      }
      console.error(`CloudEvent validation error: ${err.message}`);
      return res.status(400).json({ status: 'error', error: err.message });
    }

    const { eventId, eventTime, productUuid, productIdentifier, changedValues } = parsed;
    console.log(`[${eventId}] ${EXPECTED_EVENT_TYPE} — uuid: "${productUuid}" identifier: "${productIdentifier || 'n/a'}"`);

    // ── 3. Check whether any pipeline step attribute changed ──────────────
    if (!hasPipelineChange(changedValues, cfg.stepAttrs)) {
      const reason = `No pipeline step attribute changed on "${productUuid}" — skipping.`;
      console.log(reason);
      return res.status(200).json({ status: 'skipped', reason });
    }
    console.log(`Pipeline attribute change detected — regenerating card.`);

    // ── 4. Authenticate ───────────────────────────────────────────────────
    const token = await getAccessToken(cfg);
    console.log('Authenticated with Akeneo.');

    // ── 5. Fetch current product values ───────────────────────────────────
    // Always fetch by UUID — the identifier is optional and absent when
    // send_product_identifier is not enabled on the subscription.
    const values = await fetchProductValues(cfg.host, token, productUuid);

    const productName = readValue(values, cfg.productNameAttr) || productIdentifier || productUuid;
    const steps = cfg.stepAttrs.map(attr => {
      const v = readValue(values, attr);
      return v === true ? true : null;
    });

    const pipelineDone = steps.filter(v => v === true).length;
    console.log(`Product: "${productName}" | Pipeline: ${pipelineDone}/5 steps done`);

    // ── 6. Generate SVG card ──────────────────────────────────────────────
    const svgCard = generatePipelineCard({
      identifier:  productIdentifier || productUuid,
      productName,
      steps,
    });
    console.log(`SVG card generated (${svgCard.length} chars).`);

    // ── 7. Write SVG card to product attribute ────────────────────────────
    await writePipelineCard(cfg.host, token, productUuid, cfg.cardAttribute, svgCard);

    // ── 8. PDF fact sheet (conditional on channel completeness) ───────────
    let pdfResult = null;
    try {
      const fullProduct  = await fetchProductWithCompleteness(cfg.host, token, productUuid);
      const completeness = getChannelCompleteness(fullProduct.completenesses, cfg.completenessChannel);

      console.log(`Channel "${cfg.completenessChannel}" completeness: ${completeness ?? 'n/a'}%`);

      if (completeness !== null && completeness >= cfg.completenessThreshold) {
        console.log(`Completeness ≥ ${cfg.completenessThreshold}% — generating PDF fact sheet…`);

        // Fetch attribute_as_main_media of the PDF asset family
        const familyRes = await fetch(
          `${cfg.host}/api/rest/v1/asset-families/${encodeURIComponent(cfg.pdfAssetFamily)}`,
          { headers: { Authorization: `Bearer ${token}` } }
        );
        if (!familyRes.ok) throw new Error(`Failed to fetch PDF asset family (${familyRes.status})`);
        const family        = await familyRes.json();
        const mainMediaAttr = family.attribute_as_main_media;
        if (!mainMediaAttr) throw new Error(`PDF asset family "${cfg.pdfAssetFamily}" has no attribute_as_main_media`);

        const pdfBuffer = await generateFactSheetPdf({
          productUuid,
          productName,
          values:       fullProduct.values || {},
          completeness,
          channel:      cfg.completenessChannel,
        });
        console.log(`PDF generated (${pdfBuffer.length} bytes).`);

        const assetCode = await uploadAndAssignFactSheet(
          cfg.host, token, productUuid, productName,
          cfg.pdfAssetFamily, cfg.pdfAssetCollectionAttr, mainMediaAttr, pdfBuffer
        );
        pdfResult = { generated: true, assetCode, completeness };
      } else {
        const reason = completeness === null
          ? `Channel "${cfg.completenessChannel}" not found in completenesses`
          : `Completeness ${completeness}% < threshold ${cfg.completenessThreshold}%`;
        console.log(`PDF skipped — ${reason}`);
        pdfResult = { generated: false, reason, completeness };
      }
    } catch (pdfErr) {
      // PDF failure is non-fatal — SVG card was already written
      console.error(`PDF fact sheet error (non-fatal): ${pdfErr.message}`);
      pdfResult = { generated: false, error: pdfErr.message };
    }

    // ── 9. Respond ────────────────────────────────────────────────────────
    return res.status(200).json({
      status:            'processed',
      productUuid,
      productIdentifier: productIdentifier || null,
      pipelineDone,
      cardAttribute:     cfg.cardAttribute,
      factSheet:         pdfResult,
    });

  } catch (err) {
    console.error('Unhandled error:', err.message);
    return res.status(500).json({ status: 'error', error: err.message });
  }
};

// Export pure functions for testing
module.exports.generateFactSheetPdf    = generateFactSheetPdf;
module.exports.getChannelCompleteness  = getChannelCompleteness;
