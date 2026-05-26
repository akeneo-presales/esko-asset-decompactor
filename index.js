/**
 * index.js — Google Cloud Function
 *
 * Triggered by an Akeneo Event Platform webhook delivering a
 * com.akeneo.pim.v1.asset.updated.delta CloudEvent.
 *
 * The function:
 *   1. Validates the incoming CloudEvent (type, structure)
 *   2. Inspects data.asset.changes.values for the configured media file
 *      attribute — skips if that attribute didn't change or the new value
 *      is empty/null
 *   3. Authenticates against Akeneo PIM
 *   4. Fetches the full asset record & resolves the ZIP download URL
 *      directly from the new media file path carried in the event delta
 *   5. Downloads and extracts the ZIP to a temp directory
 *   6. Finds the gs1/ folder and parses every .xml file inside
 *   7. Derives the product identifier from the .ai filename
 *   8. Upserts the product in Akeneo (create if absent, PATCH if present)
 *   9. Writes the GS1 JSON to the configured text attribute
 *
 * Environment variables:
 *   AKENEO_HOST              e.g. https://my-instance.cloud.akeneo.com
 *   AKENEO_CLIENT_ID         OAuth2 client id
 *   AKENEO_CLIENT_SECRET     OAuth2 client secret
 *   AKENEO_USERNAME          PIM username
 *   AKENEO_PASSWORD          PIM password
 *   AKENEO_MEDIA_ATTRIBUTE   Asset attribute code holding the ZIP media file
 *                            (e.g. zip_file) — watched for changes
 *   AKENEO_GS1_ATTRIBUTE     Product text attribute to write the JSON into
 *                            (e.g. gs1_artwork_content)
 *   AKENEO_WEBHOOK_SECRET    Primary HMAC-SHA256 secret configured on the
 *                            Akeneo Event Platform subscription — used to
 *                            verify the X-AKENEO-SIGNATURE-PRIMARY header
 *                            on every incoming request
 *
 * Dependencies (package.json):
 *   @xmldom/xmldom   — XML parser (used by parseArtworkContent)
 *   adm-zip          — ZIP extraction
 *   node-fetch       — HTTP client (or use native fetch on Node 18+)
 */

'use strict';

const os     = require('os');
const path   = require('path');
const fs     = require('fs');
const crypto = require('crypto');   // built-in — no extra dependency
const AdmZip = require('adm-zip');
const fetch  = require('node-fetch');

const { parseArtworkContentFromString } = require('./parseArtworkContent');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const EXPECTED_EVENT_TYPE = 'com.akeneo.pim.v1.asset.updated.delta';

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/**
 * Verifies the HMAC-SHA256 signature that the Akeneo Event Platform attaches
 * to every webhook delivery.
 *
 * Akeneo signs the **raw request body** with the secret configured on the
 * subscription and sends the hex-encoded digest in:
 *   X-AKENEO-SIGNATURE-PRIMARY   (mandatory — matches our primary_secret)
 *   X-AKENEO-SIGNATURE-SECONDARY (optional — present during secret rotation)
 *   X-AKENEO-SIGNATURE-ALGORITHM (currently always "HmacSHA256")
 *
 * We compute the HMAC over the raw body and compare using a constant-time
 * comparison to prevent timing attacks.
 *
 * Cloud Run Functions / Functions Framework parse the body JSON before the
 * handler runs, so we re-serialise req.body to recover the canonical raw
 * bytes. This is safe as long as the body isn't re-ordered by the framework
 * (the Functions Framework preserves the body as-is in req.rawBody when
 * available, which we prefer).
 *
 * @param {import('@google-cloud/functions-framework').Request} req
 * @param {string} secret  AKENEO_WEBHOOK_SECRET from env
 * @returns {{ valid: boolean, reason?: string }}
 */
function verifySignature(req, secret) {
  const receivedSig = req.headers['x-akeneo-signature-primary'];

  if (!receivedSig) {
    return { valid: false, reason: 'Missing X-AKENEO-SIGNATURE-PRIMARY header.' };
  }

  // Use the raw body buffer if the framework preserved it; fall back to
  // re-serialising the parsed JSON (deterministic for well-formed payloads).
  const rawBody = req.rawBody
    ? req.rawBody
    : Buffer.from(JSON.stringify(req.body));

  const expected = crypto
    .createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex');

  // Constant-time comparison — prevents timing side-channel leaks
  let valid;
  try {
    valid = crypto.timingSafeEqual(
      Buffer.from(expected,     'hex'),
      Buffer.from(receivedSig,  'hex')
    );
  } catch {
    // Buffer lengths differ → signatures can't match
    valid = false;
  }

  if (!valid) {
    return {
      valid: false,
      reason: 'Signature mismatch — request may not originate from Akeneo.',
    };
  }

  return { valid: true };
}



function getConfig() {
  const required = [
    'AKENEO_HOST',
    'AKENEO_CLIENT_ID',
    'AKENEO_CLIENT_SECRET',
    'AKENEO_USERNAME',
    'AKENEO_PASSWORD',
    'AKENEO_MEDIA_ATTRIBUTE',
    'AKENEO_GS1_ATTRIBUTE',
    'AKENEO_GS1_PROCESSED_FLAG',
    'AKENEO_WEBHOOK_SECRET',
    'AKENEO_PRODUCT_FAMILY',
    'AKENEO_GS1_RAW_XML_ATTRIBUTE',
    'AKENEO_MEDIA_ASSET_FAMILY',
    'AKENEO_MEDIA_ASSET_PRODUCT_REF_ATTRIBUTE',
    'AKENEO_STATUS_CARD_ATTRIBUTE',
  ];
  const missing = required.filter(k => !process.env[k]);
  if (missing.length) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }

  // Optional: comma-separated list of asset family codes to process.
  // When set, events from other families are silently skipped with 200.
  // e.g. "eskozipfiles,artwork_assets"
  const familyFilterRaw = process.env.AKENEO_ASSET_FAMILY_FILTER || '';
  const assetFamilyFilter = familyFilterRaw
    ? new Set(familyFilterRaw.split(',').map(s => s.trim()).filter(Boolean))
    : null;

  return {
    host:                       process.env.AKENEO_HOST.replace(/\/$/, ''),
    clientId:                   process.env.AKENEO_CLIENT_ID,
    clientSecret:               process.env.AKENEO_CLIENT_SECRET,
    username:                   process.env.AKENEO_USERNAME,
    password:                   process.env.AKENEO_PASSWORD,
    mediaAttribute:             process.env.AKENEO_MEDIA_ATTRIBUTE,
    gs1Attribute:               process.env.AKENEO_GS1_ATTRIBUTE,
    gs1ProcessedFlag:           process.env.AKENEO_GS1_PROCESSED_FLAG,
    webhookSecret:              process.env.AKENEO_WEBHOOK_SECRET,
    productFamily:              process.env.AKENEO_PRODUCT_FAMILY,
    gs1RawXmlAttribute:         process.env.AKENEO_GS1_RAW_XML_ATTRIBUTE,
    mediaAssetFamily:           process.env.AKENEO_MEDIA_ASSET_FAMILY,
    mediaAssetProductRefAttr:   process.env.AKENEO_MEDIA_ASSET_PRODUCT_REF_ATTRIBUTE,
    statusCardAttribute:        process.env.AKENEO_STATUS_CARD_ATTRIBUTE,
    assetFamilyFilter,          // Set<string> | null
  };
}

// ---------------------------------------------------------------------------
// CloudEvent / Event Platform parsing
// ---------------------------------------------------------------------------

/**
 * Parses and validates the incoming CloudEvent from the Akeneo Event Platform.
 *
 * The Akeneo Event Platform delivers events as HTTP POST requests whose body
 * is a CloudEvents JSON object (specversion 1.0):
 *
 *   {
 *     "specversion": "1.0",
 *     "id": "018e32f9-…",
 *     "type": "com.akeneo.pim.v1.asset.updated.delta",
 *     "source": "pim",
 *     "subject": "…",
 *     "time": "2025-12-16T15:06:00Z",
 *     "datacontenttype": "application/json",
 *     "data": { … }
 *   }
 *
 * @param {object} body  Parsed request body
 * @returns {{
 *   eventId:         string,
 *   eventTime:       string,
 *   assetCode:       string,
 *   assetFamilyCode: string,
 *   changedValues:   object   — data.asset.changes.values
 * }}
 * @throws {Error} with a descriptive message for any validation failure
 */
function parseCloudEvent(body) {
  if (!body || typeof body !== 'object') {
    throw new ValidationError('Request body is missing or not a JSON object.');
  }

  // ── CloudEvents envelope fields ─────────────────────────────────────────
  if (body.specversion !== '1.0') {
    throw new ValidationError(
      `Unexpected CloudEvents specversion: "${body.specversion}". Expected "1.0".`
    );
  }

  if (body.type !== EXPECTED_EVENT_TYPE) {
    // Return a sentinel so the caller can respond 200 without processing
    throw new IgnoredEventError(
      `Event type "${body.type}" is not handled. Expected "${EXPECTED_EVENT_TYPE}".`
    );
  }

  // ── data.asset structure ─────────────────────────────────────────────────
  const data = body.data;
  if (!data?.asset) {
    throw new ValidationError('CloudEvent data.asset is missing.');
  }

  const assetCode = data.asset.code;
  if (!assetCode) {
    throw new ValidationError('CloudEvent data.asset.code is missing.');
  }

  const assetFamilyCode = data.asset.asset_family?.code;
  if (!assetFamilyCode) {
    throw new ValidationError('CloudEvent data.asset.asset_family.code is missing.');
  }

  const changedValues = data.asset.changes?.values;
  if (!changedValues || typeof changedValues !== 'object') {
    throw new ValidationError('CloudEvent data.asset.changes.values is missing or not an object.');
  }

  return {
    eventId:         body.id,
    eventTime:       body.time,
    assetCode,
    assetFamilyCode,
    changedValues,
  };
}

/**
 * Inspects the changed values from the delta event to determine whether
 * the watched media attribute has been updated to a non-empty value.
 *
 * The delta payload structure for a media_file attribute is:
 *   changedValues[attributeCode] = [
 *     {
 *       previous: "old/path/file.zip" | null,
 *       new:      "new/path/file.zip" | null,
 *       type:     "media_file",
 *       locale:   null | string,
 *       channel:  null | string
 *     }
 *   ]
 *
 * We process when:
 *   - The attribute code is present in changedValues
 *   - At least one entry has a non-null, non-empty `new` value
 *   - The type is "media_file"
 *
 * @param {object} changedValues    data.asset.changes.values from the event
 * @param {string} mediaAttribute   Attribute code to watch (from env)
 * @returns {{ shouldProcess: boolean, newFilePath: string|null }}
 */
function inspectMediaChange(changedValues, mediaAttribute) {
  const entries = changedValues[mediaAttribute];

  if (!entries || !Array.isArray(entries) || entries.length === 0) {
    return { shouldProcess: false, newFilePath: null };
  }

  for (const entry of entries) {
    // Confirm this is a media_file attribute change
    if (entry.type !== 'media_file') {
      console.log(
        `Attribute "${mediaAttribute}" changed but type is "${entry.type}", not "media_file" — skipping.`
      );
      continue;
    }

    const newValue = entry.new;

    if (newValue === null || newValue === undefined || newValue === '') {
      console.log(
        `Attribute "${mediaAttribute}" changed but new value is empty/null — ` +
        `this looks like a file removal. Skipping.`
      );
      continue;
    }

    // Found a valid new media file path
    return { shouldProcess: true, newFilePath: newValue };
  }

  return { shouldProcess: false, newFilePath: null };
}

// ---------------------------------------------------------------------------
// Custom error types for cleaner flow control
// ---------------------------------------------------------------------------

class ValidationError extends Error {
  constructor(msg) { super(msg); this.name = 'ValidationError'; }
}

class IgnoredEventError extends Error {
  constructor(msg) { super(msg); this.name = 'IgnoredEventError'; }
}

// ---------------------------------------------------------------------------
// Akeneo authentication
// ---------------------------------------------------------------------------

/**
 * Obtains an OAuth2 access token from Akeneo (password grant).
 * Akeneo uses a hybrid flow: Basic auth (client credentials) + body (user credentials).
 *
 * @param {object} cfg  Config from getConfig()
 * @returns {Promise<string>}  Bearer token
 */
async function getAccessToken(cfg) {
  const credentials = Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString('base64');
  const res = await fetch(`${cfg.host}/api/oauth/v1/token`, {
    method:  'POST',
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Basic ${credentials}`,
    },
    body: JSON.stringify({
      grant_type: 'password',
      username:   cfg.username,
      password:   cfg.password,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Akeneo auth failed (${res.status}): ${body}`);
  }

  const data = await res.json();
  if (!data.access_token) throw new Error('Akeneo auth response missing access_token');
  return data.access_token;
}

// ---------------------------------------------------------------------------
// Akeneo API helpers
// ---------------------------------------------------------------------------

/**
 * Thin wrapper around fetch for Akeneo REST API calls.
 * Throws on non-2xx responses with the response body in the error message.
 */
async function akFetch(method, url, token, body = null) {
  const opts = {
    method,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type':  'application/json',
    },
  };
  if (body !== null) opts.body = JSON.stringify(body);

  const res = await fetch(url, opts);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Akeneo API ${method} ${url} → ${res.status}: ${text}`);
  }

  if (res.status === 204) return null;
  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? res.json() : res.buffer();
}

// ---------------------------------------------------------------------------
// ZIP download
// ---------------------------------------------------------------------------

/**
 * Builds the media file download URL from the file path stored in the event.
 *
 * The delta event carries the file path directly in `new`:
 *   "7/a/2/b/7a2b175efd1d0a2a09c0c4e04be398dbb7a3e02e_new_packshot.zip"
 *
 * This path can be used directly with the asset media files API:
 *   GET /api/rest/v1/asset-media-files/{filePath}
 *
 * @param {string} host      PIM host
 * @param {string} filePath  File path from the event delta's `new` value
 * @returns {string}         Full download URL
 */
function buildMediaFileUrl(host, filePath) {
  return `${host}/api/rest/v1/asset-media-files/${filePath}`;
}

/**
 * Downloads a file from a URL (with Bearer auth) and saves it to a local path.
 *
 * @param {string} url       Download URL
 * @param {string} token     Bearer token
 * @param {string} destPath  Local file path to write
 */
async function downloadFile(url, token, destPath) {
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`Download failed (${res.status}): ${url}`);

  const buffer = await res.buffer();
  await fs.promises.writeFile(destPath, buffer);
}

// ---------------------------------------------------------------------------
// ZIP extraction & file discovery
// ---------------------------------------------------------------------------

/**
 * Extracts a ZIP archive to a destination directory.
 * Returns the list of all extracted absolute file paths.
 *
 * @param {string} zipPath  Local path to the ZIP file
 * @param {string} destDir  Directory to extract into
 * @returns {string[]}
 */
function extractZip(zipPath, destDir) {
  const zip = new AdmZip(zipPath);
  zip.extractAllTo(destDir, true);

  function walk(dir) {
    return fs.readdirSync(dir).flatMap(name => {
      const full = path.join(dir, name);
      return fs.statSync(full).isDirectory() ? walk(full) : [full];
    });
  }
  return walk(destDir);
}

/**
 * Returns all .xml files found under any folder named "gs1" (case-insensitive).
 * Excludes macOS metadata files (._filename) that macOS adds to ZIPs when
 * archived on HFS+/APFS — these are binary AppleDouble files, not real XML.
 *
 * @param {string[]} allFiles  All extracted file paths
 * @returns {string[]}
 */
function findGs1XmlFiles(allFiles) {
  return allFiles.filter(f => {
    const parts    = f.split(path.sep);
    const basename = path.basename(f);
    // Exclude macOS AppleDouble metadata files (._filename)
    if (basename.startsWith('._')) return false;
    return parts.some(p => p.toLowerCase() === 'gs1') && /\.xml$/i.test(f);
  });
}

/**
 * Finds the first .ai (Adobe Illustrator) file and returns its basename
 * without the extension — used as the Akeneo product identifier.
 *
 * @param {string[]} allFiles  All extracted file paths
 * @returns {string}
 */
function deriveProductIdentifier(allFiles) {
  const aiFile = allFiles.find(f => /\.ai$/i.test(f));
  if (!aiFile) {
    throw new Error(
      'No .ai (Adobe Illustrator) file found in the ZIP archive. ' +
      'Cannot derive product identifier.'
    );
  }
  return path.basename(aiFile, '.ai');
}

/**
 * Walks all extracted files and returns every media file eligible for upload
 * to the Akeneo asset family.
 *
 * Rules:
 *   - Supported extensions: .png .jpg .jpeg .gif .webp .pdf
 *   - Any folder named "nft" (case-insensitive) in the path is excluded
 *   - macOS AppleDouble metadata files (._filename) are excluded
 *
 * @param {string[]} allFiles  All extracted file paths
 * @returns {string[]}         Absolute paths to eligible media files
 */
function findMediaFiles(allFiles) {
  const MEDIA_EXTENSIONS = /\.(png|jpe?g|gif|webp|pdf)$/i;

  return allFiles.filter(f => {
    const basename = path.basename(f);
    // Exclude macOS AppleDouble junk
    if (basename.startsWith('._')) return false;
    // Exclude anything inside an "nft" folder at any depth
    const parts = f.split(path.sep);
    if (parts.some(p => p.toLowerCase() === 'nft')) return false;
    return MEDIA_EXTENSIONS.test(basename);
  });
}


// ---------------------------------------------------------------------------

/**
 * Reads and parses the first GS1 XML file from the provided list.
 * Only the first file is processed — subsequent files are ignored.
 * Also returns the raw XML string so it can be minified and stored separately.
 *
 * @param {string[]} xmlPaths
 * @returns {Promise<{ filename: string, parsed: object, rawXml: string }>}
 */
async function parseGs1Files(xmlPaths) {
  const xmlPath  = xmlPaths[0];
  const filename = path.basename(xmlPath);
  console.log(`  Parsing ${filename}…`);
  const rawXml = await fs.promises.readFile(xmlPath, 'utf-8');
  const parsed = parseArtworkContentFromString(rawXml);
  return { filename, parsed, rawXml };
}

// ---------------------------------------------------------------------------
// Akeneo product upsert
// ---------------------------------------------------------------------------

/**
 * Returns true if the product exists in Akeneo (GET returns 200).
 *
 * @param {string} host       PIM host
 * @param {string} token      Bearer token
 * @param {string} productId  Product identifier
 * @returns {Promise<boolean>}
 */
async function productExists(host, token, productId) {
  const url = `${host}/api/rest/v1/products/${encodeURIComponent(productId)}`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (res.status === 404) return false;
  if (res.ok) return true;
  const text = await res.text();
  throw new Error(`Unexpected response checking product "${productId}" (${res.status}): ${text}`);
}

/**
 * Creates a minimal product skeleton in Akeneo with the configured family.
 * The attribute values are written in a subsequent PATCH.
 *
 * @param {string} host       PIM host
 * @param {string} token      Bearer token
 * @param {string} productId  Product identifier
 * @param {string} family     Product family code
 */
async function createProduct(host, token, productId, family) {
  const url = `${host}/api/rest/v1/products`;
  const res = await fetch(url, {
    method:  'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body:    JSON.stringify({ identifier: productId, family }),
  });
  // 201 Created is the success case; 422 means it already exists (race condition) — fine
  if (res.status !== 201 && res.status !== 422) {
    const text = await res.text();
    throw new Error(`Failed to create product "${productId}" (${res.status}): ${text}`);
  }
  console.log(`  Product "${productId}" created with family "${family}" (HTTP ${res.status}).`);
}

/**
 * Writes the GS1 JSON payload to a text/textarea attribute on the product
 * using a partial PATCH so all other attribute values are untouched.
 * Also ensures the product family is set (idempotent — Akeneo ignores it
 * if the family is already correct).
 *
 * The payload is stored as minified JSON (no whitespace) to stay within
 * Akeneo's 65535-character textarea limit. If the minified string still
 * exceeds the limit a clear error is thrown rather than silently truncating.
 *
 * @param {string} host         PIM host
 * @param {string} token        Bearer token
 * @param {string} productId    Product identifier
 * @param {string} family       Product family code
 * @param {string} attribute    Attribute code
 * @param {object} jsonPayload  Object to serialise and store
 */
async function writeAttributeValue(host, token, productId, family, attribute, jsonPayload) {
  const AKENEO_TEXTAREA_LIMIT = 65535;

  const data = JSON.stringify(jsonPayload);

  console.log(`  Payload size: ${data.length} chars (minified).`);

  if (data.length > AKENEO_TEXTAREA_LIMIT) {
    throw new Error(
      `Minified payload (${data.length} chars) exceeds Akeneo's ${AKENEO_TEXTAREA_LIMIT}-char ` +
      `textarea limit. Consider splitting across multiple attributes or reducing the number of XML files.`
    );
  }

  const url  = `${host}/api/rest/v1/products/${encodeURIComponent(productId)}`;
  const body = {
    identifier: productId,
    family,
    values: {
      [attribute]: [{ locale: null, scope: null, data }],
    },
  };
  await akFetch('PATCH', url, token, body);
  console.log(`  Attribute "${attribute}" updated on product "${productId}" (family: "${family}").`);
}

/**
 * Sets a boolean attribute to true on a product using a partial PATCH.
 * Used to flag that GS1 content has been successfully processed.
 *
 * @param {string} host       PIM host
 * @param {string} token      Bearer token
 * @param {string} productId  Product identifier
 * @param {string} attribute  Boolean attribute code
 */
async function writeBooleanFlag(host, token, productId, attribute) {
  const url  = `${host}/api/rest/v1/products/${encodeURIComponent(productId)}`;
  const body = {
    identifier: productId,
    values: {
      [attribute]: [{ locale: null, scope: null, data: true }],
    },
  };
  await akFetch('PATCH', url, token, body);
  console.log(`  Boolean flag "${attribute}" set to true on product "${productId}".`);
}

// ---------------------------------------------------------------------------
// XML minification
// ---------------------------------------------------------------------------

/**
 * Minifies an XML string by:
 *   - Stripping XML comments
 *   - Collapsing inter-element whitespace (newlines, indentation)
 *   - Trimming whitespace inside text nodes
 *
 * The result is a single-line XML string with no formatting whitespace.
 * Meaningful whitespace inside text content is preserved.
 *
 * @param {string} xml  Raw XML string
 * @returns {string}    Minified XML string
 */
function minifyXml(xml) {
  return xml
    .replace(/<!--[\s\S]*?-->/g, '')        // strip XML comments
    .replace(/>\s+</g, '><')                // collapse whitespace between tags
    .replace(/^\s+|\s+$/g, '')             // trim leading/trailing whitespace
    .replace(/\s{2,}/g, ' ');              // collapse remaining multi-spaces to one
}

/**
 * Writes a minified XML string to a textarea attribute on the product,
 * but only if the minified content fits within Akeneo's 65535-char limit.
 * Logs and skips silently when it doesn't fit rather than throwing — the
 * parsed JSON attribute is already written and more important.
 *
 * @param {string} host       PIM host
 * @param {string} token      Bearer token
 * @param {string} productId  Product identifier
 * @param {string} family     Product family code
 * @param {string} attribute  Textarea attribute code
 * @param {string} rawXml     Raw XML string to minify and store
 */
async function writeRawXmlAttribute(host, token, productId, family, attribute, rawXml) {
  const AKENEO_TEXTAREA_LIMIT = 65535;

  const minified = minifyXml(rawXml);
  console.log(`  Minified XML size: ${minified.length} chars (raw: ${rawXml.length} chars).`);

  if (minified.length > AKENEO_TEXTAREA_LIMIT) {
    console.warn(
      `  Minified XML (${minified.length} chars) exceeds the ${AKENEO_TEXTAREA_LIMIT}-char limit — ` +
      `skipping raw XML attribute "${attribute}".`
    );
    return { stored: false, reason: 'too_large', size: minified.length };
  }

  const url  = `${host}/api/rest/v1/products/${encodeURIComponent(productId)}`;
  const body = {
    identifier: productId,
    family,
    values: {
      [attribute]: [{ locale: null, scope: null, data: minified }],
    },
  };
  await akFetch('PATCH', url, token, body);
  console.log(`  Raw XML attribute "${attribute}" updated on product "${productId}".`);
  return { stored: true, size: minified.length };
}

// ---------------------------------------------------------------------------
// Asset media file upload
// ---------------------------------------------------------------------------

/** Maps file extensions to MIME types for the multipart upload. */
const MIME_TYPES = {
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif':  'image/gif',
  '.webp': 'image/webp',
  '.pdf':  'application/pdf',
};

/**
 * Uploads a binary media file to the Akeneo Asset Manager media-files endpoint.
 * Returns the file path string that Akeneo assigns to the uploaded file
 * (used as the value when creating/updating the asset record).
 *
 * Akeneo expects a multipart/form-data POST with a single "file" field.
 *
 * @param {string} host       PIM host
 * @param {string} token      Bearer token
 * @param {string} filePath   Local absolute path to the file
 * @param {string} productId  Product identifier — prepended to the filename before upload
 * @returns {Promise<string>} The Akeneo-assigned file path (from Location header)
 */
async function uploadAssetMediaFile(host, token, filePath, productId) {
  const ext      = path.extname(filePath).toLowerCase();
  const mimeType = MIME_TYPES[ext] || 'application/octet-stream';
  // Prefix the filename with the product identifier so it is traceable in storage
  const filename = `${productId}_${path.basename(filePath)}`;

  // Build multipart/form-data body manually — node-fetch v2 doesn't bundle FormData
  const boundary  = `----AkeneoUpload${Date.now()}`;
  const fileBuffer = await fs.promises.readFile(filePath);

  const header = Buffer.from(
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="file"; filename="${filename}"\r\n` +
    `Content-Type: ${mimeType}\r\n\r\n`
  );
  const footer = Buffer.from(`\r\n--${boundary}--\r\n`);
  const body   = Buffer.concat([header, fileBuffer, footer]);

  const res = await fetch(`${host}/api/rest/v1/asset-media-files`, {
    method:  'POST',
    headers: {
      'Authorization':  `Bearer ${token}`,
      'Content-Type':   `multipart/form-data; boundary=${boundary}`,
      'Content-Length': String(body.length),
    },
    body,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Asset media upload failed for "${filename}" (${res.status}): ${text}`);
  }

  // Akeneo returns the storage path in the Location header. The value may be:
  //   - a full URL:  https://host/api/rest/v1/asset-media-files/7/a/2/b/7a2b…_file.jpg
  //   - a path only: /api/rest/v1/asset-media-files/7/a/2/b/7a2b…_file.jpg
  // We want only the storage path segment after the API prefix:
  //   7/a/2/b/7a2b…_file.jpg
  const location = res.headers.get('location') || '';

  // Extract the pathname whether the header is a full URL or a path
  let pathname;
  try {
    pathname = new URL(location).pathname;
  } catch {
    // Not a full URL — treat it as a path directly
    pathname = location;
  }

  const assetPath = pathname.replace(/^\/api\/rest\/v1\/asset-media-files\//, '');

  if (!assetPath || assetPath === pathname) {
    throw new Error(
      `Asset media upload for "${filename}" succeeded but could not extract storage path ` +
      `from Location header: "${location}"`
    );
  }

  return assetPath;
}

/**
 * Fetches an asset family and returns its attribute_as_main_media code.
 * This is the attribute code that must be used when uploading a media file
 * to an asset record — it differs per family and cannot be assumed to be
 * "media_file".
 *
 * The result is cached in a module-level Map so subsequent calls within the
 * same function invocation do not trigger redundant API requests.
 *
 * @param {string} host             PIM host
 * @param {string} token            Bearer token
 * @param {string} assetFamilyCode  Asset family code
 * @returns {Promise<string>}       The attribute_as_main_media code
 */
const _assetFamilyCache = new Map();

async function fetchAssetFamilyMainMediaAttribute(host, token, assetFamilyCode) {
  if (_assetFamilyCache.has(assetFamilyCode)) {
    return _assetFamilyCache.get(assetFamilyCode);
  }

  const url = `${host}/api/rest/v1/asset-families/${encodeURIComponent(assetFamilyCode)}`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(
      `Failed to fetch asset family "${assetFamilyCode}" (${res.status}): ${text}`
    );
  }

  const family    = await res.json();
  const mainMedia = family.attribute_as_main_media;

  if (!mainMedia) {
    throw new Error(
      `Asset family "${assetFamilyCode}" has no attribute_as_main_media defined. ` +
      `Please configure it in the PIM under Settings → Asset families.`
    );
  }

  console.log(`  Asset family "${assetFamilyCode}" main media attribute: "${mainMedia}"`);
  _assetFamilyCache.set(assetFamilyCode, mainMedia);
  return mainMedia;
}

/**
 * Creates or updates an asset record in the given asset family.
 *
 * The asset code is derived from the filename, sanitised to match Akeneo's
 * requirements: only letters, digits and underscores ([a-zA-Z0-9_]+), must
 * start with a letter. Hyphens are converted to underscores; a leading digit
 * is handled by prepending "a_".
 *
 * The record is given:
 *   - The uploaded file path as the value of the family's main media attribute
 *     (resolved dynamically from attribute_as_main_media, not hardcoded)
 *   - The product identifier as the value of the product_ref attribute
 *
 * Uses PATCH (upsert) which creates the record if absent or updates it if present.
 *
 * @param {string} host             PIM host
 * @param {string} token            Bearer token
 * @param {string} assetFamilyCode  Asset family code
 * @param {string} mainMediaAttr    attribute_as_main_media code of the family
 * @param {string} assetFilePath    Akeneo storage path returned by uploadAssetMediaFile
 * @param {string} originalFilename Original file basename (used to derive asset code)
 * @param {string} productId        Product identifier to store in product_ref attribute
 * @param {string} productRefAttr   Asset attribute code that holds the product reference
 * @returns {Promise<string>}       The asset code used
 */
async function upsertAssetRecord(
  host, token, assetFamilyCode, mainMediaAttr, assetFilePath,
  originalFilename, productId, productRefAttr
) {
  // Derive a clean asset code from the filename (strip extension, sanitise)
  const baseName  = path.basename(originalFilename, path.extname(originalFilename));
  let assetCode = baseName
    .replace(/[^a-zA-Z0-9_]/g, '_')   // replace anything not letter/digit/underscore with _
    .replace(/_{2,}/g, '_')            // collapse consecutive underscores
    .replace(/^_+|_+$/g, '');          // strip leading/trailing underscores

  // Akeneo asset codes must start with a letter — prefix with "a_" if starts with a digit
  if (/^\d/.test(assetCode)) {
    assetCode = `a_${assetCode}`;
  }

  // Safety fallback if sanitisation produced an empty string
  if (!assetCode) {
    assetCode = `asset_${Date.now()}`;
  }

  // Prepend the sanitised product identifier so asset codes are traceable per product
  const sanitisedProductId = productId
    .replace(/[^a-zA-Z0-9_]/g, '_')
    .replace(/_{2,}/g, '_')
    .replace(/^_+|_+$/g, '');
  assetCode = `${sanitisedProductId}_${assetCode}`;

  // Akeneo enforces a 255-char max on asset codes
  if (assetCode.length > 255) {
    assetCode = assetCode.slice(0, 255);
  }

  const url  = `${host}/api/rest/v1/asset-families/${encodeURIComponent(assetFamilyCode)}/assets/${encodeURIComponent(assetCode)}`;
  const body = {
    code:   assetCode,
    values: {
      // Main media file attribute — resolved dynamically from the asset family definition
      [mainMediaAttr]: [
        { locale: null, channel: null, data: assetFilePath },
      ],
      // Product reference attribute — links asset back to the product
      [productRefAttr]: [
        { locale: null, channel: null, data: productId },
      ],
    },
  };

  const res = await fetch(url, {
    method:  'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  });

  // 201 = created, 204 = updated — both are success
  if (res.status !== 201 && res.status !== 204) {
    const text = await res.text();
    throw new Error(
      `Asset record upsert failed for "${assetCode}" in family "${assetFamilyCode}" ` +
      `(${res.status}): ${text}`
    );
  }

  return assetCode;
}

/**
 * Finds all media files in the extracted archive (excluding the nft folder),
 * uploads each one to the asset-media-files endpoint, then creates/updates
 * an asset record in the target asset family with the product reference.
 *
 * Failures on individual files are caught and logged — one bad file does not
 * abort the rest of the batch.
 *
 * @param {string}   host            PIM host
 * @param {string}   token           Bearer token
 * @param {string[]} allFiles        All extracted file paths
 * @param {string}   assetFamilyCode Target asset family code
 * @param {string}   productId       Product identifier (written to product_ref attr)
 * @param {string}   productRefAttr  Asset attribute code for the product reference
 * @returns {Promise<{
 *   total:    number,
 *   uploaded: number,
 *   skipped:  number,
 *   errors:   Array<{ file: string, error: string }>
 * }>}
 */
async function pushMediaFilesToAssetFamily(
  host, token, allFiles, assetFamilyCode, productId, productRefAttr
) {
  const mediaFiles = findMediaFiles(allFiles);
  console.log(`  Found ${mediaFiles.length} media file(s) to upload.`);

  // Fetch the family once to get the correct main media attribute code
  const mainMediaAttr = await fetchAssetFamilyMainMediaAttribute(host, token, assetFamilyCode);

  const errors   = [];
  let uploaded   = 0;
  let skipped    = 0;

  for (const filePath of mediaFiles) {
    const filename = path.basename(filePath);
    try {
      console.log(`  Uploading "${filename}"…`);
      const assetFilePath = await uploadAssetMediaFile(host, token, filePath, productId);
      const assetCode     = await upsertAssetRecord(
        host, token, assetFamilyCode, mainMediaAttr, assetFilePath,
        filename, productId, productRefAttr
      );
      console.log(`  ✓ "${filename}" → asset "${assetCode}" in family "${assetFamilyCode}".`);
      uploaded++;
    } catch (err) {
      console.error(`  ✗ Failed to upload "${filename}": ${err.message}`);
      errors.push({ file: filename, error: err.message });
      skipped++;
    }
  }

  return { total: mediaFiles.length, uploaded, skipped, errors };
}

// ---------------------------------------------------------------------------
// Status card SVG generator
// ---------------------------------------------------------------------------

/**
 * Generates a standalone SVG status card (1000×370px) summarising the
 * result of the ZIP processing pipeline.
 *
 * The SVG uses only safe SVG primitives and inline attributes — no external
 * fonts, no CSS variables, no JavaScript — so it renders correctly inside
 * Akeneo's product page textarea preview.
 *
 * The root <svg> element carries a uniqueID attribute set to the value of
 * the AKENEO_STATUS_CARD_ATTRIBUTE env var, as required by the caller.
 *
 * @param {{
 *   uniqueId:        string,   — value for the uniqueID attribute (attribute code)
 *   productId:       string,
 *   action:          string,   — "created" | "updated"
 *   sourceFile:      string,
 *   processedAt:     string,   — ISO date string
 *   assetFamilyCode: string,
 *   mediaUploaded:   number,
 *   mediaTotal:      number,
 *   gs1Attribute:    string,
 *   gs1RawAttr:      string,
 *   flagAttribute:   string,
 *   statusAttribute: string,
 *   assetCode:       string,
 *   assetFamilyCode2:string,
 *   eventType:       string,
 *   locale:          string,
 * }} opts
 * @returns {string}  SVG markup string
 */
function generateStatusCard(opts) {
  const {
    uniqueId, productId, action, sourceFile, processedAt,
    assetFamilyCode, mediaUploaded, mediaTotal,
    gs1Attribute, gs1RawAttr, flagAttribute, statusAttribute,
    assetCode, assetFamilyCode2, eventType, locale,
  } = opts;

  // Format the processedAt date as "DD Mon YYYY, HH:MM"
  const d       = new Date(processedAt);
  const months  = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const dateStr = `${d.getUTCDate()} ${months[d.getUTCMonth()]} ${d.getUTCFullYear()}, `
                + `${String(d.getUTCHours()).padStart(2,'0')}:${String(d.getUTCMinutes()).padStart(2,'0')}`;

  // Action badge colour: green for created, purple for updated
  const badgeFill   = action === 'created' ? '#EAF3DE' : '#EEEDFE';
  const badgeStroke = action === 'created' ? '#97C459' : '#AFA9EC';
  const badgeText   = action === 'created' ? '#27500A' : '#3C3489';
  const badgeDot    = action === 'created' ? '#3B6D11' : '#534AB7';

  // Truncate long strings for display
  const trunc = (s, n) => s && s.length > n ? s.slice(0, n - 1) + '…' : (s || '');

  // Pipeline pill data
  const pills = [
    { label: trunc(gs1Attribute,  22), color: '#EEEDFE', stroke: '#AFA9EC', dot: '#534AB7', text: '#3C3489' },
    { label: trunc(gs1RawAttr,    18), color: '#EEEDFE', stroke: '#AFA9EC', dot: '#534AB7', text: '#3C3489' },
    { label: trunc(flagAttribute, 22), color: '#EAF3DE', stroke: '#97C459', dot: '#3B6D11', text: '#27500A' },
    { label: trunc(statusAttribute,22),color: '#EEEDFE', stroke: '#AFA9EC', dot: '#534AB7', text: '#3C3489' },
  ];

  // Lay out pills with dynamic spacing
  let pillX = 32;
  const pillY = 264, pillH = 28, dotR = 5, textOff = 11, pillPadL = 20, pillPadR = 10, gap = 22;
  const pillRects = pills.map(p => {
    const labelW = Math.min(p.label.length * 7.2 + pillPadL + pillPadR + dotR * 2, 220);
    const rect = { x: pillX, w: Math.round(labelW), ...p };
    pillX += Math.round(labelW) + gap;
    return rect;
  });

  // Generate connector dashes between pills
  const connectors = pillRects.slice(0, -1).map((r, i) => {
    const x1 = r.x + r.w + 2;
    const x2 = pillRects[i + 1].x - 2;
    return `<line x1="${x1}" y1="${pillY + pillH / 2}" x2="${x2}" y2="${pillY + pillH / 2}" stroke="#AFA9EC" stroke-width="1" stroke-dasharray="3 2"/>`;
  }).join('');

  const pillsSvg = pillRects.map(r => `
    <rect x="${r.x}" y="${pillY}" width="${r.w}" height="${pillH}" rx="6" fill="${r.color}" stroke="${r.stroke}" stroke-width="0.5"/>
    <circle cx="${r.x + pillPadL - dotR}" cy="${pillY + pillH / 2}" r="${dotR}" fill="${r.dot}"/>
    <text x="${r.x + pillPadL + 4}" y="${pillY + pillH / 2 + 4}" font-family="'Inter',system-ui,sans-serif" font-size="11" font-weight="500" fill="${r.text}">${r.label}</text>
  `).join('');

  return `<svg width="1000" height="370" viewBox="0 0 1000 370" xmlns="http://www.w3.org/2000/svg" uniqueID="${uniqueId}">
  <rect width="1000" height="370" rx="12" fill="#F8F7F5"/>
  <rect x="0" y="0" width="6" height="370" rx="3" fill="#4B49D1"/>
  <rect x="3" y="0" width="3" height="370" fill="#4B49D1"/>
  <rect x="32" y="28" width="48" height="48" rx="12" fill="#EEEDFE" stroke="#AFA9EC" stroke-width="1"/>
  <path d="M49 52 L54 57 L63 47" fill="none" stroke="#534AB7" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="56" cy="52" r="10" fill="none" stroke="#534AB7" stroke-width="2"/>
  <text x="96" y="50" font-family="'Inter',system-ui,sans-serif" font-size="18" font-weight="600" fill="#26215C">Product successfully processed</text>
  <text x="96" y="70" font-family="'Inter',system-ui,sans-serif" font-size="13" fill="#888780">Esko ZIP archive decoded and enriched — all assets imported</text>
  <rect x="32" y="98" width="936" height="0.5" fill="#D3D1C7"/>
  <rect x="32" y="118" width="212" height="80" rx="8" fill="#FFFFFF" stroke="#D3D1C7" stroke-width="0.5"/>
  <text x="52" y="144" font-family="'Inter',system-ui,sans-serif" font-size="11" font-weight="500" fill="#888780" letter-spacing="0.06em">PRODUCT</text>
  <text x="52" y="167" font-family="'Inter',system-ui,sans-serif" font-size="15" font-weight="600" fill="#26215C">${trunc(productId, 22)}</text>
  <rect x="52" y="176" width="64" height="16" rx="8" fill="${badgeFill}" stroke="${badgeStroke}" stroke-width="0.5"/>
  <circle cx="63" cy="184" r="4" fill="${badgeDot}"/>
  <text x="70" y="188" font-family="'Inter',system-ui,sans-serif" font-size="10" font-weight="500" fill="${badgeText}">${action}</text>
  <rect x="260" y="118" width="212" height="80" rx="8" fill="#FFFFFF" stroke="#D3D1C7" stroke-width="0.5"/>
  <text x="280" y="144" font-family="'Inter',system-ui,sans-serif" font-size="11" font-weight="500" fill="#888780" letter-spacing="0.06em">SOURCE FILE</text>
  <text x="280" y="167" font-family="'Inter',system-ui,sans-serif" font-size="12" font-weight="500" fill="#26215C">${trunc(sourceFile, 28)}</text>
  <text x="280" y="185" font-family="'Inter',system-ui,sans-serif" font-size="11" fill="#888780">GS1 artwork content v3</text>
  <rect x="488" y="118" width="212" height="80" rx="8" fill="#FFFFFF" stroke="#D3D1C7" stroke-width="0.5"/>
  <text x="508" y="144" font-family="'Inter',system-ui,sans-serif" font-size="11" font-weight="500" fill="#888780" letter-spacing="0.06em">MEDIA ASSETS</text>
  <text x="508" y="167" font-family="'Inter',system-ui,sans-serif" font-size="22" font-weight="600" fill="#26215C">${mediaUploaded}</text>
  <text x="${508 + String(mediaUploaded).length * 14}" y="167" font-family="'Inter',system-ui,sans-serif" font-size="13" fill="#639922"> / ${mediaTotal} uploaded</text>
  <text x="508" y="185" font-family="'Inter',system-ui,sans-serif" font-size="11" fill="#888780">${trunc(assetFamilyCode, 26)}</text>
  <rect x="716" y="118" width="252" height="80" rx="8" fill="#FFFFFF" stroke="#D3D1C7" stroke-width="0.5"/>
  <text x="736" y="144" font-family="'Inter',system-ui,sans-serif" font-size="11" font-weight="500" fill="#888780" letter-spacing="0.06em">PROCESSED AT</text>
  <text x="736" y="167" font-family="'Inter',system-ui,sans-serif" font-size="13" font-weight="500" fill="#26215C">${dateStr}</text>
  <text x="736" y="185" font-family="'Inter',system-ui,sans-serif" font-size="11" fill="#888780">UTC</text>
  <rect x="32" y="222" width="936" height="0.5" fill="#D3D1C7"/>
  <text x="32" y="252" font-family="'Inter',system-ui,sans-serif" font-size="11" font-weight="500" fill="#888780" letter-spacing="0.06em">ATTRIBUTE PIPELINE</text>
  ${connectors}
  ${pillsSvg}
  <rect x="32" y="322" width="936" height="0.5" fill="#D3D1C7"/>
  <text x="32" y="350" font-family="'Inter',system-ui,sans-serif" font-size="11" fill="#B4B2A9">Event </text>
  <text x="70" y="350" font-family="'Inter',system-ui,sans-serif" font-size="11" fill="#888780">${trunc(eventType, 44)}</text>
  <text x="410" y="350" font-family="'Inter',system-ui,sans-serif" font-size="11" fill="#B4B2A9">  ·  Asset </text>
  <text x="455" y="350" font-family="'Inter',system-ui,sans-serif" font-size="11" fill="#888780">${trunc(assetCode, 24)}</text>
  <text x="632" y="350" font-family="'Inter',system-ui,sans-serif" font-size="11" fill="#B4B2A9">  ·  Locale </text>
  <text x="688" y="350" font-family="'Inter',system-ui,sans-serif" font-size="11" fill="#888780">${locale || 'UNKNOWN'}</text>
  <text x="968" y="350" font-family="'Inter',system-ui,sans-serif" font-size="10" fill="#B4B2A9" text-anchor="end">Esko Asset Decompactor v2</text>
</svg>`;
}

/**
 * Writes the status card SVG to the configured textarea attribute on the product.
 *
 * @param {string} host         PIM host
 * @param {string} token        Bearer token
 * @param {string} productId    Product identifier
 * @param {string} family       Product family code
 * @param {string} attribute    Textarea attribute code
 * @param {string} svgString    SVG markup to store
 */
async function writeStatusCard(host, token, productId, family, attribute, svgString) {
  const LIMIT = 65535;
  if (svgString.length > LIMIT) {
    console.warn(`  Status card SVG (${svgString.length} chars) exceeds limit — skipping.`);
    return;
  }
  const url  = `${host}/api/rest/v1/products/${encodeURIComponent(productId)}`;
  const body = {
    identifier: productId,
    family,
    values: { [attribute]: [{ locale: null, scope: null, data: svgString }] },
  };
  await akFetch('PATCH', url, token, body);
  console.log(`  Status card written to attribute "${attribute}" (${svgString.length} chars).`);
}

// ---------------------------------------------------------------------------
// Temp directory helpers
// ---------------------------------------------------------------------------

async function makeTempDir() {
  return fs.promises.mkdtemp(path.join(os.tmpdir(), 'gs1-artwork-'));
}

async function cleanupDir(dir) {
  try {
    await fs.promises.rm(dir, { recursive: true, force: true });
  } catch (err) {
    console.warn(`Cleanup warning: could not remove ${dir}: ${err.message}`);
  }
}

// ---------------------------------------------------------------------------
// Cloud Function entry point
// ---------------------------------------------------------------------------

/**
 * Google Cloud Function HTTP handler.
 *
 * Receives a CloudEvent from the Akeneo Event Platform:
 *
 *   POST /
 *   Content-Type: application/json
 *   {
 *     "specversion": "1.0",
 *     "type": "com.akeneo.pim.v1.asset.updated.delta",
 *     "data": {
 *       "asset": {
 *         "asset_family": { "code": "artwork_files" },
 *         "code": "my_asset",
 *         "changes": {
 *           "values": {
 *             "zip_file": [
 *               {
 *                 "previous": "old/path/file.zip",
 *                 "new": "new/path/file.zip",
 *                 "type": "media_file",
 *                 "locale": null,
 *                 "channel": null
 *               }
 *             ]
 *           }
 *         }
 *       }
 *     }
 *   }
 *
 * Responds:
 *   200 { status: "processed", productIdentifier, filesProcessed, attribute, action }
 *   200 { status: "skipped", reason }   — wrong event type or attribute not changed
 *   400 { status: "error",   error }    — malformed event
 *   401 { status: "error",   error }    — HMAC signature verification failed
 *   500 { status: "error",   error }    — internal processing error
 *
 * Note on raw body: the Functions Framework exposes req.rawBody (Buffer) when
 * the content-type is application/json, which is what Akeneo sends. The
 * signature is computed over this raw buffer. If req.rawBody is absent for
 * any reason the function falls back to JSON.stringify(req.body), which is
 * deterministic for well-formed Akeneo payloads.
 *
 * @param {import('@google-cloud/functions-framework').Request}  req
 * @param {import('@google-cloud/functions-framework').Response} res
 */
exports.processArtworkAsset = async (req, res) => {
  let tempDir = null;

  try {
    // ── 0. Load env config ────────────────────────────────────────────────
    const cfg = getConfig();

    // ── 1. Verify HMAC-SHA256 webhook signature ───────────────────────────
    // Must happen before any body parsing so we can reject spoofed requests
    // immediately without performing any Akeneo API calls.
    const { valid, reason } = verifySignature(req, cfg.webhookSecret);
    if (!valid) {
      console.warn(`Signature verification failed: ${reason}`);
      return res.status(401).json({ status: 'error', error: reason });
    }
    console.log('✓ Signature verified.');

    // ── 3. Parse & validate the CloudEvent ───────────────────────────────
    let parsed;
    try {
      parsed = parseCloudEvent(req.body);
    } catch (err) {
      if (err instanceof IgnoredEventError) {
        // Not our event type — acknowledge with 200 so the platform doesn't retry
        console.log(`Skipping event: ${err.message}`);
        return res.status(200).json({ status: 'skipped', reason: err.message });
      }
      // Malformed event — 400 so the platform does not retry with the same bad payload
      console.error(`CloudEvent validation error: ${err.message}`);
      return res.status(400).json({ status: 'error', error: err.message });
    }

    const { eventId, eventTime, assetCode, assetFamilyCode, changedValues } = parsed;

    console.log(
      `[${eventId}] ${EXPECTED_EVENT_TYPE} received at ${eventTime} — ` +
      `asset: ${assetFamilyCode}/${assetCode}`
    );

    // ── 4. Check whether the watched media attribute changed ──────────────
    const { shouldProcess, newFilePath } = inspectMediaChange(changedValues, cfg.mediaAttribute);

    if (!shouldProcess) {
      const reason =
        `Attribute "${cfg.mediaAttribute}" did not change or new value is empty — no action needed.`;
      console.log(reason);
      return res.status(200).json({ status: 'skipped', reason });
    }

    console.log(`Media attribute "${cfg.mediaAttribute}" changed → new file path: ${newFilePath}`);

    // ── 4a. Asset family filter (optional) ───────────────────────────────
    // When AKENEO_ASSET_FAMILY_FILTER is set, only process events from the
    // listed asset families — all others are acknowledged and ignored.
    if (cfg.assetFamilyFilter && !cfg.assetFamilyFilter.has(assetFamilyCode)) {
      const reason = `Asset family "${assetFamilyCode}" is not in the allowed list `
        + `[${[...cfg.assetFamilyFilter].join(', ')}] — skipping.`;
      console.log(reason);
      return res.status(200).json({ status: 'skipped', reason });
    }

    // ── 4b. ZIP file guard ────────────────────────────────────────────────
    // Only process .zip files — other media types (PDF, images…) may be
    // uploaded to the same attribute but cannot be extracted as archives.
    if (!/\.zip$/i.test(newFilePath)) {
      const reason = `New file "${newFilePath}" is not a ZIP archive — skipping.`;
      console.log(reason);
      return res.status(200).json({ status: 'skipped', reason });
    }

    // ── 5. Authenticate ───────────────────────────────────────────────────
    const token = await getAccessToken(cfg);
    console.log('Authenticated with Akeneo.');

    // ── 6. Build download URL & fetch the ZIP ─────────────────────────────
    // The new file path from the delta event is used directly — no need to
    // re-fetch the asset record just to get the URL.
    const zipUrl = buildMediaFileUrl(cfg.host, newFilePath);
    console.log(`Downloading ZIP from: ${zipUrl}`);

    tempDir = await makeTempDir();
    const zipPath    = path.join(tempDir, 'asset.zip');
    const extractDir = path.join(tempDir, 'extracted');
    await fs.promises.mkdir(extractDir);

    await downloadFile(zipUrl, token, zipPath);

    // ── 7. Extract ZIP ────────────────────────────────────────────────────
    console.log('Extracting ZIP…');
    const allFiles = extractZip(zipPath, extractDir);
    console.log(`Extracted ${allFiles.length} file(s).`);

    // ── 8. Locate GS1 XML files ───────────────────────────────────────────
    const xmlFiles = findGs1XmlFiles(allFiles);
    if (xmlFiles.length === 0) {
      throw new Error(
        'No XML files found under a "gs1" folder in the ZIP archive. ' +
        `Extracted paths: ${allFiles.map(f => path.relative(extractDir, f)).join(', ')}`
      );
    }
    console.log(
      `Found ${xmlFiles.length} GS1 XML file(s): ${xmlFiles.map(f => path.basename(f)).join(', ')}`
    );

    // ── 9. Derive product identifier from .ai filename ────────────────────
    const productId = deriveProductIdentifier(allFiles);
    console.log(`Product identifier: "${productId}"`);

    // ── 10. Parse first GS1 XML file ─────────────────────────────────────
    console.log('Parsing GS1 XML file…');
    const { filename, parsed: gs1Parsed, rawXml } = await parseGs1Files(xmlFiles);

    const payload = {
      _meta: {
        eventId,
        eventTime,
        assetCode,
        assetFamilyCode,
        mediaAttribute:  cfg.mediaAttribute,
        newFilePath,
        processedAt:     new Date().toISOString(),
        sourceFile:      filename,
      },
      gs1Data: gs1Parsed,
    };

    // ── 11. Upsert product ─────────────────────────────────────────────────
    const exists = await productExists(cfg.host, token, productId);
    let action;

    if (!exists) {
      console.log(`Product "${productId}" not found — creating…`);
      await createProduct(cfg.host, token, productId, cfg.productFamily);
      action = 'created';
    } else {
      console.log(`Product "${productId}" exists — updating…`);
      action = 'updated';
    }

    // ── 12. Write parsed JSON attribute & boolean flag ────────────────────
    await writeAttributeValue(cfg.host, token, productId, cfg.productFamily, cfg.gs1Attribute, payload);
    await writeBooleanFlag(cfg.host, token, productId, cfg.gs1ProcessedFlag);

    // ── 13. Write minified raw XML attribute (if within size limit) ────────
    const xmlResult = await writeRawXmlAttribute(
      cfg.host, token, productId, cfg.productFamily, cfg.gs1RawXmlAttribute, rawXml
    );

    // ── 14. Upload media files to asset family ────────────────────────────
    console.log(`Uploading media files to asset family "${cfg.mediaAssetFamily}"…`);
    const mediaResult = await pushMediaFilesToAssetFamily(
      cfg.host, token, allFiles,
      cfg.mediaAssetFamily, productId, cfg.mediaAssetProductRefAttr
    );

    // ── 15. Generate and write status card SVG ────────────────────────────
    const svgCard = generateStatusCard({
      uniqueId:         cfg.statusCardAttribute,
      productId,
      action,
      sourceFile:       filename,
      processedAt:      new Date().toISOString(),
      assetFamilyCode:  cfg.mediaAssetFamily,
      mediaUploaded:    mediaResult.uploaded,
      mediaTotal:       mediaResult.total,
      gs1Attribute:     cfg.gs1Attribute,
      gs1RawAttr:       cfg.gs1RawXmlAttribute,
      flagAttribute:    cfg.gs1ProcessedFlag,
      statusAttribute:  cfg.statusCardAttribute,
      assetCode:        `${assetFamilyCode}/${assetCode}`,
      eventType:        EXPECTED_EVENT_TYPE,
      locale:           payload._meta?.locale || 'UNKNOWN',
    });
    await writeStatusCard(cfg.host, token, productId, cfg.productFamily, cfg.statusCardAttribute, svgCard);

    // ── 16. Respond ───────────────────────────────────────────────────────
    return res.status(200).json({
      status:            'processed',
      productIdentifier: productId,
      sourceFile:        filename,
      attribute:         cfg.gs1Attribute,
      processedFlag:     cfg.gs1ProcessedFlag,
      rawXmlAttribute:   cfg.gs1RawXmlAttribute,
      rawXmlStored:      xmlResult.stored,
      ...(xmlResult.stored === false && { rawXmlSkippedReason: xmlResult.reason }),
      statusCardAttribute: cfg.statusCardAttribute,
      mediaAssets: {
        assetFamily:  cfg.mediaAssetFamily,
        total:        mediaResult.total,
        uploaded:     mediaResult.uploaded,
        skipped:      mediaResult.skipped,
        ...(mediaResult.errors.length > 0 && { errors: mediaResult.errors }),
      },
      action,
    });

  } catch (err) {
    console.error('Unhandled error:', err.message);
    return res.status(500).json({ status: 'error', error: err.message });
  } finally {
    if (tempDir) await cleanupDir(tempDir);
  }
};
