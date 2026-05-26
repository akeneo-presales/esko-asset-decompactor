# Esko Asset Decompactor — Google Cloud Run Function

Triggered by the **Akeneo Event Platform** whenever an asset media file is
updated. Downloads the ZIP archive, runs the full GS1 XML parsing and asset
import pipeline, and writes results across multiple product attributes in
Akeneo PIM.

---

## File structure

```
.
├── index.js               # Cloud Function entry point (pipeline orchestrator)
├── parseArtworkContent.js # GS1 XML parser — zero-loss, locale-aware
├── package.json
├── test-local.js          # Local test harness (4 scenarios)
└── README.md
```

---

## Environment variables

Required variables are listed below. `AKENEO_ASSET_FAMILY_FILTER` is optional.
Missing any required variable causes the function to return 500 immediately.

| Variable | Description | Example |
|---|---|---|
| `AKENEO_HOST` | PIM base URL (no trailing slash) | `https://my-instance.cloud.akeneo.com` |
| `AKENEO_CLIENT_ID` | OAuth2 client ID | `1_abc123…` |
| `AKENEO_CLIENT_SECRET` | OAuth2 client secret | `secretxyz…` |
| `AKENEO_USERNAME` | PIM user login | `api_user` |
| `AKENEO_PASSWORD` | PIM user password | `••••••••` |
| `AKENEO_WEBHOOK_SECRET` | HMAC-SHA256 secret set on the Event Platform subscription — used to verify `X-AKENEO-SIGNATURE-PRIMARY` | `YQL1Vw4q…` |
| `AKENEO_MEDIA_ATTRIBUTE` | Asset attribute code holding the ZIP media file — **watched for changes** | `media` |
| `AKENEO_PRODUCT_FAMILY` | Product family code assigned on product create/update | `snack` |
| `AKENEO_GS1_ATTRIBUTE` | Product textarea attribute for the parsed GS1 JSON | `gs1_attributes_values` |
| `AKENEO_GS1_RAW_XML_ATTRIBUTE` | Product textarea attribute for the minified raw XML (written only if ≤ 65535 chars) | `gs1_raw_xml` |
| `AKENEO_GS1_PROCESSED_FLAG` | Product boolean attribute set to `true` after a successful run | `AI_Process_GS1_contents_` |
| `AKENEO_MEDIA_ASSET_FAMILY` | Asset family code where extracted media files are uploaded | `product_images` |
| `AKENEO_MEDIA_ASSET_PRODUCT_REF_ATTRIBUTE` | Asset attribute code that holds the product reference (used by the product link rule) | `product_ref` |
| `AKENEO_ASSET_FAMILY_FILTER` | *(optional)* Comma-separated list of asset family codes to process — events from other families are skipped | `eskozipfiles,artwork_assets` |

---

## Trigger — Akeneo Event Platform

The function is triggered by a `com.akeneo.pim.v1.asset.updated.delta`
CloudEvent delivered via an Akeneo Event Platform webhook subscription.

### CloudEvent payload

```json
{
  "specversion": "1.0",
  "id": "018e32f9-dfe4-760e-a273-5da1c089dfdb",
  "type": "com.akeneo.pim.v1.asset.updated.delta",
  "source": "pim",
  "subject": "01948d3c-6625-7833-8a03-dd96245862d3",
  "time": "2026-05-26T07:39:00Z",
  "datacontenttype": "application/json",
  "data": {
    "asset": {
      "asset_family": { "code": "eskozipfiles" },
      "code": "test1",
      "changes": {
        "values": {
          "media": [
            {
              "previous": null,
              "new": "3/6/e/f/36ef1d39…_Package.zip",
              "type": "media_file",
              "locale": null,
              "channel": null
            }
          ]
        }
      }
    },
    "author": { "identifier": "julia", "type": "user" }
  }
}
```

### When the function processes

Proceeds only when **all** of the following are true:

1. HMAC-SHA256 signature on `X-AKENEO-SIGNATURE-PRIMARY` header verifies against `AKENEO_WEBHOOK_SECRET`
2. CloudEvent `type` is `com.akeneo.pim.v1.asset.updated.delta`
3. `data.asset.changes.values` contains the attribute named `AKENEO_MEDIA_ATTRIBUTE`
4. That entry has `type: "media_file"` and a non-null, non-empty `new` value

### When the function skips (returns 200, no action)

| Situation | HTTP status |
|---|---|
| Signature mismatch | 401 |
| Wrong event type | 200 skipped |
| Watched attribute not in delta | 200 skipped |
| New value is null/empty (file removed) | 200 skipped |
| New file is not a `.zip` (PDF, image…) | 200 skipped |
| Asset family not in `AKENEO_ASSET_FAMILY_FILTER` (when set) | 200 skipped |

All skip cases return `200` (or `401`) to prevent the Event Platform from
retrying with the same payload.

---

## Processing pipeline

```
POST CloudEvent (Akeneo Event Platform)
    │
    ▼
Step 1 — Verify HMAC-SHA256 signature
    ├── Invalid → 401
    └── Valid → continue
    │
    ▼
Step 2 & 3 — Parse & validate CloudEvent
    ├── Wrong type / malformed → 200 skipped / 400
    └── Valid → continue
    │
    ▼
Step 4 — Inspect media attribute delta
    ├── Not changed / null → 200 skipped
    └── New file path present → continue
    │
    ▼
Step 4a — Asset family filter (optional)
    ├── Family not in AKENEO_ASSET_FAMILY_FILTER → 200 skipped
    └── Allowed (or no filter set) → continue
    │
    ▼
Step 4b — ZIP file guard
    ├── File extension is not .zip → 200 skipped
    └── Is a .zip → continue
    │
    ▼
Step 5 — Authenticate (OAuth2 password grant)
    │
    ▼
Step 6 — Download ZIP
  GET /api/rest/v1/asset-media-files/{newFilePath}
    │
    ▼
Step 7 — Extract ZIP → /tmp/gs1-artwork-XXXX/extracted/
    │
    ▼
Step 8 — Locate GS1 XML files
  Find all .xml files under any gs1/ folder
  (macOS ._dotfiles filtered out)
    │
    ▼
Step 9 — Derive product identifier
  First .ai filename without extension → product SKU
    │
    ▼
Step 10 — Parse first GS1 XML file
  parseArtworkContentFromString() → { metadata, marketingContent,
                                       ingredients, nutritionFacts, rawFields }
    │
    ▼
Step 11 — Upsert product
  GET /api/rest/v1/products/{id}
    ├── 404 → POST (create with family)
    └── 200 → PATCH (update family)
    │
    ▼
Step 12 — Write GS1 JSON + boolean flag
  PATCH → gs1_attributes_values  (minified JSON, ≤ 65535 chars)
  PATCH → AI_Process_GS1_contents_ = true
    │
    ▼
Step 13 — Write minified raw XML (conditional)
  minifyXml() → PATCH → gs1_raw_xml
  (skipped with warning if > 65535 chars)
    │
    ▼
Step 14 — Upload media files to asset family
  For each .png/.jpg/.jpeg/.gif/.webp/.pdf found outside nft/ folder:
    POST /api/rest/v1/asset-media-files  (multipart, prefixed filename)
    PATCH /api/rest/v1/asset-families/{family}/assets/{code}
         → main media attribute (resolved from attribute_as_main_media)
         → product_ref = productId
    │
    ▼
Step 15 — Cleanup /tmp/ + return 200 response
```

---

## Asset ZIP expected structure

```
Package.zip
├── artwork/
│   └── Display_2025.ai          ← product identifier = Display_2025
├── gs1/
│   ├── LSP_2600014_001_us.xml   ← only the first file is parsed
│   └── ._LSP_2600014_001_us.xml ← macOS metadata — automatically filtered
├── images/
│   ├── Thumb_front.jpg          ← uploaded to product_images asset family
│   ├── 0-Overview.pdf           ← asset code = Display_2025_a_0_Overview
│   └── variation-uuid.webp      ← asset code = Display_2025_variation_uuid
├── nft/
│   └── nft_token.png            ← entire nft/ folder excluded
└── dieline/
    └── 1-Dieline.pdf
```

**Rules:**
- The first `.ai` file found (any folder depth) names the product
- Only the **first** `.xml` file under any `gs1/` folder is parsed
- Media files (`.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.pdf`) are uploaded from all folders **except** `nft/`
- macOS AppleDouble files (`._filename`) are filtered at every step

---

## GS1 XML parser — `parseArtworkContent.js`

### Zero data loss design

Every `<artworkContentCopyElement>` in the XML is captured — the parser does
not use a fixed allowlist of type codes. Output sections:

| Section | Content |
|---|---|
| `metadata` | Document envelope (locales, IDs, creation date) |
| `marketingContent` | Well-known codes grouped under friendly keys (`brandName`, `marketingClaims`, `storageInstructions`, …) |
| `ingredients` | `INGREDIENTS_DECLARATION` blocks, split by flavour when embedded |
| `nutritionFacts` | FREE_FORM structured block — per-nutrient rows, multi-column for multi-flavour or multi-serving-size panels |
| `rawFields` | **Every other type code** not claimed above, keyed by camelCase code |

### Locale handling

Locale identifiers are normalised to Akeneo BCP-47 notation at parse time:

| XML value | Normalised |
|---|---|
| `EN-US` | `en_US` |
| `ZH-CN` | `zh_CN` |
| `EN-ZH-TW` | `en_zh_TW` |

Every text value is wrapped as `{ data: "…", locale: "en_US" }`. Multi-locale
documents produce arrays of localised values per field.

### Multi-locale nutrition facts

In multi-locale files (e.g. China), the same numeric value appears once per
locale. The parser deduplicates by keeping one value per instance, attaching
the first locale as the representative. Labels and units are collected per
locale and emitted as arrays when multiple translations exist.

### GS1 JSON payload shape

```json
{
  "_meta": {
    "eventId": "018e32f9-…",
    "eventTime": "2026-05-26T07:39:00Z",
    "assetCode": "test1",
    "assetFamilyCode": "eskozipfiles",
    "mediaAttribute": "media",
    "newFilePath": "3/6/e/f/36ef…_Package.zip",
    "processedAt": "2026-05-26T07:39:05.123Z",
    "sourceFile": "LSP_2600014_001_us.xml"
  },
  "gs1Data": {
    "metadata":        { "locales": [{ "sequence": "1", "identifier": "en_US" }], … },
    "marketingContent":{ "brandName": { "data": "OIKOS", "locale": "en_US" }, … },
    "ingredients":     [ { "flavour": "Strawberry", "data": "CULTURED…", "locale": "en_US" }, … ],
    "nutritionFacts":  { "title": { "data": "Nutrition Facts", "locale": "en_US" }, "nutrients": […] },
    "rawFields":       { "tableCell": [ … ] }
  }
}
```

The JSON is stored **minified** (no whitespace) to stay within Akeneo's
65535-character textarea limit. A 6-file package compresses from ~122 KB
pretty-printed to ~46 KB minified (62% reduction).

---

## Media asset upload

For each eligible media file found in the extracted archive:

1. **Upload** — `POST /api/rest/v1/asset-media-files` (multipart/form-data).
   The filename is prefixed with the product identifier:
   `Thumb_front.jpg` → `Display_2025_Thumb_front.jpg`

2. **Upsert asset record** — `PATCH /api/rest/v1/asset-families/{family}/assets/{code}`
   - Asset code: `{productId}_{sanitisedFilename}` (e.g. `Display_2025_Thumb_front`)
   - Asset code rules: letters, digits, underscores only; leading digits prefixed with `a_`; max 255 chars
   - Main media attribute resolved dynamically from `attribute_as_main_media` on the asset family (not hardcoded)
   - `product_ref` attribute set to the product identifier for the product link rule

### Asset family resolution

The `attribute_as_main_media` code is fetched once per invocation from
`GET /api/rest/v1/asset-families/{code}` and cached in memory for the
duration of the run. This avoids one API call per file upload.

### Product link rule

Configure the following rule on your asset family so the PIM automatically
links uploaded assets to products via the `product_ref` attribute:

```json
{
  "product_link_rules": [
    {
      "product_selections": [
        {
          "field":    "sku",
          "operator": "=",
          "value":    "{{product_ref}}"
        }
      ],
      "assign_assets_to": [
        {
          "attribute": "packshot_images",
          "mode":      "add",
          "locale":    null,
          "channel":   null
        }
      ]
    }
  ]
}
```

Apply via `PATCH /api/rest/v1/asset-families/{family_code}`.


---

## Webhook signature verification

Every incoming request is verified before any processing:

1. Akeneo signs the raw request body with `AKENEO_WEBHOOK_SECRET` using HMAC-SHA256
2. The digest is sent in the `X-AKENEO-SIGNATURE-PRIMARY` header
3. The function recomputes the HMAC over `req.rawBody` (or `JSON.stringify(req.body)` as fallback)
4. Comparison uses `crypto.timingSafeEqual` to prevent timing attacks
5. Requests that fail verification return `401` immediately — no Akeneo API calls are made

---

## Response shape

### 200 — Processed

```json
{
  "status": "processed",
  "productIdentifier": "Display_2025",
  "sourceFile": "LSP_2600014_001_us.xml",
  "attribute": "gs1_attributes_values",
  "processedFlag": "AI_Process_GS1_contents_",
  "rawXmlAttribute": "gs1_raw_xml",
  "rawXmlStored": false,
  "rawXmlSkippedReason": "too_large",
  "mediaAssets": {
    "assetFamily": "product_images",
    "total": 29,
    "uploaded": 27,
    "skipped": 2,
    "errors": [
      { "file": "corrupted.jpg", "error": "…" }
    ]
  },
  "action": "created"
}
```

### 200 — Skipped

```json
{ "status": "skipped", "reason": "Attribute \"media\" did not change or new value is empty." }
```

### 401 — Signature failure

```json
{ "status": "error", "error": "Missing X-AKENEO-SIGNATURE-PRIMARY header." }
```

### 400 — Malformed event

```json
{ "status": "error", "error": "CloudEvent data.asset.changes.values is missing." }
```

### 500 — Internal error

```json
{ "status": "error", "error": "No .ai file found in the ZIP archive." }
```

---

## Local development

### Install dependencies

```bash
npm install
```

### Set environment variables

```bash
export AKENEO_HOST=https://my-instance.cloud.akeneo.com
export AKENEO_CLIENT_ID=1_abc123
export AKENEO_CLIENT_SECRET=secretxyz
export AKENEO_USERNAME=api_user
export AKENEO_PASSWORD=mypassword
export AKENEO_WEBHOOK_SECRET=YQL1Vw4qhieTwOoOL8f8NyiepIbppsgH
export AKENEO_MEDIA_ATTRIBUTE=media
export AKENEO_PRODUCT_FAMILY=snack
export AKENEO_GS1_ATTRIBUTE=gs1_attributes_values
export AKENEO_GS1_RAW_XML_ATTRIBUTE=gs1_raw_xml
export AKENEO_GS1_PROCESSED_FLAG=AI_Process_GS1_contents_
export AKENEO_MEDIA_ASSET_FAMILY=product_images
export AKENEO_MEDIA_ASSET_PRODUCT_REF_ATTRIBUTE=product_ref
export AKENEO_ASSET_FAMILY_FILTER=eskozipfiles  # optional
```

### Run test scenarios

`test-local.js` ships with four named scenarios:

| Scenario | What it tests |
|---|---|
| `normal` | Happy path — media attribute changed with a new ZIP path |
| `wrongType` | Event type is `asset.created` — skipped with 200 |
| `unrelatedChange` | A different attribute changed — skipped with 200 |
| `fileRemoved` | New value is null — skipped with 200 |

```bash
# Happy path
TEST_SCENARIO=normal \
TEST_ASSET_CODE=test1 \
TEST_ASSET_FAMILY_CODE=eskozipfiles \
TEST_NEW_FILE_PATH=3/6/e/f/36ef1d39f9bd3b78e6c5ceaabd71dd7bc9ab2f62_Package.zip \
node test-local.js

# Skip scenarios (no real Akeneo connection needed)
TEST_SCENARIO=wrongType       node test-local.js
TEST_SCENARIO=unrelatedChange node test-local.js
TEST_SCENARIO=fileRemoved     node test-local.js
```

### Run as HTTP server (Functions Framework)

```bash
npm start

curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -H "X-AKENEO-SIGNATURE-PRIMARY: <computed-hmac>" \
  -d '{ "specversion":"1.0", "type":"com.akeneo.pim.v1.asset.updated.delta", … }'
```

---

## Deployment

### Deploy to Google Cloud Run

```bash
gcloud run deploy esko-asset-decompactor \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars \
    AKENEO_HOST=https://esko.demo.cloud.akeneo.com,\
    AKENEO_CLIENT_ID=YOUR_CLIENT_ID,\
    AKENEO_CLIENT_SECRET=YOUR_CLIENT_SECRET,\
    AKENEO_USERNAME=YOUR_USERNAME,\
    AKENEO_PASSWORD=YOUR_PASSWORD,\
    AKENEO_WEBHOOK_SECRET=YOUR_WEBHOOK_SECRET,\
    AKENEO_MEDIA_ATTRIBUTE=media,\
    AKENEO_PRODUCT_FAMILY=snack,\
    AKENEO_GS1_ATTRIBUTE=gs1_attributes_values,\
    AKENEO_GS1_RAW_XML_ATTRIBUTE=gs1_raw_xml,\
    AKENEO_GS1_PROCESSED_FLAG=AI_Process_GS1_contents_,\
    AKENEO_MEDIA_ASSET_FAMILY=product_images,\
    AKENEO_MEDIA_ASSET_PRODUCT_REF_ATTRIBUTE=product_ref
    # AKENEO_ASSET_FAMILY_FILTER=eskozipfiles  # optional
```

> **Production recommendation:** store secrets in **Google Secret Manager**
> and reference them with `--set-secrets` rather than `--set-env-vars`.

### Event Platform subscription

The subscription was created via the API with the following configuration:

| Field | Value |
|---|---|
| Subscriber ID | `019e4aa9-021a-7a17-9dbf-8ce74ba1c71b` |
| Subscription ID | `019e4aa9-afe9-7e2c-8d8a-0c10f820f24a` |
| Event type | `com.akeneo.pim.v1.asset.updated.delta` |
| Destination URL | `https://esko-asset-decompactor-3ifmzp3pha-uc.a.run.app` |
| PIM instance | `https://esko.demo.cloud.akeneo.com` |
| Notification email | `florian.lasdoulours@akeneo.com` |

The webhook secret (`AKENEO_WEBHOOK_SECRET`) matches the `primary_secret`
configured on this subscription.

---

## PIM attribute requirements

All product attributes written by the function must exist in the PIM and be
assigned to the product family before running.

| Attribute code | Type | Localisable | Scopable | Notes |
|---|---|:---:|:---:|---|
| `gs1_attributes_values` | Text area | No | No | Stores minified GS1 JSON |
| `gs1_raw_xml` | Text area | No | No | Stores minified raw XML |
| `AI_Process_GS1_contents_` | Boolean (Yes/No) | No | No | Processing flag |

The asset family (`product_images`) must also have:

| Asset attribute | Type | Notes |
|---|---|---|
| `product_ref` | Text | Non-localisable, non-scopable — used by the product link rule |
| `attribute_as_main_media` | Media file | Must be set on the family — the function reads this dynamically |

---

## Notes

- **Idempotency** — re-processing the same ZIP overwrites all attributes with
  fresh values. Asset records are upserted (created or updated) idempotently.
- **Temp directory** — written to `/tmp` (up to 512 MB). Always cleaned up in
  the `finally` block regardless of success or failure.
- **Asset code sanitisation** — characters outside `[a-zA-Z0-9_]` become
  underscores; codes starting with a digit are prefixed with `a_`; max 255 chars.
- **macOS ZIP artefacts** — `._filename` AppleDouble files are filtered at
  every discovery step (XML files, media files).
- **Single XML file** — only the first GS1 XML file found in the `gs1/` folder
  is parsed. Additional files are ignored.
- **rawFields catch-all** — any type code not recognised by the named sections
  (marketingContent, ingredients, nutritionFacts) is automatically captured in
  `rawFields` keyed by camelCase code — no data is ever silently dropped.
