/**
 * test-local.js — Local test harness for the Cloud Function
 *
 * Simulates an Akeneo Event Platform CloudEvent without deploying to GCP.
 * Set environment variables before running:
 *
 *   AKENEO_HOST=https://…  AKENEO_CLIENT_ID=… … node test-local.js
 *
 * Or configure a .env file and uncomment the dotenv line below.
 */

'use strict';

// require('dotenv').config();

const { processArtworkAsset } = require('./index');

// ---------------------------------------------------------------------------
// Scenario helpers
// ---------------------------------------------------------------------------

/**
 * Builds a realistic com.akeneo.pim.v1.asset.updated.delta CloudEvent.
 *
 * @param {object} opts
 * @param {string} opts.assetCode
 * @param {string} opts.assetFamilyCode
 * @param {string} opts.mediaAttribute   Code of the watched media attribute
 * @param {string} opts.newFilePath      New file path (simulates the event delta)
 * @param {string} [opts.previousFilePath]
 */
function buildAssetUpdatedDeltaEvent({
  assetCode,
  assetFamilyCode,
  mediaAttribute,
  newFilePath,
  previousFilePath = null,
}) {
  return {
    specversion:     '1.0',
    id:              `test-${Date.now()}`,
    type:            'com.akeneo.pim.v1.asset.updated.delta',
    source:          'pim',
    subject:         '01948d3c-6625-7833-8a03-dd96245862d3',
    time:            new Date().toISOString(),
    datacontenttype: 'application/json',
    dataschema:      'https://event.prd.sdk.akeneo.cloud/spec/com.akeneo.pim.v1.asset.updated.delta.schema.json',
    data: {
      asset: {
        asset_family: { code: assetFamilyCode },
        code:         assetCode,
        changes: {
          values: {
            [mediaAttribute]: [
              {
                previous: previousFilePath,
                new:      newFilePath,
                type:     'media_file',
                locale:   null,
                channel:  null,
              },
            ],
          },
        },
      },
      author: {
        identifier: 'test-user',
        type:       'user',
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Test scenarios
// ---------------------------------------------------------------------------

const SCENARIOS = {
  // ── Happy path — media attribute changed with a ZIP file ────────────────
  normal: buildAssetUpdatedDeltaEvent({
    assetCode:       process.env.TEST_ASSET_CODE        || 'my_artwork_asset',
    assetFamilyCode: process.env.TEST_ASSET_FAMILY_CODE || 'artwork_files',
    mediaAttribute:  process.env.AKENEO_MEDIA_ATTRIBUTE || 'zip_file',
    newFilePath:     process.env.TEST_NEW_FILE_PATH
                       || '7/a/2/b/7a2b175efd1d0a2a09c0c4e04be398dbb7a3e02e_artwork.zip',
    previousFilePath: process.env.TEST_PREV_FILE_PATH   || null,
  }),

  // ── Skipped — wrong event type ───────────────────────────────────────────
  wrongType: {
    specversion: '1.0',
    id:          'test-wrong-type',
    type:        'com.akeneo.pim.v1.asset.created',
    source:      'pim',
    subject:     '01948d3c-0000-0000-0000-000000000000',
    time:        new Date().toISOString(),
    datacontenttype: 'application/json',
    data: {
      asset: { asset_family: { code: 'artwork_files' }, code: 'my_asset' },
      author: { identifier: 'test-user', type: 'user' },
    },
  },

  // ── Skipped — watched attribute not in the delta ─────────────────────────
  unrelatedChange: buildAssetUpdatedDeltaEvent({
    assetCode:       'my_artwork_asset',
    assetFamilyCode: 'artwork_files',
    mediaAttribute:  'some_other_attribute',   // not the watched one
    newFilePath:     'some/path/image.jpg',
  }),

  // ── Skipped — new value is null (file removed) ───────────────────────────
  fileRemoved: (() => {
    const ev = buildAssetUpdatedDeltaEvent({
      assetCode: 'my_artwork_asset', assetFamilyCode: 'artwork_files',
      mediaAttribute: process.env.AKENEO_MEDIA_ATTRIBUTE || 'zip_file',
      newFilePath: null, previousFilePath: '7/a/2/b/old_artwork.zip',
    });
    ev.data.asset.changes.values[process.env.AKENEO_MEDIA_ATTRIBUTE || 'zip_file'][0].new = null;
    return ev;
  })(),
};

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

const SCENARIO = process.env.TEST_SCENARIO || 'normal';
const body     = SCENARIOS[SCENARIO];

if (!body) {
  console.error(`Unknown scenario "${SCENARIO}". Available: ${Object.keys(SCENARIOS).join(', ')}`);
  process.exit(1);
}

console.log(`\n─── Scenario: ${SCENARIO} ${'─'.repeat(Math.max(0, 50 - SCENARIO.length))}`);
console.log('CloudEvent:', JSON.stringify(body, null, 2));
console.log('─'.repeat(60) + '\n');

// Minimal Express req/res mock
const req = { body };
let responseStatus = null;

const res = {
  status(code) { responseStatus = code; return this; },
  json(payload) {
    console.log('\n─── Response ' + '─'.repeat(47));
    console.log(`HTTP ${responseStatus}`);
    console.log(JSON.stringify(payload, null, 2));
    console.log('─'.repeat(60) + '\n');
  },
};

processArtworkAsset(req, res).catch(err => {
  console.error('Unhandled error:', err);
  process.exit(1);
});
