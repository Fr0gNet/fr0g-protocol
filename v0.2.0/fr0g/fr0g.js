const zlib = require('zlib');

const HORIZON_URL = 'https://horizon-testnet.stellar.org';

function fr0gID2stellar(fr0g_id) {
  if (!fr0g_id || !fr0g_id.startsWith('fr0g')) {
    throw new Error('Invalid fr0g ID');
  }
  return fr0g_id.substring(4).split('').reverse().join('').toUpperCase();
}

async function retrieveData(fr0gId) {
  const stellarAddr = fr0gID2stellar(fr0gId);
  const url = `${HORIZON_URL}/accounts/${stellarAddr}`;
  const response = await fetch(url);
  if (!response.ok) {
    if (response.status === 404) return [];
    throw new Error(`Failed to fetch account data: ${response.status}`);
  }
  const accountInfo = await response.json();
  const dataEntries = accountInfo.data || {};
  const result = [];
  for (const [key, b64Value] of Object.entries(dataEntries)) {
    const valueBytes = Buffer.from(b64Value, 'base64');
    result.push([key, valueBytes]);
  }
  return result;
}

async function getMimeType(fr0gId, fileIndex = 0) {
  let currentId = fr0gId;
  const visited = new Set();
  while (!visited.has(currentId)) {
    visited.add(currentId);
    let dataEntries;
    try {
      dataEntries = await retrieveData(currentId);
    } catch (e) {
      console.warn(`Failed to retrieve data for linked ID ${currentId}: ${e.message}`);
      break;
    }
    if (!dataEntries || dataEntries.length === 0) break;

    const entryDict = Object.fromEntries(dataEntries); // key -> Buffer

    for (const [key] of dataEntries) {
      if (!key.startsWith(`fr0g:f${fileIndex}c`)) continue;
      try {
        const cSplit = key.split('c', 2);
        if (cSplit.length < 2) continue;
        const rest = cSplit[1];
        const colonSplit = rest.split(':', 2);
        if (colonSplit.length < 2) continue;
        const chunkNumStr = colonSplit[0];
        const mimeCandidate = colonSplit[1].trim();
        if (/^\d+$/.test(chunkNumStr) && mimeCandidate) {
          return mimeCandidate;
        }
      } catch (e) {
        continue;
      }
    }

    const nextKey = `fr0g:next_f${fileIndex}`;
    if (nextKey in entryDict) {
      try {
        let nextId = entryDict[nextKey];
        if (Buffer.isBuffer(nextId) || nextId instanceof Uint8Array) {
          nextId = nextId.toString('ascii').trim();
        } else if (typeof nextId !== 'string') {
          nextId = String(nextId).trim();
        }
        if (nextId.startsWith('fr0g') && nextId !== currentId) {
          currentId = nextId;
          continue;
        }
      } catch (e) {
        break;
      }
    } else {
      break;
    }
  }
  return null;
}

async function getC(id, index = 0) {
  let retrieve;
  try {
    retrieve = await retrieveData(id);
  } catch (e) {
    console.error(`Failed to retrieve data for ${id}: ${e.message}`);
    return [null, null];
  }

  const chunks = [];
  for (const [key, valueBytes] of retrieve) {
    if (!key.startsWith(`fr0g:f${index}c`)) continue;
    try {
      const cSplit = key.split('c', 2);
      if (cSplit.length < 2) continue;
      const rest = cSplit[1];
      const colonSplit = rest.split(':', 2);
      const chunkNumStr = colonSplit[0];
      if (!/^\d+$/.test(chunkNumStr)) continue;
      const chunkNum = parseInt(chunkNumStr, 10);
      chunks.push([chunkNum, valueBytes]);
    } catch (e) {
      continue;
    }
  }

  if (chunks.length === 0) {
    return [null, null];
  }

  chunks.sort((a, b) => a[0] - b[0]);
  let full = Buffer.concat(chunks.map(([, val]) => val));

  // Trim trailing 0xFF padding (added during upload)
  while (full.length > 0 && full[full.length - 1] === 0xFF) {
    full = full.slice(0, -1);
  }

  // MIME lookup always uses file_index = 0 per original Python get_c()
  let mime = await getMimeType(id) || 'application/octet-stream';
  const isGzipped = mime.includes('+gzip');
  const mimeClean = mime.replace('+gzip', '');

  if (isGzipped) {
    try {
      full = zlib.gunzipSync(full);
    } catch (e) {
      console.error(`Gzip decompress failed: ${e.message}`);
      return [null, null];
    }
  }

  return [full, mimeClean];
}

module.exports = { getC, retrieveData, getMimeType }; // for easy import
