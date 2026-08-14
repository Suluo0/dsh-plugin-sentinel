/**
 * Pure-JS tarball reader — zero dependencies, zero child processes.
 *
 * npm packs (.tgz) are gzip'd ustar archives. We inflate with the built-in
 * node:zlib and parse the tar structure by hand (512-byte headers, pax
 * extended headers, GNU long names) so audited code NEVER touches the disk:
 * a malicious payload stays bytes in memory until they are dropped.
 */

import { gunzipSync } from 'node:zlib'

/**
 * @typedef {object} TarEntry
 * @property {string} name
 * @property {'file'|'symlink'|'dir'} kind
 * @property {string} [linkname]
 * @property {Uint8Array} data
 */

const BLOCK = 512

/** Read a NUL/space-terminated string field from a header buffer. */
function field(buf, start, end) {
  let stop = start
  while (stop < end && buf[stop] !== 0) stop++
  return new TextDecoder('latin1').decode(buf.subarray(start, stop)).trim()
}

/** Parse a numeric field: standard octal, GNU base-256, or empty → 0. */
function numeric(buf, start, end) {
  if (buf[start] & 0x80) {
    // GNU base-256: first byte carries the high bit + 7 value bits
    let value = buf[start] & 0x7f
    for (let i = start + 1; i < end; i++) value = value * 256 + buf[i]
    return value
  }
  const s = field(buf, start, end)
  return s === '' ? 0 : parseInt(s, 8)
}

/** Parse pax extended-header records ("<len> <key>=<value>\n"). */
function parsePaxRecords(data) {
  const text = new TextDecoder('utf-8').decode(data)
  const out = {}
  let pos = 0
  while (pos < text.length) {
    const spaceAt = text.indexOf(' ', pos)
    if (spaceAt < 0) break
    const len = parseInt(text.slice(pos, spaceAt), 10)
    if (!Number.isFinite(len) || len <= 0) break
    const record = text.slice(pos, pos + len)
    const eq = record.indexOf('=')
    if (eq > 0) {
      const key = record.slice(spaceAt - pos + 1, eq)
      const value = record.slice(eq + 1).replace(/\n$/, '')
      out[key] = value
    }
    pos += len
  }
  return out
}

/**
 * Parse tar bytes into entries. Accepts gzipped or plain tar.
 * @param {Uint8Array} bytes
 * @returns {{ entries: TarEntry[], warnings: string[] }}
 */
export function parseTar(bytes) {
  const warnings = []
  let buf = bytes
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    buf = gunzipSync(bytes)
  }

  /** @type {TarEntry[]} */
  const entries = []
  let pos = 0
  let pendingLongName = null
  let pendingPax = null

  while (pos + BLOCK <= buf.length) {
    const header = buf.subarray(pos, pos + BLOCK)
    const name = field(header, 0, 100)
    const size = numeric(header, 124, 136)
    const typeflag = String.fromCharCode(header[156] || 0x30)
    const prefix = field(header, 345, 500)
    const linkname = field(header, 157, 257)

    if (name === '' && size === 0) {
      // end-of-archive: two zero blocks (we accept the first)
      pos += BLOCK
      continue
    }

    const dataStart = pos + BLOCK
    const dataEnd = dataStart + size
    if (dataEnd > buf.length) {
      warnings.push(`truncated entry "${name}" — archive ends mid-file`)
      break
    }
    const data = buf.subarray(dataStart, dataEnd)
    pos = dataEnd + (size % BLOCK === 0 ? 0 : BLOCK - (size % BLOCK))

    if (typeflag === 'L') {
      // GNU long name applies to the NEXT entry
      pendingLongName = new TextDecoder('utf-8').decode(data).replace(/\0$/, '')
      continue
    }
    if (typeflag === 'x' || typeflag === 'X') {
      pendingPax = parsePaxRecords(data)
      continue
    }
    if (typeflag === 'g') {
      // global pax header: affects everything; note and continue
      warnings.push('archive carries a global pax header (records applied to all entries)')
      continue
    }
    if (typeflag === '1') continue // hardlink — no payload
    if (typeflag === '5' || (name.endsWith('/') && typeflag === '0')) {
      entries.push({ name: fullName(pendingLongName, pendingPax, name, prefix), kind: 'dir', data: new Uint8Array(0) })
      pendingLongName = null; pendingPax = null
      continue
    }

    const resolved = fullName(pendingLongName, pendingPax, name, prefix)
    pendingLongName = null; pendingPax = null
    entries.push({
      name: resolved,
      kind: typeflag === '2' ? 'symlink' : 'file',
      linkname: typeflag === '2' ? linkname : undefined,
      data,
    })
  }

  return { entries, warnings }
}

/** Compose the effective entry name from GNU longname / pax / ustar prefix. */
function fullName(longName, pax, name, prefix) {
  const base = longName ?? pax?.path ?? (prefix ? `${prefix}/${name}` : name)
  return base.replace(/^\.\//, '')
}
