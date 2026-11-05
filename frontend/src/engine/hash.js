// File & hash analysis. Files are only read as bytes: never executed, opened, or unpacked.
import SparkMD5 from 'spark-md5'
import { Confidence, Severity, Status, finding, unknown } from './findings.js'

const MODULE = 'file'
const MAGIC = [
  ['%PDF-', 0, 'PDF document', ['pdf']],
  ['MZ', 0, 'Windows executable (PE/DOS)', ['exe', 'dll', 'scr', 'sys', 'com', 'cpl', 'ocx', 'drv', 'efi']],
  ['\x7fELF', 0, 'Linux/Unix executable (ELF)', ['', 'so', 'bin', 'elf', 'o']],
  ['\xcf\xfa\xed\xfe', 0, 'macOS executable (Mach-O)', ['', 'dylib', 'bundle']],
  ['\xca\xfe\xba\xbe', 0, 'Mach-O universal binary / Java class', ['', 'class', 'dylib']],
  ['PK\x03\x04', 0, 'ZIP archive (also DOCX/XLSX/PPTX/JAR/APK)', ['zip', 'docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'pptm', 'jar', 'apk', 'odt', 'ods', 'epub', 'kmz', 'xpi']],
  ['\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 0, 'OLE2 compound file (legacy DOC/XLS/PPT/MSG/MSI)', ['doc', 'xls', 'ppt', 'msg', 'msi', 'dot', 'xlt', 'pub', 'vsd']],
  ['Rar!\x1a\x07', 0, 'RAR archive', ['rar']], ['7z\xbc\xaf\x27\x1c', 0, '7-Zip archive', ['7z']],
  ['\x1f\x8b', 0, 'GZIP archive', ['gz', 'tgz']], ['BZh', 0, 'BZIP2 archive', ['bz2']], ['\xfd7zXZ\x00', 0, 'XZ archive', ['xz']],
  ['CD001', 0x8001, 'ISO 9660 disk image', ['iso', 'img']],
  ['\x4c\x00\x00\x00\x01\x14\x02\x00', 0, 'Windows shortcut (LNK)', ['lnk']],
  ['{\\rtf', 0, 'Rich Text Format', ['rtf', 'doc']], ['\x89PNG\r\n\x1a\n', 0, 'PNG image', ['png']],
  ['\xff\xd8\xff', 0, 'JPEG image', ['jpg', 'jpeg', 'jfif']], ['GIF8', 0, 'GIF image', ['gif']],
  ['RIFF', 0, 'RIFF container (WAV/AVI/WEBP)', ['wav', 'avi', 'webp']], ['MSCF', 0, 'Microsoft Cabinet archive', ['cab']],
  ['koly', -512, 'Apple disk image (DMG)', ['dmg']],
]
const DANGEROUS_EXT = new Set(['exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'ps1', 'msi',
  'lnk', 'iso', 'img', 'vhd', 'vhdx', 'jar', 'docm', 'xlsm', 'pptm', 'cpl', 'reg', 'html', 'htm', 'svg', 'one', 'xll', 'appx', 'msix', 'dll', 'chm'])
const EXECUTABLE_TYPES = new Set(['Windows executable (PE/DOS)', 'Linux/Unix executable (ELF)', 'macOS executable (Mach-O)', 'Windows shortcut (LNK)'])

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')

export async function hashes(bytes) {
  const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  const [sha1, sha256] = await Promise.all([crypto.subtle.digest('SHA-1', buf), crypto.subtle.digest('SHA-256', buf)])
  return { md5: SparkMD5.ArrayBuffer.hash(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)), sha1: hex(sha1), sha256: hex(sha256) }
}

const latin = (bytes, start, len) => String.fromCharCode(...bytes.slice(start, start + len))

export function detectType(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  for (const [magic, offset, label, exts] of MAGIC) {
    const start = offset >= 0 ? offset : b.length + offset
    if (start < 0 || start + magic.length > b.length) continue
    if (latin(b, start, magic.length) === magic) return { label, expected_extensions: [...exts].sort(), method: 'magic bytes' }
  }
  const head = latin(b, 0, Math.min(512, b.length)).replace(/^\s+/, '')
  if (head.startsWith('#!')) return { label: 'Script with interpreter line (#!)', expected_extensions: ['sh', 'py', 'pl', ''], method: 'shebang' }
  const low = head.slice(0, 200).toLowerCase()
  if (low.startsWith('<!doctype html') || low.startsWith('<html') || low.includes('<script')) return { label: 'HTML document', expected_extensions: ['html', 'htm'], method: 'content sniff' }
  if (low.startsWith('<svg') || (low.startsWith('<?xml') && latin(b, 0, Math.min(2048, b.length)).toLowerCase().includes('<svg')))
    return { label: 'SVG image (can contain script)', expected_extensions: ['svg'], method: 'content sniff' }
  try { new TextDecoder('utf-8', { fatal: true }).decode(b.slice(0, 4096)); return { label: 'Plain text (UTF-8/ASCII)', expected_extensions: [], method: 'content sniff' } }
  catch { return { label: 'Unknown binary', expected_extensions: [], method: 'none' } }
}

export const extensionOf = (filename) => { const n = (filename || '').split('/').pop().split('\\').pop(); return n.includes('.') ? n.split('.').pop().toLowerCase() : '' }

export async function analyzeBytes(bytes, filename, { module = MODULE } = {}) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  const h = await hashes(b)
  const ftype = detectType(b)
  const ext = extensionOf(filename)
  const parts = (filename || '').toLowerCase().split('.')
  const doubleExt = parts.length >= 3 && DANGEROUS_EXT.has(parts.at(-1)) && parts.at(-2).length <= 4
  const mismatch = ftype.expected_extensions.length > 0 && !ftype.expected_extensions.includes(ext)
  const findings = [
    finding(module, `File hashes for ${filename || 'upload'}`, Status.CONFIRMED,
      `SHA-256 ${h.sha256} · SHA-1 ${h.sha1} · MD5 ${h.md5} · ${b.length} bytes`, 'Computed locally from the file bytes.',
      'A unique fingerprint for this exact file. Share the SHA-256 with investigators instead of the file itself.',
      'Anything about whether the file is malicious.', Confidence.HIGH, 'Look the SHA-256 up in reputation services, or include it in your report.'),
    finding(module, `Detected type: ${ftype.label}`, Status.CONFIRMED,
      `Content signature (${ftype.method}) indicates ${ftype.label}; file name claims '.${ext || '(none)'}'.`,
      'Magic-byte inspection of the first bytes of the file.', 'What the file actually is, regardless of its name.',
      'What the file does when opened.', ftype.method === 'magic bytes' ? Confidence.HIGH : Confidence.MEDIUM, 'Do not open the file on your own computer.'),
  ]
  if (mismatch) findings.push(finding(module, 'File type does not match its extension', Status.CONFIRMED,
    `Named '.${ext || '(none)'}' but the content is ${ftype.label}.`, 'Magic bytes vs. filename.',
    'Disguising a file\'s real type is a classic malware delivery trick (for example an executable named .pdf).',
    'That the file is malicious — some software mislabels files.', Confidence.HIGH, 'Treat the file as dangerous; do not open it.',
    { severity: EXECUTABLE_TYPES.has(ftype.label) ? Severity.HIGH : Severity.MEDIUM }))
  if (DANGEROUS_EXT.has(ext) || EXECUTABLE_TYPES.has(ftype.label)) findings.push(finding(module, 'High-risk file type', Status.CONFIRMED,
    `'.${ext}' / ${ftype.label} can run code or scripts when opened.`, 'Extension and content signature.',
    'Files like this are commonly used to deliver malware by email.', 'That this particular file is malicious.', Confidence.HIGH,
    'Never open it. Report the sender; share only the hash.', { severity: Severity.HIGH }))
  if (doubleExt) findings.push(finding(module, 'Double extension in file name', Status.CONFIRMED, filename, 'File name',
    "Names like 'invoice.pdf.exe' rely on hidden extensions to disguise the real type.", 'That the file is malicious.', Confidence.HIGH,
    'Do not open it.', { severity: Severity.HIGH }))
  return { kind: 'file', filename, size: b.length, hashes: h, detected_type: ftype, claimed_extension: ext, extension_mismatch: mismatch,
           executed: false, findings }
}

const HASH_RE = { md5: /^[a-f0-9]{32}$/, sha1: /^[a-f0-9]{40}$/, sha256: /^[a-f0-9]{64}$/ }

export function analyzeHash(value) {
  const v = (value || '').trim().toLowerCase()
  const algorithm = Object.keys(HASH_RE).find((k) => HASH_RE[k].test(v)) || null
  if (!algorithm) return { kind: 'hash', input: value, algorithm: null, error: 'Not a valid MD5, SHA-1 or SHA-256 hex digest.', findings: [] }
  return { kind: 'hash', input: value, algorithm,
           findings: [unknown('hash', 'No hash reputation source in the browser edition', v,
             'Reputation lookups need a private API key, which cannot be kept secret in a web page',
             'Search the hash on VirusTotal yourself, or run the server edition with VIRUSTOTAL_API_KEY set.')] }
}
