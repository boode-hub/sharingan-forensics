/**
 * A Sigma rule engine: paste a rule, get the rows it would alert on.
 *
 * Sigma describes a detection as named selections of field conditions and a
 * condition that combines them. Rather than translate the rule into another
 * query language and lose whatever does not map, it is evaluated directly
 * against the rows in memory, using the same field lookup as the filter
 * language: a column by name, or a field inside the event's own XML.
 *
 * Specification: https://github.com/SigmaHQ/sigma-specification
 *
 * Supported: every documented value modifier except expand (placeholders need
 * a site-specific mapping), keywords, null and empty values, wildcards and
 * their escapes, the full condition grammar including "1 of" and "all of" with
 * patterns, and logsource restriction for Windows services and the Sysmon
 * categories, including process_creation from Security 4688. Aggregations
 * ("| count() > 5") and timeframes need a correlation over time rather than a
 * row test; a rule that uses them is still run without them, and says so.
 */
import type { Column, Row } from '../core/types';
import { columnIndex, eventFields, fieldValues, norm } from './fields';
import { fmt } from './format';

export class SigmaError extends Error {}

export interface SigmaRule {
  title: string;
  id: string | null;
  level: string | null;
  status: string | null;
  description: string | null;
  author: string | null;
  tags: string[];
  logsource: Record<string, string>;
  /** What in the rule this engine could not honour, said plainly. */
  notes: string[];
  test: (row: Row) => boolean;
}

type Test = (row: Row) => boolean;

// ---------------------------------------------------------- logsource ---

const SYSMON = 'Microsoft-Windows-Sysmon/Operational';
const PS = 'Microsoft-Windows-PowerShell/Operational';

/** Sigma service names to the event log channels they mean. */
const SERVICES: Record<string, string[]> = {
  security: ['Security'],
  system: ['System'],
  application: ['Application'],
  sysmon: [SYSMON],
  powershell: [PS, 'PowerShellCore/Operational'],
  'powershell-classic': ['Windows PowerShell'],
  taskscheduler: ['Microsoft-Windows-TaskScheduler/Operational'],
  wmi: ['Microsoft-Windows-WMI-Activity/Operational'],
  windefend: ['Microsoft-Windows-Windows Defender/Operational'],
  'bits-client': ['Microsoft-Windows-Bits-Client/Operational'],
  'codeintegrity-operational': ['Microsoft-Windows-CodeIntegrity/Operational'],
  'firewall-as': ['Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'],
  'terminalservices-localsessionmanager': [
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
  ],
  ntlm: ['Microsoft-Windows-NTLM/Operational'],
  'dns-server': ['DNS Server'],
  'dns-client': ['Microsoft-Windows-DNS Client Events/Operational'],
  'driver-framework': ['Microsoft-Windows-DriverFrameworks-UserMode/Operational'],
  openssh: ['OpenSSH/Operational'],
  'smbclient-security': ['Microsoft-Windows-SmbClient/Security'],
  'smbclient-connectivity': ['Microsoft-Windows-SmbClient/Connectivity'],
  'appxdeployment-server': ['Microsoft-Windows-AppXDeploymentServer/Operational'],
  'appxpackaging-om': ['Microsoft-Windows-AppxPackaging/Operational'],
  applocker: [
    'Microsoft-Windows-AppLocker/MSI and Script',
    'Microsoft-Windows-AppLocker/EXE and DLL',
    'Microsoft-Windows-AppLocker/Packaged app-Deployment',
    'Microsoft-Windows-AppLocker/Packaged app-Execution',
  ],
  'printservice-admin': ['Microsoft-Windows-PrintService/Admin'],
  'printservice-operational': ['Microsoft-Windows-PrintService/Operational'],
  'shell-core': ['Microsoft-Windows-Shell-Core/Operational'],
  'lsa-server': ['Microsoft-Windows-LSA/Operational'],
  capi2: ['Microsoft-Windows-CAPI2/Operational'],
  'certificateservicesclient-lifecycle-system': [
    'Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational',
  ],
  'diagnosis-scripted': ['Microsoft-Windows-Diagnosis-Scripted/Operational'],
  'kernel-shimengine': [
    'Microsoft-Windows-Kernel-ShimEngine/Operational',
    'Microsoft-Windows-Kernel-ShimEngine/Diagnostic',
  ],
  'msexchange-management': ['MSExchange Management'],
  'security-mitigations': [
    'Microsoft-Windows-Security-Mitigations/Kernel Mode',
    'Microsoft-Windows-Security-Mitigations/User Mode',
  ],
  vhdmp: ['Microsoft-Windows-VHDMP/Operational'],
  bitlocker: ['Microsoft-Windows-BitLocker/BitLocker Management'],
  dhcp: ['Microsoft-Windows-DHCP-Server/Operational'],
};

/** Sigma categories to the channel and event ids that carry them. */
const CATEGORIES: Record<string, Array<{ channel: string; ids: number[] }>> = {
  process_creation: [
    { channel: SYSMON, ids: [1] },
    // The same events from Windows' own auditing, with different field names;
    // see PROCESS_CREATION_4688.
    { channel: 'Security', ids: [4688] },
  ],
  file_change: [{ channel: SYSMON, ids: [2] }],
  network_connection: [{ channel: SYSMON, ids: [3] }],
  sysmon_status: [{ channel: SYSMON, ids: [4, 16] }],
  process_termination: [{ channel: SYSMON, ids: [5] }],
  driver_load: [{ channel: SYSMON, ids: [6] }],
  image_load: [{ channel: SYSMON, ids: [7] }],
  create_remote_thread: [{ channel: SYSMON, ids: [8] }],
  raw_access_thread: [{ channel: SYSMON, ids: [9] }],
  process_access: [{ channel: SYSMON, ids: [10] }],
  file_event: [{ channel: SYSMON, ids: [11] }],
  registry_add: [{ channel: SYSMON, ids: [12] }],
  registry_delete: [{ channel: SYSMON, ids: [12] }],
  registry_set: [{ channel: SYSMON, ids: [13] }],
  registry_rename: [{ channel: SYSMON, ids: [14] }],
  registry_event: [{ channel: SYSMON, ids: [12, 13, 14] }],
  create_stream_hash: [{ channel: SYSMON, ids: [15] }],
  pipe_created: [{ channel: SYSMON, ids: [17, 18] }],
  wmi_event: [{ channel: SYSMON, ids: [19, 20, 21] }],
  dns_query: [{ channel: SYSMON, ids: [22] }],
  file_delete: [{ channel: SYSMON, ids: [23, 26] }],
  clipboard_capture: [{ channel: SYSMON, ids: [24] }],
  process_tampering: [{ channel: SYSMON, ids: [25] }],
  file_block_executable: [{ channel: SYSMON, ids: [27] }],
  file_block_shredding: [{ channel: SYSMON, ids: [28] }],
  file_executable_detected: [{ channel: SYSMON, ids: [29] }],
  sysmon_error: [{ channel: SYSMON, ids: [255] }],
  ps_module: [{ channel: PS, ids: [4103] }],
  ps_script: [{ channel: PS, ids: [4104] }],
  ps_classic_start: [{ channel: 'Windows PowerShell', ids: [400] }],
  ps_classic_provider_start: [{ channel: 'Windows PowerShell', ids: [600] }],
  ps_classic_script: [{ channel: 'Windows PowerShell', ids: [800] }],
};

/**
 * Sysmon process-creation field names as Security 4688 spells them, so a
 * process_creation rule works on a machine with auditing but no Sysmon. This
 * is the mapping the pySigma Windows audit pipeline uses.
 */
const PROCESS_CREATION_4688: Record<string, string> = {
  image: 'NewProcessName',
  parentimage: 'ParentProcessName',
  processid: 'NewProcessId',
  parentprocessid: 'ProcessId',
  user: 'SubjectUserName',
  logonid: 'SubjectLogonId',
};

function channelOf(row: Row): string {
  return typeof row.channel === 'string' ? row.channel.toLowerCase() : '';
}

function eventIdOf(row: Row): number | null {
  const v = row.eventId;
  if (typeof v === 'number') return v;
  const fromXml = eventFields(row).get('eventid')?.[0];
  return fromXml !== undefined && /^\d+$/.test(fromXml) ? Number(fromXml) : null;
}

// -------------------------------------------------------------- values ---

/**
 * A Sigma value as a regular expression fragment: * and ? are wildcards, and a
 * backslash escapes *, ? and itself. Anywhere else a backslash is just a
 * backslash, which is why paths need no escaping.
 */
function wildcardSource(pattern: string): string {
  let src = '';
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === '\\' && i + 1 < pattern.length && '*?\\'.includes(pattern[i + 1])) {
      src += pattern[i + 1].replace(/[\\*?]/g, (c) => `\\${c}`);
      i++;
    } else if (ch === '*') {
      src += '.*';
    } else if (ch === '?') {
      src += '.';
    } else {
      src += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return src;
}

function wildcardRegex(pattern: string, cased: boolean): RegExp {
  return new RegExp(`^${wildcardSource(pattern)}$`, cased ? 's' : 'is');
}

function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function encode(value: string, mods: Set<string>): Uint8Array {
  if (mods.has('utf16le') || mods.has('wide') || mods.has('utf16')) {
    const out = new Uint8Array(value.length * 2 + (mods.has('utf16') ? 2 : 0));
    let at = 0;
    if (mods.has('utf16')) {
      out[0] = 0xff; // byte order mark
      out[1] = 0xfe;
      at = 2;
    }
    for (let i = 0; i < value.length; i++) {
      const c = value.charCodeAt(i);
      out[at++] = c & 0xff;
      out[at++] = c >> 8;
    }
    return out;
  }
  if (mods.has('utf16be')) {
    const out = new Uint8Array(value.length * 2);
    for (let i = 0; i < value.length; i++) {
      const c = value.charCodeAt(i);
      out[i * 2] = c >> 8;
      out[i * 2 + 1] = c & 0xff;
    }
    return out;
  }
  return new TextEncoder().encode(value);
}

/**
 * The three base64 fragments a value can appear as inside a longer encoded
 * string, depending on where it falls relative to the 3-byte groups. This is
 * the algorithm the Sigma specification gives for base64offset.
 */
function base64Offsets(value: string, mods: Set<string>): string[] {
  const out: string[] = [];
  const raw = encode(value, mods);
  for (let i = 0; i < 3; i++) {
    // Shift the value by 0, 1 or 2 bytes, then drop the characters that
    // depend on the padding or on whatever follows it.
    const padded = new Uint8Array(i + raw.length).fill(0x20, 0, i);
    padded.set(raw, i);
    const enc = toBase64(padded);
    const start = [0, 2, 3][i];
    const tail = [0, -3, -2][(raw.length + i) % 3];
    out.push(tail === 0 ? enc.slice(start) : enc.slice(start, tail));
  }
  return out;
}

/** Command-line switches written with any of the dashes Windows accepts. */
function windashVariants(value: string): string[] {
  const out = new Set([value]);
  for (const dash of ['/', '–', '—', '―']) {
    out.add(value.replace(/(^|\s)-/g, `$1${dash}`));
  }
  return [...out];
}

function parseIPv4(s: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s.trim());
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function parseIPv6(s: string): bigint | null {
  const text = s.trim().replace(/^\[|\]$/g, '').split('%')[0];
  if (!text.includes(':')) return null;
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = 8 - head.length - tail.length;
  if (fill < 0 || (halves.length === 1 && fill !== 0)) return null;
  const groups = [...head, ...Array(halves.length === 2 ? fill : 0).fill('0'), ...tail];
  let out = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    out = (out << 16n) | BigInt(parseInt(g, 16));
  }
  return out;
}

/** An address test for one CIDR block, v4 or v6. */
function cidrTest(block: string): (value: string) => boolean {
  const [addr, bitsText] = block.split('/');
  const v4 = parseIPv4(addr);
  if (v4 !== null) {
    const bits = bitsText === undefined ? 32 : Number(bitsText);
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (value) => {
      const ip = parseIPv4(value.replace(/^::ffff:/i, ''));
      return ip !== null && (ip & mask) >>> 0 === (v4 & mask) >>> 0;
    };
  }
  const v6 = parseIPv6(addr);
  if (v6 !== null) {
    const bits = BigInt(bitsText === undefined ? 128 : Number(bitsText));
    const mask = bits === 0n ? 0n : ((1n << bits) - 1n) << (128n - bits);
    return (value) => {
      const ip = parseIPv6(value);
      return ip !== null && (ip & mask) === (v6 & mask);
    };
  }
  throw new SigmaError(`"${block}" is not a CIDR block`);
}

const TRANSFORMS = new Set(['base64', 'base64offset', 'utf16le', 'utf16be', 'utf16', 'wide', 'windash']);
const KNOWN = new Set([
  ...TRANSFORMS,
  'contains',
  'startswith',
  'endswith',
  'all',
  're',
  'i',
  'm',
  's',
  'cidr',
  'exists',
  'gt',
  'gte',
  'lt',
  'lte',
  'cased',
  'fieldref',
  'expand',
]);

/** A test over one value of a field, compiled from one pattern. */
type ValueTest = (value: string) => boolean;

function compilePattern(raw: unknown, mods: Set<string>, where: string): ValueTest {
  const cased = mods.has('cased');

  if (mods.has('re')) {
    const flags = new Set(['s']);
    if (mods.has('i')) flags.add('i');
    if (mods.has('m')) flags.add('m');
    // Sigma regular expressions are PCRE-flavoured, and rules often open with
    // an inline flag group such as (?i). JavaScript does not accept that form,
    // so it becomes the equivalent flag instead.
    let source = String(raw);
    const inline = /^\(\?([imsx]+)\)/.exec(source);
    if (inline) {
      for (const f of inline[1]) if (f !== 'x') flags.add(f);
      source = source.slice(inline[0].length);
    }
    try {
      const re = new RegExp(source, [...flags].join(''));
      return (v) => re.test(v);
    } catch (e) {
      throw new SigmaError(`${where}: regular expression does not compile: ${(e as Error).message}`);
    }
  }

  if (mods.has('cidr')) {
    const test = cidrTest(String(raw));
    return (v) => test(v);
  }

  for (const op of ['gt', 'gte', 'lt', 'lte']) {
    if (!mods.has(op)) continue;
    const n = Number(raw);
    if (Number.isNaN(n)) throw new SigmaError(`${where}: |${op} needs a number, not "${raw}"`);
    return (v) => {
      if (!/^-?\d+(\.\d+)?$/.test(v.trim())) return false;
      const x = Number(v);
      return op === 'gt' ? x > n : op === 'gte' ? x >= n : op === 'lt' ? x < n : x <= n;
    };
  }

  // Values in a YAML rule can be numbers or booleans; the field is text.
  let variants = [typeof raw === 'string' ? raw : String(raw)];
  if (mods.has('windash')) variants = variants.flatMap(windashVariants);
  if (mods.has('base64offset')) {
    variants = variants.flatMap((v) => base64Offsets(v, mods));
  } else if (mods.has('base64')) {
    variants = variants.map((v) => toBase64(encode(v, mods)));
  }

  // Base64 output is case-sensitive by nature; a case-insensitive match on it
  // would find encodings of different text.
  const caseSensitive = cased || mods.has('base64') || mods.has('base64offset');
  const encoded = mods.has('base64') || mods.has('base64offset');
  const res = variants.map((v) => {
    // Compile the value on its own and only then add the wildcards the
    // modifier implies. Adding them as text first would let a trailing
    // backslash - '\Temp\' is everywhere in Sigma - escape the added *.
    // Encoded variants are literal text; wildcards in them would be accidents.
    const body = encoded ? v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : wildcardSource(v);
    const src =
      mods.has('contains') || mods.has('base64offset')
        ? `.*${body}.*`
        : mods.has('startswith')
          ? `${body}.*`
          : mods.has('endswith')
            ? `.*${body}`
            : body;
    return new RegExp(`^${src}$`, caseSensitive ? 's' : 'is');
  });
  return (v) => res.some((re) => re.test(v));
}

// ----------------------------------------------------------- selections --

interface Context {
  index: Map<string, string>;
  /** Field renames for rows that carry the event under a different name. */
  alias: (row: Row, field: string) => string;
  notes: Set<string>;
}

function valuesOf(row: Row, field: string, ctx: Context): string[] {
  return fieldValues(row, ctx.alias(row, field), ctx.index).map((v) => fmt(v));
}

function everyValue(row: Row, columns: string[]): string[] {
  const out: string[] = [];
  for (const k of columns) {
    const v = row[k];
    if (v !== null && v !== undefined) out.push(fmt(v));
  }
  for (const list of eventFields(row).values()) out.push(...list);
  return out;
}

function compileFieldSpec(spec: string, raw: unknown, ctx: Context, where: string): Test {
  const [field, ...modList] = spec.split('|');
  const mods = new Set(modList.map((m) => m.toLowerCase()));
  for (const m of mods) {
    if (!KNOWN.has(m)) throw new SigmaError(`${where}: unknown modifier |${m}`);
  }
  if (mods.has('expand')) {
    ctx.notes.add(
      '|expand placeholders such as %Admins% need a site-specific value list; they are matched as literal text',
    );
  }

  if (mods.has('exists')) {
    const want = raw === true || String(raw).toLowerCase() === 'true';
    return (row) => (valuesOf(row, field, ctx).length > 0) === want;
  }

  if (mods.has('fieldref')) {
    const others = (Array.isArray(raw) ? raw : [raw]).map(String);
    const all = mods.has('all');
    return (row) => {
      const mine = valuesOf(row, field, ctx).map((v) => v.toLowerCase());
      const check = (other: string) => {
        const theirs = valuesOf(row, other, ctx).map((v) => v.toLowerCase());
        return mine.some((m) => theirs.includes(m));
      };
      return all ? others.every(check) : others.some(check);
    };
  }

  const list = Array.isArray(raw) ? raw : [raw];

  // null means the field is absent or empty; it cannot take modifiers.
  const tests: ValueTest[] = [];
  let wantsNull = false;
  for (const item of list) {
    if (item === null || item === undefined) {
      wantsNull = true;
      continue;
    }
    if (typeof item === 'object') {
      throw new SigmaError(`${where}: the value of ${field} is a nested structure, not a value`);
    }
    tests.push(compilePattern(item, mods, where));
  }

  const all = mods.has('all');
  return (row) => {
    const values = valuesOf(row, field, ctx);
    const isNull = values.length === 0 || values.every((v) => v === '');
    if (wantsNull && isNull) return true;
    if (tests.length === 0) return false;
    const hit = (t: ValueTest) => values.some((v) => t(v));
    return all ? tests.every(hit) : tests.some(hit);
  };
}

function compileSelection(
  name: string,
  body: unknown,
  ctx: Context,
  columns: string[],
): Test {
  const where = `selection "${name}"`;

  // A list of strings, or one string: keywords, searched for anywhere.
  const keywords = (items: unknown[]): Test => {
    const tests = items.map((k) => {
      const text = String(k);
      // A keyword is found anywhere in a value unless it places its own
      // wildcards.
      const body = wildcardSource(text);
      const re = new RegExp(/[*?]/.test(text) ? `^${body}$` : `^.*${body}.*$`, 'is');
      return (row: Row) => everyValue(row, columns).some((v) => re.test(v));
    });
    return (row) => tests.some((t) => t(row));
  };

  if (typeof body === 'string' || typeof body === 'number') return keywords([body]);

  if (Array.isArray(body)) {
    if (body.every((b) => typeof b !== 'object' || b === null)) return keywords(body);
    // A list of maps: any one of them.
    const tests = body.map((b, i) => compileSelection(`${name}[${i}]`, b, ctx, columns));
    return (row) => tests.some((t) => t(row));
  }

  if (body && typeof body === 'object') {
    const entries = Object.entries(body as Record<string, unknown>);
    if (entries.length === 0) throw new SigmaError(`${where} is empty`);
    // Every field of a map must hold.
    const tests = entries.map(([spec, value]) => compileFieldSpec(spec, value, ctx, where));
    return (row) => tests.every((t) => t(row));
  }

  throw new SigmaError(`${where} is neither a map of fields nor a list of keywords`);
}

// ------------------------------------------------------------ condition --

type CondToken = { t: '(' | ')' | 'and' | 'or' | 'not' } | { t: 'of'; quantifier: 'one' | 'all'; target: string } | { t: 'id'; name: string };

function tokenizeCondition(text: string): CondToken[] {
  const words = text.replace(/\(/g, ' ( ').replace(/\)/g, ' ) ').trim().split(/\s+/);
  const out: CondToken[] = [];
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    const lower = w.toLowerCase();
    if (w === '(' || w === ')') out.push({ t: w });
    else if (lower === 'and' || lower === 'or' || lower === 'not') out.push({ t: lower });
    else if ((lower === '1' || lower === 'all' || lower === 'any') && words[i + 1]?.toLowerCase() === 'of') {
      const target = words[i + 2];
      if (!target) throw new SigmaError(`"${w} of" in the condition names nothing`);
      out.push({ t: 'of', quantifier: lower === 'all' ? 'all' : 'one', target });
      i += 2;
    } else if (w) out.push({ t: 'id', name: w });
  }
  return out;
}

function compileCondition(text: string, selections: Map<string, Test>, notes: Set<string>): Test {
  let condition = text;
  const pipe = condition.indexOf('|');
  if (pipe >= 0) {
    notes.add(
      `the aggregation "${condition.slice(pipe + 1).trim()}" needs events correlated over time and is not applied; the rows shown are those that meet the rest of the condition`,
    );
    condition = condition.slice(0, pipe);
  }

  const tokens = tokenizeCondition(condition);
  let pos = 0;

  const resolve = (pattern: string): Test[] => {
    if (pattern === 'them') return [...selections.values()];
    const re = wildcardRegex(pattern, true);
    const found = [...selections.entries()].filter(([n]) => re.test(n)).map(([, t]) => t);
    if (found.length === 0) throw new SigmaError(`the condition refers to "${pattern}", which is not defined`);
    return found;
  };

  const orExpr = (): Test => {
    const items = [andExpr()];
    while (tokens[pos]?.t === 'or') {
      pos++;
      items.push(andExpr());
    }
    return items.length === 1 ? items[0] : (row) => items.some((t) => t(row));
  };
  const andExpr = (): Test => {
    const items = [notExpr()];
    while (tokens[pos]?.t === 'and') {
      pos++;
      items.push(notExpr());
    }
    return items.length === 1 ? items[0] : (row) => items.every((t) => t(row));
  };
  const notExpr = (): Test => {
    if (tokens[pos]?.t === 'not') {
      pos++;
      const inner = notExpr();
      return (row) => !inner(row);
    }
    return atom();
  };
  const atom = (): Test => {
    const t = tokens[pos++];
    if (!t) throw new SigmaError('the condition ends where a selection was expected');
    if (t.t === '(') {
      const inner = orExpr();
      if (tokens[pos++]?.t !== ')') throw new SigmaError('a "(" in the condition is never closed');
      return inner;
    }
    if (t.t === 'of') {
      const tests = resolve(t.target);
      return t.quantifier === 'all' ? (row) => tests.every((x) => x(row)) : (row) => tests.some((x) => x(row));
    }
    if (t.t === 'id') {
      const test = selections.get(t.name);
      if (!test) throw new SigmaError(`the condition refers to "${t.name}", which is not defined`);
      return test;
    }
    throw new SigmaError(`"${t.t}" in the condition is missing something to apply to`);
  };

  const test = orExpr();
  if (pos < tokens.length) throw new SigmaError('the condition could not be read to its end');
  return test;
}

// ---------------------------------------------------------------- rule ---

/**
 * Parses and compiles a Sigma rule against the columns of an artifact.
 *
 * Throws SigmaError, with a message an analyst can act on, when the rule is
 * not valid Sigma or uses something this engine cannot evaluate at all.
 */
export async function compileSigma(text: string, columns: Column[]): Promise<SigmaRule> {
  const { parseAllDocuments } = await import('yaml');

  const docs = parseAllDocuments(text);
  if (docs.length === 0) throw new SigmaError('the rule is empty');
  for (const d of docs) {
    if (d.errors.length) throw new SigmaError(`not valid YAML: ${d.errors[0].message.split('\n')[0]}`);
  }
  const notes = new Set<string>();
  if (docs.length > 1) {
    notes.add(`the text holds ${docs.length} YAML documents; only the first rule is used`);
  }

  const rule = docs[0].toJS() as Record<string, unknown> | null;
  if (!rule || typeof rule !== 'object') throw new SigmaError('the rule is not a YAML map');
  const detection = rule.detection as Record<string, unknown> | undefined;
  if (!detection || typeof detection !== 'object') {
    throw new SigmaError('the rule has no detection section');
  }
  const conditionRaw = detection.condition;
  if (conditionRaw === undefined) throw new SigmaError('the detection section has no condition');

  const logsource = Object.fromEntries(
    Object.entries((rule.logsource ?? {}) as Record<string, unknown>).map(([k, v]) => [
      k.toLowerCase(),
      String(v).toLowerCase(),
    ]),
  );

  const category = logsource.category;
  const ctx: Context = {
    index: columnIndex(columns),
    notes,
    alias: (row, field) =>
      category === 'process_creation' && eventIdOf(row) === 4688
        ? (PROCESS_CREATION_4688[norm(field)] ?? field)
        : field,
  };

  if (detection.timeframe !== undefined) {
    notes.add(`the timeframe "${detection.timeframe}" belongs to a correlation and is not applied`);
  }

  const keys = columns.map((c) => c.key);
  const selections = new Map<string, Test>();
  for (const [name, body] of Object.entries(detection)) {
    if (name === 'condition' || name === 'timeframe') continue;
    selections.set(name, compileSelection(name, body, ctx, keys));
  }
  if (selections.size === 0) throw new SigmaError('the detection section defines no selections');

  const conditions = Array.isArray(conditionRaw) ? conditionRaw.map(String) : [String(conditionRaw)];
  const tests = conditions.map((c) => compileCondition(c, selections, notes));
  const matchesCondition: Test = (row) => tests.some((t) => t(row));

  // The logsource says which events the rule is written for. Without it a
  // Security rule about EventID 4624 would also fire on any other log that
  // happened to have a 4624.
  const scopes: Test[] = [];
  const product = logsource.product;
  if (product && product !== 'windows') {
    notes.add(
      `the rule is for ${product}; every artifact this tool reads is from Windows, so it cannot match`,
    );
    scopes.push(() => false);
  }
  if (category) {
    const targets = CATEGORIES[category];
    if (targets) {
      scopes.push((row) => {
        const channel = channelOf(row);
        const id = eventIdOf(row);
        return targets.some((t) => t.channel.toLowerCase() === channel && id !== null && t.ids.includes(id));
      });
    } else {
      notes.add(`the category "${category}" has no mapping here, so the rule is run against every row`);
    }
  }
  const service = logsource.service;
  if (service) {
    const channels = SERVICES[service];
    if (channels) {
      const lower = channels.map((c) => c.toLowerCase());
      scopes.push((row) => lower.includes(channelOf(row)));
    } else {
      notes.add(`the service "${service}" has no mapping here, so the rule is run against every row`);
    }
  }

  const str = (v: unknown) => (v === undefined || v === null ? null : String(v));
  return {
    title: str(rule.title) ?? '(untitled rule)',
    id: str(rule.id),
    level: str(rule.level),
    status: str(rule.status),
    description: str(rule.description),
    author: str(rule.author),
    tags: Array.isArray(rule.tags) ? rule.tags.map(String) : [],
    logsource,
    notes: [...notes],
    test: (row) => scopes.every((s) => s(row)) && matchesCondition(row),
  };
}
