"""FIFA 19 Live Editor: reads and writes the game's in-memory database and serves the UI on localhost."""
import ctypes as C, ctypes.wintypes as W, struct, json, os, sys, threading, webbrowser, datetime, subprocess, csv, io, unicodedata, time, random, re
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
META = json.load(open(os.path.join(HERE, 'meta.json'), encoding='utf-8'))
CACHE = os.path.join(HERE, 'cache.json')
PORT = 8919
EPOCH = datetime.date(1582, 10, 14).toordinal()  # birthdates are days since this date
GAME_START = 20180901                            # used for ages outside career mode
NATIONAL_LEAGUES = {78, 2136}
POS = ['GK', 'SW', 'RWB', 'RB', 'RCB', 'CB', 'LCB', 'LB', 'LWB', 'RDM', 'CDM', 'LDM', 'RM', 'RCM', 'CM', 'LCM',
       'LM', 'RAM', 'CAM', 'LAM', 'RF', 'CF', 'LF', 'RW', 'RS', 'ST', 'LS', 'LW']

# ---------------------------------------------------------------- process memory
k32 = C.WinDLL('kernel32', use_last_error=True)
class MBI(C.Structure):
    _fields_ = [('BaseAddress', C.c_void_p), ('AllocationBase', C.c_void_p), ('AllocationProtect', W.DWORD),
                ('PartitionId', W.WORD), ('RegionSize', C.c_size_t), ('State', W.DWORD), ('Protect', W.DWORD), ('Type', W.DWORD)]
k32.OpenProcess.restype = W.HANDLE
k32.VirtualQueryEx.argtypes = [W.HANDLE, C.c_void_p, C.POINTER(MBI), C.c_size_t]
k32.ReadProcessMemory.argtypes = [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
k32.WriteProcessMemory.argtypes = [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
k32.GetExitCodeProcess.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]


class Proc:
    def __init__(self, pid):
        self.pid = pid
        self.h = k32.OpenProcess(0x0010 | 0x0020 | 0x0008 | 0x0400, False, pid)  # VM_READ|VM_WRITE|VM_OPERATION|QUERY_INFO
        if not self.h:
            raise RuntimeError('Нет доступа к процессу игры. Запусти редактор от имени администратора.')

    def alive(self):
        code = W.DWORD()
        return bool(k32.GetExitCodeProcess(self.h, C.byref(code))) and code.value == 259

    def read(self, a, n):
        b = C.create_string_buffer(n); got = C.c_size_t()
        k32.ReadProcessMemory(self.h, a, b, n, C.byref(got))
        return b.raw[:got.value]

    def write(self, a, data):
        got = C.c_size_t()
        if not k32.WriteProcessMemory(self.h, a, data, len(data), C.byref(got)):
            raise RuntimeError(f'Запись в память не удалась (код {C.get_last_error()})')

    def find_all(self, pat, align=1):
        """Yield addresses of pat in committed private read-write memory (where the game keeps its DB)."""
        a, m, step = 0, MBI(), 64 << 20
        while k32.VirtualQueryEx(self.h, a, C.byref(m), C.sizeof(m)):
            base = m.BaseAddress or 0
            if m.State == 0x1000 and m.Type == 0x20000 and m.Protect == 0x04:
                for off in range(0, m.RegionSize, step):
                    d = self.read(base + off, min(step + len(pat), m.RegionSize - off))
                    i = d.find(pat)
                    while i != -1:
                        if i < step and (base + off + i) % align == 0:
                            yield base + off + i
                        i = d.find(pat, i + 1)
            a = base + m.RegionSize


def find_pid():
    out = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq FIFA19.exe', '/FO', 'CSV', '/NH'], capture_output=True,
                         creationflags=subprocess.CREATE_NO_WINDOW).stdout  # no console flash under pythonw
    for row in csv.reader(io.StringIO(out.decode('ascii', 'replace'))):
        if row and row[0].lower() == 'fifa19.exe':
            return int(row[1])


# ---------------------------------------------------------------- perfect timed finishing
# The per-frame timed-shot update (FIFA19.exe+0x11f65a.., twin of the function FIFA 23 Live Editor hooks) picks the
# timing quality into xmm0, then stores it to state+0x7c and to shot data [arg2+0x48]+0x60. We replace the pick with
# 1.0f, so every timed shot counts as perfect ("green"). Verified on FIFA19.exe 19.0.3865658; eax is dead at this point.
TF_SITE = 0x151f65c1e
TF_CTX = bytes.fromhex('418b8290000000418982') + b'\x8c\x00\x00\x00'   # mov eax,[r10+0x90]; mov [r10+0x8c],eax
TF_ORIG = bytes.fromhex('84db74050f28c6eb214d8d')                       # test bl,bl; je; movaps xmm0,xmm6; jmp; lea..
TF_NEW = bytes.fromhex('b80000803f660f6ec0eb1f')                        # mov eax,1.0f; movd xmm0,eax; jmp store
k32.VirtualProtectEx.argtypes = [W.HANDLE, C.c_void_p, C.c_size_t, W.DWORD, C.POINTER(W.DWORD)]
k32.FlushInstructionCache.argtypes = [W.HANDLE, C.c_void_p, C.c_size_t]
k32.OpenThread.restype = W.HANDLE
k32.OpenThread.argtypes = [W.DWORD, W.BOOL, W.DWORD]
k32.SuspendThread.argtypes = [W.HANDLE]
k32.ResumeThread.argtypes = [W.HANDLE]
k32.CloseHandle.argtypes = [W.HANDLE]
k32.CreateToolhelp32Snapshot.restype = W.HANDLE
k32.Thread32First.argtypes = [W.HANDLE, C.c_void_p]
k32.Thread32Next.argtypes = [W.HANDLE, C.c_void_p]


def tf_site(p):
    """Address of the patch site, or None if this is not the expected FIFA19.exe build."""
    if p.read(TF_SITE - len(TF_CTX), len(TF_CTX)) == TF_CTX and p.read(TF_SITE, len(TF_ORIG)) in (TF_ORIG, TF_NEW):
        return TF_SITE


def tf_state(p):
    site = tf_site(p)
    if site is None:
        return 'unavailable'
    return 'on' if p.read(site, len(TF_NEW)) == TF_NEW else 'off'


def tf_set(p, on):
    site = tf_site(p)
    if site is None:
        raise RuntimeError('Эта версия FIFA19.exe не поддерживается: патч рассчитан на версию 19.0.3865658')
    patch_code(p, site, TF_NEW if on else TF_ORIG)


# ---------------------------------------------------------------- transfer market without scouting
# Aranaktu's FIFA 19 CM table, "Reveal player data": the Global Transfer Network checks whether a player is scouted
# (test eax,eax; jne reveal). Turning that jne into jmp shows every player's full data without a scout report.
GTN_AOB = re.compile(re.escape(bytes.fromhex('85c0')) + b'[\x75\xeb]' + re.escape(bytes.fromhex('0c4c8d868c020000')))


def find_code(p, pat):
    """Address of the single match of pat in FIFA19.exe's executable image, or None."""
    a, m, hits = 0, MBI(), []
    while k32.VirtualQueryEx(p.h, a, C.byref(m), C.sizeof(m)):
        b = m.BaseAddress or 0
        if m.State == 0x1000 and m.Type == 0x1000000 and m.Protect in (0x10, 0x20, 0x40, 0x80):
            hits += [b + x.start() for x in pat.finditer(p.read(b, m.RegionSize))]
        a = b + m.RegionSize
    return hits[0] if len(hits) == 1 else None


# ---------------------------------------------------------------- exact OVR/POT for scouted youth
# Aranaktu's "Reveal ovr and pot": the loop that stores a prospect's potential variances (6 values, two arrays 0x18
# apart) gets a detour that stores 0 instead, so scout reports show exact OVR and POT instead of ranges.
YA_ORIG = bytes.fromhex('8907ffc34883c704')                        # mov [rdi],eax; inc ebx; add rdi,4
YA_AOB = re.compile(b'\xf0\xff\x05....(?:' + re.escape(YA_ORIG) + b'|\xe9....\x90\x90\x90)\x83\xfb\x06', re.S)
k32.VirtualAllocEx.restype = C.c_void_p
k32.VirtualAllocEx.argtypes = [W.HANDLE, C.c_void_p, C.c_size_t, W.DWORD, W.DWORD]


def alloc_near(p, site, size=0x1000):
    """Executable memory within rel32 reach of site (a jmp can only span ±2 GB)."""
    a, m = max(0x10000, site - 0x7FF00000), MBI()
    while a < site + 0x7FF00000 and k32.VirtualQueryEx(p.h, a, C.byref(m), C.sizeof(m)):
        b = m.BaseAddress or 0
        if m.State == 0x10000 and m.RegionSize >= size + 0x10000:  # MEM_FREE
            got = k32.VirtualAllocEx(p.h, (b + 0xFFFF) & ~0xFFFF, size, 0x3000, 0x40)
            if got and abs(got - site) < 0x7FF00000:
                return got
        a = b + m.RegionSize
    raise RuntimeError('Не нашёл свободную память рядом с кодом игры')


def ya_state(p, site):
    return 'unavailable' if site is None else 'on' if p.read(site, 1) == b'\xe9' else 'off'


def ya_set(p, site, on):
    if not on:
        return patch_code(p, site, YA_ORIG)
    cave = alloc_near(p, site)
    back = site + len(YA_ORIG)
    code = bytes.fromhex('31c0' '8947e8' '8907' 'ffc3' '4883c704')  # xor eax,eax; mov [rdi-18],eax; mov [rdi],eax; ...
    code += b'\xe9' + struct.pack('<i', back - (cave + len(code) + 5))
    p.write(cave, code)
    patch_code(p, site, b'\xe9' + struct.pack('<i', cave - (site + 5)) + b'\x90' * 3)


def gtn_state(p, site):
    return 'unavailable' if site is None else 'on' if p.read(site + 2, 1) == b'\xeb' else 'off'


def patch_code(p, site, data):
    snap = k32.CreateToolhelp32Snapshot(0x4, 0)
    te = (C.c_uint32 * 7)(); te[0] = 28; tids = []
    ok = k32.Thread32First(snap, te)
    while ok:
        if te[3] == p.pid: tids.append(te[2])
        ok = k32.Thread32Next(snap, te)
    k32.CloseHandle(snap)
    # freeze the game so no thread executes these bytes mid-write
    hs = [h for h in (k32.OpenThread(0x0002, False, t) for t in tids) if h]
    for h in hs: k32.SuspendThread(h)
    try:
        old = W.DWORD()
        if not k32.VirtualProtectEx(p.h, site, len(data), 0x40, C.byref(old)):
            raise RuntimeError(f'Не удалось открыть код игры на запись (код {C.get_last_error()})')
        try:
            p.write(site, data)
            k32.FlushInstructionCache(p.h, site, len(data))
        finally:
            k32.VirtualProtectEx(p.h, site, len(data), old.value, C.byref(W.DWORD()))
    finally:
        for h in hs:
            k32.ResumeThread(h); k32.CloseHandle(h)


# ---------------------------------------------------------------- DB tables
# In-memory table object: +0x00 marker shared by all tables, +0x08 owning DB, +0x38 records, +0x40 string pool,
# +0x48 the same header as in .db files (shortname, record size, bit count, ... +60 record count, +66 field count,
# +68 field descriptors: type, bit offset, shortname, bit depth).
HDR = 0x48


class Table:
    def __init__(self, p, obj):
        self.p, self.obj = p, obj
        h = p.read(obj, HDR + 68)
        self.short = h[HDR:HDR + 4].decode()
        self.rsize = struct.unpack_from('<I', h, HDR + 4)[0]
        nf = h[HDR + 66]
        meta = META.get(self.short, {'fields': {}})['fields']
        d = p.read(obj + HDR + 68, 16 * nf)
        self.fields = {}
        for i in range(nf):
            ty, bo, sn, dp = struct.unpack_from('<II4sI', d, 16 * i)
            name, lo, hi = meta.get(sn.decode(), [sn.decode(), 0, 0])
            full = lo + (1 << dp) - 1
            self.fields[name] = (ty, bo, dp, lo, min(hi, full) if hi > lo else full)

    def state(self):
        h = self.p.read(self.obj + 0x38, HDR + 62 - 0x38)
        recs, pool = struct.unpack_from('<QQ', h, 0)
        return recs, pool, struct.unpack_from('<H', h, HDR + 60 - 0x38)[0]

    def rows(self):
        recs, _, n = self.state()
        d = self.p.read(recs, n * self.rsize)
        return [d[i:i + self.rsize] for i in range(0, len(d) - self.rsize + 1, self.rsize)]

    def get(self, rec, name):
        ty, bo, dp, lo, hi = self.fields[name]
        if ty == 0:
            return rec[bo // 8: bo // 8 + dp // 8].split(b'\0')[0].decode('utf-8', 'replace')
        if ty == 4:
            return round(struct.unpack_from('<f', rec, bo // 8)[0], 4)
        v = int.from_bytes(rec[bo // 8: bo // 8 + 8], 'little')
        return ((v >> (bo % 8)) & ((1 << dp) - 1)) + lo

    def row_dict(self, rec):
        return {n: self.get(rec, n) for n, f in self.fields.items() if f[0] in (0, 3, 4)}

    def put(self, idx, name, value):
        ty, bo, dp, lo, hi = self.fields[name]
        recs, _, n = self.state()
        if not 0 <= idx < n:
            raise ValueError('Запись больше не существует, обнови список')
        if ty == 0:
            raw = str(value).encode('utf-8')[:dp // 8 - 1].ljust(dp // 8, b'\0')
            return self.p.write(recs + idx * self.rsize + bo // 8, raw)
        if ty != 3:
            raise ValueError(f'Поле {name} нельзя менять')
        v = int(value)
        if not lo <= v <= hi:
            raise ValueError(f'{name}: допустимо от {lo} до {hi}')
        first, last = bo // 8, (bo + dp - 1) // 8
        a = recs + idx * self.rsize + first
        cur = int.from_bytes(self.p.read(a, last - first + 1), 'little')
        mask = ((1 << dp) - 1) << (bo % 8)
        new = (cur & ~mask) | ((v - lo) << (bo % 8))
        self.p.write(a, new.to_bytes(last - first + 1, 'little'))


def huffman_names(t):
    """playernames keeps names Huffman-coded in its pool; the tree sits at the pool start as 2-byte entries:
    (child_index, 0) for a branch, (0, char) for a leaf. Each string is [char count][bits, MSB first]."""
    rows = t.rows()
    _, pool, _ = t.state()
    bo = t.fields['name'][1] // 8
    offs = [struct.unpack_from('<I', r, bo)[0] for r in rows]
    buf = t.p.read(pool, max([o for o in offs if o < 1 << 24] or [0]) + 256)
    out = {}
    for r, off in zip(rows, offs):
        if off >= len(buf):
            continue
        n, s, node, i, bit = buf[off], bytearray(), 0, off + 1, 0
        while len(s) < n and i < len(buf):
            b = (buf[i] >> (7 - bit)) & 1
            bit += 1
            if bit == 8:
                bit, i = 0, i + 1
            lo, hi = buf[4 * node + 2 * b], buf[4 * node + 2 * b + 1]
            if lo == 0:
                s.append(hi); node = 0
            else:
                node = lo
        out[t.get(r, 'nameid')] = s.decode('utf-8', 'replace')
    return out


def fold(s):
    return ''.join(c for c in unicodedata.normalize('NFKD', s.lower()) if not unicodedata.combining(c))


def ymd_to_date(v):
    try:
        return datetime.date(v // 10000, v // 100 % 100, v % 100)
    except ValueError:
        return datetime.date(2018, 9, 1)


PINS = os.path.join(HERE, 'pins.json')


def load_pins():
    """{(scope, playerid, field): value}"""
    try:
        return {(s, int(p), f): v for s, p, f, v in json.load(open(PINS, encoding='utf-8'))}
    except (OSError, ValueError):
        return {}


def save_pin(scope, pid, field, value):
    pins = load_pins()
    if value is None:
        pins.pop((scope, pid, field), None)
    else:
        pins[(scope, pid, field)] = value
    json.dump([[s, p, f, v] for (s, p, f), v in pins.items()], open(PINS, 'w', encoding='utf-8'), ensure_ascii=False)


def load_cache():
    try:
        return json.load(open(CACHE))
    except (OSError, ValueError):
        return {}


def save_cache(**kw):
    c = load_cache(); c.update(kw)
    json.dump(c, open(CACHE, 'w'))


# ---------------------------------------------------------------- game session
class Game:
    def __init__(self):
        self.lock = threading.Lock()
        self.p, self.t, self.names = None, {}, {}
        self.state, self.msg = 'idle', ''
        self.last_try = 0.0
        self.restored = 0
        self.pro_copy = {}
        self.rlc, self.rlc_try, self.rlc_car = None, 0.0, None
        self.gtn = self.ya = None

    def attach(self):
        self.last_try = time.time()
        with self.lock:
            self.state, self.msg, self.p, self.t = 'scan', 'Ищу базу данных в памяти игры…', None, {}
            self.rlc, self.rlc_try, self.rlc_car = None, 0.0, None
            try:
                pid = find_pid()
                if not pid:
                    self.state, self.msg = 'nogame', 'FIFA 19 не запущена'
                    return
                p = Proc(pid)
                if load_cache().get('timed') and tf_state(p) == 'off':
                    tf_set(p, True)  # the patch lives in game memory, so a restarted game needs it again
                self.gtn = find_code(p, GTN_AOB)
                if load_cache().get('reveal') and gtn_state(p, self.gtn) == 'off':
                    patch_code(p, self.gtn + 2, b'\xeb')
                ya = find_code(p, YA_AOB)
                self.ya = ya + 7 if ya is not None else None
                if load_cache().get('exact') and ya_state(p, self.ya) == 'off':
                    ya_set(p, self.ya, True)
                objs = self._scan(p)
                self.t = {s: Table(p, o) for s, o in objs.items()}
                self.names = huffman_names(self.t['BGwe']) if 'BGwe' in self.t else {}
                self.p, self.state, self.msg = p, 'ready', ''
            except Exception as e:
                self.state, self.msg = 'error', str(e)

    def timed(self, on=None):
        with self.lock:
            self.ok()
            if on is not None:
                tf_set(self.p, on)
                save_cache(timed=bool(on))
            return {'state': tf_state(self.p)}

    def reveal(self, on):
        with self.lock:
            self.ok()
            if self.gtn is None:
                raise RuntimeError('Не нашёл нужное место в коде FIFA19.exe: эта версия игры не поддерживается')
            patch_code(self.p, self.gtn + 2, b'\xeb' if on else b'\x75')
            save_cache(reveal=bool(on))
            return {'state': gtn_state(self.p, self.gtn)}

    def exact(self, on):
        with self.lock:
            self.ok()
            if self.ya is None:
                raise RuntimeError('Не нашёл нужное место в коде FIFA19.exe: эта версия игры не поддерживается')
            if (ya_state(self.p, self.ya) == 'on') != on:
                ya_set(self.p, self.ya, on)
            save_cache(exact=bool(on))
            return {'state': ya_state(self.p, self.ya)}

    def _scan(self, p):
        cache = load_cache()
        objs = self._by_marker(p, bytes.fromhex(cache['marker'])) if 'marker' in cache else {}
        if 'CZUM' not in objs:
            # players table: record size 100 bytes, 799 bits. Its object tells us the marker every table shares.
            hit = next(p.find_all(b'CZUM' + struct.pack('<II', 100, 799)), None)
            if hit is None:
                raise RuntimeError('Игра ещё загружается: база появится в главном меню. Редактор попробует снова через 15 секунд.')
            marker = p.read(hit - HDR, 8)
            objs = self._by_marker(p, marker)
            save_cache(marker=marker.hex())
        return objs

    def _by_marker(self, p, marker):
        found = []
        for a in p.find_all(marker, 8):
            h = p.read(a, HDR + 68)
            if len(h) == HDR + 68 and h[HDR:HDR + 4].decode('latin1') in META and h[HDR + 66]:
                found.append((h[HDR:HDR + 4].decode(), a, h[8:16]))
        owner = next((o for s, a, o in found if s == 'CZUM'), None)
        return {s: a for s, a, o in found if o == owner}

    def ok(self):
        if self.state == 'ready' and not self.p.alive():
            self.state, self.msg = 'nogame', 'Игра закрыта'
        if self.state != 'ready':
            raise RuntimeError(self.msg or 'Редактор не подключён к игре')

    # ---- queries
    def career(self):
        users, cal = self.t.get('mPrV'), self.t.get('GJUr')
        u = users.rows()[:1] if users else []
        if not u:
            return None
        c = cal.rows()[:1] if cal else []
        club = users.get(u[0], 'clubteamid')
        date = cal.get(c[0], 'currdate') if c else None
        d = ymd_to_date(date or GAME_START)
        return {'clubid': club, 'club': self.team_names().get(club, str(club)),
                'manager': f"{users.get(u[0], 'firstname')} {users.get(u[0], 'surname')}".strip(),
                'date': d.strftime('%d.%m.%Y'), 'season_end': d.year + (d.month >= 7)}

    def team_names(self):
        T = self.t['lyxL']
        return {T.get(r, 'teamid'): T.get(r, 'teamname') for r in T.rows()}

    def watch(self):
        """Attach whenever the game runs (also when no browser is open); quit a minute after the game closes."""
        seen = None
        while True:
            if find_pid():
                seen = time.time()
                if self.state not in ('ready', 'scan') and time.time() - self.last_try > 15:
                    self.attach()
                elif self.state == 'ready':
                    try:
                        car = self.career()
                        key = car and (car['manager'], car['clubid'])
                        if key != self.rlc_car:  # another career: the old vector may be freed memory now
                            self.rlc, self.rlc_car, self.rlc_try = None, key, time.time() - 50
                        if car and self._rlc() is None and time.time() - self.rlc_try > 60:
                            self.rlc_try = time.time()
                            self.rlc = self._rlc_find()
                        if car:
                            self.youth_apply()
                    except Exception:
                        pass  # career still loading; next try in a minute
            else:
                if self.state in ('ready', 'idle'):
                    self.state, self.msg = 'nogame', 'FIFA 19 не запущена'
                if seen and time.time() - seen > 60:
                    os._exit(0)
            time.sleep(5)

    # ---- youth scouting: every prospect a scout reports is an ordinary players row linked to one hidden team
    # ("World League"); the game shows the scout's ranges around these real values. Rules lift new prospects.
    YOUTH_POOL = 112264
    KEEPER = ['gkdiving', 'gkhandling', 'gkkicking', 'gkpositioning', 'gkreflexes', 'reactions']

    def youth_pool(self):
        R = self.t['RrqT']
        return {R.get(r, 'playerid') for r in R.rows() if R.get(r, 'teamid') == self.YOUTH_POOL}

    def youth_apply(self):
        """Bring every prospect in the scout pool up to the saved rules. Idempotent: a prospect that already
        fits is left alone, so it is safe to run every few seconds."""
        rules = load_cache().get('youth') or {}
        if not rules.get('on'):
            return
        ovrmin, potmin, hmin, hmax = (rules.get(k) for k in ('ovrmin', 'potmin', 'hmin', 'hmax'))
        with self.lock:
            pool = self.youth_pool()
            if not pool:
                return
            P = self.t['CZUM']
            for i, r in enumerate(P.rows()):
                if P.get(r, 'playerid') not in pool:
                    continue
                ovr, pot, h = P.get(r, 'overallrating'), P.get(r, 'potential'), P.get(r, 'height')
                # ponytail: random spread of +0..3 above the minimum so prospects are not clones
                if ovrmin and ovr < ovrmin:
                    new = random.randint(ovrmin, min(99, ovrmin + 3))
                    # OVR is a weighted mean of the position's attributes: lifting them all by d lifts it by ~d
                    outfield = [f for f in self.PRO_ORDER if not f.startswith('gk') and f != 'potential']
                    for f in self.KEEPER if P.get(r, 'preferredposition1') == 0 else outfield:
                        P.put(i, f, max(1, min(99, P.get(r, f) + new - ovr)))
                    P.put(i, 'overallrating', new)
                    ovr = new
                if potmin and pot < potmin:
                    pot = random.randint(potmin, min(99, potmin + 3))
                    P.put(i, 'potential', pot)
                if pot < ovr:
                    P.put(i, 'potential', ovr)
                if (hmin and h < hmin) or (hmax and h > hmax):
                    lo, hi = hmin or hmax - 5, hmax or hmin + 5  # one bound given: land within 5 cm of it
                    if lo <= hi:
                        P.put(i, 'height', random.randint(lo, hi))

    def youth(self, rules=None):
        if rules is not None:
            clean = {k: int(rules[k]) if str(rules.get(k, '')).isdigit() else None for k in ('ovrmin', 'potmin', 'hmin', 'hmax')}
            save_cache(youth={**clean, 'on': bool(rules.get('on'))})
        with self.lock:
            self.ok()
            S = self.t.get('zlrC')
            scouts = [{'i': j, 'fields': S.row_dict(r)} for j, r in enumerate(S.rows())] if S else []
            M = self.t.get('apoo')
            missions = {M.get(r, 'scoutid'): M.get(r, 'returningdate') for r in M.rows()} if M else {}
            for s in scouts:
                s['returning'] = missions.get(s['fields']['scoutid'])
        return {'rules': load_cache().get('youth') or {}, 'scouts': scouts}

    # ---- release clauses are not in the DB: the career keeps an EASTL vector of {playerid, teamid, fee} (12 bytes each),
    # the same struct FIFA 20 Live Editor edits. Many vectors share the allocator pointer in front of begin/end/capacity,
    # so we pick the one where every entry is a real player, a real team and a plausible fee (only one matches).
    RLC_ALLOC = 0x146649690

    def _rlc(self, h=None):
        """(begin, end, capacity) of the release clause vector, or None if it is gone."""
        h = h or self.rlc
        if not h or not self.p:
            return None
        a, s, e, c = struct.unpack('<4Q', self.p.read(h, 32).ljust(32, b'\0'))
        if a != self.RLC_ALLOC or not s or not s <= e <= c or (e - s) % 12 or c - s > 1 << 24:
            return None
        if e > s:  # first entry must still look like {playerid, teamid, fee}
            p, t, f = struct.unpack('<III', self.p.read(s, 12).ljust(12, b'\0'))
            if not (0 < p <= 500000 and 0 < t <= 200000 and f >= 1000):
                return None
        return s, e, c

    def _rlc_find(self):
        teams, P = set(self.team_names()), self.t['CZUM']
        pids = {P.get(r, 'playerid') for r in P.rows()}
        for h in self.p.find_all(struct.pack('<Q', self.RLC_ALLOC), 8):
            v = self._rlc(h)
            if v and (v[1] - v[0]) // 12 >= 20:
                d = self.p.read(v[0], v[1] - v[0])
                if all(p in pids and t in teams and f >= 1000 for p, t, f in struct.iter_unpack('<III', d)):
                    return h

    def _rlc_get(self, pid):
        """(entry address, teamid, fee) or None."""
        s, e, _ = self._rlc()
        d = self.p.read(s, e - s)
        for k, (p, t, f) in enumerate(struct.iter_unpack('<III', d)):
            if p == pid:
                return s + 12 * k, t, f

    def _set_release(self, pid, fee, teamid):
        v = self._rlc()
        if v is None:
            raise RuntimeError('Отступные ещё не найдены в памяти игры, подожди минуту')
        s, e, c = v
        hit = self._rlc_get(pid)
        if fee <= 0:
            if hit:  # remove: shift the tail down, shrink end
                self.p.write(hit[0], self.p.read(hit[0] + 12, e - hit[0] - 12))
                self.p.write(self.rlc + 16, struct.pack('<Q', e - 12))
            return {'value': 0}
        if fee > 2147483646:
            raise ValueError('Отступные: не больше 2 147 483 646')
        if hit:
            self.p.write(hit[0] + 8, struct.pack('<I', fee))
        else:
            if e + 12 > c:
                raise RuntimeError('В списке отступных игры нет места для новой записи')
            if not teamid:
                raise ValueError('Игрок без клуба: отступные не к кому привязать')
            self.p.write(e, struct.pack('<III', pid, teamid, fee))
            self.p.write(self.rlc + 16, struct.pack('<Q', e + 12))
        return {'value': fee}

    def status(self):
        out = {'state': self.state, 'msg': self.msg}
        if self.state == 'ready':
            with self.lock:
                try:
                    self.ok()
                    out.update(pid=self.p.pid, players=self.t['CZUM'].state()[2], career=self.career(), timed=tf_state(self.p), restored=self.restored,
                               rlc=self._rlc() is not None, reveal=gtn_state(self.p, self.gtn), exact=ya_state(self.p, self.ya))
                except Exception as e:
                    out.update(state=self.state, msg=str(e))
        return out

    def _context(self):
        """Lookups shared by list and detail views."""
        teams = self.team_names()
        L = self.t['qdZF']
        league = {L.get(r, 'teamid'): L.get(r, 'leagueid') for r in L.rows()}
        links = {}
        R = self.t['RrqT']
        for i, r in enumerate(R.rows()):
            links.setdefault(R.get(r, 'playerid'), []).append((i, R.get(r, 'teamid')))
        edited = {}
        if 'nQVU' in self.t:
            E = self.t['nQVU']
            edited = {E.get(r, 'playerid'): E.row_dict(r) for r in E.rows()}
        car = self.career()
        today = datetime.datetime.strptime(car['date'], '%d.%m.%Y').date() if car else ymd_to_date(GAME_START)
        return teams, league, links, edited, car, today

    def player_name(self, P, r, edited):
        e = edited.get(P.get(r, 'playerid'))
        if e:
            return e.get('commonname') or f"{e.get('firstname', '')} {e.get('surname', '')}".strip()
        n = self.names
        common = n.get(P.get(r, 'commonnameid'), '')
        return common or f"{n.get(P.get(r, 'firstnameid'), '')} {n.get(P.get(r, 'lastnameid'), '')}".strip()

    @staticmethod
    def age(P, r, today):
        b = datetime.date.fromordinal(EPOCH + P.get(r, 'birthdate'))
        return today.year - b.year - ((today.month, today.day) < (b.month, b.day))

    POS_GROUPS = {'GK': range(0, 1), 'DEF': range(1, 9), 'MID': range(9, 20), 'ATT': range(20, 28)}

    def players(self, q='', team=None, agemax=None, potmin=None, pos=None, contract=None, sort='ovr', desc=True, limit=500):
        with self.lock:
            self.ok()
            P = self.t['CZUM']
            teams, league, links, edited, car, today = self._context()
            fq = fold(q.strip())
            group = self.POS_GROUPS.get(pos)
            out = []
            for i, r in enumerate(P.rows()):
                pid = P.get(r, 'playerid')
                if not pid:
                    continue
                tl = [t for _, t in links.get(pid, [])]
                if team is not None and team not in tl:
                    continue
                p1 = P.get(r, 'preferredposition1')
                if group is not None and p1 not in group:
                    continue
                age, pot, con = self.age(P, r, today), P.get(r, 'potential'), P.get(r, 'contractvaliduntil')
                if (agemax is not None and age > agemax) or (potmin is not None and pot < potmin) or (contract is not None and con > contract):
                    continue
                name = self.player_name(P, r, edited)
                if fq and fq not in fold(name) and fq != str(pid):
                    continue
                club = next((t for t in tl if league.get(t) not in NATIONAL_LEAGUES), None)
                out.append({'i': i, 'id': pid, 'name': name, 'club': teams.get(club, '—'), 'clubid': club,
                            'pos': POS[p1] if p1 < 28 else '?', 'posn': p1, 'age': age,
                            'ovr': P.get(r, 'overallrating'), 'pot': pot, 'contract': con})
            key = {'name': lambda x: fold(x['name']), 'club': lambda x: fold(x['club']), 'pos': lambda x: x['posn']}.get(sort, lambda x: x.get(sort, 0))
            out.sort(key=key, reverse=desc)
            return {'total': len(out), 'players': out[:limit]}

    def player(self, i, pid):
        with self.lock:
            self.ok()
            P = self.t['CZUM']
            rows = P.rows()
            i = self._locate(P, rows, i, 'playerid', pid)
            r = rows[i]
            teams, league, links, edited, car, today = self._context()
            R = self.t['RrqT']
            rrows = R.rows()
            out = {'i': i, 'name': self.player_name(P, r, edited), 'age': self.age(P, r, today),
                   'fields': P.row_dict(r), 'range': {n: f[3:] for n, f in P.fields.items()},
                   'links': [{'i': li, 'team': teams.get(t, str(t)), 'national': league.get(t) in NATIONAL_LEAGUES,
                              'fields': R.row_dict(rrows[li])} for li, t in links.get(pid, [])],
                   'linkrange': {n: f[3:] for n, f in R.fields.items()}}
            if car and 'DvsP' in self.t:
                D = self.t['DvsP']
                out['contracts'] = [{'i': ci, 'fields': D.row_dict(c)} for ci, c in enumerate(D.rows()) if D.get(c, 'playerid') == pid]
                out['contractrange'] = {n: f[3:] for n, f in D.fields.items()}
                if self._rlc():
                    hit = self._rlc_get(pid)
                    out['release'] = hit[2] if hit else 0
            scope = self._pin_scope()
            out['pins'] = {f: v for (s, p, f), v in load_pins().items() if s == scope and p == pid}
            row = self._row('bxis', 'playerid', pid)
            if row:
                out['playercareer'] = row
                out['careeruser'] = self._row('mPrV', 'userid', 0)  # the wage the game shows for your pro
            return out

    @staticmethod
    def _locate(T, rows, i, key, val):
        """Records can shift when the game reloads a DB; find the row by key if the index went stale."""
        if 0 <= i < len(rows) and T.get(rows[i], key) == val:
            return i
        for j, r in enumerate(rows):
            if T.get(r, key) == val:
                return j
        raise ValueError('Игрок не найден в текущей базе, обнови список')

    def nations(self):
        with self.lock:
            self.ok()
            N = self.t['Crbb']
            return {N.get(r, 'nationid'): N.get(r, 'nationname') for r in N.rows()}

    def teams(self):
        with self.lock:
            self.ok()
            teams = self.team_names()
            L = self.t['qdZF']
            league = {L.get(r, 'teamid'): L.get(r, 'leagueid') for r in L.rows()}
            G = self.t['onMQ']
            lnames = {G.get(r, 'leagueid'): G.get(r, 'leaguename') for r in G.rows()}
            T = self.t['lyxL']
            ovr = {T.get(r, 'teamid'): T.get(r, 'overallrating') for r in T.rows()} if 'overallrating' in T.fields else {}
            out = [{'id': t, 'name': n, 'league': lnames.get(league.get(t), ''), 'leagueid': league.get(t), 'ovr': ovr.get(t)}
                   for t, n in teams.items()]
            return sorted(out, key=lambda x: x['name'].lower())

    def team(self, tid):
        with self.lock:
            self.ok()
            T = self.t['lyxL']
            rows = T.rows()
            i = self._locate(T, rows, -1, 'teamid', tid)
            L = self.t['qdZF']
            lid = next((L.get(r, 'leagueid') for r in L.rows() if L.get(r, 'teamid') == tid), None)
            G = self.t['onMQ']
            lname = next((G.get(r, 'leaguename') for r in G.rows() if G.get(r, 'leagueid') == lid), '')
            out = {'i': i, 'fields': T.row_dict(rows[i]), 'range': {n: f[3:] for n, f in T.fields.items()}, 'league': lname}
            row = self._row('biWl', 'clubteamid', tid)
            if row:
                out['manager'] = row
            return out

    def _row(self, table, key, val):
        """First row of a small career table where key == val, as {i, fields, range}, or None."""
        T = self.t.get(table)
        if not T:
            return None
        for j, r in enumerate(T.rows()):
            if T.get(r, key) == val:
                return {'i': j, 'fields': T.row_dict(r), 'range': {n: f[3:] for n, f in T.fields.items()}}

    def set(self, table, i, key, field, value):
        if table not in ('CZUM', 'RrqT', 'DvsP', 'lyxL', 'bxis', 'biWl', 'mPrV', 'RLC', 'zlrC'):
            raise ValueError('Эту таблицу менять нельзя')
        with self.lock:
            self.ok()
            if table == 'RLC':
                pid = int(key['playerid'])
                _, league, links, *_ = self._context()
                club = next((t for _, t in links.get(pid, []) if league.get(t) not in NATIONAL_LEAGUES), None)
                return {'i': 0, **self._set_release(pid, int(value), club)}
            T = self.t[table]
            rows = T.rows()
            (kname, kval), = key.items()
            i = self._locate(T, rows, i, kname, kval)
            before = rows[i]
            T.put(i, field, value)
            new = T.get(T.rows()[i], field)
            if table == 'CZUM':
                synced = self._sync_pro_copy(kval, before, field, new)
                # copy written: the game keeps the value by itself, an old pin would only fight it.
                # otherwise (not the pro, or copy not found) pin it as before.
                save_pin(self._pin_scope(), kval, field, None if synced else new)
                return {'i': i, 'value': new, 'permanent': synced is True}
            return {'i': i, 'value': new}

    # ---- player career: the career keeps its own copy of your pro (34 attributes in FIFA's internal order, then
    # potential) and rebuilds his players record from it after every match; it refreshes that copy from the DB when
    # it saves. Writing the copy together with the DB makes an edit stick without the editor.
    PRO_ORDER = ['acceleration', 'sprintspeed', 'agility', 'balance', 'jumping', 'stamina', 'strength', 'reactions', 'aggression',
                 'composure', 'interceptions', 'positioning', 'vision', 'ballcontrol', 'crossing', 'dribbling', 'finishing',
                 'freekickaccuracy', 'headingaccuracy', 'longpassing', 'shortpassing', 'marking', 'shotpower', 'longshots',
                 'standingtackle', 'slidingtackle', 'volleys', 'curve', 'penalties', 'gkdiving', 'gkhandling', 'gkkicking',
                 'gkreflexes', 'gkpositioning', 'potential']

    def _pro_id(self):
        B = self.t.get('bxis')
        r = B.rows()[:1] if B else []
        return B.get(r[0], 'playerid') if r else None

    def _sync_pro_copy(self, pid, before_rec, field, new):
        """True: copy updated. False: pro, but copy not found. None: not the pro or not a copied field."""
        if field not in self.PRO_ORDER or pid != self._pro_id():
            return None
        P = self.t['CZUM']
        expect = bytes(P.get(before_rec, f) for f in self.PRO_ORDER)
        key = (self.p.pid, pid)
        addr = self.pro_copy.get(key)
        if addr is None or self.p.read(addr, len(expect)) != expect:
            addr = None
            for a in self.p.find_all(expect[:29]):
                # skip the copy inside a serialized save buffer (starts with FBCHUNKS 1584 bytes earlier)
                if self.p.read(a, len(expect)) == expect and self.p.read(a - 1584, 8) != b'FBCHUNKS':
                    addr = a
                    break
            if addr is None:
                return False
            self.pro_copy[key] = addr
        self.p.write(addr + self.PRO_ORDER.index(field), bytes([max(0, min(255, new))]))
        return True

    # ---- pins: the career rewrites some players after every match (e.g. your own pro in player career) from
    # its own copy, undoing edits. Pinned values are written back whenever they drift, while the editor runs.
    def _pin_scope(self):
        car = self.career()
        return f"career:{car['manager']}" if car else 'squads'

    def unpin(self, pid, field):
        with self.lock:
            self.ok()
            save_pin(self._pin_scope(), pid, field, None)
            return {'ok': True}

    def pin_loop(self):
        while True:
            time.sleep(2)
            try:
                if self.state != 'ready':
                    continue
                with self.lock:
                    if not self.p.alive():
                        continue
                    scope = self._pin_scope()
                    mine = {(p, f): v for (s, p, f), v in load_pins().items() if s == scope}
                    if not mine:
                        continue
                    P = self.t['CZUM']
                    rows = P.rows()
                    index = {P.get(r, 'playerid'): i for i, r in enumerate(rows)}
                    for (pid, field), v in mine.items():
                        i = index.get(pid)
                        if i is not None and field in P.fields and P.get(rows[i], field) != v:
                            P.put(i, field, v)
                            self.restored += 1
            except Exception:
                pass  # the game may be mid-reload; try again on the next tick


GAME = Game()


# ---------------------------------------------------------------- HTTP
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype='application/json; charset=utf-8'):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def route(self, method):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if method == 'GET' and u.path == '/':
            return self.send(200, open(os.path.join(HERE, 'index.html'), 'rb').read(), 'text/html; charset=utf-8')
        if method == 'GET' and u.path.startswith('/fonts/'):
            name = os.path.basename(u.path)
            path = os.path.join(HERE, 'fonts', name)
            if name.endswith('.otf') and os.path.isfile(path):
                return self.send(200, open(path, 'rb').read(), 'font/otf')
        if method == 'GET' and u.path == '/api/status':
            return self.send(200, GAME.status())
        if method == 'POST' and u.path == '/api/attach':
            threading.Thread(target=GAME.attach, daemon=True).start()
            return self.send(200, {'ok': True})
        try:
            if method == 'GET' and u.path == '/api/players':
                num = lambda k: int(q[k]) if q.get(k, '').lstrip('-').isdigit() else None
                return self.send(200, GAME.players(q.get('q', ''), num('team'), num('agemax'), num('potmin'), q.get('pos') or None,
                                                   num('contract'), q.get('sort', 'ovr'), q.get('desc', '1') == '1'))
            if method == 'GET' and u.path == '/api/player':
                return self.send(200, GAME.player(int(q['i']), int(q['id'])))
            if method == 'GET' and u.path == '/api/teams':
                return self.send(200, GAME.teams())
            if method == 'GET' and u.path == '/api/team':
                return self.send(200, GAME.team(int(q['id'])))
            if method == 'GET' and u.path == '/api/nations':
                return self.send(200, GAME.nations())
            if method == 'GET' and u.path == '/api/youth':
                return self.send(200, GAME.youth())
            if method == 'POST' and u.path == '/api/youth':
                return self.send(200, GAME.youth(json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))))
            if method == 'POST' and u.path == '/api/unpin':
                b = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
                return self.send(200, GAME.unpin(int(b['playerid']), str(b['field'])))
            if method == 'POST' and u.path == '/api/exact':
                b = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
                return self.send(200, GAME.exact(bool(b['on'])))
            if method == 'POST' and u.path == '/api/reveal':
                b = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
                return self.send(200, GAME.reveal(bool(b['on'])))
            if method == 'POST' and u.path == '/api/timed':
                b = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
                return self.send(200, GAME.timed(bool(b['on'])))
            if method == 'POST' and u.path == '/api/set':
                b = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
                return self.send(200, GAME.set(b['table'], int(b['i']), b['key'], b['field'], b['value']))
        except (ValueError, RuntimeError, KeyError) as e:
            return self.send(400, {'error': str(e)})
        self.send(404, {'error': 'not found'})

    def do_GET(self):
        self.route('GET')

    def do_POST(self):
        # localhost only, but still refuse cross-site form posts from a browser page
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            return self.send(415, {'error': 'json only'})
        self.route('POST')


if __name__ == '__main__':
    # from Steam: pythonw le.py --game "D:\...\FIFA19.exe" starts the game and the editor together, without a window
    game = sys.argv[sys.argv.index('--game') + 1] if '--game' in sys.argv else None
    if game:
        subprocess.Popen([game], cwd=os.path.dirname(game))
    try:
        srv = ThreadingHTTPServer(('127.0.0.1', PORT), H)
    except OSError:
        if not game:
            webbrowser.open(f'http://127.0.0.1:{PORT}/')  # already running
        sys.exit()
    threading.Thread(target=GAME.pin_loop, daemon=True).start()
    threading.Thread(target=GAME.watch, daemon=True).start()
    print(f'FIFA 19 Live Editor: http://127.0.0.1:{PORT}/')
    if not game and '--no-browser' not in sys.argv:
        webbrowser.open(f'http://127.0.0.1:{PORT}/')
    srv.serve_forever()
