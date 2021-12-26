import bisect
import json
import pathlib
import re
from enum import Enum
from tempfile import TemporaryDirectory

import adb

SCRIPT_DIR = pathlib.Path(__file__).parent
MS_IN_S = 10 ** 6
MS_IN_H = MS_IN_S * 60 * 60
MODEL_FILE = SCRIPT_DIR / 'models.json'


class Comp:
    def __init__(self, name: str):
        self.name = name
        self.model = {}
        self.patterns = ()
        self.event_parsers = ()
        self.ts = []
        self.events = ()
        self.partial_event = True

    @staticmethod
    def ftrace_pattern(event: str, detail: str):
        return re.compile(fr'(\d+)\.(\d+): {event}: {detail}')

    @staticmethod
    def default_parser(match):
        return match.group(3)

    def try_event(self, e: str):
        for i, p in enumerate(self.patterns):
            match = p.search(e)
            if match:
                t = int(match.group(1)) * MS_IN_S + int(match.group(2))
                self.ts.append(t)
                es = self.events[i]
                es.append(self.event_parsers[i](match))
                for ev in self.events:
                    if ev is not es:
                        ev.append(None)

    def done_parsing_ftrace(self):
        for es in self.events:
            last = None
            for i, e in enumerate(es):
                if e is None:
                    es[i] = last
                else:
                    last = e

    def power(self, idx: int) -> float:
        raise NotImplementedError

    def energy(self, begin: int, end: int) -> float:
        bi = bisect.bisect_right(self.ts, begin)
        ei = bisect.bisect_left(self.ts, end)
        ts_clip = self.ts[bi:ei]

        if self.partial_event:
            bi -= 1
            ei += 1
            ts_clip.insert(0, begin)
            ts_clip.append(end)

        e = 0
        for i in range(bi, ei - 1):
            ts_idx = i - bi
            e = e + self.power(i) * (ts_clip[ts_idx + 1] - ts_clip[ts_idx])
        return e * 1000 / MS_IN_H


class OneEventComp(Comp):
    def __init__(self, name: str):
        super().__init__(name)
        self.events = ([],)

    def power(self, idx: int) -> float:
        return self.model[self.events[0][idx]]


class TwoEventsComp(Comp):
    def __init__(self, name: str):
        super().__init__(name)
        self.events = ([], [])

    def power(self, idx: int) -> float:
        return self.model[self.events[0][idx]][self.events[1][idx]]


class CpuBase(Comp):
    def __init__(self):
        super().__init__('CpuBase')
        self.model = 0

    def power(self, idx: int) -> float:
        raise NotImplementedError

    def energy(self, begin: int, end: int) -> float:
        return self.model * 1000 * (end - begin) / MS_IN_H


class Cpu(TwoEventsComp):
    def __init__(self, cpu_id: int, little: bool = False):
        super().__init__('Cpu' + ('Little' if little else 'Big'))
        pat = fr'state=(\d+) cpu_id={cpu_id}'
        self.patterns = tuple(Comp.ftrace_pattern(e, pat)
                              for e in ('cpu_idle', 'cpu_frequency'))
        self.event_parsers = (Cpu._idle_parser, Comp.default_parser)

    @staticmethod
    def _idle_parser(match):
        state = match.group(3)
        if len(state) == 1:
            return '0'
        else:
            return '1'


class Gpu(TwoEventsComp):
    def __init__(self):
        super().__init__('Gpu')
        state = Comp.ftrace_pattern('kgsl_pwr_set_state', r'.*state=([A-Z]+)')
        clk = Comp.ftrace_pattern('kgsl_clk', r'.*active_freq=(\d+)')
        self.patterns = (state, clk)
        self.event_parsers = (Comp.default_parser, Comp.default_parser)


class Wifi(TwoEventsComp):
    class State(Enum):
        IDLE = 1
        TAIL = 2
        ACTIVE = 3

    def __init__(self):
        super().__init__('Wifi')
        self.patterns = (Comp.ftrace_pattern('', ''), Comp.ftrace_pattern(
            '(net_dev_xmit|netif_rx)', r'dev=wlan0.*len=(\d+)'))
        self.event_parsers = (None, Wifi._len_parser)
        self.partial_event = False

    @staticmethod
    def _len_parser(match):
        return int(match.group(4))

    def done_parsing_ftrace(self):
        act_intvl = self.model['ActIntvl']
        tail_len = self.model['TailLen']
        states = self.events[0]

        last_act = 0
        i = 0
        while i < len(self.ts) - 1:
            t = self.ts[i]
            nt = self.ts[i + 1]
            if nt - t <= act_intvl:
                states[i] = Wifi.State.ACTIVE
                last_act = nt
            elif nt - last_act <= tail_len:
                states[i] = Wifi.State.TAIL
            elif t - last_act < tail_len:
                states[i] = Wifi.State.TAIL
                i += 1
                self.ts.insert(i, last_act + tail_len)
                states.insert(i, Wifi.State.IDLE)
                self.events[1].insert(i, 0)
            else:
                states[i] = Wifi.State.IDLE
            i += 1

    def power(self, idx: int) -> float:
        s = self.events[0][idx]
        if s == Wifi.State.ACTIVE:
            intvl = self.ts[idx + 1] - self.ts[idx]
            if intvl:
                xput = self.events[1][idx] * 8 / intvl
            else:
                xput = 0
            return self.model['ACTIVE_COEFF'] * xput \
                + self.model['ACTIVE_INTERCEPT']
        else:
            return self.model[s.name]


class FtraceParser:
    def __init__(self):
        self._comp = [CpuBase(), Gpu(), Wifi()]
        with MODEL_FILE.open(encoding='ascii') as f:
            models = json.load(f)
            self._comp.extend(Cpu(i, True) for i in models['CpuLittleId'])
            self._comp.extend(Cpu(i) for i in models['CpuBigId'])
            for c in self._comp:
                c.model = models[c.name]

    def parse_ftrace(self, ftrace_file):
        with open(ftrace_file, encoding='ascii') as f:
            for ln in f:
                for c in self._comp:
                    c.try_event(ln)
        for c in self._comp:
            c.done_parsing_ftrace()

    def energy(self, begin: int, end: int, separate=False):
        energy_per_comp = {}
        for c in self._comp:
            energy_per_comp[c.name] \
                = energy_per_comp.get(c.name, 0) + c.energy(begin, end)
        if separate:
            return energy_per_comp
        else:
            return sum(energy_per_comp.values())


class FtraceEnergy:
    DEV_TMP_DIR = pathlib.PurePosixPath('/data/local/tmp')
    FTRACE_FILE = 'ftrace.sh'
    GETTIME_FILE = 'gettime'
    DEV_FTRACE = DEV_TMP_DIR / FTRACE_FILE
    DEV_GETTIME = DEV_TMP_DIR / GETTIME_FILE
    TRACE_OUTPUT = 'trace_output'

    def __init__(self):
        self._start_time = None

    @staticmethod
    def prepare():
        adb.push(SCRIPT_DIR / FtraceEnergy.FTRACE_FILE, FtraceEnergy.DEV_FTRACE)
        adb.push(SCRIPT_DIR / FtraceEnergy.GETTIME_FILE,
                 FtraceEnergy.DEV_GETTIME)
        FtraceEnergy._toggle_ftrace('on')

    def start(self):
        self._start_time = self._get_dev_time()

    def stop_and_calc(self, separate=False, ftrace_file=None):
        stop_time = self._get_dev_time()
        self._toggle_ftrace('off')
        tmp_dir = None
        try:
            if ftrace_file:
                with open(ftrace_file + '_time', 'w', encoding='ascii') as out:
                    out.write(f'{self._start_time} {stop_time}\n')
            else:
                tmp_dir = TemporaryDirectory()
                ftrace_file = pathlib.Path(
                    tmp_dir.name, FtraceEnergy.TRACE_OUTPUT)

            adb.pull(FtraceEnergy.DEV_TMP_DIR / FtraceEnergy.TRACE_OUTPUT,
                     ftrace_file)
            parser = FtraceParser()
            parser.parse_ftrace(ftrace_file)
            return parser.energy(self._start_time, stop_time, separate)
        finally:
            if tmp_dir:
                tmp_dir.cleanup()

    @staticmethod
    def _toggle_ftrace(toggle: str):
        adb.shell(['sh', str(FtraceEnergy.DEV_FTRACE), toggle], True)

    @staticmethod
    def _get_dev_time() -> int:
        return int(adb.shell([str(FtraceEnergy.DEV_GETTIME)]).stdout)
