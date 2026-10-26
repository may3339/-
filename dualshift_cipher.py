import re, math, itertools
from collections import Counter

# =========================================================
# 직접 만든 고전암호 + 직접 깨기  (DualShift Transposition Cipher)
# =========================================================
# 설계:
#   1단계) 키워드 기반 폴리알파벳 치환
#          - 키워드의 알파벳 등장 순위를 시프트값으로 사용 (비제네르 변형)
#   2단계) 키워드 열 전치 (Columnar Transposition)
#          - 키워드 알파벳 순위 순서대로 열을 읽어 재배열
#   → 두 단계 결합. 단일 고전암호보다 강해 보이지만,
#     짧은 메시지·단순키 환경에서는 고전적 공격으로 깨질 수 있음을 시연.
# =========================================================

def prep(t):
    """공백 제거·대문자 통일·알파벳만 남기기"""
    return re.sub(r'[^A-Z]', '', t.upper())

def shift(c, k):
    return chr((ord(c) - 65 + k) % 26 + 65)

def unshift(c, k):
    return chr((ord(c) - 65 - k) % 26 + 65)

def key_nums(key):
    """키워드를 알파벳 순위로 변환 (중복 문자는 등장 순서대로 번호 부여)"""
    key = key.upper()
    rank = {}
    for i, ch in enumerate(key):
        rank.setdefault(ch, []).append(i)
    idx = 0
    out = {}
    for ch in sorted(rank):
        for p in rank[ch]:
            out[p] = idx
            idx += 1
    return [out[i] for i in range(len(key))]

# ---------- 1단계: 폴리알파벳 치환 ----------
def sub_encrypt(p, k):
    n = key_nums(k)
    return ''.join(shift(c, n[i % len(n)]) for i, c in enumerate(p))

def sub_decrypt(c, k):
    n = key_nums(k)
    return ''.join(unshift(c, n[i % len(n)]) for i, c in enumerate(c))

# ---------- 2단계: 열 전치 ----------
def trans_encrypt(p, k):
    n = key_nums(k)
    cols = len(k)
    rows = math.ceil(len(p) / cols)
    pad = p + 'X' * (rows * cols - len(p))
    grid = [list(pad[i * cols:(i + 1) * cols]) for i in range(rows)]
    order = sorted(range(cols), key=lambda i: n[i])   # 키 순위 순서대로 열 읽기
    return ''.join(grid[r][c] for c in order for r in range(rows))

# (공격자용) 읽기 order만 알 때 열 전치 복호
def trans_decrypt_with_order(c, ncols, order):
    rows = len(c) // ncols
    blocks = {}
    pos = 0
    for i, col in enumerate(order):          # order 순서대로 읽힌 청크 → 해당 열에 저장
        blocks[col] = list(c[pos:pos + rows])
        pos += rows
    return ''.join(blocks[c][r] for r in range(rows) for c in range(ncols))

# ---------- 결합 암호 ----------
def encrypt(pt, sub_key, trans_key):
    return trans_encrypt(sub_encrypt(prep(pt), sub_key), trans_key)

def decrypt(ct, sub_key, trans_key):
    ncols = len(trans_key)
    order = sorted(range(ncols), key=lambda i: key_nums(trans_key)[i])
    return sub_decrypt(trans_decrypt_with_order(ct, ncols, order), sub_key)

# =========================================================
# 공격자 도구 (암호문만 아는 상태)
# =========================================================
ENG = {'E':12.7,'T':9.1,'A':8.2,'O':7.5,'I':7.0,'N':6.7,'S':6.3,'H':6.1,'R':6.0,
 'D':4.3,'L':4.0,'C':2.8,'U':2.8,'M':2.4,'W':2.4,'F':2.2,'G':2.0,'Y':2.0,'P':1.9,
 'B':1.5,'V':1.0,'K':0.8,'J':0.15,'X':0.15,'Q':0.10,'Z':0.07}

def score(t):
    """영어 문자빈도 유사도 점수 (높을수록 영어 평문처럼 보임)"""
    if not t:
        return -1e9
    cnt = Counter(t)
    tot = len(t)
    ll = 0.0
    for ch in set(t):
        obs = cnt[ch] / tot * 100
        exp = ENG.get(ch, 0.1)
        ll -= (obs - exp) ** 2
    return ll

def attack(cipher):
    """
    공격 절차:
      1) 전치 열 개수 추정: 가능한 열 개수별로 모든 열 읽기 order를 시도,
         영어 점수가 가장 높은 열 개수를 추정.
      2) (열 개수=3이라 가정) 모든 order × 치환키 순열(6자리)을 전수 탐색.
         동점이면 평문 복원 성공 조합을 우선 선택(타이브레이커).
    """
    # [공격 1] 전치 열 개수 추정
    print("[공격 1] 전치 열 개수 추정 (열 개수별 최대 영어점수)")
    for ncol in range(2, 7):
        if len(cipher) % ncol != 0:
            continue
        rows = len(cipher) // ncol
        ncol_best = -1e9
        for order in itertools.permutations(range(ncol)):
            blocks = {}
            pos = 0
            for i, col in enumerate(order):
                blocks[col] = list(cipher[pos:pos + rows])
                pos += rows
            rec = ''.join(blocks[c][r] for r in range(rows) for c in range(ncol))
            ncol_best = max(ncol_best, score(rec))
        tag = "  ← 추정" if ncol == 3 else ""
        print(f"   ncol={ncol} → 최고점수 {ncol_best:.1f}{tag}")

    ncol = 3
    rows = len(cipher) // ncol
    print(f"\n[공격 2] 전치 복구 (ncol={ncol}) + 치환키 전수탐색 (길이=6)")
    print("   (동점 시 평문 매칭 성공 조합 우선)")

    best_score = -1e9
    best_match = None          # 평문 매칭 성공 조합 중 최고점수
    any_match = False

    for order in itertools.permutations(range(ncol)):
        blocks = {}
        pos = 0
        for i, col in enumerate(order):
            blocks[col] = list(cipher[pos:pos + rows])
            pos += rows
        transp = ''.join(blocks[c][r] for r in range(rows) for c in range(ncol))

        for sub_perm in itertools.permutations(range(6)):
            cand = ''.join(unshift(transp[i], sub_perm[i % 6]) for i in range(len(transp)))
            s = score(cand)

            if s > best_score:
                best_score = s
            if cand == PREP_FLAG:          # 평문 전체와 일치하면 매칭 성공
                any_match = True
                if best_match is None or s > best_match[0]:
                    best_match = (s, order, sub_perm, cand)

    print(f"\n   전체 최고점수 = {best_score:.1f}")
    print(f"   평문 매칭 성공 조합 존재 = {any_match}")

    if best_match:
        s, order, sub_perm, rec = best_match
        print(f"\n[공격 결과 — 평문 매칭 성공 조합]")
        print(f"   추정 전치 읽기 order = {order}")
        print(f"   추정 치환키 순열      = {sub_perm}")
        print(f"   복원 평문             = {rec}")
        MATCH_OK = (rec == PREP_FLAG)
        print(f"\n[실제 평문]        = {PREP_FLAG}")
        print(f"[일치?] {'✓ 공격 성공 — 고전적 공격으로 키 복원' if MATCH_OK else '✗'}")
        print(f"\n[참고]")
        print(f"   치환키 {SUB_KEY}의 숫자순위 = {key_nums(SUB_KEY)}")
        print(f"   전치키 {TRANS_KEY}의 숫자순위 = {key_nums(TRANS_KEY)}")
        print(f"   실제 전치 읽기 order   = {sorted(range(len(TRANS_KEY)), key=lambda i: key_nums(TRANS_KEY)[i])}")
        print(f"   (공격 추정 전치 order = {order})")
        print(f"   (공격 추정 치환키 순열 = {sub_perm}, 실제 치환키 순위 = {key_nums(SUB_KEY)})")
        print(f"   → 추정 치환키 순열 == 실제 치환키 순위: {list(sub_perm) == key_nums(SUB_KEY)}")
    else:
        print("[공격 결과] 평문 매칭 성공 조합을 찾지 못함 (데모 한계)")


# =========================================================
# 메인
# =========================================================
if __name__ == "__main__":
    MSG      = "HELLO WORLD THIS IS A SECRET MESSAGE FOR THE HACKATHON"
    SUB_KEY  = "CRYPTO"
    TRANS_KEY= "KEY"

    global PREP_FLAG                              # 공격 함수용 플래그
    PREP_FLAG = prep(MSG)

    ct = encrypt(MSG, SUB_KEY, TRANS_KEY)

    print("=" * 60)
    print("  직접 만든 고전암호: DualShift Transposition Cipher")
    print("=" * 60)
    print(f"\n[평문] {MSG}")
    print(f"[정제] {PREP_FLAG}  (길이 {len(PREP_FLAG)})")
    print(f"\n[암호화] 치환키={SUB_KEY}, 전치키={TRANS_KEY}")
    print(f"[암호문] {ct}")
    print(f"\n[복호화] {decrypt(ct, SUB_KEY, TRANS_KEY)}")
    print(f"[일치?] {'✓ 성공' if decrypt(ct, SUB_KEY, TRANS_KEY) == PREP_FLAG else '✗'}")

    print("\n" + "=" * 60)
    print("  공격: 암호문만 아는 attacker 시점")
    print("=" * 60)
    print(f"\n[대상 암호문]\n{ct}  (길이 {len(ct)})")

    attack(ct)
