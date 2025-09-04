#!/usr/bin/env python3
# zw_universal_decoder.py
# Universal zero-width / invisible-char steganography extractor
# Usage:
#   Verbose mode (default): python3 zw_universal_decoder.py [options] <file>
#   Quiet mode (secret only): python3 zw_universal_decoder.py --secret-only <file>

import sys, os, itertools, unicodedata, argparse, base64, binascii, zlib, gzip, math

def print_banner():
    red = "\033[91m"
    green = "\033[92m"
    blue = "\033[94m"
    reset = "\033[0m"

    banner = r"""
  _____             _   _         _                                _       ____                         _
 |__  /__      __  | | | | _ __  (_)__   __ ___  _ __  ___   __ _ | |     |  _ \   ___   ___  ___    __| |  ___  _ __
   / / \ \ /\ / /  | | | || '_ \ | |\ \ / // _ \| '__|/ __| / _` || |     | | | | / _ \ / __|/ _ \  / _` | / _ \| '__|
  / /_  \ V  V /   | |_| || | | || | \ V /|  __/| |   \__ \| (_| || |     | |_| ||  __/| (__| (_) || (_| ||  __/| |
 /____|  \_/\_/_____\___/ |_| |_||_|  \_/  \___||_|   |___/ \__,_||_|_____|____/  \___| \___|\___/  \__,_| \___||_|

"""
    print(f"{blue}{banner}{reset}")
    print(f"{green}Author: Mustafa-Almohsen{reset}")
    print("=" * 60)



CANDIDATES = [
    "\u200B", # ZERO WIDTH SPACE
    "\u200C", # ZERO WIDTH NON-JOINER
    "\u200D", # ZERO WIDTH JOINER
    "\u2060", # WORD JOINER
    "\uFEFF", # ZERO WIDTH NO-BREAK SPACE (BOM)
    "\u180E", # MONGOLIAN VOWEL SEPARATOR (deprecated)
    "\u200E", # LEFT-TO-RIGHT MARK
    "\u200F", # RIGHT-TO-LEFT MARK
    "\u2062", # INVISIBLE TIMES
    "\u2063", # INVISIBLE SEPARATOR
    "\u202A", # LEFT-TO-RIGHT EMBEDDING
    "\u202B", # RIGHT-TO-LEFT EMBEDDING
    "\u202C", # POP DIRECTIONAL FORMATTING
    "\u202D", # LEFT-TO-RIGHT OVERRIDE
    "\u202E", # RIGHT-TO-LEFT OVERRIDE
    # some visible spaces (may be abused)
    "\u0020", # SPACE (include to detect ascii separators)
    "\u00A0", # NO-BREAK SPACE
    "\u2000", "\u2001", "\u2002", "\u2003", "\u2004", "\u2005", "\u2006", "\u2007", "\u2008", "\u2009", "\u200A",
    "\u202F", "\u205F", "\u3000"
]


DEFAULT_MAX_PERMS = 2000
DEFAULT_MAX_MULTI_CHARS = 6  


def char_name(c):
    try:
        return unicodedata.name(c)
    except:
        return f"U+{ord(c):04X}"

def printable_ratio(s):
    if not s:
        return 0.0
    good = sum(1 for ch in s if ch.isprintable() and ch not in '\r\t')
    return good / len(s)

def english_score(s):

    if not s:
        return 0.0
    s_low = s.lower()
    score = 0.0
    common = [" the ", " and ", " you ", " that ", " secret", "flag", "found", "message", "hello", "game", "password", " is "]
    for w in common:
        if w in s_low:
            score += 2.0
   
    vowels = sum(1 for ch in s_low if ch in 'aeiou')
    score += (vowels / max(1, len(s_low))) * 1.5
 
    score += printable_ratio(s)
    return score

def read_text(fname):
    with open(fname, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def collect_seq(text, include_all_candidates=True):
   
    seq = [c for c in text if (c in CANDIDATES) or unicodedata.category(c) == "Cf"]
   
    return seq

def try_3char_mappings(seq, unique, max_perms=DEFAULT_MAX_PERMS):
    """
    Try permutations of 3-char mapping: (separator, '0', '1').
    separator splits variable-length binary groups (like original encoder).
    """
    pool = unique[:]
    if len(pool) < 3:
        for c in CANDIDATES:
            if c not in pool:
                pool.append(c)
            if len(pool) >= 3:
                break
    perms = list(itertools.permutations(pool, 3))
    if len(perms) > max_perms:
        perms = perms[:max_perms]
    results = []
    tried = 0
    for sep, z0, z1 in perms:
        tried += 1
       
        token = "".join(( ' ' if c==sep else ('0' if c==z0 else ('1' if c==z1 else '')) ) for c in seq)
        if not token:
            continue
        if ' ' not in token:
            continue
        groups = [g for g in token.split(' ') if g != ""]
        try:
            decoded = "".join(chr(int(g, 2)) for g in groups)
            pr = printable_ratio(decoded)
            results.append({
                'mapping': (sep,z0,z1),
                'decoded': decoded,
                'token': token,
                'printable_ratio': pr,
                'tried_index': tried
            })
        except Exception:
            
            continue
    return results, tried

def continuous_twochar(seq, unique):
    """Try continuous bit heuristics: consider pairs as 0/1 and attempt 8/7-bit decoding."""
    results = []
    pairs_tried = 0
    for a,b in itertools.permutations(unique, 2):
        bitstr = "".join('0' if c==a else ('1' if c==b else '') for c in seq)
        if not bitstr:
            continue
        pairs_tried += 1
        
        for offset in range(8):
            bytes_list = []
            for i in range(offset, len(bitstr), 8):
                chunk = bitstr[i:i+8]
                if len(chunk) < 8:
                    break
                bytes_list.append(int(chunk, 2))
            raw = bytes(bytes_list)
            for enc in ('utf-8','latin1'):
                try:
                    dec = raw.decode(enc)
                    results.append(((a,b), f"8-bit offset {offset} ({enc})", dec, raw))
                except Exception:
                    pass
        
        for offset in range(7):
            bytes_list = []
            for i in range(offset, len(bitstr), 7):
                chunk = bitstr[i:i+7]
                if len(chunk) < 7:
                    break
                bytes_list.append(int(chunk, 2))
            raw = bytes(bytes_list)
            for enc in ('utf-8','latin1'):
                try:
                    dec = raw.decode(enc)
                    results.append(((a,b), f"7-bit offset {offset} ({enc})", dec, raw))
                except Exception:
                    pass
    return results

def try_multibit(seq, unique, max_chars=DEFAULT_MAX_MULTI_CHARS):
    """
    Try multi-bit-per-char mapping when there are multiple unique invisible chars.
    Example: 4 chars -> each char maps to 2 bits (00,01,10,11).
    We'll only attempt for len(unique) in {3,4,5,6} up to max_chars to avoid explosion.
    """
    results = []
    m = len(unique)
    if m < 3 or m > max_chars:
        return results
    
    k = math.ceil(math.log2(m))
    symbols = unique[:m]
    # generate mapping from symbol -> k-bit code by assigning combinations (try a few permutations only)
    # To keep bounded, try permutations of symbols only up to some limit
    perms = list(itertools.permutations(symbols))
    max_perm = 500
    if len(perms) > max_perm:
        perms = perms[:max_perm]
    for perm in perms:
        
        mapping = { perm[i]: format(i, 'b').zfill(k) for i in range(len(perm)) }
        # produce full bit stream
        bitstr = "".join(mapping.get(c, '') for c in seq)
        if not bitstr:
            continue
        # try decode as continuous 8-bit
        bytes_list = []
        for i in range(0, len(bitstr), 8):
            chunk = bitstr[i:i+8]
            if len(chunk) < 8:
                break
            try:
                bytes_list.append(int(chunk, 2))
            except:
                bytes_list = []
                break
        if not bytes_list:
            continue
        raw = bytes(bytes_list)
        for enc in ('utf-8','latin1'):
            try:
                dec = raw.decode(enc)
                results.append({
                    'perm': perm,
                    'k': k,
                    'decoded': dec,
                    'raw': raw,
                    'bitstr': bitstr
                })
            except Exception:
                pass
    return results

# Post-decode heuristics: try additional transforms
def post_process_candidate(decoded_or_raw):
    """
    Accepts either str (decoded text) or bytes (raw). Returns list of plausible transforms:
    - if str: try base64 decode, hex decode, zlib/gzip decompress if base64/hex returns bytes
    - if bytes: try interpret as text with utf-8/latin1, try base64->utf-8, try zlib/gzip
    """
    candidates = []
    if isinstance(decoded_or_raw, str):
        s = decoded_or_raw
        candidates.append(('utf-8/text', s))
        # try base64
        try:
            b = base64.b64decode(s, validate=True)
            try:
                candidates.append(('base64->utf8', b.decode('utf-8')))
            except:
                candidates.append(('base64->raw', b))
 
            try:
                candidates.append(('base64->zlib->utf8', zlib.decompress(b).decode('utf-8')))
            except:
                pass
            try:
                candidates.append(('base64->gzip->utf8', gzip.decompress(b).decode('utf-8')))
            except:
                pass
        except Exception:
            pass
        # try hex decode
        try:
            b = binascii.unhexlify(s.strip())
            try:
                candidates.append(('hex->utf8', b.decode('utf-8')))
            except:
                candidates.append(('hex->raw', b))
        except Exception:
            pass

        try:
            b0 = s.encode('latin1')
            try:
                candidates.append(('zlib->utf8', zlib.decompress(b0).decode('utf-8')))
            except:
                pass
            try:
                candidates.append(('gzip->utf8', gzip.decompress(b0).decode('utf-8')))
            except:
                pass
        except:
            pass
    else:
        # bytes
        raw = decoded_or_raw
        for enc in ('utf-8','latin1'):
            try:
                candidates.append((f'raw->{enc}', raw.decode(enc)))
            except:
                pass
    
        try:
            b = base64.b64decode(raw)
            try:
                candidates.append(('raw->base64->utf8', b.decode('utf-8')))
            except:
                candidates.append(('raw->base64->raw', b))
        except:
            pass

        try:
            b = binascii.unhexlify(raw)
            try:
                candidates.append(('raw->hex->utf8', b.decode('utf-8')))
            except:
                candidates.append(('raw->hex->raw', b))
        except:
            pass
        # zlib/gzip
        try:
            candidates.append(('zlib->utf8', zlib.decompress(raw).decode('utf-8')))
        except:
            pass
        try:
            candidates.append(('gzip->utf8', gzip.decompress(raw).decode('utf-8')))
        except:
            pass
    return candidates

def save_outputs(base, mappings_found, continuous_candidates, multibit_results, dump_bins=False):
    cand_file = f"zw_{base}_candidates.txt"
    best_file = f"zw_{base}_best.txt"
    saved = []
    with open(cand_file, "w", encoding="utf-8") as out:
        out.write(f"File: {base}\n\n")
        out.write("=== 3-char mapping candidates ===\n\n")
        for r in mappings_found:
            sep,z0,z1 = r['mapping']
            out.write(f"MAPPING: sep={char_name(sep)} U+{ord(sep):04X}  0={char_name(z0)} U+{ord(z0):04X}  1={char_name(z1)} U+{ord(z1):04X}\n")
            out.write(f"printable_ratio={r['printable_ratio']:.3f}\n")
            out.write("decoded:\n")
            out.write(r['decoded'] + "\n\n")
    saved.append(cand_file)

    with open(best_file, "w", encoding="utf-8") as b:

        best = None
        best_score = -1
        for r in mappings_found:
            sc = english_score(r['decoded'])
            if sc > best_score:
                best = r
                best_score = sc
        if best:
            b.write(best['decoded'])
            saved.append(best_file)
        else:
            b.write("")
            saved.append(best_file)


    cont_file = f"zw_{base}_continuous.txt"
    with open(cont_file, "w", encoding="utf-8") as c:
        for pair, method, dec, raw in continuous_candidates:
            c.write(f"PAIR: 0<-{char_name(pair[0])} 1<-{char_name(pair[1])} METHOD: {method}\n")
            try:
                c.write(dec + "\n\n")
            except:
                c.write(str(dec) + "\n\n")
    saved.append(cont_file)


    mb_file = f"zw_{base}_multibit.txt"
    with open(mb_file, "w", encoding="utf-8") as mb:
        for r in multibit_results:
            mb.write(f"perm: {','.join([char_name(x) for x in r['perm']])} k={r['k']}\n")
            mb.write(r['decoded'] + "\n\n")
    saved.append(mb_file)


    if dump_bins and mappings_found:
        best = sorted(mappings_found, key=lambda x: x['printable_ratio'], reverse=True)[0]
        token = best['token']
        groups = [g for g in token.split(' ') if g != ""]
        try:
            raw = bytes(int(g,2) for g in groups)
            raw_name = f"zw_{base}_raw.bin"
            with open(raw_name, "wb") as wf:
                wf.write(raw)
            saved.append(raw_name)
        except Exception:
            pass

    return saved


def _highlight_secret(mappings_found, continuous_candidates, multibit_results):
    pool = []
    for r in mappings_found:
        pool.append(r['decoded'])
    for _, _, dec, _ in continuous_candidates:
        pool.append(dec)
    for r in multibit_results:
        pool.append(r['decoded'])
    if not pool:
        return None
    return max(pool, key=english_score)

def analyze_file(fname, aggressive=False, dump_bins=False, max_perms=DEFAULT_MAX_PERMS, secret_only=False):
    text = read_text(fname)
    seq = collect_seq(text)
    if not seq:
        if secret_only:
            return None
        print("[!] No zero-width/format characters found in the file.")
        return None

    unique = []
    for c in seq:
        if c not in unique:
            unique.append(c)
    if not secret_only:
        print(f"[+] Found {len(seq)} zero-width/format characters (unique: {len(unique)})")
        for i,c in enumerate(unique,1):
            print(f"    {i}. {repr(c)}  {char_name(c)}  (U+{ord(c):04X})")

 
    limit = max_perms if aggressive else min(max_perms, 1500)
    if not secret_only:
        print("\n[*] Trying 3-char mappings (separator, '0', '1') ...")
    mappings_found, perms_tried = try_3char_mappings(seq, unique, max_perms=limit)
    mappings_found.sort(key=lambda r: (r['printable_ratio'], len(r['decoded'])), reverse=True)

    if not secret_only:
        if mappings_found:
            print(f"[+] Found {len(mappings_found)} candidate decodes (showing best 6):\n")
            for i,r in enumerate(mappings_found[:6],1):
                sep,z0,z1 = r['mapping']
                print(f"Candidate #{i} (tried idx {r['tried_index']})")
                print(f"  separator: {char_name(sep)} (U+{ord(sep):04X})")
                print(f"  '0'      : {char_name(z0)} (U+{ord(z0):04X})")
                print(f"  '1'      : {char_name(z1)} (U+{ord(z1):04X})")
                print(f"  printable ratio: {r['printable_ratio']:.3f}")
                snippet = r['decoded'][:400]
                print("----- BEGIN DECODED -----")
                print(snippet)
                print("------ END DECODED ------\n")
        else:
            print("[!] No candidate decoded using 3-char separator mapping.")


    if not secret_only:
        print("[*] Trying continuous-bit heuristics (two-char mappings -> continuous bitstream)...")
    continuous_candidates = continuous_twochar(seq, unique)
    if not secret_only:
        if continuous_candidates:
            print(f"[+] Continuous candidates found: {len(continuous_candidates)} (showing up to 6):\n")
            for i,(pair, method, dec, raw) in enumerate(continuous_candidates[:6],1):
                a,b = pair
                print(f"Continuous Candidate #{i}")
                print(f"  0 <- {char_name(a)}  (U+{ord(a):04X})")
                print(f"  1 <- {char_name(b)}  (U+{ord(b):04X})")
                print(f"  method: {method}")
                pr = printable_ratio(dec)
                print(f"  printable ratio={pr:.3f}")
                print("----- BEGIN DECODED -----")
                print(dec[:400])
                print("------ END DECODED ------\n")
        else:
            print("[!] No continuous-bit candidates found.")

 
    if not secret_only:
        print("[*] Trying multi-bit-per-char heuristics (if multiple uniques exist)...")
    multibit_results = []
    if 3 <= len(unique) <= DEFAULT_MAX_MULTI_CHARS:
        multibit_results = try_multibit(seq, unique, max_chars=DEFAULT_MAX_MULTI_CHARS)
        if not secret_only:
            if multibit_results:
                print(f"[+] Multi-bit candidates found: {len(multibit_results)} (showing up to 6):\n")
                for i,r in enumerate(multibit_results[:6],1):
                    print(f"Multi-bit Candidate #{i} k={r['k']} perm={','.join(char_name(c) for c in r['perm'])}")
                    print("----- BEGIN DECODED -----")
                    print(r['decoded'][:400])
                    print("------ END DECODED ------\n")
            else:
                print("[!] No multi-bit candidates found or none decoded as text.")
    else:
        if not secret_only:
            print("[*] Skipping multi-bit mapping (unique count out of allowed range).")

  
    if secret_only:
        return _highlight_secret(mappings_found, continuous_candidates, multibit_results)

   
    saved = save_outputs(os.path.basename(fname), mappings_found, continuous_candidates, multibit_results, dump_bins=dump_bins)
    print("\n[+] Saved candidate files:", ", ".join(saved))
    print("[+] Done. Inspect the *_candidates.txt and *_best.txt files and raw bin(s) if present.")
    return None

def main():
    parser = argparse.ArgumentParser(description="Universal zero-width stego extractor")

    print_banner()

    parser.add_argument("file", help="file to analyze")
    parser.add_argument("--aggressive", action="store_true", help="increase brute-force limits (slower)")
    parser.add_argument("--dump-bins", action="store_true", help="dump extracted raw binary for best candidate")
    parser.add_argument("--max-perms", type=int, default=DEFAULT_MAX_PERMS, help="max permutations to try (safety cap)")
   
    parser.add_argument("--secret-only", action="store_true", help="only print the highlighted secret (quiet mode)")
    args = parser.parse_args()

    if args.secret_only:
        secret = analyze_file(args.file, aggressive=args.aggressive, dump_bins=args.dump_bins, max_perms=args.max_perms, secret_only=True)
    
        if secret:
            print(secret, end="")
            sys.exit(0)
        else:
            sys.exit(1)
    else:

        analyze_file(args.file, aggressive=args.aggressive, dump_bins=args.dump_bins, max_perms=args.max_perms, secret_only=False)

if __name__ == "__main__":
    main()
