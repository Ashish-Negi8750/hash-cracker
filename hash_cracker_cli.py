import argparse
import hashlib
import itertools
import multiprocessing
from datetime import datetime

# --- Hashing ---
def hash_word(word, algo):
    word = word.strip()
    if algo == "md5":
        return hashlib.md5(word.encode()).hexdigest()
    elif algo == "sha1":
        return hashlib.sha1(word.encode()).hexdigest()
    elif algo == "sha256":
        return hashlib.sha256(word.encode()).hexdigest()
    return None

# --- Logging ---
def log_result(password, hash_value, algo):
    with open("cracked_log.txt", "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} | {algo.upper()} | {hash_value} → {password}\n")

# --- MutationHashs ---
def mutate(word):
    return [
        word,
        word + "123",
        word + "!",
        word.capitalize(),
        word[::-1],
        word.replace("a", "@").replace("s", "$").replace("o", "0"),
    ]

# --- Mask Parser ---
def parse_mask(mask):
    mask_map = {
        "?l": "abcdefghijklmnopqrstuvwxyz",
        "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "?d": "0123456789",
        "?s": "!@#$%^&*"
    }
    charset_list = []
    i = 0
    while i < len(mask):
        if mask[i:i+2] in mask_map:
            charset_list.append(mask_map[mask[i:i+2]])
            i += 2
        else:
            charset_list.append(mask[i])
            i += 1
    return (''.join(candidate) for candidate in itertools.product(*charset_list))

# --- Brute-force ---
def brute_worker(args):
    word, target_hash, algo = args
    return word if hash_word(word, algo) == target_hash else None

def brute_force_parallel(target_hash, charset, max_len, algo):
    candidates = (''.join(p) for l in range(1, max_len+1) for p in itertools.product(charset, repeat=l))
    with multiprocessing.Pool() as pool:
        for result in pool.imap_unordered(brute_worker, ((word, target_hash, algo) for word in candidates), chunksize=1000):
            if result:
                return result
    return None

# --- Main CLI Logic ---
def main():
    parser = argparse.ArgumentParser(description="CLI Hash Cracker")
    parser.add_argument("--mode", required=True, choices=["dictionary", "rule", "brute", "mask", "combo"])
    parser.add_argument("--hash", required=True)
    parser.add_argument("--algo", required=True, choices=["md5", "sha1", "sha256"])
    parser.add_argument("--wordlist", help="Path to wordlist file")
    parser.add_argument("--wordlist2", help="Second wordlist for combinator mode")
    parser.add_argument("--charset", help="Charset for brute-force", default="abcdefghijklmnopqrstuvwxyz0123456789")
    parser.add_argument("--maxlen", type=int, help="Max length for brute-force", default=4)
    parser.add_argument("--mask", help="Mask pattern for mask attack")

    args = parser.parse_args()
    target_hash = args.hash
    algo = args.algo

    if args.mode == "dictionary":
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            for word in f:
                if hash_word(word, algo) == target_hash:
                    print(f"[+] Cracked: {word.strip()}")
                    log_result(word.strip(), target_hash, algo)
                    return
        print("[-] No match found.")

    elif args.mode == "rule":
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            for word in f:
                for variant in mutate(word.strip()):
                    if hash_word(variant, algo) == target_hash:
                        print(f"[+] Cracked: {variant}")
                        log_result(variant, target_hash, algo)
                        return
        print("[-] No match found.")

    elif args.mode == "brute":
        result = brute_force_parallel(target_hash, args.charset, args.maxlen, algo)
        if result:
            print(f"[+] Cracked: {result}")
            log_result(result, target_hash, algo)
        else:
            print("[-] No match found.")

    elif args.mode == "mask":
        for word in parse_mask(args.mask):
            if hash_word(word, algo) == target_hash:
                print(f"[+] Cracked: {word}")
                log_result(word, target_hash, algo)
                return
        print("[-] No match found.")

    elif args.mode == "combo":
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f1, open(args.wordlist2, "r", encoding="utf-8", errors="ignore") as f2:
            list1 = [w.strip() for w in f1]
            list2 = [w.strip() for w in f2]
            for w1 in list1:
                for w2 in list2:
                    for combo in [w1 + w2, w2 + w1]:
                        if hash_word(combo, algo) == target_hash:
                            print(f"[+] Cracked: {combo}")
                            log_result(combo, target_hash, algo)
                            return
        print("[-] No match found.")

if __name__ == "__main__":
    main()