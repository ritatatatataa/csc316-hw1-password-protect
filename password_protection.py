#!/usr/bin/env python3
"""
CSC316 - HW#1 : Password Protection
-----------------------------------
Demonstrates three ways of storing user passwords:

    Table 1 -> plain text            (insecure)
    Table 2 -> SHA-256(password)     (better, but breakable)
    Table 3 -> SHA-256(salt + password) with a unique per-user salt

Hashing is done with Python's standard `hashlib` library (SHA-256).
No hashing function is implemented by hand.

Salt construction (as required by the assignment):
    salt = SHA-256(username + user_id + timestamp)
It is deterministic and reproducible, but unique per user because the
user_id (UUID4) and the registration timestamp are unique per user.

NOTE: Printing passwords is done here ONLY for learning purposes.
      A real system must never log or display passwords.
"""

import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone

DB_FILE = "password_db.json"

EMPTY_DB = {
    "table1_plain": [],    # user_id / username / password_plain
    "table2_hashed": [],   # user_id / username / password_hash
    "table3_salted": [],   # user_id / username / salt / password_salted_hash
}


# --------------------------------------------------------------------------
# Storage helpers (a JSON file stands in for a database)
# --------------------------------------------------------------------------
def load_db():
    if not os.path.exists(DB_FILE):
        return json.loads(json.dumps(EMPTY_DB))
    with open(DB_FILE, "r", encoding="utf-8") as f:
        try:
            db = json.load(f)
        except json.JSONDecodeError:
            return json.loads(json.dumps(EMPTY_DB))
    for key in EMPTY_DB:
        db.setdefault(key, [])
    return db


def save_db(db):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)


# --------------------------------------------------------------------------
# Crypto helpers  (hashlib = existing, vetted library)
# --------------------------------------------------------------------------
def sha256_hex(text):
    """SHA-256 of a UTF-8 string, returned as a 64-char hex digest."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_salt(username, user_id, timestamp):
    """Deterministic, reproducible, and unique per user."""
    return sha256_hex(username + user_id + timestamp)


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------
def find_user(table, username):
    for row in table:
        if row["username"].lower() == username.lower():
            return row
    return None


def register(db, username, password):
    if find_user(db["table1_plain"], username):
        return None, "That username is already registered."

    user_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    salt = build_salt(username, user_id, timestamp)

    db["table1_plain"].append({
        "user_id": user_id,
        "username": username,
        "timestamp": timestamp,
        "password_plain": password,
    })

    db["table2_hashed"].append({
        "user_id": user_id,
        "username": username,
        "timestamp": timestamp,
        "password_hash": sha256_hex(password),
    })

    db["table3_salted"].append({
        "user_id": user_id,
        "username": username,
        "timestamp": timestamp,
        "salt": salt,
        "password_salted_hash": sha256_hex(salt + password),
    })

    save_db(db)
    return user_id, None


# --------------------------------------------------------------------------
# Login verification (bonus)
# --------------------------------------------------------------------------
def verify(db, username, password):
    """Check the candidate password against each of the three tables."""
    results = {}

    row1 = find_user(db["table1_plain"], username)
    results["Table 1 (plain)"] = (
        row1 is not None and row1["password_plain"] == password
    )

    row2 = find_user(db["table2_hashed"], username)
    results["Table 2 (hash)"] = (
        row2 is not None and row2["password_hash"] == sha256_hex(password)
    )

    row3 = find_user(db["table3_salted"], username)
    results["Table 3 (salt+hash)"] = (
        row3 is not None
        and row3["password_salted_hash"] == sha256_hex(row3["salt"] + password)
    )

    return results, (row1 is not None)


# --------------------------------------------------------------------------
# Display
# --------------------------------------------------------------------------
def line(char="="):
    print(char * 78)


def show_user(db, user_id):
    """Print the three stored versions of one freshly registered user."""
    r1 = next(r for r in db["table1_plain"] if r["user_id"] == user_id)
    r2 = next(r for r in db["table2_hashed"] if r["user_id"] == user_id)
    r3 = next(r for r in db["table3_salted"] if r["user_id"] == user_id)

    line()
    print("STORED RESULTS FOR THIS REGISTRATION")
    line()
    print(f"  user_id   : {r1['user_id']}")
    print(f"  username  : {r1['username']}")
    print(f"  timestamp : {r1['timestamp']}")
    print()
    print("  TABLE 1 - plain text")
    print(f"    password_plain       : {r1['password_plain']}")
    print()
    print("  TABLE 2 - SHA-256(password)")
    print(f"    password_hash        : {r2['password_hash']}")
    print()
    print("  TABLE 3 - SHA-256(salt + password)")
    print(f"    salt                 : {r3['salt']}")
    print(f"    password_salted_hash : {r3['password_salted_hash']}")
    line()


def show_all(db):
    if not db["table1_plain"]:
        print("\nNo users registered yet.\n")
        return

    line()
    print("TABLE 1 : PLAIN TEXT")
    line("-")
    print(f"{'user_id':38} {'username':14} password_plain")
    for r in db["table1_plain"]:
        print(f"{r['user_id']:38} {r['username']:14} {r['password_plain']}")

    print()
    line()
    print("TABLE 2 : UNSALTED SHA-256")
    line("-")
    for r in db["table2_hashed"]:
        print(f"{r['user_id']:38} {r['username']:14}")
        print(f"{'':38} hash: {r['password_hash']}")

    print()
    line()
    print("TABLE 3 : SALTED SHA-256")
    line("-")
    for r in db["table3_salted"]:
        print(f"{r['user_id']:38} {r['username']:14}")
        print(f"{'':38} salt: {r['salt']}")
        print(f"{'':38} hash: {r['password_salted_hash']}")
    line()
    print()


def dictionary_attack(db):
    """
    Shows WHY salting matters. An attacker who steals the tables can
    pre-compute SHA-256 for a list of common passwords once, and that one
    table breaks every unsalted entry at the same time. With per-user salts,
    the attacker has to redo the whole list separately for each user.
    """
    wordlist = ["123456", "password", "qwerty", "letmein", "admin",
                "iloveyou", "welcome", "monkey", "dragon", "abc123",
                "P@ssw0rd", "football", "111111", "sunshine"]

    rainbow = {sha256_hex(w): w for w in wordlist}   # built ONE time

    line()
    print(f"OFFLINE DICTIONARY ATTACK  ({len(wordlist)}-word list)")
    line("-")

    print("Table 1 -> nothing to crack, the passwords are simply read off.")
    for r in db["table1_plain"]:
        print(f"   {r['username']:14} -> {r['password_plain']}")

    print("\nTable 2 -> one pre-computed table is reused for every user:")
    cracked2 = 0
    for r in db["table2_hashed"]:
        guess = rainbow.get(r["password_hash"])
        if guess:
            cracked2 += 1
            print(f"   {r['username']:14} -> CRACKED: {guess}")
        else:
            print(f"   {r['username']:14} -> not in the word list")
    print(f"   hashes computed by the attacker: {len(wordlist)}")

    print("\nTable 3 -> the word list must be re-hashed with each user's salt:")
    cracked3 = 0
    work = 0
    for r in db["table3_salted"]:
        found = None
        for w in wordlist:
            work += 1
            if sha256_hex(r["salt"] + w) == r["password_salted_hash"]:
                found = w
                break
        if found:
            cracked3 += 1
            print(f"   {r['username']:14} -> CRACKED: {found}")
        else:
            print(f"   {r['username']:14} -> not in the word list")
    print(f"   hashes computed by the attacker: {work}")

    print()
    print(f"Weak passwords fall in both cases ({cracked2} vs {cracked3}), but the cost")
    print("for Table 3 grows with the number of users, and identical passwords")
    print("no longer produce identical hashes, so the leak reveals nothing extra.")
    line()
    print()


# --------------------------------------------------------------------------
# Menu
# --------------------------------------------------------------------------
MENU = """
============================ PASSWORD PROTECTION ============================
  1) Register a new user
  2) Display all three tables
  3) Log in (verify against each table)
  4) Run dictionary-attack demonstration
  5) Reset the database
  0) Exit
=============================================================================
"""


def main():
    db = load_db()

    while True:
        print(MENU)
        choice = input("Choice: ").strip()

        if choice == "1":
            username = input("  Username: ").strip()
            password = input("  Password: ").strip()
            if not username or not password:
                print("\n  Username and password cannot be empty.\n")
                continue
            user_id, err = register(db, username, password)
            if err:
                print(f"\n  {err}\n")
            else:
                show_user(db, user_id)

        elif choice == "2":
            show_all(db)

        elif choice == "3":
            username = input("  Username: ").strip()
            password = input("  Password: ").strip()
            results, exists = verify(db, username, password)
            if not exists:
                print("\n  No such user.\n")
                continue
            print()
            for table, ok in results.items():
                print(f"  {table:22} -> {'LOGIN SUCCESS' if ok else 'LOGIN FAILED'}")
            print()

        elif choice == "4":
            dictionary_attack(db)

        elif choice == "5":
            confirm = input("  Delete all stored users? (y/n): ").strip().lower()
            if confirm == "y":
                db = json.loads(json.dumps(EMPTY_DB))
                save_db(db)
                print("\n  Database cleared.\n")

        elif choice == "0":
            print("\nBye.\n")
            sys.exit(0)

        else:
            print("\n  Invalid choice.\n")


if __name__ == "__main__":
    main()
