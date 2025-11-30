def load_oui_db(path="oui.txt"):
    """Load IEEE OUI database file into a dictionary {prefix: vendor}"""
    db = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "(hex)" in line:
                    mac, vendor = line.split("(hex)")
                    prefix = mac.strip().replace("-", ":").lower()
                    db[prefix] = vendor.strip()
    except FileNotFoundError:
        print(f"[WARN] OUI file '{path}' not found.")
    except Exception as e:
        print(f"[WARN] Error loading OUI file: {e}")
    return db


def get_vendor(mac, db):
    """Lookup vendor from MAC using OUI database"""
    if not mac:
        return None
    prefix = mac.lower()[0:8]  # first 6 hex digits
    return db.get(prefix)
